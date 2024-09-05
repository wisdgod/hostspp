package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"hosts++/internal/config"
	"hosts++/pkg/certificate"
	"hosts++/pkg/logger"
	"hosts++/pkg/metrics"
	"io"
	"net/http"
	"regexp"
	"time"

	"golang.org/x/exp/rand"
)

type Proxy struct {
	config      *config.Config
	logger      *logger.Logger
	metrics     *metrics.Metrics
	certManager *certificate.CertManager
}

func New(cfg *config.Config) *Proxy {
	return &Proxy{
		config:      cfg,
		logger:      logger.GetInstance(),
		metrics:     metrics.GetInstance(),
		certManager: certificate.NewCertManager(time.Hour), // 缓存1小时
	}
}

func (p *Proxy) WithAPIHandler(apiHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" || r.URL.Path == "/api/" || r.URL.Path == "/api/rules" || r.URL.Path == "/api/rule" {
			apiHandler.ServeHTTP(w, r)
		} else {
			p.handleRequest(w, r)
		}
	})
}

func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	p.metrics.IncrementRequestCount()

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}

	duration := time.Since(start)
	p.metrics.AddResponseTime(duration)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	p.logger.Info("Handling HTTP request for: %s", r.Host)

	rule, realHost := p.findMatchingRule(r.Host)
	if rule == nil {
		http.Error(w, "Host not found in rules", http.StatusNotFound)
		p.metrics.IncrementFailureCount()
		return
	}

	r.URL.Scheme = "http"
	r.URL.Host = realHost

	// 应用请求头规则
	p.applyHeaderRules(r.Header, rule.Headers.Request)

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		p.metrics.IncrementFailureCount()
		return
	}
	defer resp.Body.Close()

	// 应用响应头规则
	p.applyHeaderRules(resp.Header, rule.Headers.Response)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	p.metrics.IncrementSuccessCount()
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	p.logger.Info("Handling CONNECT request for: %s", r.Host)

	rule, realHost := p.findMatchingRule(r.Host)
	if rule == nil {
		p.logger.Error("Host not found in rules: %s", r.Host)
		http.Error(w, "Host not found in rules", http.StatusNotFound)
		p.metrics.IncrementFailureCount()
		return
	}
	p.logger.Info("Mapping %s to %s", r.Host, realHost)

	// 响应 CONNECT 请求
	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logger.Error("Hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		p.metrics.IncrementFailureCount()
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.logger.Error("Failed to hijack connection: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		p.metrics.IncrementFailureCount()
		return
	}
	defer clientConn.Close()

	// 为客户端连接创建 TLS 配置
	var cert *tls.Certificate
	var certChain []*x509.Certificate

	if p.config.CopyRealCertStatus {
		certInfo, exists := p.certManager.Get(realHost)
		if exists {
			cert = certInfo.Cert
			certChain = certInfo.Chain
		} else {
			cert, certChain, err = p.getRealServerCertAndChain(realHost)
			if err != nil {
				p.logger.Warn("Failed to get real server certificate, falling back to default: %v", err)
				cert, err = certificate.GenerateCert(r.Host, nil)
				if err != nil {
					p.logger.Error("Failed to generate fallback certificate: %v", err)
					p.metrics.IncrementFailureCount()
					return
				}
				certChain = []*x509.Certificate{cert.Leaf}
			} else {
				p.certManager.Set(realHost, cert, certChain)
			}
		}
	} else {
		cert, err = certificate.GenerateCert(r.Host, nil)
		if err != nil {
			p.logger.Error("Failed to generate certificate: %v", err)
			p.metrics.IncrementFailureCount()
			return
		}
		certChain = []*x509.Certificate{cert.Leaf}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cert, nil
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// 这里可以添加自定义的证书验证逻辑
			return nil
		},
	}

	// 如果我们有证书链，设置它
	if len(certChain) > 0 {
		tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{
				Certificate: [][]byte{cert.Certificate[0]},
				PrivateKey:  cert.PrivateKey,
				Leaf:        certChain[0],
			}, nil
		}
	}

	// 将连接升级为 TLS
	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	// 从 TLS 连接中读取 HTTP 请求
	req, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		p.logger.Error("Failed to read request from TLS connection: %v", err)
		p.metrics.IncrementFailureCount()
		return
	}

	// 修改请求以发送到真实主机
	req.URL.Scheme = "https"
	req.URL.Host = realHost
	req.Host = realHost

	// 应用请求头规则
	p.applyHeaderRules(r.Header, rule.Headers.Request)

	// 创建到真实主机的 HTTPS 连接
	targetConn, err := tls.Dial("tcp", realHost, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		p.logger.Error("Failed to connect to target: %v", err)
		p.metrics.IncrementFailureCount()
		return
	}
	defer targetConn.Close()

	// 发送请求到真实主机
	err = req.Write(targetConn)
	if err != nil {
		p.logger.Error("Failed to write request to target: %v", err)
		p.metrics.IncrementFailureCount()
		return
	}

	// 从真实主机读取响应
	resp, err := http.ReadResponse(bufio.NewReader(targetConn), req)
	if err != nil {
		p.logger.Error("Failed to read response from target: %v", err)
		p.metrics.IncrementFailureCount()
		return
	}
	defer resp.Body.Close()

	// 应用响应头规则
	p.applyHeaderRules(resp.Header, rule.Headers.Response)

	// 将响应发送回客户端
	err = resp.Write(tlsConn)
	if err != nil {
		p.logger.Error("Failed to write response to client: %v", err)
		p.metrics.IncrementFailureCount()
		return
	}

	p.logger.Info("Successfully proxied HTTPS request")
	p.metrics.IncrementSuccessCount()
}

func (p *Proxy) findMatchingRule(host string) (*config.Rule, string) {
	for _, rule := range p.config.Rules {
		switch rule.Type {
		case "single-to-single":
			if rule.FakeHosts[0] == host {
				return &rule, rule.RealHosts[0]
			}
		case "multi-to-single":
			for _, fakeHost := range rule.FakeHosts {
				if fakeHost == host {
					return &rule, rule.RealHosts[0]
				}
			}
		case "single-to-multi":
			if rule.FakeHosts[0] == host {
				return &rule, rule.RealHosts[rand.Intn(len(rule.RealHosts))]
			}
		case "multi-to-multi":
			re := regexp.MustCompile(rule.Pattern)
			if re.MatchString(host) {
				realHost := re.ReplaceAllString(host, rule.Replacement)
				return &rule, realHost
			}
		}
	}
	return nil, ""
}

func (p *Proxy) applyHeaderRules(headers http.Header, rules map[string]string) {
	for k, v := range rules {
		if v == "" {
			headers.Del(k)
		} else {
			headers.Set(k, v)
		}
	}
}

func (p *Proxy) getRealServerCertAndChain(host string) (*tls.Certificate, []*x509.Certificate, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // 当复制真实证书时，我们不需要验证
	}

	conn, err := tls.Dial("tcp", host, tlsConfig)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates found")
	}

	// 生成一个新的证书，模仿第一个（叶子）证书
	newCert, err := certificate.GenerateCert(host, certs[0])
	if err != nil {
		return nil, nil, err
	}

	return newCert, certs, nil
}
