package proxy

import (
	"bufio"
	"crypto/tls"
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
	config  *config.Config
	logger  *logger.Logger
	metrics *metrics.Metrics
}

func New(cfg *config.Config) *Proxy {
	return &Proxy{
		config:  cfg,
		logger:  logger.GetInstance(),
		metrics: metrics.GetInstance(),
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
	cert, err := certificate.GenerateCert(r.Host)
	if err != nil {
		p.logger.Error("Failed to generate certificate: %v", err)
		p.metrics.IncrementFailureCount()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
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
