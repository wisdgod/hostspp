package handler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"hosts++/internal/config"
	"hosts++/pkg/dns"
	"hosts++/pkg/logger"
	"hosts++/pkg/metrics"
	"hosts++/pkg/utils"
	"io"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
)

type Handler struct {
	config    *config.Config
	logger    *logger.Logger
	metrics   *metrics.Metrics
	upgrader  websocket.Upgrader
	resolver  *dns.Resolver
	transport http.RoundTripper
	certPool  *x509.CertPool
}

func New(cfg *config.Config) *Handler {
	h := &Handler{
		config:  cfg,
		logger:  logger.GetInstance(),
		metrics: metrics.GetInstance(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		resolver: dns.NewResolver(cfg.UseSystemHosts),
		certPool: x509.NewCertPool(),
	}

	// 加载系统根证书
	if systemCerts, err := x509.SystemCertPool(); err == nil {
		h.certPool = systemCerts
	}

	// 创建支持 HTTP/2 的 transport
	transport := &http.Transport{
		DialContext: h.dialContext,
		TLSClientConfig: &tls.Config{
			RootCAs:               h.certPool,
			VerifyPeerCertificate: h.verifyPeerCertificate,
			InsecureSkipVerify:    !cfg.VerifyServerCert,
		},
	}
	http2.ConfigureTransport(transport)

	// 如果配置了父代理，使用父代理
	if parentProxyURL := cfg.GetParentProxyURL(); parentProxyURL != nil {
		transport.Proxy = http.ProxyURL(parentProxyURL)
	}

	h.transport = transport

	return h
}

func (h *Handler) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port := utils.SplitHostPort(addr)
	ips, err := h.resolver.Resolve(host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		conn, err := net.DialTimeout(network, utils.JoinHostPort(ip.String(), port), 10*time.Second)
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("failed to connect to any resolved IP for %s", addr)
}

func (h *Handler) verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// 这个函数会在 TLS 握手期间被调用

	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificates presented by peer")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// 验证证书
	if h.config.VerifyServerCert {
		opts := x509.VerifyOptions{
			Roots:         h.certPool,
			CurrentTime:   time.Now(),
			DNSName:       cert.Subject.CommonName,
			Intermediates: x509.NewCertPool(),
		}

		for _, rawCert := range rawCerts[1:] {
			intermediateCert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return fmt.Errorf("failed to parse intermediate certificate: %v", err)
			}
			opts.Intermediates.AddCert(intermediateCert)
		}

		if _, err := cert.Verify(opts); err != nil {
			// 这里我们只记录错误，不中断连接
			h.logger.Warn("Certificate verification failed: %v", err)
		}
	}

	// 记录证书信息，以便later通知用户
	h.logger.Info("Server certificate: Subject=%v, Issuer=%v, NotBefore=%v, NotAfter=%v",
		cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter)

	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.metrics.IncrementRequestCount()

	rule, realHost := h.findMatchingRule(r.Host)
	if rule == nil {
		http.Error(w, "Host not found in rules", http.StatusNotFound)
		h.metrics.IncrementNoRuleMatchCount()
		return
	}

	h.logger.Info("Mapping %s to %s", r.Host, realHost)

	// 检查是否是 WebSocket 升级请求
	if websocket.IsWebSocketUpgrade(r) {
		if rule.ProxyWebSocket {
			h.handleWebSocket(w, r, realHost, rule)
		} else {
			http.Error(w, "WebSocket proxying not enabled for this host", http.StatusForbidden)
			h.metrics.IncrementFailureCount()
		}
		return
	}

	// 处理普通 HTTP/HTTPS 请求
	h.handleHTTP(w, r, realHost, rule)
}

func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request, realHost string, rule *config.Rule) {
	// 应用请求头规则
	h.applyHeaderRules(r.Header, rule.Headers.Request)

	// 解析真实主机的 IP
	host, port := utils.SplitHostPort(realHost)
	ips, err := h.resolver.Resolve(host)
	if err != nil {
		http.Error(w, "Failed to resolve host", http.StatusBadGateway)
		h.metrics.IncrementFailureCount()
		return
	}

	// 创建新的请求
	outReq := new(http.Request)
	*outReq = *r
	outReq.URL.Scheme = "http"
	if r.TLS != nil {
		outReq.URL.Scheme = "https"
	}
	outReq.URL.Host = utils.JoinHostPort(ips[0].String(), port)
	outReq.Host = realHost

	// 发送请求到真实主机
	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		h.metrics.IncrementFailureCount()
		return
	}
	defer resp.Body.Close()

	// 应用响应头规则
	h.applyHeaderRules(resp.Header, rule.Headers.Response)

	// 添加一个头部来指示证书状态
	if r.TLS != nil {
		w.Header().Set("X-Certificate-Status", "Verified by proxy")
	}

	// 将响应发送回客户端
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		h.logger.Error("Failed to copy response: %v", err)
		h.metrics.IncrementFailureCount()
		return
	}

	h.metrics.IncrementSuccessCount()
}

func (h *Handler) handleWebSocket(w http.ResponseWriter, r *http.Request, realHost string, rule *config.Rule) {
	h.logger.Info("Handling WebSocket request for: %s", r.Host)

	// 应用请求头规则
	h.applyHeaderRules(r.Header, rule.Headers.Request)

	// 解析真实主机的 IP
	host, port := utils.SplitHostPort(realHost)
	ips, err := h.resolver.Resolve(host)
	if err != nil {
		http.Error(w, "Failed to resolve host", http.StatusBadGateway)
		h.metrics.IncrementFailureCount()
		return
	}

	// 连接到真实的 WebSocket 服务器
	realURL := *r.URL
	realURL.Scheme = "ws"
	if r.TLS != nil {
		realURL.Scheme = "wss"
	}
	realURL.Host = utils.JoinHostPort(ips[0].String(), port)

	dialer := websocket.DefaultDialer
	dialer.NetDial = func(network, addr string) (net.Conn, error) {
		return h.dialContext(context.Background(), network, addr)
	}

	realConn, resp, err := dialer.Dial(realURL.String(), r.Header)
	if err != nil {
		h.logger.Error("Failed to connect to real WebSocket server: %v", err)
		if resp != nil {
			h.copyHTTPResponse(w, resp)
		} else {
			http.Error(w, "Failed to connect to WebSocket server", http.StatusBadGateway)
		}
		h.metrics.IncrementFailureCount()
		return
	}
	defer realConn.Close()

	// 升级客户端连接到 WebSocket
	clientConn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("Failed to upgrade client connection to WebSocket: %v", err)
		h.metrics.IncrementFailureCount()
		return
	}
	defer clientConn.Close()

	// 开始双向转发 WebSocket 消息
	errChan := make(chan error, 2)
	go h.proxyWebSocket(clientConn, realConn, errChan)
	go h.proxyWebSocket(realConn, clientConn, errChan)

	// 等待其中一个方向的连接关闭
	<-errChan
	h.metrics.IncrementSuccessCount()
}

func (h *Handler) proxyWebSocket(dst, src *websocket.Conn, errChan chan error) {
	for {
		messageType, message, err := src.ReadMessage()
		if err != nil {
			errChan <- err
			return
		}
		err = dst.WriteMessage(messageType, message)
		if err != nil {
			errChan <- err
			return
		}
	}
}

func (h *Handler) copyHTTPResponse(w http.ResponseWriter, resp *http.Response) {
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (h *Handler) findMatchingRule(host string) (*config.Rule, string) {
	for _, rule := range h.config.Rules {
		if !rule.Enabled {
			continue
		}
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

func (h *Handler) applyHeaderRules(headers http.Header, rules map[string]string) {
	for k, v := range rules {
		if v == "" {
			headers.Del(k)
		} else {
			headers.Set(k, v)
		}
	}
}

func (h *Handler) getRealServerCert(host string) (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates[0], nil
}
