package handler

import (
	"context"
	"fmt"
	"hosts++/internal/config"
	"hosts++/pkg/dns"
	"hosts++/pkg/logger"
	"hosts++/pkg/metrics"
	"hosts++/pkg/utils"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
)

type Handler struct {
	config      *config.Config
	logger      *logger.Logger
	metrics     *metrics.Metrics
	upgrader    websocket.Upgrader
	resolver    *dns.Resolver
	transport   http.RoundTripper
	certManager *CertManager
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
		resolver:    dns.NewResolver(cfg.UseSystemHosts),
		certManager: NewCertManager(time.Hour), // 1小时缓存
	}

	// 创建支持 HTTP/2 的 transport
	transport := &http.Transport{
		DialContext:     h.dialContext,
		TLSClientConfig: h.createTLSConfig(),
	}
	http2.ConfigureTransport(transport)

	// 如果配置了父代理，使用父代理
	if parentProxyURL := cfg.GetParentProxyURL(); parentProxyURL != nil {
		transport.Proxy = http.ProxyURL(parentProxyURL)
	}

	h.transport = transport

	return h
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

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.metrics.IncrementRequestCount()

	rule, realHost := h.findMatchingRule(r.Host)
	if rule == nil {
		if r.Method == http.MethodConnect {
			h.handleDirectConnect(w, r)
		} else {
			h.handleDirectRequest(w, r)
		}
		return
	}

	h.logger.Info("Mapping %s to %s", r.Host, realHost)

	if r.Method == http.MethodConnect {
		// 检查是否是 WebSocket 升级请求
		if websocket.IsWebSocketUpgrade(r) && rule.ProxyWebSocket {
			h.logger.Info("Detected WebSocket upgrade request for %s", r.Host)
			h.handleWebSocketConnect(w, r, realHost, rule)
		} else {
			h.handleConnect(w, r, realHost, rule)
		}
	} else if websocket.IsWebSocketUpgrade(r) {
		if rule.ProxyWebSocket {
			h.logger.Info("Handling WebSocket request for %s", r.Host)
			h.handleWebSocket(w, r, realHost, rule)
		} else {
			http.Error(w, "WebSocket proxying not enabled for this host", http.StatusForbidden)
			h.metrics.IncrementFailureCount()
		}
	} else {
		h.handleHTTP(w, r, realHost, rule)
	}
}

func (h *Handler) WithAPIHandler(apiHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" || r.URL.Path == "/api/" || r.URL.Path == "/api/rules" || r.URL.Path == "/api/rule" {
			apiHandler.ServeHTTP(w, r)
		} else {
			h.ServeHTTP(w, r)
		}
	})
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
