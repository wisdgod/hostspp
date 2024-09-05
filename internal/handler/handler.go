package handler

import (
	"hosts++/internal/config"
	"hosts++/pkg/logger"
	"hosts++/pkg/metrics"
	"io"
	"math/rand"
	"net/http"
	"regexp"
)

type Handler struct {
	config  *config.Config
	logger  *logger.Logger
	metrics *metrics.Metrics
}

func New(cfg *config.Config) *Handler {
	return &Handler{
		config:  cfg,
		logger:  logger.GetInstance(),
		metrics: metrics.GetInstance(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.metrics.IncrementRequestCount()

	rule, realHost := h.findMatchingRule(r.Host)
	if rule == nil {
		http.Error(w, "Host not found in rules", http.StatusNotFound)
		h.metrics.IncrementFailureCount()
		return
	}

	h.logger.Info("Mapping %s to %s", r.Host, realHost)

	// 应用请求头规则
	h.applyHeaderRules(r.Header, rule.Headers.Request)

	// 创建新的请求
	outReq := new(http.Request)
	*outReq = *r
	outReq.URL.Scheme = "http"
	if r.TLS != nil {
		outReq.URL.Scheme = "https"
	}
	outReq.URL.Host = realHost
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

func (h *Handler) findMatchingRule(host string) (*config.Rule, string) {
	for _, rule := range h.config.Rules {
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
