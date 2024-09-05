package handler

import (
	"hosts++/internal/config"
	"hosts++/pkg/utils"
	"io"
	"net/http"
)

func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request, realHost string, rule *config.Rule) {
	h.applyHeaderRules(r.Header, rule.Headers.Request)

	host, port := utils.SplitHostPort(realHost)
	ips, err := h.resolver.Resolve(host)
	if err != nil {
		http.Error(w, "Failed to resolve host", http.StatusBadGateway)
		h.metrics.IncrementFailureCount()
		return
	}

	outReq := new(http.Request)
	*outReq = *r
	outReq.URL.Scheme = "http"
	if r.TLS != nil {
		outReq.URL.Scheme = "https"
	}
	outReq.URL.Host = utils.JoinHostPort(ips[0].String(), port)
	outReq.Host = realHost

	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		h.metrics.IncrementFailureCount()
		return
	}
	defer resp.Body.Close()

	h.applyHeaderRules(resp.Header, rule.Headers.Response)

	if r.TLS != nil {
		w.Header().Set("X-Certificate-Status", "Verified by proxy")
	}

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

func (h *Handler) applyHeaderRules(headers http.Header, rules map[string]string) {
	for k, v := range rules {
		if v == "" {
			headers.Del(k)
		} else {
			headers.Set(k, v)
		}
	}
}
