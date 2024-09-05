package handler

import (
	"bufio"
	"crypto/tls"
	"hosts++/internal/config"
	"net/http"
)

func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request, realHost string, rule *config.Rule) {
	h.logger.Info("Handling CONNECT request for: %s", r.Host)

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		h.logger.Error("Hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		h.metrics.IncrementFailureCount()
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		h.logger.Error("Failed to hijack connection: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		h.metrics.IncrementFailureCount()
		return
	}
	defer clientConn.Close()

	cert, err := h.certManager.GetCertificate(r.Host, realHost)
	if err != nil {
		h.logger.Error("Failed to get certificate: %v", err)
		h.metrics.IncrementFailureCount()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	req, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		h.logger.Error("Failed to read request from TLS connection: %v", err)
		h.metrics.IncrementFailureCount()
		return
	}

	req.URL.Scheme = "https"
	req.URL.Host = realHost
	req.Host = realHost

	h.applyHeaderRules(req.Header, rule.Headers.Request)

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		h.logger.Error("Failed to send request to target: %v", err)
		h.metrics.IncrementFailureCount()
		return
	}
	defer resp.Body.Close()

	h.applyHeaderRules(resp.Header, rule.Headers.Response)

	err = resp.Write(tlsConn)
	if err != nil {
		h.logger.Error("Failed to write response to client: %v", err)
		h.metrics.IncrementFailureCount()
		return
	}

	h.logger.Info("Successfully proxied HTTPS request")
	h.metrics.IncrementSuccessCount()
}
