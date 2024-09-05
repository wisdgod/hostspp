package handler

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

func (h *Handler) handleDirectConnect(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("No matching rule found, forwarding CONNECT request directly: %s", r.Host)

	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		h.metrics.IncrementFailureCount()
		return
	}
	defer targetConn.Close()

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		h.metrics.IncrementFailureCount()
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		h.metrics.IncrementFailureCount()
		return
	}
	defer clientConn.Close()

	go transfer(targetConn, clientConn)
	transfer(clientConn, targetConn)

	h.metrics.IncrementSuccessCount()
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func (h *Handler) handleDirectRequest(w http.ResponseWriter, r *http.Request) {
	// 构建正确的URL
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.RequestURI())
	h.logger.Info("No matching rule found, forwarding request directly: %s", url)

	// 创建一个新的 Transport，不使用我们的证书验证逻辑
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // 使用系统的证书验证
		},
	}

	// 创建一个新的 http.Client 使用这个 transport
	client := &http.Client{Transport: transport}

	// 创建一个新的请求，使用正确构建的URL
	outreq, err := http.NewRequestWithContext(r.Context(), r.Method, url, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		h.metrics.IncrementFailureCount()
		return
	}

	// 复制原始请求的headers
	outreq.Header = make(http.Header)
	for k, v := range r.Header {
		outreq.Header[k] = v
	}

	// 执行请求
	resp, err := client.Do(outreq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		h.metrics.IncrementFailureCount()
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// 写入状态码
	w.WriteHeader(resp.StatusCode)

	// 复制响应体
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		h.logger.Error("Failed to copy response body: %v", err)
		h.metrics.IncrementFailureCount()
		return
	}

	h.metrics.IncrementSuccessCount()
}
