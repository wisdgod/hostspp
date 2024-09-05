package handler

import (
	"crypto/tls"
	"hosts++/internal/config"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

func (h *Handler) handleWebSocketConnect(w http.ResponseWriter, r *http.Request, realHost string, rule *config.Rule) {
	h.logger.Debug("Handling WebSocket CONNECT request for %s", r.Host)

	// 应用规则中的请求头修改
	for k, v := range rule.Headers.Request {
		if v == "" {
			r.Header.Del(k)
		} else {
			r.Header.Set(k, v)
		}
	}

	// 建立到真实主机的 TCP 连接
	targetConn, err := net.DialTimeout("tcp", realHost, 10*time.Second)
	if err != nil {
		h.logger.Error("Failed to connect to real host: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer targetConn.Close()

	// 回复 CONNECT 请求
	w.WriteHeader(http.StatusOK)

	// 劫持连接
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		h.logger.Error("Hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		h.logger.Error("Hijacking failed: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	h.logger.Debug("WebSocket CONNECT request hijacked, starting bidirectional proxy")

	// 开始双向代理
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
	}()

	wg.Wait()
	h.logger.Debug("WebSocket CONNECT proxy completed")
}

func (h *Handler) handleWebSocket(w http.ResponseWriter, r *http.Request, realHost string, rule *config.Rule) {
	h.logger.Debug("Starting WebSocket handling for %s", r.Host)

	// 解析真实的WebSocket URL
	u, err := url.Parse(r.URL.String())
	if err != nil {
		h.logger.Error("Failed to parse URL: %v", err)
		http.Error(w, "Failed to parse URL", http.StatusInternalServerError)
		h.metrics.IncrementFailureCount()
		return
	}

	// 使用realHost替换主机名
	u.Host = realHost
	if r.TLS != nil {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}

	h.logger.Debug("Real WebSocket URL: %s", u.String())

	// 复制请求头
	header := make(http.Header)
	for k, v := range r.Header {
		header[k] = v
	}

	// 应用rule中的请求header修改
	h.applyHeaderRules(header, rule.Headers.Request)

	// 修改Origin头，如果存在的话
	if origin := header.Get("Origin"); origin != "" {
		originURL, err := url.Parse(origin)
		if err == nil {
			originURL.Host = realHost
			header.Set("Origin", originURL.String())
		}
	}

	h.logger.Debug("Modified headers: %v", header)

	// 升级客户端连接为WebSocket
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("Failed to upgrade client connection: %v", err)
		h.metrics.IncrementFailureCount()
		return
	}
	defer clientConn.Close()

	h.logger.Debug("Client WebSocket connection upgraded")

	// 连接到真实的WebSocket服务器
	dialer := websocket.DefaultDialer
	dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: !h.config.VerifyServerCert}
	serverConn, resp, err := dialer.Dial(u.String(), header)
	if err != nil {
		h.logger.Error("Failed to connect to WebSocket server: %v", err)
		if resp != nil {
			h.logger.Debug("Server response: %v", resp)
		}
		h.metrics.IncrementFailureCount()
		return
	}
	defer serverConn.Close()

	h.logger.Debug("Connected to real WebSocket server")

	// 使用 WaitGroup 来等待两个方向的转发都完成
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		h.proxyWebSocket(clientConn, serverConn, "client -> server")
	}()

	go func() {
		defer wg.Done()
		h.proxyWebSocket(serverConn, clientConn, "server -> client")
	}()

	h.logger.Debug("Started bidirectional WebSocket proxying")

	// 等待两个方向的转发都完成
	wg.Wait()

	h.logger.Debug("WebSocket proxying completed")
	h.metrics.IncrementSuccessCount()
}

func (h *Handler) proxyWebSocket(dst, src *websocket.Conn, direction string) {
	for {
		messageType, message, err := src.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				h.logger.Error("WebSocket read error (%s): %v", direction, err)
			} else {
				h.logger.Debug("WebSocket connection closed (%s): %v", direction, err)
			}
			break
		}

		h.logger.Debug("Received message (%s): type=%d, length=%d", direction, messageType, len(message))

		err = dst.WriteMessage(messageType, message)
		if err != nil {
			h.logger.Error("WebSocket write error (%s): %v", direction, err)
			break
		}

		h.logger.Debug("Forwarded message (%s): type=%d, length=%d", direction, messageType, len(message))
	}

	h.logger.Debug("Exiting WebSocket proxy loop (%s)", direction)
}
