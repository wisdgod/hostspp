package http

import (
	"errors"
	"fmt"
	"hosts++/pkg/ca"
	"hosts++/pkg/logger"
	"hosts++/pkg/proxy/config"
	"net"
	"net/http"
)

func getNetworkType(portType string) string {
	switch portType {
	case "http", "socks4", "socks5", "mixed":
		return "tcp"
	default:
		return "tcp" // 默认使用tcp
	}
}

// StartProxyServer 启动统一的代理服务器，同时处理HTTP和HTTPS请求
func StartProxyServer() (chan struct{}, error) {
	address := getListenAddress()
	logger.Infof("启动代理服务器，监听地址: %s", address)

	tlsConfig, err := createTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("创建 TLS 配置失败: %v", err)
	}

	listener, err := net.Listen(getNetworkType(config.Configure.PortType), address)
	if err != nil {
		logger.Errorf("无法启动代理服务器: %v", err)
		return nil, err
	}

	// 导出 PEM 格式的根证书
	if err := ca.ExportRootCert("./root_cert.crt"); err != nil {
		logger.Errorf("导出 PEM 格式根证书失败: %v", err)
	}

	// 导出 PKCS12 格式的证书
	if err := ca.Ca.ExportPKCS12("./root_cert.p12", "changeit"); err != nil {
		logger.Errorf("导出 PKCS12 格式证书失败: %v", err)
	}

	server := &http.Server{
		Handler:   http.HandlerFunc(handleRequest),
		TLSConfig: tlsConfig,
	}

	started := make(chan struct{})
	go func() {
		close(started)
		for {
			conn, err := listener.Accept()
			if err != nil {
				logger.Errorf("接受连接错误: %v", err)
				continue
			}
			go handleConnection(conn, server)
		}
	}()

	return started, nil
}

func handleConnection(conn net.Conn, server *http.Server) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	logger.Debugf("新连接来自: %s", remoteAddr)

	err := server.Serve(newSingleConnListener(conn))
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Debugf("服务连接时发生错误: %v", err)
	}
}

type singleConnListener struct {
	conn net.Conn
	done chan struct{}
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{
		conn: conn,
		done: make(chan struct{}),
	}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		<-l.done
		return nil, net.ErrClosed
	}
	c := l.conn
	l.conn = nil
	close(l.done)
	return c, nil
}

func (l *singleConnListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// getListenAddress 根据配置返回监听地址
func getListenAddress() string {
	if config.Configure.AllowLAN {
		return fmt.Sprintf("0.0.0.0:%d", config.Configure.Port)
	}
	return fmt.Sprintf("127.0.0.1:%d", config.Configure.Port)
}
