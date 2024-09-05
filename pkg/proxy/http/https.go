package http

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hosts++/pkg/ca"
	"hosts++/pkg/logger"
	"hosts++/pkg/proxy/config"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

var (
	certCache     = make(map[string]*tls.Certificate)
	certCacheLock sync.RWMutex
)

// createTLSConfig 创建TLS配置
func createTLSConfig() (*tls.Config, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Ca.Cert.Raw,
	})

	privKeyPEM, err := rsaPrivateKeyToPEM(ca.Ca.Key)
	if err != nil {
		logger.Errorf("无法编码私钥: %v", err)
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		logger.Errorf("无法创建X509密钥对: %v", err)
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return getCertificate(info)
		},
	}, nil
}

// rsaPrivateKeyToPEM 将RSA私钥转换为PEM格式
func rsaPrivateKeyToPEM(privateKey *rsa.PrivateKey) ([]byte, error) {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return privKeyPEM, nil
}

// handleHTTPS 处理HTTPS请求
func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	logger.Infof("处理HTTPS请求: %s", r.Host)

	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	modifiedHost := modifyHost(host)
	if modifiedHost != "" {
		host = modifiedHost
		logger.Infof("修改 Host: %s -> %s", r.Host, modifiedHost)
	}

	targetConn, err := net.Dial("tcp", host)
	if err != nil {
		logger.Errorf("无法连接到目标服务器: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logger.Error("Hijacking not supported")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		logger.Errorf("Hijack失败: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}

// getCertificate 获取或生成证书
func getCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certCacheLock.RLock()
	cert, ok := certCache[info.ServerName]
	certCacheLock.RUnlock()

	if ok {
		return cert, nil
	}

	certCacheLock.Lock()
	defer certCacheLock.Unlock()

	cert, ok = certCache[info.ServerName]
	if ok {
		return cert, nil
	}

	certificate, err := ca.Ca.GenerateCert(info.ServerName, config.Configure.CA.ValidFor)
	if err != nil {
		return nil, fmt.Errorf("生成证书失败: %v", err)
	}

	cert = new(tls.Certificate)
	*cert, err = tls.X509KeyPair(certificate.CertPEM, certificate.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %v", err)
	}

	certCache[info.ServerName] = cert

	return cert, nil
}
