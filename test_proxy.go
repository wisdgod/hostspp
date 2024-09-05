package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

func main() {
	// 读取 CA 证书
	caCert, err := os.ReadFile("ca.crt")
	if err != nil {
		fmt.Println("Error reading CA cert:", err)
		return
	}

	// 创建一个新的证书池并添加 CA 证书
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		fmt.Println("Failed to append CA cert")
		return
	}

	// 创建一个自定义的 TLS 配置
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	// 设置代理 URL
	proxyURL, _ := url.Parse("http://localhost:8080")

	// 创建一个自定义的 HTTP 客户端
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: tlsConfig,
		},
	}

	// 发送请求
	resp, err := client.Get("https://api.openai.com")
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	fmt.Println("Response status:", resp.Status)
	fmt.Println("Response body:", string(body)) // 只打印前100个字符
}
