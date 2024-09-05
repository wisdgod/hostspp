package utils

import (
	"net"
	"strings"
)

// SplitHostPort 分割主机名和端口
func SplitHostPort(hostport string) (host, port string) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, ""
	}
	return host, port
}

// JoinHostPort 连接主机名和端口
func JoinHostPort(host, port string) string {
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

// RemovePort 从主机名中移除端口
func RemovePort(host string) string {
	return strings.Split(host, ":")[0]
}
