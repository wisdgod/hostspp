package config

import (
	"fmt"
	"net/url"
	"strings"
)

type ProxyConfig struct {
	UseSystemProxy bool   `yaml:"use-system-proxy"`
	Enable         bool   `yaml:"enable"`
	Server         string `yaml:"server"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	Type           string `yaml:"type"`
}

// Validate 验证代理配置
func (c *ProxyConfig) Validate() error {
	if c.UseSystemProxy {
		return nil // 如果使用系统代理，不需要进一步验证
	}

	if !c.Enable {
		return nil // 如果代理未启用，不需要进一步验证
	}

	// 验证服务器地址
	if c.Server == "" {
		return fmt.Errorf("代理已启用但未指定服务器地址")
	}

	// 验证代理类型
	validTypes := map[string]bool{"http": true, "socks4": true, "socks5": true}
	if !validTypes[strings.ToLower(c.Type)] {
		return fmt.Errorf("无效的代理类型: %s", c.Type)
	}

	// 验证服务器地址格式
	if _, err := url.Parse(c.Server); err != nil {
		return fmt.Errorf("无效的代理服务器地址: %s", c.Server)
	}

	// 如果提供了用户名，确保也提供了密码
	if c.Username != "" && c.Password == "" {
		return fmt.Errorf("提供了用户名但未提供密码")
	}

	return nil
}
