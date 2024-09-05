package config

import (
	"fmt"
	"net/url"
)

type DNSConfig struct {
	Enable     bool     `yaml:"enable"`
	Nameserver []string `yaml:"nameserver"`
}

// Validate 验证DNS配置
func (c *DNSConfig) Validate() error {
	if !c.Enable {
		return nil // 如果DNS未启用，不需要进一步验证
	}

	if len(c.Nameserver) == 0 {
		return fmt.Errorf("DNS已启用但未指定nameserver")
	}

	for _, ns := range c.Nameserver {
		if _, err := url.Parse(ns); err != nil {
			return fmt.Errorf("无效的nameserver URL: %s", ns)
		}
	}

	return nil
}
