package config

import (
	"net/url"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	Type           string   `yaml:"type"`
	Enabled        bool     `yaml:"enabled"`
	FakeHosts      []string `yaml:"fake_hosts"`
	RealHosts      []string `yaml:"real_hosts"`
	Pattern        string   `yaml:"pattern,omitempty"`
	Replacement    string   `yaml:"replacement,omitempty"`
	Headers        Headers  `yaml:"headers"`
	ProxyWebSocket bool     `yaml:"proxy_websocket"`
}

type Headers struct {
	Request  map[string]string `yaml:"request"`
	Response map[string]string `yaml:"response"`
}

type Config struct {
	ListenAddr         string          `yaml:"listen_addr"`
	Rules              map[string]Rule `yaml:"rules"`
	LogLevel           string          `yaml:"log_level"`
	UseSystemHosts     bool            `yaml:"use_system_hosts"`
	DNSCacheDuration   time.Duration   `yaml:"dns_cache_duration"`
	ParentProxy        string          `yaml:"parent_proxy"`
	VerifyServerCert   bool            `yaml:"verify_server_cert"`
	CopyRealCertStatus bool            `yaml:"copy_real_cert_status"`
	mu                 sync.RWMutex
	parentProxyURL     *url.URL
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	if cfg.Rules == nil {
		cfg.Rules = make(map[string]Rule)
	}

	if cfg.ParentProxy != "" {
		proxyURL, err := url.Parse(cfg.ParentProxy)
		if err != nil {
			return nil, err
		}
		cfg.parentProxyURL = proxyURL
	}

	return &cfg, nil
}

func (c *Config) Save(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (c *Config) AddRule(name string, rule Rule) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Rules[name] = rule
}

func (c *Config) RemoveRule(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.Rules, name)
}

func (c *Config) GetRules() map[string]Rule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rules := make(map[string]Rule)
	for k, v := range c.Rules {
		rules[k] = v
	}
	return rules
}

func (c *Config) GetParentProxyURL() *url.URL {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.parentProxyURL
}
