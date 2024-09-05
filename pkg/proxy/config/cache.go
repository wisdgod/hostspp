package config

type CacheConfig struct {
	DNS        bool `yaml:"dns"`
	ProxyRules bool `yaml:"proxy-rules"`
}
