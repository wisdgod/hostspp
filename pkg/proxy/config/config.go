package config

import (
	"crypto/x509/pkix"
	"fmt"
	"hosts++/pkg/ca"
	"hosts++/pkg/logger"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 版本
const ConfigVersion = "1.0"

var (
	Configure Config
	configMu  sync.RWMutex
)

// Config 结构体定义
type Config struct {
	Version  string      `yaml:"version"`
	PortType string      `yaml:"port-type"`
	Port     int         `yaml:"port"`
	AllowLAN bool        `yaml:"allow-lan"`
	Log      LogConfig   `yaml:"log"`
	DNS      DNSConfig   `yaml:"dns"`
	Proxy    ProxyConfig `yaml:"proxy"`
	Bypass   []string    `yaml:"bypass"`
	Cache    CacheConfig `yaml:"cache"`
	Rulesets []RuleSet   `yaml:"rulesets"`
	CA       ca.CAConfig `yaml:"ca"`
}

type CAConfigYAML struct {
	CertPath string        `yaml:"cert-path"`
	KeyPath  string        `yaml:"key-path"`
	ValidFor time.Duration `yaml:"valid-for"`
	Subject  struct {
		Organization       []string `yaml:"organization"`
		OrganizationalUnit []string `yaml:"organizational-unit"`
		CommonName         string   `yaml:"common-name"`
	} `yaml:"subject"`
}

// LoadConfig 从 YAML 配置文件加载配置
func LoadConfig(configPath string) error {
	configMu.Lock()
	defer configMu.Unlock()

	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("无法打开配置文件: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("无法读取配置文件: %v", err)
	}

	var tempConfig struct {
		Config
		CA CAConfigYAML `yaml:"ca"`
	}

	err = yaml.Unmarshal(data, &tempConfig)
	if err != nil {
		return fmt.Errorf("配置文件解析错误: %v", err)
	}

	newConfig := tempConfig.Config
	if newConfig.Version == "" {
		newConfig.Version = ConfigVersion
	}

	// 处理 CA 配置
	newConfig.CA = ca.CAConfig{
		CertPath: tempConfig.CA.CertPath,
		KeyPath:  tempConfig.CA.KeyPath,
		ValidFor: tempConfig.CA.ValidFor,
		Subject: pkix.Name{
			Organization:       tempConfig.CA.Subject.Organization,
			OrganizationalUnit: tempConfig.CA.Subject.OrganizationalUnit,
			CommonName:         tempConfig.CA.Subject.CommonName,
		},
	}

	setDefaultValues(&newConfig)

	if err := newConfig.Validate(); err != nil {
		return fmt.Errorf("配置验证失败: %v", err)
	}

	Configure = newConfig

	// 初始化日志
	if err := initLogger(); err != nil {
		return fmt.Errorf("日志初始化失败: %v", err)
	}

	// 初始化 CA
	if err := initCA(); err != nil {
		return fmt.Errorf("CA 初始化失败: %v", err)
	}

	logger.Infof("配置文件从 %s 加载成功", configPath)
	return nil
}

// Validate 验证整个配置的有效性
func (c *Config) Validate() error {
	if !isValidPortType(c.PortType) {
		return fmt.Errorf("无效的端口类型: %s", c.PortType)
	}

	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("无效的端口号: %d", c.Port)
	}

	if err := c.Log.Validate(); err != nil {
		return fmt.Errorf("日志配置无效: %v", err)
	}

	if err := c.DNS.Validate(); err != nil {
		return fmt.Errorf("DNS配置无效: %v", err)
	}

	if err := c.Proxy.Validate(); err != nil {
		return fmt.Errorf("代理配置无效: %v", err)
	}

	if err := validateRules(c.Rulesets); err != nil {
		return fmt.Errorf("规则配置无效: %v", err)
	}

	return nil
}

// ReloadConfig 重新加载配置
func ReloadConfig(configPath string) error {
	configMu.Lock()
	defer configMu.Unlock()

	newConfig := Config{}
	if err := LoadConfig(configPath); err != nil {
		return fmt.Errorf("重新加载配置失败: %v", err)
	}

	// 应用新配置
	Configure = newConfig

	// 重新初始化相关组件
	if err := initLogger(); err != nil {
		return fmt.Errorf("重新初始化日志失败: %v", err)
	}

	if err := initCA(); err != nil {
		return fmt.Errorf("重新初始化CA失败: %v", err)
	}

	logger.Info("配置已成功重新加载")
	return nil
}

// SaveConfig 将当前配置保存到文件
func SaveConfig(configPath string) error {
	configMu.RLock()
	defer configMu.RUnlock()

	data, err := yaml.Marshal(Configure)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %v", err)
	}

	err = os.WriteFile(configPath, data, 0644)
	if err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}

	logger.Infof("配置已保存到 %s", configPath)
	return nil
}

// setDefaultValues 设置默认值
func setDefaultValues(config *Config) {
	if strings.TrimSpace(config.PortType) == "" {
		config.PortType = "mixed"
	}

	if config.Port == 0 {
		config.Port = 7769
	}

	if config.Log.Level == "" {
		config.Log.Level = "info"
	}

	if config.Log.Output == "" {
		config.Log.Output = "console"
	}

	if config.Log.File == "" {
		config.Log.File = "./logs/hosts++.log"
	}

	if config.Log.Timezone == "" {
		config.Log.Timezone = "Local"
	}

	if !config.DNS.Enable {
		config.DNS.Nameserver = []string{}
	} else if len(config.DNS.Nameserver) == 0 {
		config.DNS.Nameserver = []string{
			"https://1.1.1.1/dns-query",
			"https://8.8.8.8/dns-query",
		}
	}

	if config.Proxy.UseSystemProxy {
		config.Proxy.Enable = false
	}

	if len(config.Rulesets) == 0 {
		config.Rulesets = []RuleSet{
			{
				Name: "default-rules",
				Rules: []Rule{
					{Type: "single-to-single", From: "api.openai.com:443", To: "my-api.wisdgod.com:443"},
				},
			},
		}
	}

	if config.CA.CertPath == "" {
		config.CA.CertPath = "./ca.pem"
	}

	if config.CA.KeyPath == "" {
		config.CA.KeyPath = "./ca.key"
	}

	if config.CA.ValidFor == 0 {
		config.CA.ValidFor = 8760 * time.Hour // 1 year
	}
}

func initLogger() error {
	return logger.InitLogger(
		logger.GetLevelInt(Configure.Log.Level),
		Configure.Log.Output,
		Configure.Log.File,
		Configure.Log.Timezone,
		Configure.Log.Archive,
		Configure.Log.Compress,
	)
}

func initCA() error {
	return ca.InitCA(Configure.CA)
}

func isValidPortType(portType string) bool {
	switch strings.ToLower(portType) {
	case "http", "socks4", "socks5", "mixed":
		return true
	default:
		return false
	}
}

// IsPortAvailable 检查端口是否可用
func IsPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// FindAvailablePort 查找可用端口
func FindAvailablePort(startPort int) int {
	for port := startPort; port < 65535; port++ {
		if IsPortAvailable(port) {
			return port
		}
	}
	return -1 // 没有找到可用端口
}

// GetConfigDir 获取配置文件目录
func GetConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	configDir := filepath.Join(homeDir, ".hosts++")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", err
	}
	return configDir, nil
}

// GetDefaultConfigPath 获取默认配置文件路径
func GetDefaultConfigPath() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "config.yaml"), nil
}

// GetConfig 获取当前配置的副本
func GetConfig() Config {
	configMu.RLock()
	defer configMu.RUnlock()
	return Configure
}

// UpdateConfig 更新配置
func UpdateConfig(updater func(*Config) error) error {
	configMu.Lock()
	defer configMu.Unlock()

	newConfig := Configure // 创建当前配置的副本
	if err := updater(&newConfig); err != nil {
		return err
	}

	if err := newConfig.Validate(); err != nil {
		return err
	}

	Configure = newConfig
	return nil
}
