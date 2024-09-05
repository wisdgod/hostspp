package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// LogConfig 结构定义，用于配置日志系统
type LogConfig struct {
	Level    string `yaml:"level"`    // 日志级别
	Output   string `yaml:"output"`   // 输出方式（控制台、文件、双输出、无输出）
	File     string `yaml:"file"`     // 日志文件路径
	Timezone string `yaml:"timezone"` // 时区配置
	Archive  bool   `yaml:"archive"`  // 是否启用日志归档
	Compress bool   `yaml:"compress"` // 是否在归档后压缩日志文件
}

// Validate 验证日志配置
func (c *LogConfig) Validate() error {
	// 验证日志级别
	validLevels := map[string]bool{"debug": true, "info": true, "warning": true, "error": true}
	if !validLevels[c.Level] {
		return fmt.Errorf("无效的日志级别: %s", c.Level)
	}

	// 验证输出方式
	validOutputs := map[string]bool{"console": true, "file": true, "both": true, "none": true}
	if !validOutputs[c.Output] {
		return fmt.Errorf("无效的日志输出方式: %s", c.Output)
	}

	// 如果输出方式包含文件，验证文件路径
	if c.Output == "file" || c.Output == "both" {
		dir := filepath.Dir(c.File)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("日志文件目录不存在: %s", dir)
		}
	}

	// 验证时区
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return fmt.Errorf("无效的时区: %s", c.Timezone)
	}

	return nil
}
