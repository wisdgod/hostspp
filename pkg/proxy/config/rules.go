package config

import (
	"fmt"
	"hosts++/pkg/logger"
	"regexp"
	"strings"
	"sync"
)

// RuleSet 配置结构体
type RuleSet struct {
	Name  string `yaml:"name"`
	Rules []Rule `yaml:"rules"`
}

// Rule 配置结构体
type Rule struct {
	Type  string `yaml:"type"`
	From  string `yaml:"from"`
	To    string `yaml:"to"`
	Regex bool   `yaml:"regex"`
}

var (
	rulesMutex sync.RWMutex
	ruleCache  map[string]*regexp.Regexp
)

func init() {
	ruleCache = make(map[string]*regexp.Regexp)
}

// UpdateRules 动态更新代理规则
func (c *Config) UpdateRules(newRulesets []RuleSet) error {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()

	// 验证新规则
	if err := validateRules(newRulesets); err != nil {
		return err
	}

	c.Rulesets = newRulesets
	clearRuleCache()
	logger.Info("代理规则已更新")
	return nil
}

// ApplyRule 应用规则到给定的主机
func (c *Config) ApplyRule(host string) string {
	rulesMutex.RLock()
	defer rulesMutex.RUnlock()

	for _, ruleSet := range c.Rulesets {
		for _, rule := range ruleSet.Rules {
			newHost, applied := applyRule(rule, host)
			if applied {
				return newHost
			}
		}
	}
	return host
}

func applyRule(rule Rule, host string) (string, bool) {
	switch rule.Type {
	case "single-to-single":
		if rule.From == host {
			return rule.To, true
		}
	case "multi-to-single":
		for _, from := range strings.Split(rule.From, ",") {
			if strings.TrimSpace(from) == host {
				return rule.To, true
			}
		}
	case "single-to-multi":
		if rule.From == host {
			toHosts := strings.Split(rule.To, ",")
			return strings.TrimSpace(toHosts[0]), true // 可以改进为随机选择
		}
	case "multi-to-multi":
		if rule.Regex {
			re, err := getOrCompileRegex(rule.From)
			if err != nil {
				logger.Warningf("正则表达式编译失败: %v", err)
				return host, false
			}
			if re.MatchString(host) {
				return re.ReplaceAllString(host, rule.To), true
			}
		} else {
			fromHosts := strings.Split(rule.From, ",")
			toHosts := strings.Split(rule.To, ",")
			for i, from := range fromHosts {
				if strings.TrimSpace(from) == host && i < len(toHosts) {
					return strings.TrimSpace(toHosts[i]), true
				}
			}
		}
	}
	return host, false
}

func getOrCompileRegex(pattern string) (*regexp.Regexp, error) {
	if re, ok := ruleCache[pattern]; ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	ruleCache[pattern] = re
	return re, nil
}

func clearRuleCache() {
	ruleCache = make(map[string]*regexp.Regexp)
}

func validateRules(rulesets []RuleSet) error {
	for _, ruleset := range rulesets {
		for _, rule := range ruleset.Rules {
			if err := validateRule(rule); err != nil {
				return fmt.Errorf("规则集 '%s' 中的规则无效: %v", ruleset.Name, err)
			}
		}
	}
	return nil
}

func validateRule(rule Rule) error {
	switch rule.Type {
	case "single-to-single", "multi-to-single", "single-to-multi", "multi-to-multi":
		// 验证规则类型是否正确
	default:
		return fmt.Errorf("未知的规则类型: %s", rule.Type)
	}

	if rule.Regex {
		if _, err := regexp.Compile(rule.From); err != nil {
			return fmt.Errorf("无效的正则表达式: %s", rule.From)
		}
	}

	return nil
}
