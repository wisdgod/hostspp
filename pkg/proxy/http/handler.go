package http

import (
	"hosts++/pkg/logger"
	"hosts++/pkg/proxy/config"
	"io"
	"net/http"
	"regexp"
	"strings"

	"golang.org/x/exp/rand"
)

// handleRequest 处理所有incoming请求
func handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		handleHTTPS(w, r)
	} else {
		handleHTTP(w, r)
	}
}

// handleHTTP 处理HTTP请求
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infof("处理HTTP请求: %s %s", r.Method, r.URL)

	modifiedHost := modifyHost(r.Host)
	if modifiedHost != "" {
		r.Host = modifiedHost
		r.URL.Host = modifiedHost
		logger.Infof("修改 Host: %s -> %s", r.Host, modifiedHost)
	}

	proxyReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		logger.Errorf("创建代理请求失败: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	proxyReq.Header = make(http.Header)
	for h, val := range r.Header {
		proxyReq.Header[h] = val
	}

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		logger.Errorf("发送请求到目标服务器失败: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for h, val := range resp.Header {
		w.Header()[h] = val
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// modifyHost 根据规则修改Host
func modifyHost(originalHost string) string {
	for _, ruleSet := range config.Configure.Rulesets {
		for _, rule := range ruleSet.Rules {
			switch rule.Type {
			case "single-to-single":
				if rule.From == originalHost {
					return rule.To
				}
			case "multi-to-single":
				for _, from := range strings.Split(rule.From, ",") {
					if strings.TrimSpace(from) == originalHost {
						return rule.To
					}
				}
			case "single-to-multi":
				if rule.From == originalHost {
					toHosts := strings.Split(rule.To, ",")
					return strings.TrimSpace(toHosts[rand.Intn(len(toHosts))])
				}
			case "multi-to-multi":
				if rule.Regex {
					re, err := regexp.Compile(rule.From)
					if err != nil {
						logger.Warningf("正则表达式编译失败: %v", err)
						continue
					}
					if re.MatchString(originalHost) {
						replacedHost := re.ReplaceAllString(originalHost, rule.To)
						logger.Infof("multi-to-multi (regex): %s -> %s", originalHost, replacedHost)
						return replacedHost
					}
				} else {
					fromHosts := strings.Split(rule.From, ",")
					toHosts := strings.Split(rule.To, ",")
					for i, from := range fromHosts {
						if strings.TrimSpace(from) == originalHost && i < len(toHosts) {
							return strings.TrimSpace(toHosts[i])
						}
					}
				}
			}
		}
	}
	return originalHost
}
