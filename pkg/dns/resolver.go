package dns

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"

	"hosts++/pkg/logger"
)

type Resolver struct {
	useSystemHosts bool
	systemHosts    map[string]string
	cache          map[string][]net.IP
	cacheMutex     sync.RWMutex
	logger         *logger.Logger
}

func NewResolver(useSystemHosts bool) *Resolver {
	r := &Resolver{
		useSystemHosts: useSystemHosts,
		systemHosts:    make(map[string]string),
		cache:          make(map[string][]net.IP),
		logger:         logger.GetInstance(),
	}
	if useSystemHosts {
		r.loadSystemHosts()
	}
	return r
}

func (r *Resolver) loadSystemHosts() {
	file, err := os.Open(hostsFile)
	if err != nil {
		r.logger.Error("Failed to open hosts file (%s): %v", hostsFile, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ip := fields[0]
			for _, hostname := range fields[1:] {
				r.systemHosts[hostname] = ip
			}
		}
	}

	if err := scanner.Err(); err != nil {
		r.logger.Error("Error reading hosts file: %v", err)
	}
}

func (r *Resolver) Resolve(host string) ([]net.IP, error) {
	r.cacheMutex.RLock()
	if ips, ok := r.cache[host]; ok {
		r.cacheMutex.RUnlock()
		return ips, nil
	}
	r.cacheMutex.RUnlock()

	var ips []net.IP

	if r.useSystemHosts {
		if ip, ok := r.systemHosts[host]; ok {
			ips = append(ips, net.ParseIP(ip))
		}
	}

	if len(ips) == 0 {
		resolvedIPs, err := net.LookupIP(host)
		if err != nil {
			return nil, err
		}
		ips = resolvedIPs
	}

	r.cacheMutex.Lock()
	r.cache[host] = ips
	r.cacheMutex.Unlock()

	return ips, nil
}

func (r *Resolver) ClearCache() {
	r.cacheMutex.Lock()
	r.cache = make(map[string][]net.IP)
	r.cacheMutex.Unlock()
}
