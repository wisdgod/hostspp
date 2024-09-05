package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"
)

type CertManager struct {
	cache      map[string]*CertInfo
	mutex      sync.RWMutex
	expiration time.Duration
}

type CertInfo struct {
	Cert      *tls.Certificate
	Chain     []*x509.Certificate
	ExpiresAt time.Time
}

func NewCertManager(expiration time.Duration) *CertManager {
	return &CertManager{
		cache:      make(map[string]*CertInfo),
		expiration: expiration,
	}
}

func (cm *CertManager) Get(host string) (*CertInfo, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	info, exists := cm.cache[host]
	if !exists {
		return nil, false
	}

	if time.Now().After(info.ExpiresAt) {
		delete(cm.cache, host)
		return nil, false
	}

	return info, true
}

func (cm *CertManager) Set(host string, cert *tls.Certificate, chain []*x509.Certificate) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.cache[host] = &CertInfo{
		Cert:      cert,
		Chain:     chain,
		ExpiresAt: time.Now().Add(cm.expiration),
	}
}
