package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"hosts++/pkg/certificate"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
	"golang.org/x/sync/singleflight"
)

type CertManager struct {
	cache      map[string]*CertInfo
	mutex      sync.RWMutex
	expiration time.Duration
	rootCAs    *x509.CertPool
}

type CertInfo struct {
	Cert  *tls.Certificate
	Chain []*x509.Certificate
}

type certCacheEntry struct {
	verifiedChains [][]*x509.Certificate
	ocspResponse   *ocsp.Response
	crlValid       bool
	expiresAt      time.Time
}

var (
	certCache   sync.Map
	verifyGroup singleflight.Group
)

func NewCertManager(expiration time.Duration) *CertManager {
	cm := &CertManager{
		cache:      make(map[string]*CertInfo),
		expiration: expiration,
		rootCAs:    x509.NewCertPool(),
	}

	// 加载系统根证书
	if systemCerts, err := x509.SystemCertPool(); err == nil {
		cm.rootCAs = systemCerts
	}

	return cm
}

func (cm *CertManager) GetCertificate(host, realHost string) (*tls.Certificate, error) {
	cm.mutex.RLock()
	certInfo, exists := cm.cache[realHost]
	cm.mutex.RUnlock()

	if exists {
		return certInfo.Cert, nil
	}

	cert, chain, err := cm.generateCertificate(host, realHost)
	if err != nil {
		return nil, err
	}

	cm.mutex.Lock()
	cm.cache[realHost] = &CertInfo{Cert: cert, Chain: chain}
	cm.mutex.Unlock()

	return cert, nil
}

func (cm *CertManager) generateCertificate(host, realHost string) (*tls.Certificate, []*x509.Certificate, error) {
	realCert, err := getRealServerCert(realHost)
	if err != nil {
		return certificate.GenerateCert(host, nil)
	}

	return certificate.GenerateCert(host, realCert)
}

func getRealServerCert(host string) (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	return certs[0], nil
}

func (h *Handler) createTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: !h.config.VerifyServerCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return h.verifyPeerCertificate(rawCerts, verifiedChains)
		},
		RootCAs: h.certManager.GetRootCAs(),
	}
}

func (h *Handler) verifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if !h.config.VerifyServerCert || h.config.CopyRealCertStatus {
		return nil
	}

	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificates presented by peer")
	}

	certs := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return fmt.Errorf("failed to parse certificate #%d: %v", i, err)
		}
		certs[i] = cert
	}

	// 使用 singleflight 来防止对同一证书的并发验证
	cacheKey := string(rawCerts[0])
	result, err, _ := verifyGroup.Do(cacheKey, func() (interface{}, error) {
		return h.verifyCertificate(certs)
	})

	if err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}

	h.logger.Info("Certificate verification succeeded")
	entry := result.(certCacheEntry)
	for i, chain := range entry.verifiedChains {
		h.logger.Info("Verified chain #%d:", i)
		for j, cert := range chain {
			h.logger.Info("  Certificate #%d: Subject=%v, Issuer=%v, NotBefore=%v, NotAfter=%v",
				j, cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter)
		}
	}

	return nil
}

func (h *Handler) verifyCertificate(certs []*x509.Certificate) (certCacheEntry, error) {
	// 检查缓存
	if entry, ok := certCache.Load(string(certs[0].Raw)); ok {
		cachedEntry := entry.(certCacheEntry)
		if time.Now().Before(cachedEntry.expiresAt) {
			h.logger.Info("Using cached certificate verification result")
			return cachedEntry, nil
		}
	}

	// 验证证书链
	opts := x509.VerifyOptions{
		Roots:         h.certManager.GetRootCAs(),
		CurrentTime:   time.Now(),
		DNSName:       certs[0].Subject.CommonName,
		Intermediates: x509.NewCertPool(),
	}

	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}

	chains, err := certs[0].Verify(opts)
	if err != nil {
		return certCacheEntry{}, fmt.Errorf("certificate chain verification failed: %v", err)
	}

	entry := certCacheEntry{
		verifiedChains: chains,
		expiresAt:      time.Now().Add(h.config.CertCacheExpiration),
	}

	// OCSP 检查
	if h.config.EnableOCSP {
		ocspResp, err := h.checkOCSP(certs[0], certs[1])
		if err != nil {
			h.logger.Warn("OCSP check failed: %v", err)
		} else {
			entry.ocspResponse = ocspResp
			if ocspResp.Status == ocsp.Revoked {
				return entry, fmt.Errorf("certificate has been revoked")
			}
		}
	}

	// CRL 检查
	if h.config.EnableCRL {
		crlValid, err := h.checkCRL(certs[0])
		if err != nil {
			h.logger.Warn("CRL check failed: %v", err)
		} else {
			entry.crlValid = crlValid
			if !crlValid {
				return entry, fmt.Errorf("certificate is in the CRL")
			}
		}
	}

	// 更新缓存
	certCache.Store(string(certs[0].Raw), entry)

	return entry, nil
}

func (h *Handler) checkOCSP(cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	// 获取 OCSP 服务器 URL
	if len(cert.OCSPServer) == 0 {
		return nil, fmt.Errorf("no OCSP server specified")
	}

	// 创建 OCSP 请求
	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating OCSP request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), h.config.OCSPTimeout)
	defer cancel()

	// 发送 OCSP 请求
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cert.OCSPServer[0], bytes.NewReader(ocspReq))
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP request: %v", err)
	}
	httpReq.Header.Add("Content-Type", "application/ocsp-request")

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("error sending OCSP request: %v", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading OCSP response: %v", err)
	}

	// 解析 OCSP 响应
	ocspResp, err := ocsp.ParseResponse(body, issuer)
	if err != nil {
		return nil, fmt.Errorf("error parsing OCSP response: %v", err)
	}

	return ocspResp, nil
}

func (h *Handler) checkCRL(cert *x509.Certificate) (bool, error) {
	if len(cert.CRLDistributionPoints) == 0 {
		return true, nil
	}

	for _, crlDP := range cert.CRLDistributionPoints {
		ctx, cancel := context.WithTimeout(context.Background(), h.config.CRLTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlDP, nil)
		if err != nil {
			continue
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		crlBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			continue
		}

		for _, revokedCert := range crl.RevokedCertificateEntries {
			if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
				return false, nil
			}
		}
	}

	return true, nil
}

func (cm *CertManager) GetRootCAs() *x509.CertPool {
	return cm.rootCAs
}

// 更新根证书池
func (cm *CertManager) UpdateRootCAs() error {
	newPool, err := x509.SystemCertPool()
	if err != nil {
		return err
	}
	cm.rootCAs = newPool
	return nil
}
