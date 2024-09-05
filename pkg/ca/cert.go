package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"hosts++/pkg/logger"
	"math/big"
	"net"
	"os"
	"time"
)

// Certificate 结构体用于存储 PEM 编码的证书和私钥
type Certificate struct {
	CertPEM []byte
	KeyPEM  []byte
}

// GenerateCert 方法为指定的主机名生成一个临时证书
func (ca *CA) GenerateCert(hostname string, validFor time.Duration) (*Certificate, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	logger.Infof("正在为主机名生成证书: %s", hostname)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("无法生成私钥: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("无法生成证书序列号: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, hostname)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.Cert, &priv.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("无法生成证书: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := encodePrivateKeyToPEM(priv)
	if err != nil {
		return nil, fmt.Errorf("无法编码私钥: %v", err)
	}

	logger.Infof("成功为主机名生成证书: %s", hostname)

	return &Certificate{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

func encodePrivateKeyToPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), nil
}

// SaveCertToFile 方法将生成的证书和私钥保存到指定的文件
func (cert *Certificate) SaveCertToFile(certPath, keyPath string) error {
	logger.Infof("正在将证书保存到文件: %s 和 %s", certPath, keyPath)

	if err := os.WriteFile(certPath, cert.CertPEM, 0644); err != nil {
		return fmt.Errorf("无法保存证书: %v", err)
	}

	if err := os.WriteFile(keyPath, cert.KeyPEM, 0600); err != nil {
		return fmt.Errorf("无法保存私钥: %v", err)
	}

	logger.Info("证书和私钥已成功保存到文件")
	return nil
}
