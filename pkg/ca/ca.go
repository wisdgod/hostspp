package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"hosts++/pkg/logger"
	"math/big"
	"os"
	"sync"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// CA 表示一个包含证书和私钥的证书颁发机构
type CA struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
	mu   sync.RWMutex
}

// CAConfig 包含 CA 的配置细节
type CAConfig struct {
	CertPath string        `yaml:"cert-path"`
	KeyPath  string        `yaml:"key-path"`
	ValidFor time.Duration `yaml:"valid-for"`
	Subject  pkix.Name     `yaml:"subject"`
}

// 全局 CA 实例
var Ca CA

// InitCA 初始化 CA，如果不存在则创建新的
func InitCA(config CAConfig) error {
	err := LoadCA(config.CertPath, config.KeyPath)
	if err != nil {
		logger.Warningf("加载CA失败，尝试生成新的CA: %v", err)
		return GenerateCA(config)
	}
	return nil
}

// LoadCA 从指定路径加载现有的 CA 证书和私钥
func LoadCA(certPath, keyPath string) error {
	Ca.mu.Lock()
	defer Ca.mu.Unlock()

	logger.Info("加载 CA 证书和私钥")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("读取 CA 证书文件失败: %v", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("读取 CA 私钥文件失败: %v", err)
	}

	cert, err := parseCertificate(certPEM)
	if err != nil {
		return err
	}

	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return err
	}

	Ca.Cert = cert
	Ca.Key = key

	logger.Info("成功加载 CA 证书和私钥")
	return nil
}

// GenerateCA 根据提供的配置生成新的 CA 证书和私钥
func GenerateCA(config CAConfig) error {
	Ca.mu.Lock()
	defer Ca.mu.Unlock()

	logger.Info("生成新的 CA 证书和私钥")

	// 使用RSA而不是ECDSA以提高兼容性
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("生成 CA 私钥失败: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("生成证书序列号失败: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               config.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(config.ValidFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("生成 CA 证书失败: %v", err)
	}

	Ca.Cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("解析生成的证书失败: %v", err)
	}
	Ca.Key = key

	if err := saveCertAndKey(config.CertPath, config.KeyPath, certDER, key); err != nil {
		return err
	}

	logger.Info("成功生成并保存 CA 证书和私钥")
	return nil
}

func ExportRootCert(certPath string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: Ca.Cert.Raw,
	})

	return os.WriteFile(certPath, certPEM, 0644)
}

// ExportPKCS12 exports the CA certificate and private key as a PKCS12 file
func (ca *CA) ExportPKCS12(filename string, password string) error {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	// Create PKCS12 data using Modern.Encode
	pfxData, err := pkcs12.Modern.Encode(ca.Key, ca.Cert, nil, password)
	if err != nil {
		return fmt.Errorf("无法创建 PKCS12 数据: %v", err)
	}

	// Write to file
	err = os.WriteFile(filename, pfxData, 0600)
	if err != nil {
		return fmt.Errorf("无法写入 PKCS12 文件: %v", err)
	}

	return nil
}

func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("无效的 CA 证书文件")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("无效的 CA 私钥文件")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func saveCertAndKey(certPath, keyPath string, certDER []byte, key *rsa.PrivateKey) error {
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("创建证书文件失败: %v", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建私钥文件失败: %v", err)
	}
	defer keyOut.Close()
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

	return nil
}
