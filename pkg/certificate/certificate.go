package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"hosts++/pkg/utils"
	"math/big"
	"os"
	"time"
)

var (
	rootCA  *x509.Certificate
	rootKey *ecdsa.PrivateKey
)

const (
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"
)

func init() {
	loadOrGenerateCA()
}

func loadOrGenerateCA() {
	var err error
	rootCA, rootKey, err = loadCA()
	if err != nil || isCAExpiringSoon(rootCA) {
		rootCA, rootKey, err = generateCA()
		if err != nil {
			panic(err)
		}
		if err := saveCA(rootCA, rootKey); err != nil {
			panic(err)
		}
	}
}

func loadCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return nil, nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Hosts++ Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func saveCA(cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(caCertFile, certPEM, 0644); err != nil {
		return err
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return os.WriteFile(caKeyFile, keyPEM, 0600)
}

func isCAExpiringSoon(cert *x509.Certificate) bool {
	return time.Now().Add(30 * 24 * time.Hour).After(cert.NotAfter)
}

func GenerateCert(host string, templateCert *x509.Certificate) (*tls.Certificate, []*x509.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	// 移除端口号
	host = utils.RemovePort(host)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	if templateCert != nil {
		template.NotBefore = templateCert.NotBefore
		template.NotAfter = templateCert.NotAfter
		template.KeyUsage = templateCert.KeyUsage
		template.ExtKeyUsage = templateCert.ExtKeyUsage
		template.DNSNames = append(template.DNSNames, templateCert.DNSNames...)
		template.IPAddresses = append(template.IPAddresses, templateCert.IPAddresses...)
		template.EmailAddresses = append(template.EmailAddresses, templateCert.EmailAddresses...)
		template.URIs = append(template.URIs, templateCert.URIs...)
		template.IsCA = templateCert.IsCA
		template.BasicConstraintsValid = templateCert.BasicConstraintsValid
		template.SubjectKeyId = templateCert.SubjectKeyId
		template.AuthorityKeyId = templateCert.AuthorityKeyId
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCA, &priv.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}

	// 解析生成的证书
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	// 创建证书链
	certChain := []*x509.Certificate{parsedCert, rootCA}

	return &cert, certChain, nil
}

func GetRootCAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCA.Raw})
}
