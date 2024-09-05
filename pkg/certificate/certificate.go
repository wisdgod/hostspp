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
	"time"
)

var (
	rootCA  *x509.Certificate
	rootKey *ecdsa.PrivateKey
)

func init() {
	var err error
	rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	rootCA = &x509.Certificate{
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

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootCA, rootCA, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}

	rootCA, err = x509.ParseCertificate(rootCertDER)
	if err != nil {
		panic(err)
	}
}

func GenerateCert(host string, templateCert *x509.Certificate) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
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
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	return &cert, err
}

func GetRootCAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCA.Raw})
}
