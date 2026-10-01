// Package pki contains the certificate helpers shared by the manager and nodes.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// CA is a certificate authority able to sign certificates.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n.Add(n, big.NewInt(1))
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// NewCA creates a self-signed ECDSA CA. Returns PEM cert and PEM key.
func NewCA(commonName string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"RadMAN"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = EncodeKey(key)
	return EncodeCert(der), keyPEM, err
}

func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	c, err := ParseCert(certPEM)
	if err != nil {
		return nil, err
	}
	k, err := ParseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: c, Key: k}, nil
}

// SignOpts controls leaf issuance.
type SignOpts struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	Validity   time.Duration
	Client     bool
	Server     bool
}

// Sign issues a leaf certificate for pub.
func (ca *CA) Sign(pub crypto.PublicKey, o SignOpts) ([]byte, *x509.Certificate, error) {
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: o.CommonName, Organization: []string{"RadMAN"}},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(o.Validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     o.DNSNames,
		IPAddresses:  o.IPs,
	}
	if o.Client {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if o.Server {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return EncodeCert(der), c, err
}

// SelfSigned creates a self-signed server certificate + key (PEM).
func SelfSigned(host string, names []string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host, Organization: []string{"RadMAN"}},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range append([]string{host}, names...) {
		if n == "" {
			continue
		}
		if ip := net.ParseIP(n); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = EncodeKey(key)
	return EncodeCert(der), keyPEM, err
}

// NewCSR builds a CSR PEM and key PEM for the given names.
func NewCSR(cn string, names []string) (csrPEM, keyPEM []byte, err error) {
	key, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	for _, n := range names {
		if n == "" {
			continue
		}
		if ip := net.ParseIP(n); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = EncodeKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), keyPEM, err
}

func ParseCSR(p []byte) (*x509.CertificateRequest, error) {
	b, _ := pem.Decode(p)
	if b == nil {
		return nil, errors.New("no PEM data in CSR")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, csr.CheckSignature()
}

func EncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func EncodeKey(k crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func ParseCert(p []byte) (*x509.Certificate, error) {
	cs, err := ParseCerts(p)
	if err != nil {
		return nil, err
	}
	return cs[0], nil
}

// ParseCerts parses every CERTIFICATE block (PEM). DER input is also accepted.
func ParseCerts(p []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := p
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		if c, err := x509.ParseCertificate(p); err == nil {
			return []*x509.Certificate{c}, nil
		}
		return nil, errors.New("no certificate found in input")
	}
	return out, nil
}

func ParseKey(p []byte) (crypto.Signer, error) {
	b, _ := pem.Decode(p)
	if b == nil {
		return nil, errors.New("no PEM data in key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key format")
}

func Fingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

func FingerprintPEM(p []byte) (string, error) {
	c, err := ParseCert(p)
	if err != nil {
		return "", err
	}
	return Fingerprint(c), nil
}

// SerialHex returns the lower-case hex serial of c.
func SerialHex(c *x509.Certificate) string { return strings.ToLower(c.SerialNumber.Text(16)) }

// Describe returns a short human description of a certificate.
func Describe(c *x509.Certificate) string {
	return fmt.Sprintf("%s (expires %s)", c.Subject.CommonName, c.NotAfter.Format("2006-01-02"))
}

// CRLURLs returns the CRL distribution points in c.
func CRLURLs(c *x509.Certificate) []string { return c.CRLDistributionPoints }

// SelfSignedRSA creates a self-signed RSA certificate (used as the SAML SP key pair).
func SelfSignedRSA(cn string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = EncodeKey(key)
	return EncodeCert(der), keyPEM, err
}
