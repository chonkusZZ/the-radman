package manager

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"radman/internal/pki"
)

// WebTLS describes how the management web UI obtains its certificate.
type WebTLS struct {
	Mode    string   `json:"mode"` // selfsigned | uploaded | letsencrypt
	Domains []string `json:"domains"`
	Email   string   `json:"email"`
	Staging bool     `json:"staging"`
}

type webTLS struct {
	mu   sync.RWMutex
	mode string
	cert *tls.Certificate
	auto *autocert.Manager
}

func (w *webTLS) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	w.mu.RLock()
	mode, cert, auto := w.mode, w.cert, w.auto
	w.mu.RUnlock()
	if mode == "letsencrypt" && auto != nil {
		if c, err := auto.GetCertificate(h); err == nil {
			return c, nil
		}
		// fall back to the self-signed cert until issuance succeeds
	}
	if cert == nil {
		return nil, errors.New("no certificate available")
	}
	return cert, nil
}

func (a *App) WebTLSSettings(ctx context.Context) WebTLS {
	s := WebTLS{Mode: "selfsigned"}
	a.St.GetJSON(ctx, "webtls", &s)
	return s
}

// ReloadWebTLS applies the stored web TLS settings.
func (a *App) ReloadWebTLS(ctx context.Context) error {
	if a.web == nil {
		a.web = &webTLS{}
	}
	s := a.WebTLSSettings(ctx)
	self, err := a.selfSignedWebCert(ctx)
	if err != nil {
		return err
	}
	w := a.web
	w.mu.Lock()
	defer w.mu.Unlock()
	w.mode, w.cert, w.auto = s.Mode, self, nil
	switch s.Mode {
	case "uploaded":
		cp, kp, _ := a.getPEM(ctx, "web_uploaded")
		if cp != nil {
			if tc, err := tls.X509KeyPair(cp, kp); err == nil {
				w.cert = &tc
			} else {
				a.Log.Printf("uploaded web certificate unusable, using self-signed: %v", err)
			}
		}
	case "letsencrypt":
		if len(s.Domains) == 0 {
			break
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.Domains...),
			Cache:      &dbCache{a: a}, // shared by every manager instance, encrypted at rest
			Email:      s.Email,
		}
		if s.Staging {
			m.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
		}
		w.auto = m
	}
	return nil
}

func (a *App) selfSignedWebCert(ctx context.Context) (*tls.Certificate, error) {
	host := a.General(ctx).PublicHost
	cp, kp, _ := a.getPEM(ctx, "web_self")
	if cp != nil {
		if c, err := pki.ParseCert(cp); err == nil && time.Until(c.NotAfter) > 30*24*time.Hour && (host == "" || c.VerifyHostname(host) == nil) {
			if tc, err := tls.X509KeyPair(cp, kp); err == nil {
				return &tc, nil
			}
		}
	}
	names := []string{"localhost", "127.0.0.1", "::1"}
	if h, _ := hostnameGuess(); h != "" {
		names = append(names, h)
	}
	cp, kp, err := pki.SelfSigned(firstNonEmpty(host, "localhost"), names, 365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	if err := a.putPEM(ctx, "web_self", cp, kp); err != nil {
		return nil, err
	}
	tc, err := tls.X509KeyPair(cp, kp)
	return &tc, err
}

func (a *App) RegenerateSelfSigned(ctx context.Context) error {
	a.St.DelSecret(ctx, "web_self_cert")
	a.St.DelSecret(ctx, "web_self_key")
	return a.ReloadWebTLS(ctx)
}

// CreateWebCSR generates a key + CSR the admin can submit to a public CA.
func (a *App) CreateWebCSR(ctx context.Context, cn string, sans []string) (csrPEM string, err error) {
	csr, key, err := pki.NewCSR(cn, append([]string{cn}, sans...))
	if err != nil {
		return "", err
	}
	if err := a.St.SetSecret(ctx, "web_csr_key", a.seal(string(key))); err != nil {
		return "", err
	}
	if err := a.St.SetSecret(ctx, "web_csr_pem", a.seal(string(csr))); err != nil {
		return "", err
	}
	return string(csr), nil
}

func (a *App) PendingCSR(ctx context.Context) string {
	s, _ := a.St.GetSecret(ctx, "web_csr_pem")
	if s == "" {
		return ""
	}
	p, _ := a.open(s)
	return p
}

// InstallWebCert stores an uploaded certificate. If keyPEM is empty the key generated with the pending CSR is used.
func (a *App) InstallWebCert(ctx context.Context, certPEM, keyPEM []byte) error {
	certs, err := pki.ParseCerts(certPEM)
	if err != nil {
		return err
	}
	if len(keyPEM) == 0 {
		enc, _ := a.St.GetSecret(ctx, "web_csr_key")
		if enc == "" {
			return errors.New("no private key supplied and no pending CSR")
		}
		k, err := a.open(enc)
		if err != nil {
			return err
		}
		keyPEM = []byte(k)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return errors.New("certificate does not match the private key (for CSR flow: it must be issued for the CSR generated here)")
	}
	_ = certs
	if err := a.putPEM(ctx, "web_uploaded", certPEM, keyPEM); err != nil {
		return err
	}
	a.St.DelSecret(ctx, "web_csr_key")
	a.St.DelSecret(ctx, "web_csr_pem")
	s := a.WebTLSSettings(ctx)
	s.Mode = "uploaded"
	if err := a.St.SetJSON(ctx, "webtls", s); err != nil {
		return err
	}
	return a.ReloadWebTLS(ctx)
}

func (a *App) WebCertInfo(ctx context.Context) (subject string, notAfter time.Time, names []string) {
	if a.web == nil {
		return
	}
	a.web.mu.RLock()
	defer a.web.mu.RUnlock()
	if a.web.cert != nil {
		if c, err := pki.ParseCert(pki.EncodeCert(a.web.cert.Certificate[0])); err == nil {
			return c.Subject.CommonName, c.NotAfter, append(c.DNSNames, ipStrings(c.IPAddresses)...)
		}
	}
	return
}

func ipStrings(ips []net.IP) []string {
	var o []string
	for _, i := range ips {
		o = append(o, i.String())
	}
	return o
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
