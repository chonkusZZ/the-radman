// Package crl fetches CRLs and validates client certificates (chain, revocation, policy).
package crl

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"radman/internal/pki"
	"radman/internal/proto"
)

// Fetch downloads a CRL (DER or PEM) over http(s).
func Fetch(url string) ([]byte, *x509.RevocationList, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, nil, errors.New("only http(s) CRL URLs are supported")
	}
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, nil, err
	}
	rl, err := Parse(b)
	return b, rl, err
}

func Parse(b []byte) (*x509.RevocationList, error) {
	if bytesHasPEM(b) {
		if blk := pemDecode(b); blk != nil {
			b = blk
		}
	}
	return x509.ParseRevocationList(b)
}

// PKIState is a compiled PKI profile ready for validation.
type PKIState struct {
	Cfg    proto.PKI
	Roots  *x509.CertPool
	Inters *x509.CertPool
	CAs    []*x509.Certificate
	mu     sync.RWMutex
	crls   map[string]*entry // url -> parsed CRL
}

type entry struct {
	rl     *x509.RevocationList
	der    []byte
	source string
}

func Compile(p proto.PKI) (*PKIState, error) {
	cas, err := pki.ParseCerts([]byte(p.CAs))
	if err != nil {
		return nil, fmt.Errorf("PKI %q: %w", p.Name, err)
	}
	s := &PKIState{Cfg: p, Roots: x509.NewCertPool(), Inters: x509.NewCertPool(), CAs: cas, crls: map[string]*entry{}}
	for _, c := range cas {
		if c.CheckSignatureFrom(c) == nil && string(c.RawSubject) == string(c.RawIssuer) {
			s.Roots.AddCert(c)
		} else {
			s.Inters.AddCert(c)
		}
	}
	for u, der := range p.CRLs {
		if rl, err := Parse(der); err == nil {
			s.crls[u] = &entry{rl: rl, der: der, source: "manager"}
		}
	}
	return s, nil
}

// SetCRL stores a freshly fetched CRL if it is newer than what we hold.
func (s *PKIState) SetCRL(url string, der []byte, rl *x509.RevocationList, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.crls[url]; ok && old.rl.ThisUpdate.After(rl.ThisUpdate) {
		return
	}
	s.crls[url] = &entry{rl: rl, der: der, source: source}
}

func (s *PKIState) Status() []proto.CRLStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []proto.CRLStatus
	for u, e := range s.crls {
		out = append(out, proto.CRLStatus{URL: u, NextUpdate: e.rl.NextUpdate, Source: e.source})
	}
	return out
}

// NeedsRefresh reports URLs whose CRL is missing or past half of its validity.
func (s *PKIState) NeedsRefresh() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, u := range s.Cfg.CRLURLs {
		e, ok := s.crls[u]
		if !ok || time.Now().After(e.rl.ThisUpdate.Add(e.rl.NextUpdate.Sub(e.rl.ThisUpdate)/2)) {
			out = append(out, u)
		}
	}
	return out
}

// Verify builds a chain for leaf (+ presented intermediates) and checks revocation.
// Returns the verified chain.
func (s *PKIState) Verify(leaf *x509.Certificate, presented []*x509.Certificate, now time.Time) ([]*x509.Certificate, error) {
	inter := s.Inters.Clone()
	for _, c := range presented {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: s.Roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ch := range chains {
		if err := s.checkRevocation(ch, now); err != nil {
			lastErr = err
			continue
		}
		return ch, nil
	}
	return nil, lastErr
}

func (s *PKIState) checkRevocation(chain []*x509.Certificate, now time.Time) error {
	// every non-root cert in the chain is checked against the CRL of its issuer
	for i := 0; i < len(chain)-1; i++ {
		cert, issuer := chain[i], chain[i+1]
		s.mu.RLock()
		var found *entry
		for _, e := range s.crls {
			if string(e.rl.RawIssuer) == string(issuer.RawSubject) && e.rl.CheckSignatureFrom(issuer) == nil {
				if found == nil || e.rl.ThisUpdate.After(found.rl.ThisUpdate) {
					found = e
				}
			}
		}
		s.mu.RUnlock()
		if found == nil {
			if len(s.Cfg.CRLURLs) == 0 && i > 0 {
				continue // no CRL configured at all for intermediates
			}
			if len(s.Cfg.CRLURLs) == 0 {
				continue
			}
			if s.Cfg.StalePolicy == "fail_open" {
				continue
			}
			return fmt.Errorf("no CRL available for issuer %q (fail-closed)", issuer.Subject.CommonName)
		}
		if now.After(found.rl.NextUpdate.Add(time.Duration(s.Cfg.StaleGraceHours) * time.Hour)) {
			if s.Cfg.StalePolicy != "fail_open" {
				return fmt.Errorf("CRL for %q is stale (expired %s, fail-closed)", issuer.Subject.CommonName, found.rl.NextUpdate.Format(time.RFC3339))
			}
		}
		for _, r := range found.rl.RevokedCertificateEntries {
			if r.SerialNumber.Cmp(cert.SerialNumber) == 0 && !r.RevocationTime.After(now) {
				return fmt.Errorf("certificate serial %s revoked at %s", pki.SerialHex(cert), r.RevocationTime.Format(time.RFC3339))
			}
		}
	}
	return nil
}

// Decision is the outcome of evaluating policy for a verified certificate.
type Decision struct {
	Allow  bool
	VLAN   string
	Rule   string
	PKI    string
	Reason string
}

// Identity extracts match attributes from a certificate.
func SANs(c *x509.Certificate) []string {
	out := append([]string{}, c.DNSNames...)
	out = append(out, c.EmailAddresses...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	for _, u := range c.URIs {
		out = append(out, u.String())
	}
	out = append(out, otherNameUPNs(c)...)
	return out
}

func match(op, val, target string) bool {
	switch op {
	case "equals":
		return strings.EqualFold(target, val)
	case "contains":
		return strings.Contains(strings.ToLower(target), strings.ToLower(val))
	case "regex":
		re, err := regexp.Compile(val)
		return err == nil && re.MatchString(target)
	}
	return false
}

// Evaluate runs the ordered rules; first match wins, otherwise default action.
func Evaluate(p proto.Policy, leaf *x509.Certificate, pkiName string) Decision {
	for _, r := range p.Rules {
		var targets []string
		switch r.Field {
		case "subject_cn":
			targets = []string{leaf.Subject.CommonName}
		case "issuer_cn":
			targets = []string{leaf.Issuer.CommonName}
		case "san":
			targets = SANs(leaf)
		case "pki":
			targets = []string{pkiName}
		}
		for _, t := range targets {
			if match(r.Op, r.Value, t) {
				d := Decision{Allow: r.Action == "allow", VLAN: r.VLAN, Rule: r.Name, PKI: pkiName}
				if d.VLAN == "" {
					d.VLAN = p.DefaultVLAN
				}
				if !d.Allow {
					d.Reason = "denied by rule " + r.Name
				}
				return d
			}
		}
	}
	if p.DefaultAction == "deny" {
		return Decision{Reason: "no rule matched (default deny)", PKI: pkiName}
	}
	return Decision{Allow: true, VLAN: p.DefaultVLAN, Rule: "default", PKI: pkiName}
}
