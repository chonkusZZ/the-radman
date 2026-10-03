package crl

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"radman/internal/pki"
	"radman/internal/proto"
)

// azureChain mirrors Microsoft Azure Cloud PKI: a root CA, an issuing CA below it, and client certificates from the issuing CA.
// Only the issuing CA publishes a CRL; the root has none.
type azureChain struct {
	root, issuing *pki.CA
	bundle        string
}

func newAzureChain(t *testing.T) *azureChain {
	rc, rk, _ := pki.NewRootCA("Cloud PKI Root", 24*time.Hour)
	root, _ := pki.LoadCA(rc, rk)
	ic, ik, err := pki.NewIntermediate(root, "Cloud PKI Issuing CA", 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuing, _ := pki.LoadCA(ic, ik)
	return &azureChain{root, issuing, string(rc) + string(ic)}
}

func (c *azureChain) leaf(t *testing.T, ca *pki.CA) *x509.Certificate {
	k, _ := pki.GenerateKey()
	_, cert, err := ca.Sign(&k.PublicKey, pki.SignOpts{CommonName: "device", Validity: time.Hour, Client: true})
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func makeCRL(t *testing.T, ca *pki.CA, this, next time.Time, revoked ...*big.Int) []byte {
	tpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: this, NextUpdate: next}
	for _, s := range revoked {
		tpl.RevokedCertificateEntries = append(tpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: this})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (c *azureChain) state(t *testing.T, policy string, grace int, crls map[string][]byte) *PKIState {
	cfg := proto.PKI{ID: "1", Name: "Azure", CAs: c.bundle, CRLURLs: []string{"http://crl.test/issuing.crl"}, CRLs: crls, StalePolicy: policy, StaleGraceHours: grace}
	st, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestAzureCloudPKIIssuingCRLOnly(t *testing.T) {
	c := newAzureChain(t)
	now := time.Now()
	leaf := c.leaf(t, c.issuing)
	goodCRL := makeCRL(t, c.issuing, now.Add(-time.Hour), now.Add(24*time.Hour))
	revokedCRL := makeCRL(t, c.issuing, now.Add(-time.Hour), now.Add(24*time.Hour), leaf.SerialNumber)
	staleCRL := makeCRL(t, c.issuing, now.Add(-72*time.Hour), now.Add(-48*time.Hour))
	crls := func(der []byte) map[string][]byte { return map[string][]byte{"http://crl.test/issuing.crl": der} }

	// the reported bug: fail-closed with a CRL for the issuing CA only (the root has none) must ACCEPT a good client
	if _, err := c.state(t, "fail_closed", 24, crls(goodCRL)).Verify(leaf, nil, now); err != nil {
		t.Fatalf("good client rejected although the issuing CA's CRL is present and the root has none: %v", err)
	}
	// ... and still reject a revoked one
	if _, err := c.state(t, "fail_closed", 24, crls(revokedCRL)).Verify(leaf, nil, now); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked client must be rejected: %v", err)
	}
	// fail-closed: CRL configured but not downloaded yet -> reject; fail-open -> accept
	if _, err := c.state(t, "fail_closed", 24, nil).Verify(leaf, nil, now); err == nil || !strings.Contains(err.Error(), "Cloud PKI Issuing CA") {
		t.Fatalf("missing CRL for the issuing CA must fail closed: %v", err)
	}
	if _, err := c.state(t, "fail_open", 24, nil).Verify(leaf, nil, now); err != nil {
		t.Fatalf("fail-open should accept without a CRL: %v", err)
	}
	// stale CRL: beyond the grace period fail-closed rejects, within it accepts
	if _, err := c.state(t, "fail_closed", 24, crls(staleCRL)).Verify(leaf, nil, now); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale CRL beyond grace must fail closed: %v", err)
	}
	if _, err := c.state(t, "fail_closed", 24*7, crls(staleCRL)).Verify(leaf, nil, now); err != nil {
		t.Fatalf("stale CRL within the grace period should be accepted: %v", err)
	}
	// a CRL that does not belong to the leaf's issuer (only a root CRL) cannot vouch for the leaf
	rootCRL := makeCRL(t, c.root, now.Add(-time.Hour), now.Add(24*time.Hour))
	if _, err := c.state(t, "fail_closed", 24, crls(rootCRL)).Verify(leaf, nil, now); err == nil {
		t.Fatal("a root-only CRL must not satisfy the requirement for the issuing CA's CRL")
	}
	// the profile has no revocation configured at all: nothing is checked
	st, _ := Compile(proto.PKI{ID: "1", Name: "x", CAs: c.bundle, StalePolicy: "fail_closed"})
	if _, err := st.Verify(leaf, nil, now); err != nil {
		t.Fatalf("no CRL configured should not reject: %v", err)
	}
}

// If the root DOES publish a CRL it is honoured for the issuing CA.
func TestRootCRLRevokesIssuingCA(t *testing.T) {
	c := newAzureChain(t)
	now := time.Now()
	leaf := c.leaf(t, c.issuing)
	issuingCRL := makeCRL(t, c.issuing, now.Add(-time.Hour), now.Add(24*time.Hour))
	both := func(rootCRL []byte) map[string][]byte {
		return map[string][]byte{"http://crl.test/issuing.crl": issuingCRL, "http://crl.test/root.crl": rootCRL}
	}
	st := c.state(t, "fail_closed", 24, both(makeCRL(t, c.root, now.Add(-time.Hour), now.Add(24*time.Hour), c.issuing.Cert.SerialNumber)))
	if _, err := st.Verify(leaf, nil, now); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a revoked issuing CA must invalidate its clients: %v", err)
	}
	st = c.state(t, "fail_closed", 24, both(makeCRL(t, c.root, now.Add(-time.Hour), now.Add(24*time.Hour))))
	if _, err := st.Verify(leaf, nil, now); err != nil {
		t.Fatalf("root CRL without the issuing CA listed should pass: %v", err)
	}
}

// Some CAs encode the same distinguished name differently (PrintableString vs UTF8String). The CRL must still be
// matched to its issuer, which is what real-world CRLs from such CAs need.
func TestCRLMatchedBySignatureNotNameBytes(t *testing.T) {
	rc, rk, _ := pki.NewRootCA("Root", 24*time.Hour)
	root, _ := pki.LoadCA(rc, rk)
	key, _ := pki.GenerateKey()
	mkSubject := func(utf8 bool) []byte {
		tag := asn1.TagPrintableString
		if utf8 {
			tag = asn1.TagUTF8String
		}
		atv := struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}{asn1.ObjectIdentifier{2, 5, 4, 3}, asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, Bytes: []byte("Issuing CA")}}
		// build SEQUENCE{ SET{ SEQUENCE{ oid, value } } } by hand
		inner, _ := asn1.Marshal(atv)
		setDER, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: inner})
		seq, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: setDER})
		return seq
	}
	issue := func(subject []byte) *x509.Certificate {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(77), RawSubject: subject, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, err := x509.CreateCertificate(rand.Reader, tpl, root.Cert, &key.PublicKey, root.Key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	inChain, forCRL := issue(mkSubject(false)), issue(mkSubject(true)) // same key, same name, different bytes
	if string(inChain.RawSubject) == string(forCRL.RawSubject) {
		t.Fatal("test setup: the encodings should differ")
	}
	now := time.Now()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour)}, forCRL, key)
	if err != nil {
		t.Fatal(err)
	}
	ltpl := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "dev"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	ldat, err := x509.CreateCertificate(rand.Reader, ltpl, inChain, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(ldat)
	st, err := Compile(proto.PKI{ID: "1", Name: "x", CAs: string(rc) + string(pki.EncodeCert(inChain.Raw)), CRLURLs: []string{"u"}, CRLs: map[string][]byte{"u": crlDER}, StalePolicy: "fail_closed"})
	if err != nil {
		t.Fatal(err)
	}
	if string(inChain.RawSubject) == string(func() []byte { rl, _ := Parse(crlDER); return rl.RawIssuer }()) {
		t.Fatal("test setup: CRL issuer bytes should differ from the chain certificate's subject bytes")
	}
	if _, err := st.Verify(leaf, nil, now); err != nil {
		t.Fatalf("CRL with differently-encoded issuer name was not matched: %v", err)
	}
}
