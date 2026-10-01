package crl

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"radman/internal/pki"
	"radman/internal/proto"
)

// makeCertWithUPN builds a client certificate carrying a Microsoft UPN otherName SAN (as Intune/Cloud PKI issues).
func makeCertWithUPN(t *testing.T, upn string) *x509.Certificate {
	t.Helper()
	k, _ := pki.GenerateKey()
	utf8, _ := asn1.MarshalWithParams(upn, "utf8")
	explicit, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: utf8})
	oid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3})
	other, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(oid, explicit...)})
	san, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: other})
	tpl := &x509.Certificate{
		SerialNumber:    big.NewInt(7),
		Subject:         pkix.Name{CommonName: "dev"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidSAN, Value: san}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestUPNExtractionAndPolicy(t *testing.T) {
	c := makeCertWithUPN(t, "jane@corp.example")
	found := false
	for _, s := range SANs(c) {
		if s == "jane@corp.example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("UPN not extracted: %v", SANs(c))
	}
	pol := proto.Policy{DefaultAction: "deny", Rules: []proto.Rule{
		{Name: "corp", Field: "san", Op: "regex", Value: `@corp\.example$`, Action: "allow", VLAN: "12"},
	}}
	d := Evaluate(pol, c, "p")
	if !d.Allow || d.VLAN != "12" {
		t.Fatalf("decision %+v", d)
	}
	pol.Rules[0].Value = `@other\.example$`
	if Evaluate(pol, c, "p").Allow {
		t.Fatal("default deny not applied")
	}
}
