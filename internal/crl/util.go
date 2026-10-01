package crl

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
)

func bytesHasPEM(b []byte) bool { return bytes.Contains(b, []byte("-----BEGIN")) }

func pemDecode(b []byte) []byte {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil
	}
	return blk.Bytes
}

var oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}
var oidUPN = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

// otherNameUPNs extracts Microsoft UPN otherName values from the SAN extension.
func otherNameUPNs(c *x509.Certificate) []string {
	var out []string
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidSAN) {
			continue
		}
		var seq asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &seq); err != nil {
			continue
		}
		rest := seq.Bytes
		for len(rest) > 0 {
			var v asn1.RawValue
			var err error
			rest, err = asn1.Unmarshal(rest, &v)
			if err != nil {
				break
			}
			if v.Class != asn1.ClassContextSpecific || v.Tag != 0 {
				continue
			}
			var oid asn1.ObjectIdentifier
			r2, err := asn1.Unmarshal(v.Bytes, &oid)
			if err != nil || !oid.Equal(oidUPN) {
				continue
			}
			var explicit asn1.RawValue
			if _, err := asn1.Unmarshal(r2, &explicit); err != nil {
				continue
			}
			var s string
			if _, err := asn1.UnmarshalWithParams(explicit.Bytes, &s, "utf8"); err == nil {
				out = append(out, s)
			}
		}
	}
	return out
}

// CDPFromPEM returns CRL distribution points from a sample certificate.
func CDPFromPEM(p []byte) ([]string, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, bytes.ErrTooLarge
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	return c.CRLDistributionPoints, nil
}
