package manager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"radman/internal/pki"
)

// CreateInternalEAPCert issues a RADIUS server certificate for supplicants from the tenant's own EAP CA.
func (a *App) CreateInternalEAPCert(ctx context.Context, tenantID, name, cn string, dns []string) (string, error) {
	if len(dns) == 0 {
		dns = []string{cn}
	}
	cert, key, err := a.issueEAP(ctx, tenantID, cn, dns)
	if err != nil {
		return "", err
	}
	na, _, _ := certExpiry(cert)
	var id string
	err = a.St.DB.QueryRow(ctx, `INSERT INTO eap_certs(tenant_id,name,source,cert_pem,key_enc,not_after,dns_names) VALUES($1,$2,'internal',$3,$4,$5,$6) RETURNING id::text`,
		tenantID, name, string(cert), a.seal(string(key)), na, dns).Scan(&id)
	return id, err
}

func (a *App) issueEAP(ctx context.Context, tenantID, cn string, dns []string) (certPEM, keyPEM []byte, err error) {
	ca, err := a.tenantCA(ctx, tenantID, "eap")
	if err != nil {
		return nil, nil, err
	}
	k, err := pki.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	if len(dns) == 0 {
		dns = []string{cn}
	}
	c, _, err := ca.Sign(&k.PublicKey, pki.SignOpts{CommonName: cn, DNSNames: dns, Validity: 730 * 24 * time.Hour, Server: true})
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = pki.EncodeKey(k)
	// present the issuing CA after the leaf so supplicants can build the chain
	return append(c, pki.EncodeCert(ca.Cert.Raw)...), keyPEM, err
}

// renewInternalEAPCerts re-issues internal EAP certs nearing expiry (same row, so sites keep their assignment).
func (a *App) renewInternalEAPCerts(ctx context.Context) {
	rows, err := a.St.DB.Query(ctx, `SELECT id::text, tenant_id::text, name, cert_pem FROM eap_certs WHERE source='internal' AND not_after < now() + interval '60 days'`)
	if err != nil {
		return
	}
	type item struct{ id, tenant, name, pem string }
	var items []item
	for rows.Next() {
		var it item
		rows.Scan(&it.id, &it.tenant, &it.name, &it.pem)
		items = append(items, it)
	}
	rows.Close()
	for _, it := range items {
		c, err := pki.ParseCert([]byte(it.pem))
		if err != nil {
			continue
		}
		cert, key, err := a.issueEAP(ctx, it.tenant, c.Subject.CommonName, c.DNSNames)
		if err != nil {
			continue
		}
		na, _, _ := certExpiry(cert)
		a.St.DB.Exec(ctx, `UPDATE eap_certs SET cert_pem=$2, key_enc=$3, not_after=$4 WHERE id=$1::uuid`, it.id, string(cert), a.seal(string(key)), na)
		a.Audit(withTenant(ctx, it.tenant), "system", "eapcert.renew", fmt.Sprintf("renewed %s", it.name))
	}
	// node-specific server certificates renew the same way (same names)
	nrows, err := a.St.DB.Query(ctx, `SELECT n.id::text, s.tenant_id::text, n.name, n.eap_names FROM nodes n JOIN sites s ON s.id=n.site_id
		WHERE n.eap_cert_pem <> '' AND n.eap_not_after < now() + interval '60 days'`)
	if err != nil {
		return
	}
	type nitem struct {
		id, tenant, name string
		names            []string
	}
	var nodes []nitem
	for nrows.Next() {
		var x nitem
		nrows.Scan(&x.id, &x.tenant, &x.name, &x.names)
		nodes = append(nodes, x)
	}
	nrows.Close()
	for _, x := range nodes {
		if err := a.setNodeServerNames(ctx, x.tenant, x.id, x.names); err == nil {
			a.Audit(withTenant(ctx, x.tenant), "system", "node.cert_renew", "renewed server certificate of "+x.name)
		}
	}
}

var hostLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ParseServerNames turns "radius.example.com, 10.1.0.5" into a validated, de-duplicated name list.
// Each entry is an IP address or a DNS name (a leading "*." wildcard is allowed). The first name becomes the CN;
// all names (including the first) go into the subject alternative names, which is what modern supplicants actually check.
func ParseServerNames(in string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(in, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' || r == '\r' }) {
		name := strings.ToLower(strings.TrimSpace(f))
		if name == "" {
			continue
		}
		if ip := net.ParseIP(name); ip != nil {
			name = ip.String()
		} else {
			host := strings.TrimPrefix(name, "*.")
			if len(name) > 253 || host == "" {
				return nil, fmt.Errorf("%q is not a valid host name", f)
			}
			allNumeric := true
			for _, label := range strings.Split(host, ".") {
				if len(label) > 63 || !hostLabelRe.MatchString(label) {
					return nil, fmt.Errorf("%q is not a valid host name or IP address", f)
				}
				if strings.Trim(label, "0123456789") != "" {
					allNumeric = false
				}
			}
			if allNumeric { // e.g. 10.1.0.999: looks like an IP but is not one
				return nil, fmt.Errorf("%q is not a valid IP address", f)
			}
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	if len(out) > 20 {
		return nil, errors.New("at most 20 names are supported")
	}
	return out, nil
}

// issueEAPNames issues a server certificate for the given names (first = CN) from the tenant's EAP CA.
func (a *App) issueEAPNames(ctx context.Context, tenantID string, names []string) (certPEM, keyPEM []byte, notAfter time.Time, err error) {
	if len(names) == 0 {
		return nil, nil, time.Time{}, errors.New("no names given")
	}
	ca, err := a.tenantCA(ctx, tenantID, "eap")
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	k, err := pki.GenerateKey()
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	so := pki.SignOpts{CommonName: names[0], Validity: 730 * 24 * time.Hour, Server: true}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			so.IPs = append(so.IPs, ip)
		} else {
			so.DNSNames = append(so.DNSNames, n)
		}
	}
	c, leaf, err := ca.Sign(&k.PublicKey, so)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	keyPEM, err = pki.EncodeKey(k)
	return append(c, pki.EncodeCert(ca.Cert.Raw)...), keyPEM, leaf.NotAfter, err
}

// setNodeServerNames gives a node its own server certificate for the names, or (empty list) returns it to the site certificate.
func (a *App) setNodeServerNames(ctx context.Context, tenantID, nodeID string, names []string) error {
	if len(names) == 0 {
		_, err := a.St.DB.Exec(ctx, `UPDATE nodes SET eap_names='{}', eap_cert_pem='', eap_key_enc='', eap_not_after=NULL WHERE id=$1::uuid`, nodeID)
		return err
	}
	cert, key, na, err := a.issueEAPNames(ctx, tenantID, names)
	if err != nil {
		return err
	}
	_, err = a.St.DB.Exec(ctx, `UPDATE nodes SET eap_names=$2, eap_cert_pem=$3, eap_key_enc=$4, eap_not_after=$5 WHERE id=$1::uuid`, nodeID, names, string(cert), a.seal(string(key)), na)
	return err
}
