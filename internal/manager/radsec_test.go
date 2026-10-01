package manager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"radman/internal/pki"
)

func csrPEM(t *testing.T, key any) string {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "browser-chosen-name"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return "-----BEGIN CERTIFICATE REQUEST-----\n" + wrap(der) + "-----END CERTIFICATE REQUEST-----\n"
}

func TestRadSecIssueAndRevoke(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	s := &server{a: a}
	tn, _ := a.CreateTenant(ctx, "Acme")
	eap, _ := a.CreateInternalEAPCert(ctx, tn.ID, "srv", "radius.test", nil)
	var siteID, apID string
	a.St.DB.QueryRow(ctx, `INSERT INTO sites(tenant_id,name,eap_cert_id,radsec_port) VALUES($1::uuid,'hq',$2::uuid,2083) RETURNING id::text`, tn.ID, eap).Scan(&siteID)
	a.St.DB.QueryRow(ctx, `INSERT INTO aps(site_id,name,addr,secret_enc) VALUES($1,'Hall AP','10.0.0.1',$2) RETURNING id::text`, siteID, a.seal("secretsecret")).Scan(&apID)
	u := &User{Email: "admin@x", Platform: RoleGlobalAdmin, Tenant: tn}

	sign := func(csr string) (int, map[string]string) {
		form := url.Values{"csr": {csr}, "days": {"30"}}
		r := httptest.NewRequest("POST", "/aps/"+apID+"/radsec/sign", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetPathValue("id", apID)
		r.ParseForm()
		w := httptest.NewRecorder()
		s.radsecSign(w, r, u)
		var out map[string]string
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	ek, _ := pki.GenerateKey()
	code, out := sign(csrPEM(t, ek))
	if code != 200 {
		t.Fatalf("EC CSR: %d %v", code, out)
	}
	cert, _ := pki.ParseCert([]byte(out["cert"]))
	if cert.Subject.CommonName != "Hall AP" {
		t.Fatalf("subject must be chosen by the manager, got %q", cert.Subject.CommonName)
	}
	pool := x509.NewCertPool()
	rsCA, _ := a.tenantCA(ctx, tn.ID, "radsec")
	pool.AddCert(rsCA.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("issued cert does not verify: %v", err)
	}
	if out["server_ca"] == "" {
		t.Fatal("server CA chain missing")
	}

	cfg, err := a.BuildSiteConfig(ctx, siteID)
	if err != nil || cfg.RadSecPort != 2083 || cfg.RadSecCA == "" || len(cfg.APs[0].RadSecSerials) != 1 || cfg.APs[0].RadSecSerials[0] != out["serial"] {
		t.Fatalf("config: %v %+v", err, cfg.APs)
	}

	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	if code, _ := sign(csrPEM(t, weak)); code != 400 {
		t.Fatalf("1024-bit RSA accepted: %d", code)
	}
	if code, _ := sign("garbage"); code != 400 {
		t.Fatalf("garbage CSR: %d", code)
	}

	a.St.DB.Exec(ctx, `UPDATE radsec_certs SET revoked_at=now()`)
	cfg, _ = a.BuildSiteConfig(ctx, siteID)
	if len(cfg.APs[0].RadSecSerials) != 0 {
		t.Fatal("revoked certificate still listed")
	}
	// RadSec disabled for the site -> issuing refused
	a.St.DB.Exec(ctx, `UPDATE sites SET radsec_port=0`)
	if code, _ := sign(csrPEM(t, ek)); code != 409 {
		t.Fatalf("disabled site: %d", code)
	}
}

func wrap(der []byte) string {
	const hexdigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var enc []byte
	for i := 0; i < len(der); i += 3 {
		var b [3]byte
		n := copy(b[:], der[i:])
		v := uint(b[0])<<16 | uint(b[1])<<8 | uint(b[2])
		enc = append(enc, hexdigits[v>>18&63], hexdigits[v>>12&63], '=', '=')
		if n > 1 {
			enc[len(enc)-2] = hexdigits[v>>6&63]
		}
		if n > 2 {
			enc[len(enc)-1] = hexdigits[v&63]
		}
	}
	var sb strings.Builder
	for i := 0; i < len(enc); i += 64 {
		sb.Write(enc[i:min(i+64, len(enc))])
		sb.WriteByte('\n')
	}
	return sb.String()
}
