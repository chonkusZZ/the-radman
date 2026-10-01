package manager

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"strings"
	"testing"
	"time"

	"radman/internal/pki"
	"radman/internal/proto"
)

func TestParseServerNames(t *testing.T) {
	good := map[string][]string{
		"radius.example.com":                                  {"radius.example.com"},
		"Radius.Example.COM, 10.1.0.5":                        {"radius.example.com", "10.1.0.5"},
		"a.example.com;b.example.com c.example.com\n10.0.0.1": {"a.example.com", "b.example.com", "c.example.com", "10.0.0.1"},
		"*.corp.example, 2001:db8::1":                         {"*.corp.example", "2001:db8::1"},
		"radius01":                                            {"radius01"},
		"10.1.0.5, 10.1.0.5, RADIUS01,radius01":               {"10.1.0.5", "radius01"},
		"":                                                    nil,
		" , ,":                                                nil,
		"0010.001.000.005":                                    nil, // placeholder replaced below
	}
	delete(good, "0010.001.000.005")
	for in, want := range good {
		got, err := ParseServerNames(in)
		if err != nil || strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%q -> %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"bad name!", "http://radius.example.com", "radius.example.com/path", "-leading.example.com", "trailing-.example.com", "under_score.example.com",
		"10.1.0.999", "1.2.3", "a..b.example.com", "*.", "*.*.example.com", strings.Repeat("a", 64) + ".example.com", "radius@example.com", "[::1]"} {
		if got, err := ParseServerNames(in); err == nil {
			t.Errorf("%q accepted as %v", in, got)
		}
	}
	var many []string
	for i := 0; i < 21; i++ {
		many = append(many, "h"+strings.Repeat("x", i)+".example.com")
	}
	if _, err := ParseServerNames(strings.Join(many, ",")); err == nil {
		t.Error("more than 20 names accepted")
	}
}

func TestNodeServerCertificate(t *testing.T) {
	a := testApp(t)
	w := newStatWorld(t, a, "Names Co")
	ctx := w.ctx
	var node2 string
	a.St.DB.QueryRow(ctx, `INSERT INTO nodes(site_id,name,status) VALUES($1::uuid,'n2','active') RETURNING id::text`, w.site).Scan(&node2)

	siteCfg, err := a.BuildSiteConfig(ctx, w.site)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"radius.example.com", "10.1.0.5", "*.corp.example", "2001:db8::1"}
	if err := a.setNodeServerNames(ctx, w.tenant, w.node, names); err != nil {
		t.Fatal(err)
	}
	cfg, err := a.BuildNodeConfig(ctx, w.site, w.node)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.ParseCert([]byte(cfg.EAPCert))
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "radius.example.com" {
		t.Errorf("CN %q", leaf.Subject.CommonName)
	}
	for _, h := range []string{"radius.example.com", "10.1.0.5", "2001:db8::1", "anything.corp.example"} {
		if err := leaf.VerifyHostname(h); err != nil {
			t.Errorf("certificate should be valid for %s: %v", h, err)
		}
	}
	if leaf.VerifyHostname("other.example.com") == nil || leaf.VerifyHostname("10.1.0.6") == nil {
		t.Error("certificate valid for a name it should not cover")
	}
	if len(leaf.DNSNames) != 2 || len(leaf.IPAddresses) != 2 {
		t.Errorf("SANs: dns=%v ip=%v", leaf.DNSNames, leaf.IPAddresses)
	}
	hasServerAuth := false
	for _, e := range leaf.ExtKeyUsage {
		hasServerAuth = hasServerAuth || e == x509.ExtKeyUsageServerAuth
	}
	if !hasServerAuth {
		t.Error("missing serverAuth EKU")
	}
	// chains to the tenant's EAP CA and the key matches (the node would otherwise refuse the config)
	capem, _ := a.tenantCAPEM(ctx, w.tenant, "eap")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(capem)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "radius.example.com", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("does not verify against the tenant's EAP CA: %v", err)
	}
	if _, err := tls.X509KeyPair([]byte(cfg.EAPCert), []byte(cfg.EAPKey)); err != nil {
		t.Errorf("certificate/key mismatch: %v", err)
	}
	other, _ := a.CreateTenant(ctx, "Other Co")
	ocapem, _ := a.tenantCAPEM(ctx, other.ID, "eap")
	opool := x509.NewCertPool()
	opool.AppendCertsFromPEM(ocapem)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: opool}); err == nil {
		t.Error("certificate also verifies against another tenant's CA")
	}

	// other nodes of the site and the site itself keep the site certificate
	cfg2, _ := a.BuildNodeConfig(ctx, w.site, node2)
	if cfg2.EAPCert != siteCfg.EAPCert || cfg2.EAPCert == cfg.EAPCert {
		t.Error("a node without names must keep using the site certificate")
	}
	if again, _ := a.BuildSiteConfig(ctx, w.site); again.EAPCert != siteCfg.EAPCert {
		t.Error("the site's own configuration changed")
	}
	if proto.HashConfig(cfg) == proto.HashConfig(cfg2) {
		t.Error("node configurations should differ so the node picks up its certificate")
	}

	// automatic renewal keeps the names
	oldSerial := leaf.SerialNumber.String()
	a.St.DB.Exec(ctx, `UPDATE nodes SET eap_not_after = now() + interval '10 days' WHERE id=$1::uuid`, w.node)
	a.renewInternalEAPCerts(ctx)
	cfg3, _ := a.BuildNodeConfig(ctx, w.site, w.node)
	renewed, _ := pki.ParseCert([]byte(cfg3.EAPCert))
	if renewed.SerialNumber.String() == oldSerial || renewed.VerifyHostname("10.1.0.5") != nil || time.Until(renewed.NotAfter) < 600*24*time.Hour {
		t.Errorf("renewal: serial changed=%v names ok=%v", renewed.SerialNumber.String() != oldSerial, renewed.VerifyHostname("10.1.0.5") == nil)
	}

	// clearing the names returns the node to the site certificate
	if err := a.setNodeServerNames(ctx, w.tenant, w.node, nil); err != nil {
		t.Fatal(err)
	}
	if back, _ := a.BuildNodeConfig(ctx, w.site, w.node); back.EAPCert != siteCfg.EAPCert {
		t.Error("clearing the names should restore the site certificate")
	}
}

func TestNodeNamesUI(t *testing.T) {
	w := newWorld(t)
	A, B := "Alpha", "Bravo"
	aadmin, aro := w.as(t, "aadmin", A), w.as(t, "aro", A)

	code, _ := aadmin.do(t, "POST", "/sites/"+w.site[A]+"/nodes", url.Values{"name": {"edge1"}, "server_names": {"radius.alpha.example, 10.9.8.7"}})
	expect(t, "create node with names", code, 303)
	var id string
	var names []string
	if err := w.a.St.DB.QueryRow(w.ctx, `SELECT id::text, eap_names FROM nodes WHERE name='edge1'`).Scan(&id, &names); err != nil || strings.Join(names, ",") != "radius.alpha.example,10.9.8.7" {
		t.Fatalf("node names: %v %v", err, names)
	}
	cfg, err := w.a.BuildNodeConfig(w.ctx, w.site[A], id)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := pki.ParseCert([]byte(cfg.EAPCert))
	if leaf.VerifyHostname("radius.alpha.example") != nil || leaf.VerifyHostname("10.9.8.7") != nil {
		t.Error("certificate does not carry the requested names")
	}
	_, page := aadmin.do(t, "GET", "/nodes/"+id, nil)
	if !strings.Contains(page, "radius.alpha.example") || !strings.Contains(page, "10.9.8.7") {
		t.Error("node page should show the certificate names")
	}

	// invalid input is rejected and nothing is created
	code, _ = aadmin.do(t, "POST", "/sites/"+w.site[A]+"/nodes", url.Values{"name": {"edge2"}, "server_names": {"not a host!!"}})
	expect(t, "invalid names", code, 303)
	if w.count(`SELECT count(*) FROM nodes WHERE name='edge2'`) != 0 {
		t.Error("a node was created despite invalid names")
	}
	// no names: site certificate
	aadmin.do(t, "POST", "/sites/"+w.site[A]+"/nodes", url.Values{"name": {"edge3"}})
	if w.count(`SELECT count(*) FROM nodes WHERE name='edge3' AND eap_cert_pem=''`) != 1 {
		t.Error("a node without names should have no certificate of its own")
	}

	// edit, then clear
	aadmin.do(t, "POST", "/nodes/"+id+"/names", url.Values{"server_names": {"new.alpha.example"}})
	w.a.St.DB.QueryRow(w.ctx, `SELECT eap_names FROM nodes WHERE id=$1::uuid`, id).Scan(&names)
	if len(names) != 1 || names[0] != "new.alpha.example" {
		t.Errorf("after edit: %v", names)
	}
	aadmin.do(t, "POST", "/nodes/"+id+"/names", url.Values{"server_names": {""}})
	if w.count(`SELECT count(*) FROM nodes WHERE id=$1::uuid AND eap_cert_pem='' AND cardinality(eap_names)=0`, id) != 1 {
		t.Error("clearing names should remove the node certificate")
	}

	// permissions and isolation
	code, _ = aro.do(t, "POST", "/sites/"+w.site[A]+"/nodes", url.Values{"name": {"ro-node"}, "server_names": {"x.example"}})
	expect(t, "read-only creates a node", code, 403)
	code, _ = aro.do(t, "POST", "/nodes/"+id+"/names", url.Values{"server_names": {"x.example"}})
	expect(t, "read-only edits names", code, 403)
	code, _ = aadmin.do(t, "POST", "/nodes/"+w.node[B]+"/names", url.Values{"server_names": {"evil.example"}})
	expect(t, "edit another tenant's node", code, 404)
	if w.count(`SELECT count(*) FROM nodes WHERE id=$1::uuid AND cardinality(eap_names)>0`, w.node[B]) != 0 {
		t.Error("another tenant's node was modified")
	}
	code, _ = aadmin.do(t, "POST", "/sites/"+w.site[B]+"/nodes", url.Values{"name": {"x"}, "server_names": {"evil.example"}})
	expect(t, "create a node in another tenant's site", code, 404)
}
