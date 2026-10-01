package manager

import (
	"net/url"
	"strings"
	"testing"
)

// configureTenantSSO connects a tenant to a (test) IdP exactly as a tenant administrator would end up with.
func (w *world) configureTenantSSO(t *testing.T, tenant string, idp *idpEnv, mutate func(*SAML)) {
	c := SAML{Enabled: true, MetadataXML: idp.metadataXML(t), EmailAttr: "mail", NameAttr: "cn", GroupAttr: "eduPersonAffiliation",
		GroupRoles: []GroupMap{{"grp-admins", RoleTenantAdmin}, {"grp-ro", RoleReadOnly}}}
	if mutate != nil {
		mutate(&c)
	}
	if err := w.a.St.SetJSON(w.ctx, "saml:"+w.tenant[tenant].ID, c); err != nil {
		t.Fatal(err)
	}
	idp.register(t, w.srv.Client(), w.srv.URL+"/t/"+w.tenant[tenant].Slug+"/saml/metadata", "sp-"+w.tenant[tenant].Slug)
}

func TestTenantSSO(t *testing.T) {
	w := newWorld(t)
	A, B := "Alpha", "Bravo"
	idpA, idpB := newIdP(t), newIdP(t)
	idpA.addUser("alice", "alice@alpha.example", "grp-admins")
	idpA.addUser("bob", "bob@alpha.example", "grp-ro")
	idpA.addUser("carol", "carol@alpha.example", "grp-nobody")
	idpA.addUser("mallory1", "gadmin@test", "grp-admins")       // e-mail of a local global administrator
	idpA.addUser("mallory2", "staff@msp.example", "grp-admins") // e-mail of a platform-SSO global administrator
	idpA.addUser("mallory3", "aadmin@test", "grp-admins")       // e-mail of a local tenant administrator
	idpA.addUser("outsider", "x@evil.example", "grp-admins")
	idpB.addUser("alice-b", "alice@alpha.example", "grp-admins") // Bravo's IdP claims Alpha's user
	idpB.addUser("dave", "dave@bravo.example", "grp-admins")
	w.configureTenantSSO(t, A, idpA, nil)
	w.configureTenantSSO(t, B, idpB, nil)
	// a platform-IdP staff account that already exists
	var staffID string
	w.a.St.DB.QueryRow(w.ctx, `INSERT INTO users(email,name,password_hash,platform_role,sso,idp) VALUES('staff@msp.example','Staff','','global_admin',true,'platform') RETURNING id::text`).Scan(&staffID)

	sso := func(tenant string, idp *idpEnv, user string) (string, bool) {
		resp, cl := ssoLogin(t, w.srv.URL, w.srv.Client(), "/t/"+w.tenant[tenant].Slug+"/saml/login", idp, user, "")
		loc := resp.Header.Get("Location")
		r, _ := cl.Get(w.srv.URL + "/sites") // does the session reach a tenant page?
		return loc, loc == "/" && r.StatusCode == 200
	}

	// --- happy path: confined to the tenant ---
	loc, ok := sso(A, idpA, "alice")
	if loc != "/" || !ok {
		t.Fatalf("alice: %q ok=%v", loc, ok)
	}
	var plat, idp, role, src string
	if err := w.a.St.DB.QueryRow(w.ctx, `SELECT u.platform_role, u.idp, m.role, m.source FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.email='alice@alpha.example' AND m.tenant_id=$1::uuid`, w.tenant[A].ID).Scan(&plat, &idp, &role, &src); err != nil {
		t.Fatal(err)
	}
	if plat != "" || idp != w.tenant[A].ID || role != RoleTenantAdmin || src != "sso:"+w.tenant[A].ID {
		t.Errorf("alice: platform=%q idp=%q role=%q source=%q", plat, idp, role, src)
	}
	if w.count(`SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.email='alice@alpha.example'`) != 1 {
		t.Error("tenant SSO user got access beyond their tenant")
	}
	if _, ok := sso(A, idpA, "bob"); !ok {
		t.Error("bob (read-only group) could not sign in")
	}
	if w.count(`SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.email='bob@alpha.example' AND m.role='read_only'`) != 1 {
		t.Error("bob should be read-only")
	}

	// --- refusals ---
	if loc, _ := sso(A, idpA, "carol"); loc != "/login" {
		t.Errorf("unmapped user must be refused, got %q", loc)
	}
	if w.count(`SELECT count(*) FROM users WHERE email='carol@alpha.example'`) != 0 {
		t.Error("refused user was provisioned")
	}
	// default role: everyone authenticated by the customer's IdP becomes read-only
	w.configureTenantSSO(t, A, idpA, func(c *SAML) { c.DefaultRole = RoleReadOnly })
	if _, ok := sso(A, idpA, "carol"); !ok {
		t.Error("carol should be allowed as read-only with a default role")
	}
	w.configureTenantSSO(t, A, idpA, nil)

	// --- a customer IdP can never take over or modify an existing account ---
	for user, email := range map[string]string{"mallory1": "gadmin@test", "mallory2": "staff@msp.example", "mallory3": "aadmin@test"} {
		if loc, _ := sso(A, idpA, user); loc != "/login" {
			t.Errorf("%s: IdP-asserted e-mail %s was accepted (%q)", user, email, loc)
		}
	}
	var staffRole, staffIdp string
	w.a.St.DB.QueryRow(w.ctx, `SELECT platform_role, idp FROM users WHERE id=$1::uuid`, staffID).Scan(&staffRole, &staffIdp)
	if staffRole != RoleGlobalAdmin || staffIdp != "platform" {
		t.Errorf("platform staff account was modified by a tenant IdP: role=%q idp=%q", staffRole, staffIdp)
	}
	var gRole string
	w.a.St.DB.QueryRow(w.ctx, `SELECT platform_role FROM users WHERE email='gadmin@test'`).Scan(&gRole)
	if gRole != RoleGlobalAdmin {
		t.Error("local global administrator was modified")
	}
	if w.count(`SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.email IN ('gadmin@test','staff@msp.example') AND m.source LIKE 'sso%'`) != 0 {
		t.Error("membership injected into an existing account")
	}
	// another tenant's IdP cannot claim this tenant's user
	if loc, _ := sso(B, idpB, "alice-b"); loc != "/login" {
		t.Errorf("Bravo's IdP signed in Alpha's user (%q)", loc)
	}
	var stillA string
	w.a.St.DB.QueryRow(w.ctx, `SELECT idp FROM users WHERE email='alice@alpha.example'`).Scan(&stillA)
	if stillA != w.tenant[A].ID {
		t.Error("account binding changed")
	}
	if _, ok := sso(B, idpB, "dave"); !ok {
		t.Error("Bravo's own user should sign in")
	}
	// an assertion minted for Alpha cannot be replayed at Bravo's ACS
	resp, _ := ssoLogin(t, w.srv.URL, w.srv.Client(), "/t/alpha/saml/login", idpA, "alice", w.srv.URL+"/t/bravo/saml/acs")
	if resp.Header.Get("Location") != "/login" {
		t.Errorf("cross-tenant assertion replay accepted: %q", resp.Header.Get("Location"))
	}
	// the platform ACS refuses it too
	resp, _ = ssoLogin(t, w.srv.URL, w.srv.Client(), "/t/alpha/saml/login", idpA, "alice", w.srv.URL+"/saml/acs")
	if resp.Header.Get("Location") != "/login" {
		t.Errorf("tenant assertion accepted by the platform ACS: %q", resp.Header.Get("Location"))
	}

	// --- domain restriction and discovery (set by the platform operator) ---
	gadmin := w.as(t, "gadmin", A)
	c, _ := gadmin.do(t, "POST", "/sso", url.Values{"enabled": {"1"}, "metadata_xml": {idpA.metadataXML(t)}, "email_attr": {"mail"}, "name_attr": {"cn"}, "group_attr": {"eduPersonAffiliation"},
		"group_roles": {"grp-admins=tenant_admin\ngrp-ro=read_only"}, "domains": {"alpha.example"}})
	expect(t, "global admin saves tenant SSO", c, 303)
	if w.count(`SELECT count(*) FROM tenant_sso_domains WHERE tenant_id=$1::uuid AND domain='alpha.example'`, w.tenant[A].ID) != 1 {
		t.Fatal("domain not stored")
	}
	if loc, _ := sso(A, idpA, "outsider"); loc != "/login" {
		t.Errorf("e-mail outside the tenant's domains accepted (%q)", loc)
	}
	if _, ok := sso(A, idpA, "alice"); !ok {
		t.Error("in-domain user refused")
	}
	anon := w.as(t, "aro", A) // any client; discovery is public
	anon.cl.Jar = nil
	disc := func(email string) string {
		resp, err := anon.cl.PostForm(w.srv.URL+"/sso/discover", url.Values{"email": {email}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.Header.Get("Location")
	}
	if got := disc("alice@alpha.example"); got != "/t/alpha/saml/login" {
		t.Errorf("discovery -> %q", got)
	}
	if got := disc("someone@unknown.example"); got != "/login" {
		t.Errorf("unknown domain -> %q", got)
	}
	// Bravo cannot claim Alpha's domain; Alpha's tenant admin cannot set domains at all
	gB := w.as(t, "gadmin", B)
	gB.do(t, "POST", "/sso", url.Values{"domains": {"alpha.example"}})
	if w.count(`SELECT count(*) FROM tenant_sso_domains WHERE tenant_id=$1::uuid`, w.tenant[B].ID) != 0 {
		t.Error("a domain was claimed by two tenants")
	}
	aadmin := w.as(t, "aadmin", A)
	aadmin.do(t, "POST", "/sso", url.Values{"domains": {"bigcustomer.example"}, "enabled": {"1"}, "metadata_xml": {idpA.metadataXML(t)}, "group_roles": {"grp-admins=tenant_admin"}, "email_attr": {"mail"}, "group_attr": {"eduPersonAffiliation"}})
	if w.count(`SELECT count(*) FROM tenant_sso_domains WHERE domain='bigcustomer.example'`) != 0 {
		t.Error("a tenant administrator set e-mail domains")
	}

	// --- tenant administrators: own tenant only, SSRF guarded, no lockout ---
	code, body := aadmin.do(t, "GET", "/sso", nil)
	expect(t, "tenant admin opens SSO page", code, 200)
	if strings.Contains(body, "Bravo") {
		t.Error("SSO page leaks another tenant")
	}
	code, _ = w.as(t, "aro", A).do(t, "GET", "/sso", nil)
	expect(t, "read-only user opens SSO page", code, 403)
	code, _ = w.as(t, "aro", A).do(t, "POST", "/sso", url.Values{"enabled": {"1"}})
	expect(t, "read-only user saves SSO", code, 403)
	for _, bad := range []string{"https://127.0.0.1:9/metadata", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/metadata", "http://192.168.1.1/m", "http://[::1]/m"} {
		aadmin.do(t, "POST", "/sso", url.Values{"enabled": {"1"}, "metadata_url": {bad}, "group_roles": {"g=tenant_admin"}})
		cfg := w.a.TenantSSO(w.ctx, w.tenant[A].ID)
		if cfg.MetadataURL == bad {
			t.Errorf("tenant administrator pointed SSO at %s", bad)
		}
	}
	aadmin.do(t, "POST", "/sso", url.Values{"enabled": {"1"}, "metadata_xml": {idpA.metadataXML(t)}}) // no mapping, no default -> refused
	if cfg := w.a.TenantSSO(w.ctx, w.tenant[A].ID); len(cfg.GroupRoles) == 0 {
		t.Error("a configuration nobody could use was saved")
	}
	if cfg := w.a.TenantSSO(w.ctx, w.tenant[B].ID); !strings.Contains(cfg.MetadataXML, idpB.srv.URL) || len(cfg.GroupRoles) != 2 {
		t.Error("tenant A's administrator altered tenant B's SSO")
	}

	// --- local passwords can be switched off per tenant ---
	hash, _ := hashPassword("a-long-local-password")
	w.a.St.DB.Exec(w.ctx, `UPDATE users SET password_hash=$1 WHERE email IN ('aro@test','multi@test','gadmin@test')`, hash)
	pw := func(email string) int {
		resp, err := anon.cl.PostForm(w.srv.URL+"/login", url.Values{"email": {email}, "password": {"a-long-local-password"}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	expect(t, "password login before enforcement", pw("aro@test"), 303)
	w.configureTenantSSO(t, A, idpA, func(c *SAML) { c.RequireSSO = true })
	expect(t, "password login for a tenant-only user once SSO is required", pw("aro@test"), 401)
	expect(t, "multi-tenant user with another open tenant keeps password login", pw("multi@test"), 303)
	expect(t, "global administrator keeps password login", pw("gadmin@test"), 303)

	// --- deleting the tenant removes its IdP, key, domains and the accounts it created ---
	w.a.St.DB.Exec(w.ctx, `INSERT INTO tenant_sso_domains(domain,tenant_id) VALUES('bravo.example',$1::uuid)`, w.tenant[B].ID)
	spKeyBefore, _ := w.a.St.GetSecret(w.ctx, "tenant:"+w.tenant[B].ID+":saml_sp_key")
	if spKeyBefore == "" {
		t.Error("tenant service-provider key was never created")
	}
	gadmin2 := w.as(t, "gadmin", "")
	gadmin2.do(t, "POST", "/platform/tenants/"+w.tenant[B].ID+"/delete", url.Values{"confirm": {w.tenant[B].Slug}})
	if w.count(`SELECT count(*) FROM settings WHERE key=$1`, "saml:"+w.tenant[B].ID) != 0 || w.count(`SELECT count(*) FROM tenant_sso_domains WHERE tenant_id=$1::uuid`, w.tenant[B].ID) != 0 ||
		w.count(`SELECT count(*) FROM users WHERE idp=$1`, w.tenant[B].ID) != 0 {
		t.Error("tenant deletion left SSO data behind")
	}
	if k, _ := w.a.St.GetSecret(w.ctx, "tenant:"+w.tenant[B].ID+":saml_sp_key"); k != "" {
		t.Error("tenant SP key survived deletion")
	}
}
