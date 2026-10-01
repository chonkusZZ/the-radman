package manager

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// soloWorld is a standalone installation with one user of each edition role.
func newSoloWorld(t *testing.T) *world {
	a := testAppMode(t, ModeStandalone)
	ctx := context.Background()
	g := a.General(ctx)
	g.PublicHost = "127.0.0.1"
	a.SaveGeneral(ctx, g)
	w := &world{a: a, ctx: ctx, tenant: map[string]*Tenant{}, site: map[string]string{}, user: map[string]string{}}
	w.srv = httptest.NewTLSServer(a.NewHandler())
	t.Cleanup(w.srv.Close)
	a.Opt.HTTPSAddr = ":" + strings.Split(w.srv.URL, ":")[2]
	mk := func(label, platform, member string) {
		var id string
		a.St.DB.QueryRow(ctx, `INSERT INTO users(email,name,password_hash,platform_role) VALUES($1,$1,'x',$2) RETURNING id::text`, label+"@test", platform).Scan(&id)
		w.user[label] = id
		if member != "" {
			a.St.DB.Exec(ctx, `INSERT INTO memberships(user_id,tenant_id,role) VALUES($1::uuid,$2::uuid,$3)`, id, a.solo.ID, member)
		}
	}
	mk("admin", RoleGlobalAdmin, "")
	mk("operator", "", RoleTenantAdmin)
	mk("viewer", "", RoleReadOnly)
	mk("stranger", "", "") // an account with no access at all
	return w
}

func TestStandaloneStartup(t *testing.T) {
	admin := os.Getenv("RADMAN_TEST_DB")
	if admin == "" {
		t.Skip("set RADMAN_TEST_DB")
	}
	a := testAppMode(t, ModeStandalone)
	ctx := context.Background()
	var n int
	a.St.DB.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&n)
	if n != 1 || a.solo == nil || a.solo.Slug != "default" {
		t.Fatalf("standalone must create exactly one implicit tenant, got %d (%+v)", n, a.solo)
	}
	// an MSP database with several tenants cannot silently run as standalone
	if _, err := a.CreateTenant(ctx, "Second"); err != nil {
		t.Fatal(err)
	}
	dbURL := a.St.DB.Config().ConnString()
	opts := Options{DatabaseURL: dbURL, DataDir: a.Opt.DataDir, UDPAddr: "127.0.0.1:0", Version: "test"}
	opts.Mode = ModeStandalone
	if _, err := New(ctx, opts, log.New(io.Discard, "", 0)); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected a refusal to start, got %v", err)
	}
	opts.Mode = ModeMSP
	b, err := New(ctx, opts, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("msp mode must start on the same database: %v", err)
	}
	b.St.DB.Close()
	opts.Mode = "bogus"
	if _, err := New(ctx, opts, log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

// A standalone installation can later become an MSP installation by changing the mode: nothing is migrated or lost.
func TestStandaloneToMSP(t *testing.T) {
	a := testAppMode(t, ModeStandalone)
	ctx := context.Background()
	var op, site string
	a.St.DB.QueryRow(ctx, `INSERT INTO users(email,password_hash) VALUES('op@x','x') RETURNING id::text`).Scan(&op)
	a.setSoloRole(ctx, op, soloOperator)
	eap, _ := a.CreateInternalEAPCert(ctx, a.solo.ID, "srv", "srv.test", nil)
	a.St.DB.QueryRow(ctx, `INSERT INTO sites(tenant_id,name,eap_cert_id) VALUES($1::uuid,'HQ',$2::uuid) RETURNING id::text`, a.solo.ID, eap).Scan(&site)

	opts := a.Opt
	opts.DatabaseURL = a.St.DB.Config().ConnString()
	opts.Mode = ModeMSP
	b, err := New(ctx, opts, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer b.St.DB.Close()
	var tn, role string
	if err := b.St.DB.QueryRow(ctx, `SELECT t.name, m.role FROM sites s JOIN tenants t ON t.id=s.tenant_id JOIN memberships m ON m.tenant_id=t.id WHERE s.id=$1::uuid AND m.user_id=$2::uuid`, site, op).Scan(&tn, &role); err != nil || tn != "Default" || role != RoleTenantAdmin {
		t.Fatalf("after switching to MSP: tenant=%q role=%q err=%v", tn, role, err)
	}
	if cfg, err := b.BuildSiteConfig(ctx, site); err != nil || cfg.SiteName != "HQ" {
		t.Fatalf("site config after mode switch: %v", err)
	}
}

func TestStandaloneUI(t *testing.T) {
	w := newSoloWorld(t)
	admin, op, viewer, stranger := w.as(t, "admin", ""), w.as(t, "operator", ""), w.as(t, "viewer", ""), w.as(t, "stranger", "")

	// the simplified chrome: no tenants anywhere
	code, dash := admin.do(t, "GET", "/", nil)
	expect(t, "admin dashboard", code, 200)
	for _, want := range []string{"Settings", "Users", "Dashboard"} {
		if !strings.Contains(dash, want) {
			t.Errorf("admin nav is missing %q", want)
		}
	}
	for _, bad := range []string{"Tenants", "Platform", "Switch tenant", "tenantbox", "Single sign-on</a>"} {
		if strings.Contains(dash, bad) {
			t.Errorf("standalone UI leaks the multi-tenant concept %q", bad)
		}
	}
	if !strings.Contains(dash, "Administrator") {
		t.Error("admin role label should read Administrator")
	}

	// multi-tenant routes do not exist
	for _, p := range []string{"/platform", "/platform/users", "/platform/audit", "/platform/tenants/x", "/tenants", "/sso", "/t/default/login", "/t/default/saml/login", "/t/default/saml/metadata"} {
		code, _ := admin.do(t, "GET", p, nil)
		expect(t, "standalone GET "+p, code, 404)
	}
	for _, p := range []string{"/tenant/switch", "/sso/discover", "/platform/tenants", "/t/default/saml/acs"} {
		code, _ := admin.do(t, "POST", p, url.Values{"tenant": {w.a.solo.ID}})
		expect(t, "standalone POST "+p, code, 404, 405)
	}
	// the login page has no organisation discovery
	r, _ := admin.cl.Get(w.srv.URL + "/login")
	b, _ := io.ReadAll(r.Body)
	if strings.Contains(string(b), "/sso/discover") {
		t.Error("login page offers tenant SSO discovery in standalone mode")
	}

	// administrators: everything
	for _, p := range []string{"/settings", "/settings?tab=webtls", "/settings?tab=sso", "/settings?tab=database", "/settings?tab=branding", "/users", "/sites", "/nodes", "/pki", "/eapcerts", "/logs", "/logs/audit", "/account"} {
		code, _ := admin.do(t, "GET", p, nil)
		expect(t, "admin GET "+p, code, 200)
	}
	// operators: configure RADIUS, but not system settings or users
	code, body := op.do(t, "GET", "/", nil)
	expect(t, "operator dashboard", code, 200)
	if strings.Contains(body, `href="/settings"`) || strings.Contains(body, `href="/users"`) {
		t.Error("operator sees administrator-only navigation")
	}
	code, _ = op.do(t, "POST", "/sites", url.Values{"name": {"Branch"}})
	expect(t, "operator creates a site", code, 303)
	for _, p := range []string{"/settings", "/users", "/settings?tab=database"} {
		code, _ := op.do(t, "GET", p, nil)
		expect(t, "operator GET "+p, code, 403)
	}
	for _, p := range []string{"/users", "/settings/general", "/settings/sso"} {
		code, _ := op.do(t, "POST", p, url.Values{"email": {"x@y"}})
		expect(t, "operator POST "+p, code, 403)
	}
	// read-only: look but never touch
	code, _ = viewer.do(t, "GET", "/sites", nil)
	expect(t, "read-only GET /sites", code, 200)
	code, _ = viewer.do(t, "POST", "/sites", url.Values{"name": {"nope"}})
	expect(t, "read-only POST /sites", code, 403)
	for _, p := range []string{"/settings", "/users"} {
		code, _ := viewer.do(t, "GET", p, nil)
		expect(t, "read-only GET "+p, code, 403)
	}
	// a user with no access at all
	code, _ = stranger.do(t, "GET", "/", nil)
	expect(t, "user without access", code, 403)
	code, _ = stranger.do(t, "GET", "/sites", nil)
	expect(t, "user without access GET /sites", code, 403)

	// the audit trail of a single installation includes system-level actions
	admin.do(t, "POST", "/settings/sso", url.Values{"group_roles": {"g1=admin"}})
	_, audit := op.do(t, "GET", "/logs/audit", nil)
	if !strings.Contains(audit, "settings.sso") {
		t.Error("standalone audit log should include system-level actions")
	}
}

func TestStandaloneUserManagement(t *testing.T) {
	w := newSoloWorld(t)
	admin := w.as(t, "admin", "")
	count := func(q string, args ...any) int { return w.count(q, args...) }

	for role, wantPlat := range map[string]string{"admin": RoleGlobalAdmin, "operator": "", "read_only": ""} {
		email := role + "-new@test"
		code, _ := admin.do(t, "POST", "/users", url.Values{"email": {email}, "role": {role}, "password": {"a-long-password-123"}})
		expect(t, "create "+role, code, 303)
		var plat string
		var mem *string
		if err := w.a.St.DB.QueryRow(w.ctx, `SELECT u.platform_role, m.role FROM users u LEFT JOIN memberships m ON m.user_id=u.id WHERE u.email=$1`, email).Scan(&plat, &mem); err != nil {
			t.Fatal(err)
		}
		wantMem := map[string]string{"admin": "", "operator": RoleTenantAdmin, "read_only": RoleReadOnly}[role]
		if plat != wantPlat || (wantMem == "") != (mem == nil) || (mem != nil && *mem != wantMem) {
			t.Errorf("%s: platform=%q membership=%v", role, plat, mem)
		}
	}
	// changing a role moves the user between platform role and membership (never both)
	var id string
	w.a.St.DB.QueryRow(w.ctx, `SELECT id::text FROM users WHERE email='operator-new@test'`).Scan(&id)
	admin.do(t, "POST", "/users/"+id+"/update", url.Values{"role": {"admin"}})
	if count(`SELECT count(*) FROM users WHERE id=$1::uuid AND platform_role='global_admin'`, id) != 1 || count(`SELECT count(*) FROM memberships WHERE user_id=$1::uuid`, id) != 0 {
		t.Error("promoting to administrator should clear the membership")
	}
	admin.do(t, "POST", "/users/"+id+"/update", url.Values{"role": {"read_only"}})
	if count(`SELECT count(*) FROM users WHERE id=$1::uuid AND platform_role=''`, id) != 1 || count(`SELECT count(*) FROM memberships WHERE user_id=$1::uuid AND role='read_only'`, id) != 1 {
		t.Error("demoting should drop the platform role and set a read-only membership")
	}
	// guards: never lock everyone out
	var seedAdmin string
	w.a.St.DB.Exec(w.ctx, `DELETE FROM users WHERE email='admin-new@test'`)
	seedAdmin = w.user["admin"]
	admin.do(t, "POST", "/users/"+seedAdmin+"/update", url.Values{"role": {"read_only"}})
	admin.do(t, "POST", "/users/"+seedAdmin+"/update", url.Values{"role": {"admin"}, "disabled": {"1"}})
	admin.do(t, "POST", "/users/"+seedAdmin+"/delete", nil)
	if count(`SELECT count(*) FROM users WHERE id=$1::uuid AND platform_role='global_admin' AND NOT disabled`, seedAdmin) != 1 {
		t.Error("the last administrator was demoted, disabled or deleted")
	}
	code, _ := admin.do(t, "POST", "/users", url.Values{"email": {"bad"}, "role": {"emperor"}, "password": {"a-long-password-123"}})
	expect(t, "invalid user", code, 303)
	if count(`SELECT count(*) FROM users WHERE email='bad'`) != 0 {
		t.Error("invalid user created")
	}
}

func TestStandaloneSSOMapping(t *testing.T) {
	w := newSoloWorld(t)
	admin := w.as(t, "admin", "")
	admin.do(t, "POST", "/settings/sso", url.Values{"group_roles": {"g-admin=admin\ng-ops=operator\ng-view=read_only\ng-bad=emperor"}})
	cfg := w.a.SAMLSettings(w.ctx)
	got := map[string]string{}
	for _, m := range cfg.GroupRoles {
		got[m.Group] = m.Role
	}
	want := map[string]string{"g-admin": RoleGlobalAdmin, "g-ops": RoleTenantAdmin + "@default", "g-view": RoleReadOnly + "@default"}
	if len(got) != len(want) {
		t.Fatalf("stored mapping %v", got)
	}
	for g, r := range want {
		if got[g] != r {
			t.Errorf("%s -> %q, want %q", g, got[g], r)
		}
	}
	_, page := admin.do(t, "GET", "/settings?tab=sso", nil)
	for _, line := range []string{"g-admin=admin", "g-ops=operator", "g-view=read_only"} {
		if !strings.Contains(page, line) {
			t.Errorf("settings page does not show %q in edition vocabulary", line)
		}
	}
	if strings.Contains(page, "tenant_admin@") {
		t.Error("standalone SSO form leaks tenant vocabulary")
	}
}

func TestStandaloneSSOLogin(t *testing.T) {
	w := newSoloWorld(t)
	idp := newIdP(t)
	idp.addUser("olive", "olive@corp.example", "grp-ops")
	idp.addUser("vera", "vera@corp.example", "grp-view")
	idp.addUser("nobody", "nobody@corp.example", "grp-none")
	idp.register(t, w.srv.Client(), w.srv.URL+"/saml/metadata", "sp")
	w.a.St.SetJSON(w.ctx, "saml", SAML{Enabled: true, AllowLocal: true, MetadataXML: idp.metadataXML(t), EmailAttr: "mail", NameAttr: "cn", GroupAttr: "eduPersonAffiliation",
		GroupRoles: []GroupMap{{"grp-ops", RoleTenantAdmin + "@default"}, {"grp-view", RoleReadOnly + "@default"}}})

	resp, cl := ssoLogin(t, w.srv.URL, w.srv.Client(), "/saml/login", idp, "olive", "")
	if resp.Header.Get("Location") != "/" {
		t.Fatalf("operator via SSO: %q", resp.Header.Get("Location"))
	}
	r, _ := cl.Get(w.srv.URL + "/sites")
	r.Body.Close()
	expect(t, "SSO operator opens sites", r.StatusCode, 200)
	r, _ = cl.Get(w.srv.URL + "/settings")
	r.Body.Close()
	expect(t, "SSO operator is not an administrator", r.StatusCode, 403)
	resp, cl = ssoLogin(t, w.srv.URL, w.srv.Client(), "/saml/login", idp, "vera", "")
	cl.CheckRedirect = nil
	r, _ = cl.Get(w.srv.URL + "/")
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || !strings.Contains(string(b), "Read-only") {
		t.Errorf("read-only SSO user: %d", r.StatusCode)
	}
	resp, _ = ssoLogin(t, w.srv.URL, w.srv.Client(), "/saml/login", idp, "nobody", "")
	if resp.Header.Get("Location") != "/login" {
		t.Error("user in no mapped group must be refused")
	}
}
