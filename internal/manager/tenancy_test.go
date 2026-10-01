package manager

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"radman/internal/pki"
)

// world is a two-tenant platform with one user of every role.
type world struct {
	a      *App
	srv    *httptest.Server
	ctx    context.Context
	tenant map[string]*Tenant
	site   map[string]string // tenant name -> site id
	ap     map[string]string
	node   map[string]string
	pkiID  map[string]string
	eap    map[string]string
	user   map[string]string // label -> user id
}

type actor struct {
	w    *world
	cl   *http.Client
	csrf string
}

func newWorld(t *testing.T) *world {
	requireMSP(t)
	a := testApp(t)
	ctx := context.Background()
	w := &world{a: a, ctx: ctx, tenant: map[string]*Tenant{}, site: map[string]string{}, ap: map[string]string{}, node: map[string]string{},
		pkiID: map[string]string{}, eap: map[string]string{}, user: map[string]string{}}
	g := a.General(ctx)
	g.PublicHost = "127.0.0.1"
	a.SaveGeneral(ctx, g)
	w.srv = httptest.NewTLSServer(a.NewHandler())
	t.Cleanup(w.srv.Close)
	a.Opt.HTTPSAddr = ":" + strings.Split(w.srv.URL, ":")[2]

	var tmp string
	for _, name := range []string{"Alpha", "Bravo"} {
		tn, err := a.CreateTenant(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		w.tenant[name] = tn
		caPEM, _, _ := pki.NewCA(name+" CA", time.Hour)
		a.St.DB.QueryRow(ctx, `INSERT INTO pki_profiles(tenant_id,name,ca_pem) VALUES($1::uuid,$2,$3) RETURNING id::text`, tn.ID, name+" PKI", string(caPEM)).Scan(&tmp)
		w.pkiID[name] = tmp
		w.eap[name], _ = a.CreateInternalEAPCert(ctx, tn.ID, name+" srv", "radius."+strings.ToLower(name)+".test", nil)
		a.St.DB.QueryRow(ctx, `INSERT INTO sites(tenant_id,name,eap_cert_id) VALUES($1::uuid,$2,$3::uuid) RETURNING id::text`, tn.ID, name+" HQ", w.eap[name]).Scan(&tmp)
		w.site[name] = tmp
		a.St.DB.Exec(ctx, `INSERT INTO site_pki VALUES($1::uuid,$2::uuid)`, w.site[name], w.pkiID[name])
		a.St.DB.QueryRow(ctx, `INSERT INTO aps(site_id,name,addr,secret_enc) VALUES($1::uuid,$2,'10.0.0.1',$3) RETURNING id::text`, w.site[name], name+" AP", a.seal("secretsecret")).Scan(&tmp)
		w.ap[name] = tmp
		a.St.DB.QueryRow(ctx, `INSERT INTO nodes(site_id,name,status) VALUES($1::uuid,$2,'active') RETURNING id::text`, w.site[name], name+" node").Scan(&tmp)
		w.node[name] = tmp
	}
	mk := func(label, platform string) {
		var tmp string
		a.St.DB.QueryRow(ctx, `INSERT INTO users(email,name,password_hash,platform_role) VALUES($1,$1,'x',$2) RETURNING id::text`, label+"@test", platform).Scan(&tmp)
		w.user[label] = tmp
	}
	mk("gadmin", RoleGlobalAdmin)
	mk("gro", RoleGlobalReadonly)
	mk("aadmin", "")
	mk("aro", "")
	mk("badmin", "")
	mk("multi", "")
	grant := func(label, tenant, role string) {
		a.St.DB.Exec(ctx, `INSERT INTO memberships(user_id,tenant_id,role) VALUES($1::uuid,$2::uuid,$3)`, w.user[label], w.tenant[tenant].ID, role)
	}
	grant("aadmin", "Alpha", RoleTenantAdmin)
	grant("aro", "Alpha", RoleReadOnly)
	grant("badmin", "Bravo", RoleTenantAdmin)
	grant("multi", "Alpha", RoleTenantAdmin)
	grant("multi", "Bravo", RoleReadOnly)
	return w
}

// as opens a session for a user, optionally already inside a tenant.
func (w *world) as(t *testing.T, label, tenant string) *actor {
	sid, csrf := randToken(32), randToken(12)
	var tid any
	if tenant != "" {
		tid = w.tenant[tenant].ID
	}
	if _, err := w.a.St.DB.Exec(w.ctx, `INSERT INTO sessions(id,user_id,csrf,tenant_id,expires_at) VALUES($1,$2::uuid,$3,$4::uuid,now()+interval '1 hour')`, hashSID(sid), w.user[label], csrf, tid); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(w.srv.URL)
	jar.SetCookies(u, []*http.Cookie{{Name: cookieName, Value: sid, Path: "/", Secure: true}})
	// a client per actor: httptest's shared client would otherwise swap cookie jars between actors
	cl := &http.Client{Transport: w.srv.Client().Transport, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &actor{w: w, cl: cl, csrf: csrf}
}

func (x *actor) do(t *testing.T, method, path string, form url.Values) (int, string) {
	t.Helper()
	var resp *http.Response
	var err error
	if method == "GET" {
		resp, err = x.cl.Get(x.w.srv.URL + path)
	} else {
		if form == nil {
			form = url.Values{}
		}
		if form.Get("csrf") == "" && form.Get("nocsrf") == "" {
			form.Set("csrf", x.csrf)
		}
		form.Del("nocsrf")
		resp, err = x.cl.PostForm(x.w.srv.URL+path, form)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func expect(t *testing.T, what string, got int, want ...int) {
	t.Helper()
	for _, w := range want {
		if got == w {
			return
		}
	}
	t.Errorf("%s: got HTTP %d, want %v", what, got, want)
}

func (w *world) count(q string, args ...any) int {
	var n int
	w.a.St.DB.QueryRow(w.ctx, q, args...).Scan(&n)
	return n
}

func TestTenantIsolation(t *testing.T) {
	w := newWorld(t)
	A, B := "Alpha", "Bravo"
	aadmin := w.as(t, "aadmin", A)

	// own resources are reachable; other tenants' resources are indistinguishable from missing ones
	for _, p := range []string{"/sites/" + w.site[A], "/aps/" + w.ap[A] + "/radsec", "/nodes/" + w.node[A], "/pki/" + w.pkiID[A], "/sites", "/nodes", "/pki", "/eapcerts", "/logs", "/users"} {
		code, _ := aadmin.do(t, "GET", p, nil)
		expect(t, "tenant A admin GET "+p, code, 200)
	}
	for _, p := range []string{"/sites/" + w.site[B], "/aps/" + w.ap[B] + "/radsec", "/nodes/" + w.node[B], "/pki/" + w.pkiID[B]} {
		code, body := aadmin.do(t, "GET", p, nil)
		expect(t, "tenant A admin GET other tenant "+p, code, 404)
		if strings.Contains(body, "Bravo") {
			t.Errorf("response for %s leaks the other tenant's name", p)
		}
	}
	// mutations against another tenant's resources fail and change nothing
	mut := []struct{ path, form string }{
		{"/sites/" + w.site[B] + "/update", "name=Hacked&auth_port=1812&acct_port=1813"},
		{"/sites/" + w.site[B] + "/aps", "name=evil&addr=10.9.9.9"},
		{"/sites/" + w.site[B] + "/nodes", "name=evil"},
		{"/sites/" + w.site[B] + "/delete", ""},
		{"/aps/" + w.ap[B] + "/delete", ""},
		{"/aps/" + w.ap[B] + "/update", "name=Hacked&addr=10.0.0.9"},
		{"/aps/" + w.ap[B] + "/radsec/sign", "csr=x"},
		{"/nodes/" + w.node[B] + "/revoke", ""},
		{"/nodes/" + w.node[B] + "/delete", ""},
		{"/pki/" + w.pkiID[B] + "/delete", ""},
		{"/pki/" + w.pkiID[B] + "/update", "name=Hacked"},
		{"/eapcerts/" + w.eap[B] + "/delete", ""},
	}
	for _, m := range mut {
		v, _ := url.ParseQuery(m.form)
		code, _ := aadmin.do(t, "POST", m.path, v)
		expect(t, "cross-tenant POST "+m.path, code, 404)
	}
	if n := w.count(`SELECT count(*) FROM sites WHERE tenant_id=$1::uuid AND name='Bravo HQ'`, w.tenant[B].ID); n != 1 {
		t.Error("tenant B's site was modified or deleted by tenant A")
	}
	if w.count(`SELECT count(*) FROM aps WHERE id=$1::uuid`, w.ap[B]) != 1 || w.count(`SELECT count(*) FROM nodes WHERE id=$1::uuid AND status='active'`, w.node[B]) != 1 ||
		w.count(`SELECT count(*) FROM pki_profiles WHERE id=$1::uuid`, w.pkiID[B]) != 1 || w.count(`SELECT count(*) FROM eap_certs WHERE id=$1::uuid`, w.eap[B]) != 1 {
		t.Error("tenant B's data was changed by tenant A")
	}

	// cannot pull another tenant's PKI profile or server certificate into your own site
	code, _ := aadmin.do(t, "POST", "/sites/"+w.site[A]+"/update", url.Values{"name": {"Alpha HQ"}, "auth_port": {"1812"}, "acct_port": {"1813"}, "pki": {w.pkiID[A], w.pkiID[B]}, "eap_cert_id": {w.eap[A]}})
	expect(t, "update with foreign PKI", code, 303)
	if w.count(`SELECT count(*) FROM site_pki WHERE site_id=$1::uuid AND pki_id=$2::uuid`, w.site[A], w.pkiID[B]) != 0 {
		t.Error("foreign PKI profile attached to tenant A's site")
	}
	aadmin.do(t, "POST", "/sites/"+w.site[A]+"/update", url.Values{"name": {"Alpha HQ"}, "auth_port": {"1812"}, "acct_port": {"1813"}, "eap_cert_id": {w.eap[B]}})
	if w.count(`SELECT count(*) FROM sites WHERE id=$1::uuid AND eap_cert_id=$2::uuid`, w.site[A], w.eap[B]) != 0 {
		t.Error("foreign server certificate assigned to tenant A's site")
	}
	// and even a forced cross-tenant row never reaches a node's config
	w.a.St.DB.Exec(w.ctx, `INSERT INTO site_pki VALUES($1::uuid,$2::uuid)`, w.site[A], w.pkiID[B])
	cfg, err := w.a.BuildSiteConfig(w.ctx, w.site[A])
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range cfg.PKI {
		if p.Name == "Bravo PKI" {
			t.Error("another tenant's PKI profile leaked into a node configuration")
		}
	}
	w.a.St.DB.Exec(w.ctx, `DELETE FROM site_pki WHERE pki_id=$1::uuid AND site_id=$2::uuid`, w.pkiID[B], w.site[A])

	// switching tenants requires access
	code, _ = aadmin.do(t, "POST", "/tenant/switch", url.Values{"tenant": {w.tenant[B].ID}})
	expect(t, "switch to a tenant without access", code, 403)

	// log isolation: filters cannot be used to reach another tenant's events
	for name, subj := range map[string]string{A: "dev-of-alpha", B: "dev-of-bravo"} {
		w.a.St.DB.Exec(w.ctx, `INSERT INTO events(node_id,site_id,tenant_id,seq,ts,kind,data) VALUES($1::uuid,$2::uuid,$3::uuid,1,now(),'auth',jsonb_build_object('result','accept','subject',$4::text))`,
			w.node[name], w.site[name], w.tenant[name].ID, subj)
	}
	_, logs := aadmin.do(t, "GET", "/logs", nil)
	if !strings.Contains(logs, "dev-of-alpha") || strings.Contains(logs, "dev-of-bravo") {
		t.Error("log page does not show exactly tenant A's events")
	}
	_, logs = aadmin.do(t, "GET", "/logs?site="+w.site[B], nil)
	if strings.Contains(logs, "dev-of-bravo") {
		t.Error("site filter bypassed tenant isolation in logs")
	}
	_, dash := aadmin.do(t, "GET", "/", nil)
	if strings.Contains(dash, "dev-of-bravo") {
		t.Error("dashboard leaks events")
	}

	// tenant user management stays inside the tenant
	code, _ = aadmin.do(t, "POST", "/users", url.Values{"email": {"new-a@test"}, "role": {"read_only"}, "password": {"a-long-password-123"}})
	expect(t, "add user", code, 303)
	if w.count(`SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.email='new-a@test' AND m.tenant_id=$1::uuid AND m.role='read_only'`, w.tenant[A].ID) != 1 {
		t.Error("new tenant user missing")
	}
	aadmin.do(t, "POST", "/users/update", url.Values{"user": {w.user["badmin"]}, "role": {"read_only"}})
	aadmin.do(t, "POST", "/users/update", url.Values{"user": {w.user["badmin"]}, "remove": {"1"}})
	if w.count(`SELECT count(*) FROM memberships WHERE user_id=$1::uuid AND tenant_id=$2::uuid AND role='tenant_admin'`, w.user["badmin"], w.tenant[B].ID) != 1 {
		t.Error("tenant A admin altered a tenant B membership")
	}
	_, users := aadmin.do(t, "GET", "/users", nil)
	if strings.Contains(users, "badmin@test") {
		t.Error("tenant user list leaks other tenants' users")
	}
	code, _ = aadmin.do(t, "POST", "/users/update", url.Values{"user": {w.user["aadmin"]}, "remove": {"1"}})
	if w.count(`SELECT count(*) FROM memberships WHERE user_id=$1::uuid`, w.user["aadmin"]) != 1 {
		t.Error("an administrator removed their own access")
	}
}

func TestRolePermissions(t *testing.T) {
	w := newWorld(t)
	A, B := "Alpha", "Bravo"

	// --- read-only user: can look, cannot touch ---
	aro := w.as(t, "aro", A)
	code, body := aro.do(t, "GET", "/sites/"+w.site[A], nil)
	expect(t, "read-only GET site", code, 200)
	if strings.Contains(body, "secretsecret") {
		t.Error("read-only user can see AP shared secrets")
	}
	if strings.Contains(body, "Create site node") || strings.Contains(body, "Add access point") {
		t.Error("write controls rendered for a read-only user")
	}
	for _, m := range []struct{ path, form string }{
		{"/sites", "name=x"}, {"/sites/" + w.site[A] + "/update", "name=x&auth_port=1&acct_port=2"}, {"/sites/" + w.site[A] + "/aps", "name=x&addr=10.1.1.1"},
		{"/sites/" + w.site[A] + "/nodes", "name=x"}, {"/sites/" + w.site[A] + "/delete", ""}, {"/aps/" + w.ap[A] + "/delete", ""},
		{"/aps/" + w.ap[A] + "/radsec/sign", "csr=x"}, {"/nodes/" + w.node[A] + "/revoke", ""}, {"/pki", "name=x"}, {"/pki/" + w.pkiID[A] + "/delete", ""},
		{"/eapcerts/internal", "name=x&cn=y"}, {"/eapcerts/" + w.eap[A] + "/delete", ""}, {"/users", "email=x@y&role=read_only"},
	} {
		v, _ := url.ParseQuery(m.form)
		c, _ := aro.do(t, "POST", m.path, v)
		expect(t, "read-only POST "+m.path, c, 403)
	}
	c, _ := aro.do(t, "GET", "/users", nil)
	expect(t, "read-only GET /users", c, 403)
	if w.count(`SELECT count(*) FROM sites WHERE tenant_id=$1::uuid`, w.tenant[A].ID) != 1 || w.count(`SELECT count(*) FROM aps WHERE id=$1::uuid`, w.ap[A]) != 1 {
		t.Error("read-only user changed data")
	}

	// --- nobody below global level reaches the platform area ---
	for _, who := range []*actor{w.as(t, "aadmin", A), aro} {
		for _, p := range []string{"/platform", "/platform/users", "/platform/audit", "/settings", "/settings?tab=database", "/platform/tenants/" + w.tenant[A].ID} {
			c, _ := who.do(t, "GET", p, nil)
			expect(t, "tenant user GET "+p, c, 403)
		}
		for _, p := range []string{"/platform/tenants", "/settings/general", "/settings/sso", "/settings/keykit", "/platform/users"} {
			c, _ := who.do(t, "POST", p, url.Values{"name": {"x"}})
			expect(t, "tenant user POST "+p, c, 403)
		}
	}

	// --- global read-only: sees everything, changes nothing ---
	gro := w.as(t, "gro", "")
	for _, p := range []string{"/platform", "/platform/users", "/platform/audit", "/settings", "/settings?tab=database", "/platform/tenants/" + w.tenant[B].ID} {
		c, _ := gro.do(t, "GET", p, nil)
		expect(t, "global read-only GET "+p, c, 200)
	}
	for _, p := range []string{"/platform/tenants", "/settings/general", "/platform/users", "/platform/tenants/" + w.tenant[B].ID + "/update", "/platform/tenants/" + w.tenant[B].ID + "/delete"} {
		c, _ := gro.do(t, "POST", p, url.Values{"name": {"x"}})
		expect(t, "global read-only POST "+p, c, 403)
	}
	groIn := w.as(t, "gro", B)
	c, _ = groIn.do(t, "GET", "/sites/"+w.site[B], nil)
	expect(t, "global read-only may read any tenant", c, 200)
	c, _ = groIn.do(t, "POST", "/sites/"+w.site[B]+"/update", url.Values{"name": {"x"}, "auth_port": {"1"}, "acct_port": {"2"}})
	expect(t, "global read-only may not write to a tenant", c, 403)
	c, _ = groIn.do(t, "GET", "/users", nil)
	expect(t, "global read-only /users", c, 403)

	// --- global admin: everything ---
	gadmin := w.as(t, "gadmin", "")
	c, _ = gadmin.do(t, "GET", "/sites", nil) // no tenant chosen yet -> sent to choose one
	expect(t, "global admin without tenant context", c, 303)
	c, _ = gadmin.do(t, "POST", "/platform/tenants", url.Values{"name": {"Charlie Corp"}})
	expect(t, "global admin creates tenant", c, 303)
	if w.count(`SELECT count(*) FROM tenants WHERE slug='charlie-corp'`) != 1 {
		t.Error("tenant not created")
	}
	c, _ = gadmin.do(t, "POST", "/tenant/switch", url.Values{"tenant": {w.tenant[B].ID}})
	expect(t, "global admin switches tenant", c, 303)
	c, _ = gadmin.do(t, "POST", "/sites/"+w.site[B]+"/update", url.Values{"name": {"Bravo HQ renamed"}, "auth_port": {"1812"}, "acct_port": {"1813"}})
	expect(t, "global admin writes to any tenant", c, 303)
	if w.count(`SELECT count(*) FROM sites WHERE id=$1::uuid AND name='Bravo HQ renamed'`, w.site[B]) != 1 {
		t.Error("global admin write did not apply")
	}

	// --- multi-tenant user: role depends on the tenant ---
	multi := w.as(t, "multi", "")
	_, picker := multi.do(t, "GET", "/", nil)
	if !strings.Contains(picker, "Alpha") || !strings.Contains(picker, "Bravo") {
		t.Error("tenant picker should list both tenants")
	}
	multi.do(t, "POST", "/tenant/switch", url.Values{"tenant": {w.tenant[B].ID}})
	c, _ = multi.do(t, "POST", "/sites", url.Values{"name": {"nope"}})
	expect(t, "multi-tenant user is read-only in B", c, 403)
	multi.do(t, "POST", "/tenant/switch", url.Values{"tenant": {w.tenant[A].ID}})
	c, _ = multi.do(t, "POST", "/sites", url.Values{"name": {"allowed"}})
	expect(t, "multi-tenant user is admin in A", c, 303)

	// --- CSRF ---
	aadmin := w.as(t, "aadmin", A)
	c, _ = aadmin.do(t, "POST", "/sites", url.Values{"name": {"csrf-test"}, "csrf": {"wrong"}})
	expect(t, "bad CSRF token", c, 403)
}

func TestSuspensionAndQuotas(t *testing.T) {
	w := newWorld(t)
	A := "Alpha"
	aadmin, gadmin := w.as(t, "aadmin", A), w.as(t, "gadmin", A)

	// quota
	w.a.St.DB.Exec(w.ctx, `UPDATE tenants SET max_sites=1, max_aps=1, max_nodes=1 WHERE id=$1::uuid`, w.tenant[A].ID)
	aadmin.do(t, "POST", "/sites", url.Values{"name": {"second"}})
	aadmin.do(t, "POST", "/sites/"+w.site[A]+"/aps", url.Values{"name": {"ap2"}, "addr": {"10.1.1.2"}})
	aadmin.do(t, "POST", "/sites/"+w.site[A]+"/nodes", url.Values{"name": {"node2"}})
	if w.count(`SELECT count(*) FROM sites WHERE tenant_id=$1::uuid`, w.tenant[A].ID) != 1 || w.count(`SELECT count(*) FROM aps a JOIN sites s ON s.id=a.site_id WHERE s.tenant_id=$1::uuid`, w.tenant[A].ID) != 1 ||
		w.count(`SELECT count(*) FROM nodes n JOIN sites s ON s.id=n.site_id WHERE s.tenant_id=$1::uuid`, w.tenant[A].ID) != 1 {
		t.Error("quota not enforced")
	}
	gadmin.do(t, "POST", "/platform/tenants/"+w.tenant[A].ID+"/update", url.Values{"name": {"Alpha"}, "max_sites": {"5"}, "max_aps": {"5"}, "max_nodes": {"5"}})
	aadmin.do(t, "POST", "/sites", url.Values{"name": {"second"}})
	if w.count(`SELECT count(*) FROM sites WHERE tenant_id=$1::uuid`, w.tenant[A].ID) != 2 {
		t.Error("raising the quota did not allow creation")
	}

	// suspension freezes tenant users but not the provider
	gadmin.do(t, "POST", "/platform/tenants/"+w.tenant[A].ID+"/update", url.Values{"name": {"Alpha"}, "status": {"suspended"}})
	c, _ := aadmin.do(t, "POST", "/sites", url.Values{"name": {"third"}})
	expect(t, "suspended tenant admin write", c, 403)
	c, _ = aadmin.do(t, "GET", "/sites", nil)
	expect(t, "suspended tenant admin read", c, 200)
	c, _ = gadmin.do(t, "POST", "/sites", url.Values{"name": {"third"}})
	expect(t, "global admin writes to suspended tenant", c, 303)
}

func TestTenantDeletionRemovesEverything(t *testing.T) {
	w := newWorld(t)
	B := "Bravo"
	tid := w.tenant[B].ID
	w.a.St.DB.Exec(w.ctx, `INSERT INTO events(node_id,site_id,tenant_id,seq,ts,kind,data) VALUES($1::uuid,$2::uuid,$3::uuid,1,now(),'auth','{}')`, w.node[B], w.site[B], tid)
	gadmin := w.as(t, "gadmin", "")
	c, _ := gadmin.do(t, "POST", "/platform/tenants/"+tid+"/delete", url.Values{"confirm": {"wrong"}})
	expect(t, "delete without confirmation", c, 303)
	if w.count(`SELECT count(*) FROM tenants WHERE id=$1::uuid`, tid) != 1 {
		t.Fatal("deleted without the confirmation text")
	}
	gadmin.do(t, "POST", "/platform/tenants/"+tid+"/delete", url.Values{"confirm": {w.tenant[B].Slug}})
	for _, q := range []string{`SELECT count(*) FROM tenants WHERE id=$1::uuid`, `SELECT count(*) FROM sites WHERE tenant_id=$1::uuid`, `SELECT count(*) FROM pki_profiles WHERE tenant_id=$1::uuid`,
		`SELECT count(*) FROM eap_certs WHERE tenant_id=$1::uuid`, `SELECT count(*) FROM events WHERE tenant_id=$1::uuid`, `SELECT count(*) FROM memberships WHERE tenant_id=$1::uuid`} {
		if n := w.count(q, tid); n != 0 {
			t.Errorf("%s -> %d rows remain", q, n)
		}
	}
	if s, _ := w.a.St.GetSecret(w.ctx, tenantSecret(tid, "eap")+"_key"); s != "" {
		t.Error("tenant CA key survived deletion")
	}
	if w.count(`SELECT count(*) FROM nodes WHERE id=$1::uuid`, w.node[B]) != 0 {
		t.Error("nodes survived tenant deletion")
	}
	// the other tenant is untouched
	if w.count(`SELECT count(*) FROM sites WHERE tenant_id=$1::uuid`, w.tenant["Alpha"].ID) != 1 {
		t.Error("deleting one tenant affected another")
	}
}

func TestTenantCAsAreIndependent(t *testing.T) {
	w := newWorld(t)
	a1, _ := w.a.tenantCAPEM(w.ctx, w.tenant["Alpha"].ID, "eap")
	b1, _ := w.a.tenantCAPEM(w.ctx, w.tenant["Bravo"].ID, "eap")
	r1, _ := w.a.tenantCAPEM(w.ctx, w.tenant["Alpha"].ID, "radsec")
	if string(a1) == string(b1) || string(a1) == string(r1) {
		t.Fatal("CAs must be distinct per tenant and per purpose")
	}
	// a certificate from tenant Alpha's EAP CA does not verify against Bravo's
	cert, _, _ := w.a.issueEAP(w.ctx, w.tenant["Alpha"].ID, "x.test", nil)
	leaf, _ := pki.ParseCert(cert)
	bca, _ := pki.ParseCert(b1)
	if leaf.CheckSignatureFrom(bca) == nil {
		t.Fatal("tenant Alpha's server certificate chains to tenant Bravo's CA")
	}
}
