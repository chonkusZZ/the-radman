package manager

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml/samlidp"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"radman/internal/pki"
)

// testApp creates an App on a throw-away database. Needs RADMAN_TEST_DB, e.g.
//
//	postgres://radman:radman@localhost:55432/postgres
func testApp(t *testing.T) *App { return testAppMode(t, os.Getenv("RADMAN_TEST_MODE")) }

// requireMSP skips tests that exercise multi-tenant behaviour when the suite runs in standalone mode.
func requireMSP(t *testing.T) {
	if m := os.Getenv("RADMAN_TEST_MODE"); m == ModeStandalone {
		t.Skip("multi-tenant behaviour; not applicable in standalone mode")
	}
}

func testAppMode(t *testing.T, mode string) *App {
	admin := os.Getenv("RADMAN_TEST_DB")
	if admin == "" {
		t.Skip("set RADMAN_TEST_DB to run manager integration tests")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	name := "radman_t_" + strings.ToLower(randHex(4))
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(admin)
	u.Path = "/" + name
	a, err := New(ctx, Options{DatabaseURL: u.String(), DataDir: t.TempDir(), UDPAddr: "127.0.0.1:0", Version: "test", Mode: mode}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a.St.DB.Close()
		conn.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		conn.Close(ctx)
	})
	a.Setup = ""
	return a
}

// idpEnv is a real SAML identity provider (crewjam's samlidp) used to drive full login flows.
type idpEnv struct {
	srv *httptest.Server
	idp *samlidp.Server
}

func newIdP(t *testing.T) *idpEnv {
	var h http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	cp, kp, _ := pki.SelfSignedRSA("test idp", 24*time.Hour)
	pair, _ := tls.X509KeyPair(cp, kp)
	leaf, _ := pki.ParseCert(cp)
	u, _ := url.Parse(srv.URL)
	idp, err := samlidp.New(samlidp.Options{URL: *u, Key: pair.PrivateKey.(crypto.Signer), Certificate: leaf, Store: &samlidp.MemoryStore{}})
	if err != nil {
		t.Fatal(err)
	}
	h = idp.Handler
	return &idpEnv{srv: srv, idp: idp}
}

func (e *idpEnv) addUser(name, email, group string) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	e.idp.Store.Put("/users/"+name, &samlidp.User{Name: name, HashedPassword: hash, Email: email, CommonName: name, Groups: []string{group}})
}

// register tells the IdP about a service provider by fetching the SP's published metadata.
func (e *idpEnv) register(t *testing.T, client *http.Client, spMetadataURL, id string) {
	resp, err := client.Get(spMetadataURL)
	if err != nil {
		t.Fatal(err)
	}
	md, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	req, _ := http.NewRequest("PUT", e.srv.URL+"/services/"+id, bytes.NewReader(md))
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != 204 {
		t.Fatalf("registering SP at IdP failed: %v %v (metadata: %.200s)", err, r, md)
	}
}

func (e *idpEnv) metadataXML(t *testing.T) string {
	r, err := http.Get(e.srv.URL + "/metadata")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

// ssoLogin walks a user through the browser flow: SP login URL -> IdP login form -> assertion -> ACS.
// It returns the SP's answer to the ACS post. acsPath overrides where the assertion is delivered (for replay tests).
func ssoLogin(t *testing.T, spURL string, spClient *http.Client, loginPath string, idp *idpEnv, user, acsOverride string) (*http.Response, *http.Client) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: spClient.Transport, Jar: jar}
	r, err := client.Get(spURL + loginPath) // follows the redirect to the IdP, which answers with its login form
	if err != nil {
		t.Fatal(err)
	}
	form, _ := io.ReadAll(r.Body)
	r.Body.Close()
	val := func(name string) string {
		m := regexp.MustCompile(`name="` + name + `"[^>]*value="([^"]*)"`).FindSubmatch(form)
		if m == nil {
			t.Fatalf("login form has no %s: %s", name, form)
		}
		return html.UnescapeString(string(m[1]))
	}
	action := regexp.MustCompile(`action="([^"]*)"`).FindSubmatch(form)[1]
	r, err = client.PostForm(strings.ReplaceAll(string(action), "&amp;", "&"), url.Values{"user": {user}, "password": {"pw"}, "SAMLRequest": {val("SAMLRequest")}, "RelayState": {val("RelayState")}})
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	r, err = client.PostForm(idp.srv.URL+"/sso", url.Values{"SAMLRequest": {val("SAMLRequest")}, "RelayState": {val("RelayState")}})
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(r.Body)
	r.Body.Close()
	m := regexp.MustCompile(`action="([^"]*)"`).FindSubmatch(page)
	sr := regexp.MustCompile(`name="SAMLResponse" value="([^"]*)"`).FindSubmatch(page)
	if m == nil || sr == nil {
		t.Fatalf("no SAMLResponse from IdP: %s", page)
	}
	acs := string(m[1])
	if acsOverride != "" {
		acs = acsOverride
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.PostForm(acs, url.Values{"SAMLResponse": {html.UnescapeString(string(sr[1]))}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp, client
}

func TestSAMLLoginWithGroupMapping(t *testing.T) {
	requireMSP(t) // asserts tenant-scoped grants; the standalone variant is in solo_test.go
	a := testApp(t)
	ctx := context.Background()
	g := a.General(ctx)
	g.PublicHost = "127.0.0.1"
	a.SaveGeneral(ctx, g)

	sp := httptest.NewTLSServer(a.NewHandler())
	defer sp.Close()
	a.Opt.HTTPSAddr = ":" + strings.Split(sp.URL, ":")[2]

	idp := newIdP(t)
	idp.addUser("alice", "alice@corp.example", "grp-ops")
	idp.addUser("bob", "bob@corp.example", "grp-other")
	idp.register(t, sp.Client(), sp.URL+"/saml/metadata", "sp")

	acme, err := a.CreateTenant(ctx, "Acme Ltd")
	if err != nil {
		t.Fatal(err)
	}
	a.St.SetJSON(ctx, "saml", SAML{Enabled: true, AllowLocal: true, MetadataXML: idp.metadataXML(t),
		EmailAttr: "mail", NameAttr: "cn", GroupAttr: "eduPersonAffiliation",
		GroupRoles: []GroupMap{{"grp-ops", "tenant_admin@acme-ltd"}, {"grp-msp", "global_readonly"}}})

	// alice: mapped group -> tenant administrator of Acme, session established
	acs, client := ssoLogin(t, sp.URL, sp.Client(), "/saml/login", idp, "alice", "")
	if acs.StatusCode != 303 || acs.Header.Get("Location") != "/" {
		t.Fatalf("alice: expected redirect to /, got %d %s", acs.StatusCode, acs.Header.Get("Location"))
	}
	var plat, mrole, idpKey string
	var sso bool
	if err := a.St.DB.QueryRow(ctx, `SELECT u.platform_role, u.sso, u.idp, m.role FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.email='alice@corp.example' AND m.tenant_id=$1::uuid AND m.source='sso'`, acme.ID).Scan(&plat, &sso, &idpKey, &mrole); err != nil || plat != "" || mrole != RoleTenantAdmin || !sso || idpKey != "platform" {
		t.Fatalf("alice user: %v platform=%q membership=%q sso=%v idp=%q", err, plat, mrole, sso, idpKey)
	}
	r, _ := client.Get(sp.URL + "/")
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || !strings.Contains(string(b), "alice@corp.example") {
		t.Fatalf("alice dashboard: %d %.200s", r.StatusCode, b)
	}

	// bob: no mapped group -> denied and not provisioned
	acs, _ = ssoLogin(t, sp.URL, sp.Client(), "/saml/login", idp, "bob", "")
	if acs.StatusCode != 303 || acs.Header.Get("Location") != "/login" {
		t.Fatalf("bob should be denied, got %d %s", acs.StatusCode, acs.Header.Get("Location"))
	}
	var n int
	a.St.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE email='bob@corp.example'`).Scan(&n)
	if n != 0 {
		t.Fatal("denied SSO user must not be provisioned")
	}
}
