package manager

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"radman/internal/pki"
	"radman/internal/proto"
)

func (s *server) routes() {
	m, a, res := s.mux, s.auth, s.res
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	m.HandleFunc("GET /setup", s.setupPage)
	m.HandleFunc("POST /setup", s.setupSubmit)
	m.HandleFunc("GET /login", s.loginPage)
	m.HandleFunc("POST /login", s.loginSubmit)
	m.HandleFunc("POST /logout", a(pAny, s.logout))
	m.HandleFunc("GET /branding/logo.svg", s.logo)
	m.HandleFunc("GET /saml/login", s.samlLogin)
	m.HandleFunc("GET /saml/metadata", s.samlMetadata)
	m.HandleFunc("POST /saml/acs", s.samlACS)
	if !s.a.Standalone() {
		// per-tenant SSO: each customer registers its own service provider and uses its own sign-in URL
		m.HandleFunc("GET /t/{slug}/login", s.tenantLoginPage)
		m.HandleFunc("GET /t/{slug}/saml/login", s.tenantSAMLLogin)
		m.HandleFunc("GET /t/{slug}/saml/metadata", s.tenantSAMLMetadata)
		m.HandleFunc("POST /t/{slug}/saml/acs", s.tenantSAMLACS)
		m.HandleFunc("POST /sso/discover", s.ssoDiscover)
	}

	m.HandleFunc("GET /{$}", a(pAny, s.home))
	if !s.a.Standalone() {
		m.HandleFunc("POST /tenant/switch", a(pAny, s.tenantSwitch))
		m.HandleFunc("GET /tenants", a(pAny, func(w http.ResponseWriter, r *http.Request, u *User) {
			s.render(w, r, u, "picker", page{"Title": "Choose a tenant", "Choices": s.a.accessibleTenants(r.Context(), u)})
		}))
	}

	// ---- tenant scope ----
	m.HandleFunc("GET /sites", a(pTenantRead, s.sitesList))
	m.HandleFunc("POST /sites", a(pTenantWrite, s.siteCreate))
	m.HandleFunc("GET /sites/{id}", res("site", false, s.siteDetail))
	m.HandleFunc("POST /sites/{id}/update", res("site", true, s.siteUpdate))
	m.HandleFunc("POST /sites/{id}/delete", res("site", true, s.siteDelete))
	m.HandleFunc("POST /sites/{id}/aps", res("site", true, s.apCreate))
	m.HandleFunc("POST /aps/{id}/update", res("ap", true, s.apUpdate))
	m.HandleFunc("POST /aps/{id}/delete", res("ap", true, s.apDelete))
	m.HandleFunc("GET /aps/{id}/radsec", res("ap", false, s.radsecPage))
	m.HandleFunc("POST /aps/{id}/radsec/sign", res("ap", true, s.radsecSign))
	m.HandleFunc("POST /radsec/{id}/revoke", res("radsec", true, s.radsecRevoke))
	m.HandleFunc("POST /sites/{id}/rules", res("site", true, s.ruleAdd))
	m.HandleFunc("POST /sites/{id}/rules/{i}/delete", res("site", true, s.ruleDelete))
	m.HandleFunc("POST /sites/{id}/rules/{i}/move", res("site", true, s.ruleMove))
	m.HandleFunc("POST /sites/{id}/nodes", res("site", true, s.nodeCreate))
	m.HandleFunc("GET /nodes", a(pTenantRead, s.nodesList))
	m.HandleFunc("GET /nodes/{id}", res("node", false, s.nodeDetail))
	m.HandleFunc("GET /nodes/{id}/download/{platform}", res("node", true, s.nodeDownload))
	m.HandleFunc("POST /nodes/{id}/revoke", res("node", true, s.nodeRevoke))
	m.HandleFunc("POST /nodes/{id}/regen", res("node", true, s.nodeRegen))
	m.HandleFunc("POST /nodes/{id}/names", res("node", true, s.nodeNames))
	m.HandleFunc("POST /nodes/{id}/delete", res("node", true, s.nodeDelete))

	m.HandleFunc("GET /pki", a(pTenantRead, s.pkiList))
	m.HandleFunc("POST /pki", a(pTenantWrite, s.pkiCreate))
	m.HandleFunc("GET /pki/{id}", res("pki", false, s.pkiDetail))
	m.HandleFunc("POST /pki/{id}/update", res("pki", true, s.pkiUpdate))
	m.HandleFunc("POST /pki/{id}/delete", res("pki", true, s.pkiDelete))
	m.HandleFunc("POST /pki/{id}/refresh", res("pki", true, s.pkiRefresh))
	m.HandleFunc("GET /eapcerts", a(pTenantRead, s.eapList))
	m.HandleFunc("GET /eapcerts/ca.pem", a(pTenantRead, s.eapCAPEM))
	m.HandleFunc("POST /eapcerts/internal", a(pTenantWrite, s.eapCreateInternal))
	m.HandleFunc("POST /eapcerts/upload", a(pTenantWrite, s.eapUpload))
	m.HandleFunc("POST /eapcerts/{id}/delete", res("eap", true, s.eapDelete))

	m.HandleFunc("GET /stats", a(pTenantRead, s.statsPage))
	m.HandleFunc("GET /stats/clients", a(pTenantRead, s.statsClients))
	m.HandleFunc("GET /stats/clients/{mac}", a(pTenantRead, s.statsClient))
	m.HandleFunc("GET /stats/reports", a(pTenantRead, s.statsReports))
	m.HandleFunc("GET /stats/report/{type}", a(pTenantRead, s.statsReport))
	m.HandleFunc("GET /logs", a(pTenantRead, s.logsAuth))
	m.HandleFunc("GET /logs/acct", a(pTenantRead, s.logsAcct))
	m.HandleFunc("GET /logs/audit", a(pTenantRead, s.logsAudit))

	if s.a.Standalone() {
		// one installation = one tenant: a single user list and a single sign-on configuration (under Settings)
		m.HandleFunc("GET /users", a(pPlatformWrite, s.soloUsers))
		m.HandleFunc("POST /users", a(pPlatformWrite, s.soloUserCreate))
		m.HandleFunc("POST /users/{id}/update", a(pPlatformWrite, s.soloUserUpdate))
		m.HandleFunc("POST /users/{id}/delete", a(pPlatformWrite, s.soloUserDelete))
	} else {
		m.HandleFunc("GET /sso", a(pTenantWrite, s.tenantSSOPage))
		m.HandleFunc("POST /sso", a(pTenantWrite, s.tenantSSOSave))
		m.HandleFunc("GET /users", a(pTenantWrite, s.tenantUsers))
		m.HandleFunc("POST /users", a(pTenantWrite, s.tenantUserAdd))
		m.HandleFunc("POST /users/update", a(pTenantWrite, s.tenantUserUpdate))
	}

	m.HandleFunc("GET /account", a(pAny, s.accountPage))
	m.HandleFunc("POST /account/password", a(pAny, s.accountPassword))
	m.HandleFunc("POST /account/totp/enable", a(pAny, s.totpEnable))
	m.HandleFunc("POST /account/totp/disable", a(pAny, s.totpDisable))

	// ---- platform scope (MSP staff): tenants, users and audit across tenants ----
	if !s.a.Standalone() {
		m.HandleFunc("GET /platform", a(pPlatformRead, s.platformHome))
		m.HandleFunc("POST /platform/tenants", a(pPlatformWrite, s.tenantCreate))
		m.HandleFunc("GET /platform/tenants/{id}", a(pPlatformRead, s.tenantDetail))
		m.HandleFunc("POST /platform/tenants/{id}/update", a(pPlatformWrite, s.tenantUpdate))
		m.HandleFunc("POST /platform/tenants/{id}/delete", a(pPlatformWrite, s.tenantDelete))
		m.HandleFunc("POST /platform/tenants/{id}/members", a(pPlatformWrite, s.memberAdd))
		m.HandleFunc("POST /platform/tenants/{id}/members/remove", a(pPlatformWrite, s.memberRemove))
		m.HandleFunc("GET /platform/users", a(pPlatformRead, s.platformUsers))
		m.HandleFunc("POST /platform/users", a(pPlatformWrite, s.platformUserCreate))
		m.HandleFunc("POST /platform/users/{id}/update", a(pPlatformWrite, s.platformUserUpdate))
		m.HandleFunc("POST /platform/users/{id}/delete", a(pPlatformWrite, s.platformUserDelete))
		m.HandleFunc("GET /platform/audit", a(pPlatformRead, s.platformAudit))
	}
	// ---- system settings (both editions) ----
	m.HandleFunc("GET /settings", a(pPlatformRead, s.settingsPage))
	m.HandleFunc("POST /settings/general", a(pPlatformWrite, s.settingsGeneral))
	m.HandleFunc("POST /settings/webtls", a(pPlatformWrite, s.settingsWebTLS))
	m.HandleFunc("POST /settings/webtls/csr", a(pPlatformWrite, s.settingsWebCSR))
	m.HandleFunc("GET /settings/webtls/csr.pem", a(pPlatformWrite, s.settingsWebCSRDownload))
	m.HandleFunc("POST /settings/webtls/upload", a(pPlatformWrite, s.settingsWebUpload))
	m.HandleFunc("POST /settings/sso", a(pPlatformWrite, s.settingsSSO))
	m.HandleFunc("POST /settings/branding", a(pPlatformWrite, s.settingsBranding))
	m.HandleFunc("POST /settings/keykit", a(pPlatformWrite, s.keyKit))
}

func (a *App) nodeOnline(lastSeen *time.Time, g General) bool {
	if lastSeen == nil {
		return false
	}
	return time.Since(*lastSeen) < time.Duration(3*g.NodeIntervalSecs+15)*time.Second
}

// ---- dashboard ----

func (s *server) tenantDashboard(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	tid := u.Tenant.ID
	g := s.a.General(ctx)
	d := page{"Title": "Dashboard"}
	var sites, nodesTotal, nodesOnline, pending int
	s.a.St.DB.QueryRow(ctx, `SELECT count(*) FROM sites WHERE tenant_id=$1::uuid`, tid).Scan(&sites)
	rows, _ := s.a.St.DB.Query(ctx, `SELECT n.status, n.last_seen FROM nodes n JOIN sites s ON s.id=n.site_id WHERE s.tenant_id=$1::uuid`, tid)
	for rows.Next() {
		var st string
		var ls *time.Time
		rows.Scan(&st, &ls)
		nodesTotal++
		if st == "pending" {
			pending++
		}
		if st == "active" && s.a.nodeOnline(ls, g) {
			nodesOnline++
		}
	}
	rows.Close()
	var acc, rej int
	s.a.St.RO.QueryRow(ctx, `SELECT count(*) FILTER (WHERE data->>'result'='accept'), count(*) FILTER (WHERE data->>'result'='reject')
		FROM events WHERE tenant_id=$1::uuid AND kind='auth' AND ts > now()-interval '24 hours'`, tid).Scan(&acc, &rej)
	var eapExpiring, crlFail int
	s.a.St.DB.QueryRow(ctx, `SELECT count(*) FROM eap_certs WHERE tenant_id=$1::uuid AND not_after < now()+interval '30 days'`, tid).Scan(&eapExpiring)
	s.a.St.DB.QueryRow(ctx, `SELECT count(DISTINCT c.url) FROM crl_cache c, pki_profiles p WHERE p.tenant_id=$1::uuid AND c.url = ANY(p.crl_urls) AND (c.last_error <> '' OR c.next_update < now())`, tid).Scan(&crlFail)
	d["Sites"], d["NodesTotal"], d["NodesOnline"], d["Pending"] = sites, nodesTotal, nodesOnline, pending
	d["Accepts"], d["Rejects"], d["EAPExpiring"], d["CRLFail"] = acc, rej, eapExpiring, crlFail
	d["Recent"] = s.queryAuthEvents(r, "", "", "", 8)
	s.render(w, r, u, "dashboard", d)
}

// ---- sites ----

type siteRow struct {
	ID, Name, Description string
	APs, Nodes, Online    int
}

func (s *server) sitesList(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	g := s.a.General(ctx)
	rows, err := s.a.St.DB.Query(ctx, `SELECT s.id::text, s.name, s.description,
		(SELECT count(*) FROM aps WHERE site_id=s.id), (SELECT count(*) FROM nodes WHERE site_id=s.id) FROM sites s WHERE s.tenant_id=$1::uuid ORDER BY s.name`, u.Tenant.ID)
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	var list []*siteRow
	for rows.Next() {
		x := &siteRow{}
		rows.Scan(&x.ID, &x.Name, &x.Description, &x.APs, &x.Nodes)
		list = append(list, x)
	}
	rows.Close()
	for _, x := range list {
		lr, _ := s.a.St.DB.Query(ctx, `SELECT last_seen FROM nodes WHERE site_id=$1 AND status='active'`, x.ID)
		for lr.Next() {
			var ls *time.Time
			lr.Scan(&ls)
			if s.a.nodeOnline(ls, g) {
				x.Online++
			}
		}
		lr.Close()
	}
	s.render(w, r, u, "sites", page{"Title": "Sites", "Sites": list})
}

func (s *server) siteCreate(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		s.back(w, r, "/sites", "err", "Site name is required.")
		return
	}
	if msg := s.a.quotaExceeded(ctx, u.Tenant, "sites"); msg != "" {
		s.back(w, r, "/sites", "err", msg)
		return
	}
	eapID, err := s.a.CreateInternalEAPCert(ctx, u.Tenant.ID, name+" RADIUS server", "radius."+slug(name)+".radman.local", nil)
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	var id string
	err = s.a.St.DB.QueryRow(ctx, `INSERT INTO sites(tenant_id,name,description,eap_cert_id) VALUES($1::uuid,$2,$3,$4::uuid) RETURNING id::text`, u.Tenant.ID, name, r.PostFormValue("description"), eapID).Scan(&id)
	if err != nil {
		s.back(w, r, "/sites", "err", "Could not create site (is the name already used?).")
		return
	}
	s.a.Audit(ctx, u.Email, "site.create", name)
	s.back(w, r, "/sites/"+id, "ok", "Site created. Add access points and a PKI profile, then deploy a node.")
}

func slug(s string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(s) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

type apRow struct{ ID, Name, Addr, Secret, Vendor, Notes string }
type nodeRow struct {
	ID, SiteID, SiteName, Name, Status, Version, OS, Host, Addr string
	LastSeen, CertNotAfter                                      *time.Time
	Online, InSync                                              bool
	QueueDepth                                                  int
}
type selOpt struct {
	ID, Name string
	Selected bool
	Extra    string
}

func (s *server) loadPolicy(r *http.Request, id string) (proto.Policy, error) {
	var raw []byte
	var p proto.Policy
	if err := s.a.St.DB.QueryRow(r.Context(), `SELECT policy FROM sites WHERE id=$1::uuid`, id).Scan(&raw); err != nil {
		return p, err
	}
	return p, json.Unmarshal(raw, &p)
}

func (s *server) savePolicy(r *http.Request, id string, p proto.Policy) error {
	b, _ := json.Marshal(p)
	_, err := s.a.St.DB.Exec(r.Context(), `UPDATE sites SET policy=$2 WHERE id=$1::uuid`, id, b)
	return err
}

func (s *server) siteDetail(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	id := r.PathValue("id")
	d := page{"ID": id}
	var name, desc string
	var eapID *string
	var authPort, acctPort, radsecPort int
	if err := s.a.St.DB.QueryRow(ctx, `SELECT name, description, eap_cert_id::text, auth_port, acct_port, radsec_port FROM sites WHERE id=$1::uuid`, id).Scan(&name, &desc, &eapID, &authPort, &acctPort, &radsecPort); err != nil {
		s.fail(w, r, u, err)
		return
	}
	d["Title"], d["Name"], d["Description"], d["AuthPort"], d["AcctPort"] = name, name, desc, authPort, acctPort
	d["RadSecPort"], d["RadSecOn"] = radsecPort, radsecPort > 0
	if radsecPort == 0 {
		d["RadSecPort"] = 2083
	}
	pol, _ := s.loadPolicy(r, id)
	d["Policy"] = pol

	var aps []apRow
	rows, _ := s.a.St.DB.Query(ctx, `SELECT id::text, name, addr, secret_enc, vendor, notes FROM aps WHERE site_id=$1::uuid ORDER BY name`, id)
	for rows.Next() {
		var x apRow
		var enc string
		rows.Scan(&x.ID, &x.Name, &x.Addr, &enc, &x.Vendor, &x.Notes)
		if u.CanWrite(u.Tenant) {
			x.Secret, _ = s.a.open(enc)
		}
		aps = append(aps, x)
	}
	rows.Close()
	d["APs"] = aps

	var pkis []selOpt
	rows, _ = s.a.St.DB.Query(ctx, `SELECT p.id::text, p.name, p.kind, EXISTS(SELECT 1 FROM site_pki sp WHERE sp.site_id=$1::uuid AND sp.pki_id=p.id) FROM pki_profiles p WHERE p.tenant_id=$2::uuid ORDER BY p.name`, id, u.Tenant.ID)
	for rows.Next() {
		var x selOpt
		rows.Scan(&x.ID, &x.Name, &x.Extra, &x.Selected)
		pkis = append(pkis, x)
	}
	rows.Close()
	d["PKIs"] = pkis

	var eaps []selOpt
	rows, _ = s.a.St.DB.Query(ctx, `SELECT id::text, name, source, not_after FROM eap_certs WHERE tenant_id=$1::uuid ORDER BY name`, u.Tenant.ID)
	for rows.Next() {
		var x selOpt
		var na time.Time
		rows.Scan(&x.ID, &x.Name, &x.Extra, &na)
		x.Extra += ", expires " + na.Format("2006-01-02")
		x.Selected = eapID != nil && *eapID == x.ID
		eaps = append(eaps, x)
	}
	rows.Close()
	d["EAPCerts"] = eaps
	d["Nodes"] = s.queryNodes(r, "WHERE n.site_id=$1::uuid", id)
	d["Platforms"] = s.a.platforms()
	s.render(w, r, u, "site", d)
}

func (s *server) siteUpdate(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	id := r.PathValue("id")
	name := strings.TrimSpace(r.PostFormValue("name"))
	authPort, _ := strconv.Atoi(r.PostFormValue("auth_port"))
	acctPort, _ := strconv.Atoi(r.PostFormValue("acct_port"))
	if name == "" || authPort < 1 || authPort > 65535 || acctPort < 1 || acctPort > 65535 {
		s.back(w, r, "/sites/"+id, "err", "Invalid name or port.")
		return
	}
	eap := r.PostFormValue("eap_cert_id")
	var eapArg any
	if eap != "" {
		var ok bool
		if !isUUID(eap) || s.a.St.DB.QueryRow(ctx, `SELECT true FROM eap_certs WHERE id=$1::uuid AND tenant_id=$2::uuid`, eap, u.Tenant.ID).Scan(&ok) != nil {
			s.back(w, r, "/sites/"+id, "err", "Choose one of this tenant's server certificates.")
			return
		}
		eapArg = eap
	}
	radsecPort := 0
	if r.PostFormValue("radsec_enabled") == "1" {
		radsecPort, _ = strconv.Atoi(r.PostFormValue("radsec_port"))
		if radsecPort < 1 || radsecPort > 65535 {
			s.back(w, r, "/sites/"+id, "err", "Invalid RadSEC port.")
			return
		}
	}
	if _, err := s.a.St.DB.Exec(ctx, `UPDATE sites SET name=$2, description=$3, auth_port=$4, acct_port=$5, eap_cert_id=$6, radsec_port=$7 WHERE id=$1::uuid`,
		id, name, r.PostFormValue("description"), authPort, acctPort, eapArg, radsecPort); err != nil {
		s.back(w, r, "/sites/"+id, "err", "Could not save: "+err.Error())
		return
	}
	pol, _ := s.loadPolicy(r, id)
	pol.DefaultAction = map[bool]string{true: "deny", false: "allow"}[r.PostFormValue("default_action") == "deny"]
	pol.DefaultVLAN = strings.TrimSpace(r.PostFormValue("default_vlan"))
	s.savePolicy(r, id, pol)
	s.a.St.DB.Exec(ctx, `DELETE FROM site_pki WHERE site_id=$1::uuid`, id)
	for _, pid := range r.PostForm["pki"] {
		if isUUID(pid) { // only this tenant's profiles can be attached
			s.a.St.DB.Exec(ctx, `INSERT INTO site_pki(site_id,pki_id) SELECT $1::uuid, id FROM pki_profiles WHERE id=$2::uuid AND tenant_id=$3::uuid ON CONFLICT DO NOTHING`, id, pid, u.Tenant.ID)
		}
	}
	s.a.Audit(ctx, u.Email, "site.update", name)
	s.back(w, r, "/sites/"+id, "ok", "Site settings saved. Nodes pick this up at their next check-in.")
}

func (s *server) siteDelete(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	var name string
	s.a.St.DB.QueryRow(r.Context(), `DELETE FROM sites WHERE id=$1::uuid RETURNING name`, id).Scan(&name)
	s.a.Audit(r.Context(), u.Email, "site.delete", name)
	s.back(w, r, "/sites", "ok", "Site deleted. Its nodes can no longer check in.")
}

// ---- APs ----

func validAddr(a string) bool {
	return pkiParseAddr(a)
}

func (s *server) apCreate(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	name, addr := strings.TrimSpace(r.PostFormValue("name")), strings.TrimSpace(r.PostFormValue("addr"))
	secret := r.PostFormValue("secret")
	if secret == "" {
		secret = randToken(18)
	}
	if name == "" || !validAddr(addr) {
		s.back(w, r, "/sites/"+id, "err", "AP needs a name and a valid IP address or CIDR (the source address the AP uses to reach the node).")
		return
	}
	if len(secret) < 8 {
		s.back(w, r, "/sites/"+id, "err", "Shared secret must be at least 8 characters.")
		return
	}
	if msg := s.a.quotaExceeded(r.Context(), u.Tenant, "aps"); msg != "" {
		s.back(w, r, "/sites/"+id, "err", msg)
		return
	}
	_, err := s.a.St.DB.Exec(r.Context(), `INSERT INTO aps(site_id,name,addr,secret_enc,vendor,notes) VALUES($1::uuid,$2,$3,$4,$5,$6)`,
		id, name, addr, s.a.seal(secret), r.PostFormValue("vendor"), r.PostFormValue("notes"))
	if err != nil {
		s.back(w, r, "/sites/"+id, "err", "Could not add AP (duplicate name?).")
		return
	}
	s.a.Audit(r.Context(), u.Email, "ap.create", name+" "+addr)
	s.back(w, r, "/sites/"+id, "ok", "Access point added.")
}

func (s *server) apUpdate(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	var site string
	if err := s.a.St.DB.QueryRow(r.Context(), `SELECT site_id::text FROM aps WHERE id=$1::uuid`, id).Scan(&site); err != nil {
		s.fail(w, r, u, err)
		return
	}
	name, addr := strings.TrimSpace(r.PostFormValue("name")), strings.TrimSpace(r.PostFormValue("addr"))
	if name == "" || !validAddr(addr) {
		s.back(w, r, "/sites/"+site, "err", "Invalid name or address.")
		return
	}
	if sec := r.PostFormValue("secret"); sec != "" {
		if len(sec) < 8 {
			s.back(w, r, "/sites/"+site, "err", "Shared secret must be at least 8 characters.")
			return
		}
		s.a.St.DB.Exec(r.Context(), `UPDATE aps SET secret_enc=$2 WHERE id=$1::uuid`, id, s.a.seal(sec))
	}
	s.a.St.DB.Exec(r.Context(), `UPDATE aps SET name=$2, addr=$3, vendor=$4, notes=$5 WHERE id=$1::uuid`, id, name, addr, r.PostFormValue("vendor"), r.PostFormValue("notes"))
	s.a.Audit(r.Context(), u.Email, "ap.update", name)
	s.back(w, r, "/sites/"+site, "ok", "Access point updated.")
}

func (s *server) apDelete(w http.ResponseWriter, r *http.Request, u *User) {
	var site, name string
	s.a.St.DB.QueryRow(r.Context(), `DELETE FROM aps WHERE id=$1::uuid RETURNING site_id::text, name`, r.PathValue("id")).Scan(&site, &name)
	s.a.Audit(r.Context(), u.Email, "ap.delete", name)
	s.back(w, r, "/sites/"+site, "ok", "Access point removed.")
}

// ---- policy rules ----

func (s *server) ruleAdd(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	rule := proto.Rule{
		Name: strings.TrimSpace(r.PostFormValue("name")), Field: r.PostFormValue("field"), Op: r.PostFormValue("op"),
		Value: strings.TrimSpace(r.PostFormValue("value")), Action: r.PostFormValue("action"), VLAN: strings.TrimSpace(r.PostFormValue("vlan")),
	}
	if rule.Name == "" || rule.Value == "" || !contains([]string{"subject_cn", "san", "issuer_cn", "pki"}, rule.Field) ||
		!contains([]string{"equals", "contains", "regex"}, rule.Op) || !contains([]string{"allow", "deny"}, rule.Action) {
		s.back(w, r, "/sites/"+id, "err", "Invalid rule.")
		return
	}
	if rule.Op == "regex" {
		if err := compileCheck(rule.Value); err != nil {
			s.back(w, r, "/sites/"+id, "err", "Invalid regular expression: "+err.Error())
			return
		}
	}
	p, err := s.loadPolicy(r, id)
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	p.Rules = append(p.Rules, rule)
	s.savePolicy(r, id, p)
	s.a.Audit(r.Context(), u.Email, "policy.rule_add", rule.Name)
	s.back(w, r, "/sites/"+id+"#policy", "ok", "Rule added.")
}

func (s *server) ruleDelete(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	i, _ := strconv.Atoi(r.PathValue("i"))
	p, err := s.loadPolicy(r, id)
	if err == nil && i >= 0 && i < len(p.Rules) {
		p.Rules = append(p.Rules[:i], p.Rules[i+1:]...)
		s.savePolicy(r, id, p)
	}
	s.back(w, r, "/sites/"+id+"#policy", "ok", "Rule removed.")
}

func (s *server) ruleMove(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	i, _ := strconv.Atoi(r.PathValue("i"))
	j := i - 1
	if r.PostFormValue("dir") == "down" {
		j = i + 1
	}
	p, err := s.loadPolicy(r, id)
	if err == nil && i >= 0 && i < len(p.Rules) && j >= 0 && j < len(p.Rules) {
		p.Rules[i], p.Rules[j] = p.Rules[j], p.Rules[i]
		s.savePolicy(r, id, p)
	}
	http.Redirect(w, r, "/sites/"+id+"#policy", http.StatusSeeOther)
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// ---- nodes ----

func (s *server) queryNodes(r *http.Request, where string, args ...any) []*nodeRow {
	ctx := r.Context()
	g := s.a.General(ctx)
	var out []*nodeRow
	rows, err := s.a.St.DB.Query(ctx, `SELECT n.id::text, n.site_id::text, s.name, n.name, n.status, n.version, n.os, n.hostname, n.last_addr, n.last_seen, n.cert_not_after, n.config_hash, n.stats, n.eap_cert_pem <> ''
		FROM nodes n JOIN sites s ON s.id=n.site_id `+where+` ORDER BY s.name, n.name`, args...)
	if err != nil {
		return nil
	}
	type cfgKey struct{ site string }
	hashes := map[string]string{}
	for rows.Next() {
		x := &nodeRow{}
		var hash string
		var stats []byte
		var ownCert bool
		rows.Scan(&x.ID, &x.SiteID, &x.SiteName, &x.Name, &x.Status, &x.Version, &x.OS, &x.Host, &x.Addr, &x.LastSeen, &x.CertNotAfter, &hash, &stats, &ownCert)
		x.Online = x.Status == "active" && s.a.nodeOnline(x.LastSeen, g)
		var st proto.Stats
		json.Unmarshal(stats, &st)
		x.QueueDepth = st.QueueDepth
		key, nodeArg := x.SiteID, "" // nodes sharing the site certificate share one computed config
		if ownCert {
			key, nodeArg = x.SiteID+"/"+x.ID, x.ID
		}
		if _, ok := hashes[key]; !ok {
			if cfg, err := s.a.BuildNodeConfig(ctx, x.SiteID, nodeArg); err == nil {
				hashes[key] = proto.HashConfig(cfg)
			} else {
				hashes[key] = "-"
			}
		}
		x.InSync = hash != "" && hash == hashes[key]
		out = append(out, x)
	}
	rows.Close()
	return out
}

func (s *server) nodesList(w http.ResponseWriter, r *http.Request, u *User) {
	s.render(w, r, u, "nodes", page{"Title": "Nodes", "Nodes": s.queryNodes(r, "WHERE s.tenant_id=$1::uuid", u.Tenant.ID)})
}

func (s *server) nodeCreate(w http.ResponseWriter, r *http.Request, u *User) {
	site := r.PathValue("id")
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		s.back(w, r, "/sites/"+site, "err", "Node name is required.")
		return
	}
	if s.a.General(r.Context()).PublicHost == "" {
		s.back(w, r, "/sites/"+site, "err", "The platform's public hostname is not configured yet (a global administrator sets it under Platform settings).")
		return
	}
	if msg := s.a.quotaExceeded(r.Context(), u.Tenant, "nodes"); msg != "" {
		s.back(w, r, "/sites/"+site, "err", msg)
		return
	}
	names, err := ParseServerNames(r.PostFormValue("server_names"))
	if err != nil {
		s.back(w, r, "/sites/"+site, "err", "Server certificate names: "+err.Error())
		return
	}
	tok := randToken(24)
	hours := s.a.General(r.Context()).EnrollTokenHours
	var id string
	err = s.a.St.DB.QueryRow(r.Context(), `INSERT INTO nodes(site_id,name,token_hash,token_enc,token_expires) VALUES($1,$2,$3,$4,$5) RETURNING id::text`,
		site, name, hashToken(tok), s.a.seal(tok), time.Now().Add(time.Duration(hours)*time.Hour)).Scan(&id)
	if err != nil {
		s.back(w, r, "/sites/"+site, "err", "Could not create node (duplicate name?).")
		return
	}
	if len(names) > 0 {
		if err := s.a.setNodeServerNames(r.Context(), u.Tenant.ID, id, names); err != nil {
			s.a.St.DB.Exec(r.Context(), `DELETE FROM nodes WHERE id=$1::uuid`, id)
			s.fail(w, r, u, err)
			return
		}
	}
	s.a.Audit(r.Context(), u.Email, "node.create", name+" names="+strings.Join(names, ","))
	s.back(w, r, "/nodes/"+id, "ok", "Node created. Download the package below and run it on the site server.")
}

func (s *server) nodeDetail(w http.ResponseWriter, r *http.Request, u *User) {
	list := s.queryNodes(r, "WHERE n.id=$1::uuid", r.PathValue("id"))
	if len(list) == 0 {
		s.render(w, r, u, "error", page{"Title": "Not found", "Msg": "Node not found."}, 404)
		return
	}
	n := list[0]
	d := page{"Title": n.Name, "N": n, "Platforms": s.a.platforms()}
	var exp *time.Time
	var crls []byte
	s.a.St.DB.QueryRow(r.Context(), `SELECT token_expires, crl_status FROM nodes WHERE id=$1::uuid`, n.ID).Scan(&exp, &crls)
	d["TokenExpires"] = exp
	var cs []proto.CRLStatus
	json.Unmarshal(crls, &cs)
	d["CRLs"] = cs
	var host string
	d["Host"] = host
	var names []string
	var certExp *time.Time
	s.a.St.DB.QueryRow(r.Context(), `SELECT eap_names, eap_not_after FROM nodes WHERE id=$1::uuid`, n.ID).Scan(&names, &certExp)
	d["Names"], d["NamesText"], d["NamesExpire"] = names, strings.Join(names, ", "), certExp
	d["Public"] = s.a.General(r.Context()).PublicHost
	d["UDPPort"] = s.a.quicPort
	if n.Status == "pending" && u.CanWrite(u.Tenant) {
		var enc string
		s.a.St.DB.QueryRow(r.Context(), `SELECT token_enc FROM nodes WHERE id=$1::uuid`, n.ID).Scan(&enc)
		if tok, err := s.a.open(enc); err == nil && exp != nil && time.Now().Before(*exp) {
			d["Token"] = tok
			d["CAFP"], _ = pki.FingerprintPEM(s.a.NodeCAPEM())
		}
	}
	s.render(w, r, u, "node", d)
}

type platform struct{ OS, Arch, File, Label string }

// platforms lists node binaries available to download.
func (a *App) platforms() []platform {
	var out []platform
	entries, _ := os.ReadDir(a.Opt.NodeBinDir)
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, "radman-node_") {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(n, "radman-node_"), ".exe"), "_")
		if len(parts) != 2 {
			continue
		}
		label := map[string]string{"windows": "Windows", "linux": "Linux", "darwin": "macOS"}[parts[0]] + " " + parts[1]
		out = append(out, platform{parts[0], parts[1], n, label})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

func (s *server) nodeDownload(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	id, plat := r.PathValue("id"), r.PathValue("platform")
	var enc, name string
	var exp *time.Time
	var status string
	if err := s.a.St.DB.QueryRow(ctx, `SELECT token_enc, token_expires, name, status FROM nodes WHERE id=$1::uuid`, id).Scan(&enc, &exp, &name, &status); err != nil {
		s.fail(w, r, u, err)
		return
	}
	if status != "pending" || exp == nil || time.Now().After(*exp) {
		s.back(w, r, "/nodes/"+id, "err", "The enrollment token is used or expired. Generate a new one.")
		return
	}
	var pf *platform
	for _, p := range s.a.platforms() {
		p := p
		if p.OS+"-"+p.Arch == plat {
			pf = &p
		}
	}
	if pf == nil {
		http.NotFound(w, r)
		return
	}
	tok, err := s.a.open(enc)
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	bin, err := os.ReadFile(filepath.Join(s.a.Opt.NodeBinDir, pf.File))
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	host := s.a.General(ctx).PublicHost
	fp, _ := pki.FingerprintPEM(s.a.NodeCAPEM())
	ec, _ := json.MarshalIndent(map[string]string{
		"manager": fmt.Sprintf("%s:%d", host, s.a.quicPort), "ca_pem": string(s.a.NodeCAPEM()), "ca_sha256": fp, "token": tok,
	}, "", "  ")
	exe := "radman-node"
	if pf.OS == "windows" {
		exe += ".exe"
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: exe, Method: zip.Deflate}
	hdr.SetMode(0o755)
	fw, _ := zw.CreateHeader(hdr)
	fw.Write(bin)
	fw, _ = zw.Create("enroll.json")
	fw.Write(ec)
	fw, _ = zw.Create("README.txt")
	fmt.Fprintf(fw, readme, name, exe, exe, exe, exe)
	zw.Close()
	s.a.Audit(ctx, u.Email, "node.download", name+" "+plat)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="radman-node-%s-%s.zip"`, slug(name), plat))
	w.Write(buf.Bytes())
}

const readme = `arc's The RadMAN site node: %s

This package contains the node program and a single-use enrollment file (enroll.json).
Keep them together; enroll.json is consumed on first start.

Quick start (run as Administrator / root):
  %s install      installs the node as a service
  %s start        starts it
Or run it in the foreground to try it out:
  %s run

The node needs outbound UDP to the manager and must be reachable by your access points on UDP 1812/1813.
It keeps authenticating even if the manager becomes unreachable.
Other commands: %s help
`

func (s *server) nodeRevoke(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	s.a.St.DB.Exec(r.Context(), `UPDATE nodes SET status='revoked', cert_serial='', prev_cert_serial='', token_hash='', token_enc='' WHERE id=$1::uuid`, id)
	s.a.Audit(r.Context(), u.Email, "node.revoke", id)
	s.back(w, r, "/nodes/"+id, "ok", "Node revoked. It can no longer check in; it keeps authenticating from cached config until it is stopped.")
}

func (s *server) nodeRegen(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	tok := randToken(24)
	hours := s.a.General(r.Context()).EnrollTokenHours
	s.a.St.DB.Exec(r.Context(), `UPDATE nodes SET status='pending', cert_serial='', prev_cert_serial='', token_hash=$2, token_enc=$3, token_expires=$4 WHERE id=$1::uuid`,
		id, hashToken(tok), s.a.seal(tok), time.Now().Add(time.Duration(hours)*time.Hour))
	s.a.Audit(r.Context(), u.Email, "node.reenroll", id)
	s.back(w, r, "/nodes/"+id, "ok", "New enrollment token issued. The old certificate no longer works.")
}

func (s *server) nodeDelete(w http.ResponseWriter, r *http.Request, u *User) {
	var site string
	s.a.St.DB.QueryRow(r.Context(), `DELETE FROM nodes WHERE id=$1::uuid RETURNING site_id::text`, r.PathValue("id")).Scan(&site)
	s.a.Audit(r.Context(), u.Email, "node.delete", r.PathValue("id"))
	s.back(w, r, "/sites/"+site, "ok", "Node deleted.")
}

// nodeNames changes the names on a node's own server certificate (blank = use the site's certificate again).
func (s *server) nodeNames(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	names, err := ParseServerNames(r.PostFormValue("server_names"))
	if err != nil {
		s.back(w, r, "/nodes/"+id, "err", "Server certificate names: "+err.Error())
		return
	}
	if err := s.a.setNodeServerNames(r.Context(), u.Tenant.ID, id, names); err != nil {
		s.fail(w, r, u, err)
		return
	}
	s.a.Audit(r.Context(), u.Email, "node.names", id+" names="+strings.Join(names, ","))
	msg := "Server certificate updated; the node picks it up at its next check-in. Devices must trust the tenant's EAP CA."
	if len(names) == 0 {
		msg = "The node now uses the site's server certificate."
	}
	s.back(w, r, "/nodes/"+id, "ok", msg)
}
