package manager

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$`)

func (a *App) tenantDomains(ctx context.Context, tenantID string) []string {
	rows, err := a.St.DB.Query(ctx, `SELECT domain FROM tenant_sso_domains WHERE tenant_id=$1::uuid ORDER BY domain`, tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		rows.Scan(&d)
		out = append(out, d)
	}
	return out
}

// ---- tenant SSO settings (tenant administrators, and global administrators working inside the tenant) ----

func (s *server) tenantSSOPage(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	t := u.Tenant
	cfg := s.a.TenantSSO(ctx, t.ID)
	base := s.a.baseURL(ctx)
	prov := &ssoProv{tenant: t, cfg: cfg, prefix: "/t/" + t.Slug + "/saml", key: t.ID}
	entity := firstNonEmpty(cfg.EntityID, base+prov.prefix+"/metadata")
	s.render(w, r, u, "sso_tenant", page{"Title": "Single sign-on", "SSO": cfg, "SSOMap": cfg.MapText(),
		"EntityID": entity, "ACS": base + prov.prefix + "/acs", "MetaURL": base + prov.prefix + "/metadata", "LoginURL": base + "/t/" + t.Slug + "/login",
		"Domains": strings.Join(s.a.tenantDomains(ctx, t.ID), ", "), "CanEditDomains": u.IsGlobalAdmin()})
}

func (s *server) tenantSSOSave(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	t := u.Tenant
	back := func(kind, msg string) { s.back(w, r, "/sso", kind, msg) }
	c := SAML{
		Enabled:     r.PostFormValue("enabled") == "1",
		MetadataURL: strings.TrimSpace(r.PostFormValue("metadata_url")),
		MetadataXML: strings.TrimSpace(r.PostFormValue("metadata_xml")),
		EntityID:    strings.TrimSpace(r.PostFormValue("entity_id")),
		EmailAttr:   firstNonEmpty(r.PostFormValue("email_attr"), entraEmail),
		NameAttr:    firstNonEmpty(r.PostFormValue("name_attr"), entraName),
		GroupAttr:   firstNonEmpty(r.PostFormValue("group_attr"), entraGroup),
		RequireSSO:  r.PostFormValue("require_sso") == "1",
	}
	if r.PostFormValue("default_role") == RoleReadOnly {
		c.DefaultRole = RoleReadOnly
	}
	for _, line := range strings.Split(r.PostFormValue("group_roles"), "\n") {
		g, role, ok := strings.Cut(strings.TrimSpace(line), "=")
		g, role = strings.TrimSpace(g), strings.TrimSpace(role)
		if ok && g != "" && (role == RoleTenantAdmin || role == RoleReadOnly) {
			c.GroupRoles = append(c.GroupRoles, GroupMap{g, role})
		}
	}
	// e-mail domains steer sign-in discovery and restrict who the IdP may sign in; only the provider sets them,
	// because an unverified claim to someone else's domain would let a tenant intercept their sign-ins.
	var domains []string
	if u.IsGlobalAdmin() {
		for _, d := range strings.FieldsFunc(strings.ToLower(r.PostFormValue("domains")), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' }) {
			if !domainRe.MatchString(d) {
				back("err", "\""+d+"\" is not a valid domain name.")
				return
			}
			domains = append(domains, d)
		}
		sort.Strings(domains)
	}
	if c.Enabled {
		if !c.configured() {
			back("err", "Provide the identity provider's metadata URL or XML before enabling SSO.")
			return
		}
		if len(c.GroupRoles) == 0 && c.DefaultRole == "" {
			back("err", "Map at least one group to a role (or allow everyone as read-only), otherwise nobody could sign in.")
			return
		}
		if _, err := s.a.samlSP(ctx, &ssoProv{tenant: t, cfg: c, spName: "tenant:" + t.ID + ":saml_sp", prefix: "/t/" + t.Slug + "/saml", key: t.ID}); err != nil {
			back("err", "Could not load the identity provider's metadata, so SSO was not enabled: "+err.Error())
			return
		}
	} else if c.RequireSSO {
		c.RequireSSO = false // enforcement only makes sense while SSO is on
	}
	if u.IsGlobalAdmin() {
		tx, err := s.a.St.DB.Begin(ctx)
		if err != nil {
			s.fail(w, r, u, err)
			return
		}
		defer tx.Rollback(ctx)
		tx.Exec(ctx, `DELETE FROM tenant_sso_domains WHERE tenant_id=$1::uuid`, t.ID)
		for _, d := range domains {
			if _, err := tx.Exec(ctx, `INSERT INTO tenant_sso_domains(domain,tenant_id) VALUES($1,$2::uuid)`, d, t.ID); err != nil {
				back("err", "The domain "+d+" is already assigned to another organisation.")
				return
			}
		}
		if err := tx.Commit(ctx); err != nil {
			s.fail(w, r, u, err)
			return
		}
	}
	if err := s.a.St.SetJSON(ctx, "saml:"+t.ID, c); err != nil {
		s.fail(w, r, u, err)
		return
	}
	s.a.Audit(ctx, u.Email, "tenant.sso", "enabled="+map[bool]string{true: "yes", false: "no"}[c.Enabled])
	back("ok", "Single sign-on settings saved.")
}

// ---- public: a tenant's own sign-in page and e-mail based discovery ----

func (s *server) tenantLoginPage(w http.ResponseWriter, r *http.Request) {
	p, err := s.a.tenantProv(r.Context(), r.PathValue("slug"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, r, nil, "tenant_login", page{"Title": "Sign in", "T": p.tenant, "SSOOn": p.cfg.Enabled && p.cfg.configured()})
}

// ssoDiscover sends a user to their organisation's IdP based on the domain of their e-mail address.
func (s *server) ssoDiscover(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	_, dom, ok := strings.Cut(email, "@")
	if ok {
		var slug string
		err := s.a.St.DB.QueryRow(r.Context(), `SELECT t.slug FROM tenant_sso_domains d JOIN tenants t ON t.id=d.tenant_id WHERE d.domain=$1`, dom).Scan(&slug)
		if err == nil {
			if p, err := s.a.tenantProv(r.Context(), slug); err == nil && p.cfg.Enabled && p.cfg.configured() {
				http.Redirect(w, r, "/t/"+slug+"/saml/login", http.StatusSeeOther)
				return
			}
		}
		// staff of the platform operator use the platform IdP
		if sso := s.a.SAMLSettings(r.Context()); sso.Enabled && sso.configured() && s.isStaffDomain(r, dom) {
			http.Redirect(w, r, "/saml/login", http.StatusSeeOther)
			return
		}
	}
	s.back(w, r, "/login", "err", "No single sign-on is set up for that e-mail address. Use your password, or ask your administrator.")
}

// isStaffDomain: the platform IdP serves the e-mail domains of existing platform SSO users.
func (s *server) isStaffDomain(r *http.Request, dom string) bool {
	var n int
	s.a.St.DB.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE sso AND idp='platform' AND split_part(email,'@',2)=$1`, dom).Scan(&n)
	return n > 0
}

// localLoginBlocked: a user whose every tenant requires SSO may not sign in with a local password.
func (a *App) localLoginBlocked(ctx context.Context, userID string) bool {
	var platform string
	var memberships, open int
	a.St.DB.QueryRow(ctx, `SELECT platform_role FROM users WHERE id=$1::uuid`, userID).Scan(&platform)
	if platform != "" {
		return false
	}
	a.St.DB.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM settings s WHERE s.key='saml:'||m.tenant_id::text
		AND s.value->>'enabled'='true' AND s.value->>'require_sso'='true')) FROM memberships m WHERE m.user_id=$1::uuid`, userID).Scan(&memberships, &open)
	return memberships > 0 && open == 0
}
