package manager

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"radman/internal/netguard"
	"radman/internal/pki"
)

// SAML holds the single-sign-on configuration (Entra ID and any other SAML 2.0 IdP).
type SAML struct {
	Enabled     bool       `json:"enabled"`
	AllowLocal  bool       `json:"allow_local"`
	MetadataURL string     `json:"metadata_url"`
	MetadataXML string     `json:"metadata_xml"`
	EntityID    string     `json:"entity_id"`
	EmailAttr   string     `json:"email_attr"`
	NameAttr    string     `json:"name_attr"`
	GroupAttr   string     `json:"group_attr"`
	GroupRoles  []GroupMap `json:"group_roles"` // platform: global_admin | global_readonly | tenant_admin@<slug> | read_only@<slug>; tenant: tenant_admin | read_only
	// tenant-level only
	DefaultRole string `json:"default_role,omitempty"` // role for authenticated users in no mapped group ("" = refuse)
	RequireSSO  bool   `json:"require_sso,omitempty"`  // tenant-only members may not use local passwords
}

type GroupMap struct {
	Group string `json:"group"`
	Role  string `json:"role"`
}

const (
	entraEmail = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
	entraName  = "http://schemas.microsoft.com/identity/claims/displayname"
	entraGroup = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
)

func (s SAML) configured() bool { return s.MetadataURL != "" || s.MetadataXML != "" }

// MapText renders the group mapping for the settings form (edition vocabulary in standalone mode).
func (a *App) MapText(s SAML) string {
	var b strings.Builder
	for _, g := range s.GroupRoles {
		role := g.Role
		if a.Standalone() {
			role = a.soloTranslateOut(role)
		}
		fmt.Fprintf(&b, "%s=%s\n", g.Group, role)
	}
	return b.String()
}

func (s SAML) MapText() string {
	var b strings.Builder
	for _, g := range s.GroupRoles {
		fmt.Fprintf(&b, "%s=%s\n", g.Group, g.Role)
	}
	return b.String()
}

func (a *App) SAMLSettings(ctx context.Context) SAML {
	s := SAML{AllowLocal: true, EmailAttr: entraEmail, NameAttr: entraName, GroupAttr: entraGroup}
	a.St.GetJSON(ctx, "saml", &s)
	return s
}

func (a *App) baseURL(ctx context.Context) string {
	host := a.General(ctx).PublicHost
	port := ""
	if _, p, ok := strings.Cut(a.Opt.HTTPSAddr, ":"); ok && p != "443" && p != "" {
		port = ":" + p
	}
	return "https://" + host + port
}

// ssoProv is one SAML relationship: the platform's (MSP staff) or a single tenant's (that customer's own IdP).
type ssoProv struct {
	tenant *Tenant // nil = platform
	cfg    SAML
	spName string // secret holding this SP's key pair
	prefix string // URL prefix of its endpoints
	key    string // "platform" or the tenant id: binds cookies and accounts to this IdP
}

func (a *App) platformProv(ctx context.Context) *ssoProv {
	return &ssoProv{cfg: a.SAMLSettings(ctx), spName: "saml_sp", prefix: "/saml", key: "platform"}
}

func (a *App) TenantSSO(ctx context.Context, tenantID string) SAML {
	c := SAML{EmailAttr: entraEmail, NameAttr: entraName, GroupAttr: entraGroup}
	a.St.GetJSON(ctx, "saml:"+tenantID, &c)
	return c
}

func (a *App) tenantProv(ctx context.Context, slug string) (*ssoProv, error) {
	var tid string
	if err := a.St.DB.QueryRow(ctx, `SELECT id::text FROM tenants WHERE slug=$1`, slug).Scan(&tid); err != nil {
		return nil, err
	}
	t, err := a.loadTenant(ctx, tid)
	if err != nil {
		return nil, err
	}
	return &ssoProv{tenant: t, cfg: a.TenantSSO(ctx, tid), spName: "tenant:" + tid + ":saml_sp", prefix: "/t/" + t.Slug + "/saml", key: tid}, nil
}

// guardedClient is the HTTP client used to fetch IdP metadata. Tenant administrators supply URLs, so it must not
// become a way to reach the platform's internal network: loopback, link-local and (for tenants) private ranges are refused.
func guardedClient(allowPrivate bool) *http.Client {
	return netguard.Client(allowPrivate)
}

// samlBase returns the SP half of the configuration (enough to publish metadata).
func (a *App) samlBase(ctx context.Context, p *ssoProv) (*saml.ServiceProvider, error) {
	cp, kp, _ := a.getPEM(ctx, p.spName)
	if cp == nil {
		var err error
		if cp, kp, err = pki.SelfSignedRSA("The RadMAN SAML SP", 10*365*24*time.Hour); err != nil {
			return nil, err
		}
		if err := a.putPEM(ctx, p.spName, cp, kp); err != nil {
			return nil, err
		}
	}
	pair, err := tls.X509KeyPair(cp, kp)
	if err != nil {
		return nil, err
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("SP key cannot sign")
	}
	leaf, _ := pki.ParseCert(cp)
	base, err := url.Parse(a.baseURL(ctx))
	if err != nil {
		return nil, err
	}
	return &saml.ServiceProvider{
		EntityID:          firstNonEmpty(p.cfg.EntityID, base.JoinPath(p.prefix, "metadata").String()),
		Key:               signer,
		Certificate:       leaf,
		MetadataURL:       *base.JoinPath(p.prefix, "metadata"),
		AcsURL:            *base.JoinPath(p.prefix, "acs"),
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat,
	}, nil
}

func (a *App) samlSP(ctx context.Context, p *ssoProv) (*saml.ServiceProvider, error) {
	sp, err := a.samlBase(ctx, p)
	if err != nil {
		return nil, err
	}
	if !p.cfg.Enabled || !p.cfg.configured() {
		return nil, errors.New("single sign-on is not enabled")
	}
	if p.cfg.MetadataXML != "" {
		if len(p.cfg.MetadataXML) > 1<<20 {
			return nil, errors.New("IdP metadata is too large")
		}
		sp.IDPMetadata, err = samlsp.ParseMetadata([]byte(p.cfg.MetadataXML))
	} else {
		var u *url.URL
		if u, err = url.Parse(p.cfg.MetadataURL); err == nil && (u.Scheme != "https" && u.Scheme != "http") {
			err = errors.New("metadata URL must be http(s)")
		}
		if err == nil {
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			sp.IDPMetadata, err = samlsp.FetchMetadata(cctx, guardedClient(p.tenant == nil), *u)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("IdP metadata: %w", err)
	}
	return sp, nil
}

func (a *App) cookieMAC(ctx context.Context, v string) string {
	k, _ := a.St.GetSecret(ctx, "cookie_key")
	if k == "" {
		k = a.seal(randToken(32))
		a.St.SetSecret(ctx, "cookie_key", k)
	}
	kk, _ := a.open(k)
	m := hmac.New(sha256.New, []byte(kk))
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *server) samlMetadataP(w http.ResponseWriter, r *http.Request, p *ssoProv) {
	if s.a.General(r.Context()).PublicHost == "" {
		http.NotFound(w, r)
		return
	}
	sp, err := s.a.samlBase(r.Context(), p)
	if err != nil {
		http.Error(w, "unavailable", 500)
		return
	}
	b, _ := xml.MarshalIndent(sp.Metadata(), "", "  ")
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(b)
}

func (s *server) samlLoginP(w http.ResponseWriter, r *http.Request, p *ssoProv) {
	fail := func(msg string) {
		s.flash(w, "err", msg)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	sp, err := s.a.samlSP(r.Context(), p)
	if err != nil {
		fail("Single sign-on unavailable: " + err.Error())
		return
	}
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		fail(err.Error())
		return
	}
	redir, err := req.Redirect("", sp)
	if err != nil {
		fail(err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "rh_saml", Value: req.ID + "." + s.a.cookieMAC(r.Context(), p.key+"|"+req.ID), Path: "/", MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode})
	http.Redirect(w, r, redir.String(), http.StatusFound)
}

func (s *server) samlMetadata(w http.ResponseWriter, r *http.Request) {
	s.samlMetadataP(w, r, s.a.platformProv(r.Context()))
}
func (s *server) samlLogin(w http.ResponseWriter, r *http.Request) {
	s.samlLoginP(w, r, s.a.platformProv(r.Context()))
}
func (s *server) samlACS(w http.ResponseWriter, r *http.Request) {
	s.samlACSP(w, r, s.a.platformProv(r.Context()))
}

// tenantProvFromPath resolves /t/{slug}/saml/... ; unknown tenants look like any other missing page.
func (s *server) tenantProvFromPath(w http.ResponseWriter, r *http.Request) *ssoProv {
	p, err := s.a.tenantProv(r.Context(), r.PathValue("slug"))
	if err != nil {
		http.NotFound(w, r)
		return nil
	}
	return p
}

func (s *server) tenantSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if p := s.tenantProvFromPath(w, r); p != nil {
		s.samlMetadataP(w, r, p)
	}
}
func (s *server) tenantSAMLLogin(w http.ResponseWriter, r *http.Request) {
	if p := s.tenantProvFromPath(w, r); p != nil {
		s.samlLoginP(w, r, p)
	}
}
func (s *server) tenantSAMLACS(w http.ResponseWriter, r *http.Request) {
	if p := s.tenantProvFromPath(w, r); p != nil {
		s.samlACSP(w, r, p)
	}
}

func (s *server) samlACSP(w http.ResponseWriter, r *http.Request, p *ssoProv) {
	ctx := r.Context()
	if p.tenant != nil {
		ctx = withTenant(ctx, p.tenant.ID)
	}
	deny := func(msg string, err error) {
		if err != nil {
			s.a.Log.Printf("SAML (%s): %s: %v", p.key, msg, err)
		}
		s.a.Audit(ctx, "sso", "login.failed", msg)
		s.flash(w, "err", "Single sign-on failed: "+msg)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	sp, err := s.a.samlSP(ctx, p)
	if err != nil {
		deny(err.Error(), err)
		return
	}
	cfg := p.cfg
	r.ParseForm()
	var ids []string
	if c, err := r.Cookie("rh_saml"); err == nil {
		if id, mac, ok := strings.Cut(c.Value, "."); ok && hmac.Equal([]byte(mac), []byte(s.a.cookieMAC(ctx, p.key+"|"+id))) {
			ids = []string{id}
		}
	}
	if len(ids) == 0 {
		deny("login session expired, please try again", nil)
		return
	}
	as, err := sp.ParseResponse(r, ids)
	if err != nil {
		deny("the identity provider's response was rejected", err)
		return
	}
	attrs := map[string][]string{}
	for _, st := range as.AttributeStatements {
		for _, at := range st.Attributes {
			for _, v := range at.Values {
				attrs[at.Name] = append(attrs[at.Name], v.Value)
				if at.FriendlyName != "" {
					attrs[at.FriendlyName] = append(attrs[at.FriendlyName], v.Value)
				}
			}
		}
	}
	email := ""
	if v := attrs[cfg.EmailAttr]; len(v) > 0 {
		email = v[0]
	} else if as.Subject != nil && as.Subject.NameID != nil && strings.Contains(as.Subject.NameID.Value, "@") {
		email = as.Subject.NameID.Value
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if !strings.Contains(email, "@") {
		deny("no e-mail address in the assertion (check the attribute mapping)", nil)
		return
	}
	name := ""
	if v := attrs[cfg.NameAttr]; len(v) > 0 {
		name = v[0]
	}

	var id string
	var summary string
	if p.tenant == nil {
		id, summary, err = s.a.ssoLoginPlatform(ctx, cfg, attrs, email, name)
	} else {
		id, summary, err = s.a.ssoLoginTenant(ctx, p, attrs, email, name)
	}
	if err != nil {
		deny(err.Error(), nil)
		return
	}
	var disabled bool
	s.a.St.DB.QueryRow(ctx, `SELECT disabled FROM users WHERE id=$1::uuid`, id).Scan(&disabled)
	if disabled {
		deny("account disabled", nil)
		return
	}
	if err := s.a.newSession(ctx, w, id); err != nil {
		deny("session error", err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "rh_saml", Path: "/", MaxAge: -1})
	s.a.Audit(ctx, email, "login.sso", summary)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ssoLoginPlatform signs in staff via the platform IdP: groups become a platform role and/or per-tenant grants.
func (a *App) ssoLoginPlatform(ctx context.Context, cfg SAML, attrs map[string][]string, email, name string) (id, summary string, err error) {
	platform := ""
	type grant struct{ slug, role string }
	var grants []grant
	for _, g := range attrs[cfg.GroupAttr] {
		for _, m := range cfg.GroupRoles {
			if !strings.EqualFold(m.Group, g) {
				continue
			}
			switch role, slug, scoped := strings.Cut(m.Role, "@"); {
			case !scoped && role == RoleGlobalAdmin:
				platform = RoleGlobalAdmin
			case !scoped && role == RoleGlobalReadonly && platform != RoleGlobalAdmin:
				platform = RoleGlobalReadonly
			case scoped && (role == RoleTenantAdmin || role == RoleReadOnly):
				grants = append(grants, grant{slug, role})
			}
		}
	}
	if platform == "" && len(grants) == 0 {
		return "", "", errors.New("your account is not in a group that is allowed to use The RadMAN")
	}
	// the account must belong to the platform IdP (or be new); a local or customer-IdP account with this e-mail is never taken over
	err = a.St.DB.QueryRow(ctx, `INSERT INTO users(email,name,platform_role,sso,idp) VALUES($1,$2,$3,true,'platform')
		ON CONFLICT(email) DO UPDATE SET platform_role=EXCLUDED.platform_role, name=COALESCE(NULLIF(EXCLUDED.name,''),users.name), last_login=now()
		WHERE users.sso AND users.idp='platform' RETURNING id::text`, email, name, platform).Scan(&id)
	if err != nil {
		return "", "", errors.New("an account with this e-mail already exists under a different sign-in method; ask an administrator")
	}
	// tenant access granted by the platform IdP is re-synced on every login (manual grants are left alone)
	a.St.DB.Exec(ctx, `DELETE FROM memberships WHERE user_id=$1::uuid AND source='sso'`, id)
	for _, g := range grants {
		a.St.DB.Exec(ctx, `INSERT INTO memberships(user_id,tenant_id,role,source) SELECT $1::uuid, id, $3, 'sso' FROM tenants WHERE slug=$2
			ON CONFLICT (user_id,tenant_id) DO UPDATE SET role = CASE WHEN memberships.source='sso' THEN EXCLUDED.role ELSE memberships.role END`, id, g.slug, g.role)
	}
	return id, "platform=" + platform + " tenants=" + strconv.Itoa(len(grants)), nil
}

// ssoLoginTenant signs in a customer's user via that customer's own IdP. Whatever the IdP asserts, the result is
// confined to this one tenant: no platform role, no other tenant, and no takeover of an account owned by anything else.
func (a *App) ssoLoginTenant(ctx context.Context, p *ssoProv, attrs map[string][]string, email, name string) (id, summary string, err error) {
	cfg, tid := p.cfg, p.tenant.ID
	// optional e-mail domain restriction (set by the platform administrator)
	var nd int
	a.St.DB.QueryRow(ctx, `SELECT count(*) FROM tenant_sso_domains WHERE tenant_id=$1::uuid`, tid).Scan(&nd)
	if nd > 0 {
		_, dom, _ := strings.Cut(email, "@")
		var ok bool
		if a.St.DB.QueryRow(ctx, `SELECT true FROM tenant_sso_domains WHERE tenant_id=$1::uuid AND domain=$2`, tid, dom).Scan(&ok) != nil {
			return "", "", errors.New("this e-mail domain is not allowed for this organisation's sign-in")
		}
	}
	role := ""
	for _, g := range attrs[cfg.GroupAttr] {
		for _, m := range cfg.GroupRoles {
			if strings.EqualFold(m.Group, g) {
				if m.Role == RoleTenantAdmin {
					role = RoleTenantAdmin
				} else if m.Role == RoleReadOnly && role == "" {
					role = RoleReadOnly
				}
			}
		}
	}
	if role == "" && cfg.DefaultRole == RoleReadOnly {
		role = RoleReadOnly
	}
	if role == "" {
		return "", "", errors.New("your account is not in a group that has access to this organisation")
	}
	err = a.St.DB.QueryRow(ctx, `INSERT INTO users(email,name,platform_role,sso,idp) VALUES($1,$2,'',true,$3)
		ON CONFLICT(email) DO UPDATE SET name=COALESCE(NULLIF(EXCLUDED.name,''),users.name), last_login=now()
		WHERE users.sso AND users.idp=$3 RETURNING id::text`, email, name, tid).Scan(&id)
	if err != nil {
		return "", "", errors.New("an account with this e-mail already exists under a different sign-in method; ask an administrator")
	}
	src := "sso:" + tid
	a.St.DB.Exec(ctx, `DELETE FROM memberships WHERE user_id=$1::uuid AND source=$2`, id, src)
	if _, err := a.St.DB.Exec(ctx, `INSERT INTO memberships(user_id,tenant_id,role,source) VALUES($1::uuid,$2::uuid,$3,$4) ON CONFLICT (user_id,tenant_id) DO NOTHING`, id, tid, role, src); err != nil {
		return "", "", err
	}
	return id, "tenant=" + p.tenant.Slug + " role=" + role, nil
}

// settingsSSO saves the SSO configuration.
func (s *server) settingsSSO(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	c := SAML{
		Enabled:     r.PostFormValue("enabled") == "1",
		AllowLocal:  r.PostFormValue("allow_local") == "1",
		MetadataURL: strings.TrimSpace(r.PostFormValue("metadata_url")),
		MetadataXML: strings.TrimSpace(r.PostFormValue("metadata_xml")),
		EntityID:    strings.TrimSpace(r.PostFormValue("entity_id")),
		EmailAttr:   firstNonEmpty(r.PostFormValue("email_attr"), entraEmail),
		NameAttr:    firstNonEmpty(r.PostFormValue("name_attr"), entraName),
		GroupAttr:   firstNonEmpty(r.PostFormValue("group_attr"), entraGroup),
	}
	for _, line := range strings.Split(r.PostFormValue("group_roles"), "\n") {
		g, role, ok := strings.Cut(strings.TrimSpace(line), "=")
		g, role = strings.TrimSpace(g), strings.TrimSpace(role)
		if !ok || g == "" {
			continue
		}
		if s.a.Standalone() { // administrator / operator / read_only
			if stored := s.a.soloTranslateIn(role); stored != "" {
				c.GroupRoles = append(c.GroupRoles, GroupMap{g, stored})
			}
			continue
		}
		base, slug, scoped := strings.Cut(role, "@")
		if (!scoped && (base == RoleGlobalAdmin || base == RoleGlobalReadonly)) || (scoped && slug != "" && (base == RoleTenantAdmin || base == RoleReadOnly)) {
			c.GroupRoles = append(c.GroupRoles, GroupMap{g, role})
		}
	}
	if c.Enabled {
		if !c.configured() {
			s.back(w, r, "/settings?tab=sso", "err", "Provide the IdP metadata URL or XML before enabling SSO.")
			return
		}
		if err := s.a.St.SetJSON(ctx, "saml", c); err != nil {
			s.fail(w, r, u, err)
			return
		}
		if _, err := s.a.samlSP(ctx, s.a.platformProv(ctx)); err != nil { // validate before locking anyone out
			c.Enabled = false
			s.a.St.SetJSON(ctx, "saml", c)
			s.back(w, r, "/settings?tab=sso", "err", "Could not load the IdP metadata, SSO left disabled: "+err.Error())
			return
		}
		if !c.AllowLocal && len(c.GroupRoles) == 0 {
			c.AllowLocal = true // refuse a configuration that would lock everyone out
			s.a.St.SetJSON(ctx, "saml", c)
			s.back(w, r, "/settings?tab=sso", "err", "No group mapping is set, so nobody could sign in with SSO. Local sign-in was kept enabled.")
			return
		}
	}
	if err := s.a.St.SetJSON(ctx, "saml", c); err != nil {
		s.fail(w, r, u, err)
		return
	}
	s.a.Audit(ctx, u.Email, "settings.sso", fmt.Sprintf("enabled=%v allow_local=%v", c.Enabled, c.AllowLocal))
	s.back(w, r, "/settings?tab=sso", "ok", "SSO settings saved.")
}
