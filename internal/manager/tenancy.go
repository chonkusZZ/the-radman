package manager

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"radman/internal/pki"
)

// Roles. Three layers of access:
//
//	global_admin     full control of the platform and every tenant
//	global_readonly  can see every tenant, can change nothing
//	tenant_admin     full control of the tenants they are a member of (and only those)
//	read_only        can see the tenants they are a member of, can change nothing
const (
	RoleGlobalAdmin    = "global_admin"
	RoleGlobalReadonly = "global_readonly"
	RoleTenantAdmin    = "tenant_admin"
	RoleReadOnly       = "read_only"
)

type Tenant struct {
	ID, Name, Slug, Status string
	MaxSites, MaxNodes     int
	MaxAPs                 int
}

func (t *Tenant) Suspended() bool { return t != nil && t.Status == "suspended" }

type ctxTenantKey struct{}

func withTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, ctxTenantKey{}, tenantID)
}

func tenantFrom(ctx context.Context) string {
	s, _ := ctx.Value(ctxTenantKey{}).(string)
	return s
}

// RoleIn returns the user's effective role in a tenant ("" = no access).
func (u *User) RoleIn(tenantID string) string {
	switch u.Platform {
	case RoleGlobalAdmin:
		return RoleTenantAdmin
	case RoleGlobalReadonly:
		return RoleReadOnly
	}
	return u.Member[tenantID]
}

func (u *User) IsGlobalAdmin() bool     { return u.Platform == RoleGlobalAdmin }
func (u *User) IsGlobal() bool          { return u.Platform != "" }
func (u *User) CanRead(tid string) bool { return u.RoleIn(tid) != "" }

// CanWrite: tenant admins (and global admins) may change a tenant; suspended tenants are frozen for everyone but global admins.
func (u *User) CanWrite(t *Tenant) bool {
	if t == nil {
		return false
	}
	if u.IsGlobalAdmin() {
		return true
	}
	return u.RoleIn(t.ID) == RoleTenantAdmin && !t.Suspended()
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func makeSlug(name string) string {
	s := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if s == "" {
		s = "tenant"
	}
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	return s
}

func (a *App) loadTenant(ctx context.Context, id string) (*Tenant, error) {
	t := &Tenant{}
	err := a.St.DB.QueryRow(ctx, `SELECT id::text, name, slug, status, max_sites, max_nodes, max_aps FROM tenants WHERE id::text=$1`, id).
		Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.MaxSites, &t.MaxNodes, &t.MaxAPs)
	return t, err
}

// accessibleTenants lists the tenants a user can open.
func (a *App) accessibleTenants(ctx context.Context, u *User) []*Tenant {
	q := `SELECT id::text, name, slug, status, max_sites, max_nodes, max_aps FROM tenants ORDER BY name`
	args := []any{}
	if !u.IsGlobal() {
		q = `SELECT t.id::text, t.name, t.slug, t.status, t.max_sites, t.max_nodes, t.max_aps FROM tenants t JOIN memberships m ON m.tenant_id=t.id WHERE m.user_id::text=$1 ORDER BY t.name`
		args = append(args, u.ID)
	}
	rows, err := a.St.DB.Query(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*Tenant
	for rows.Next() {
		t := &Tenant{}
		rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.MaxSites, &t.MaxNodes, &t.MaxAPs)
		out = append(out, t)
	}
	return out
}

// CreateTenant creates a tenant together with its own private CAs.
// Each tenant has separate EAP-server and RadSec CAs so one customer's devices/APs never trust another customer's issuance.
func (a *App) CreateTenant(ctx context.Context, name string) (*Tenant, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("a tenant name is required")
	}
	base := makeSlug(name)
	slug := base
	for i := 2; ; i++ {
		var n int
		a.St.DB.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE slug=$1`, slug).Scan(&n)
		if n == 0 {
			break
		}
		slug = fmt.Sprintf("%s-%d", base, i)
	}
	t := &Tenant{Name: name, Slug: slug, Status: "active"}
	if err := a.St.DB.QueryRow(ctx, `INSERT INTO tenants(name,slug) VALUES($1,$2) RETURNING id::text`, name, slug).Scan(&t.ID); err != nil {
		return nil, errors.New("could not create tenant (is the name already used?)")
	}
	for _, kind := range []string{"eap", "radsec"} {
		if _, err := a.tenantCA(ctx, t.ID, kind); err != nil {
			a.St.DB.Exec(ctx, `DELETE FROM tenants WHERE id::text=$1`, t.ID)
			return nil, err
		}
	}
	return t, nil
}

// DeleteTenant removes a tenant and everything in it, including its CA keys.
func (a *App) DeleteTenant(ctx context.Context, id string) error {
	if _, err := a.St.DB.Exec(ctx, `DELETE FROM events WHERE tenant_id::text=$1`, id); err != nil {
		return err
	}
	if _, err := a.St.DB.Exec(ctx, `DELETE FROM tenants WHERE id::text=$1`, id); err != nil {
		return err
	}
	for _, kind := range []string{"eap", "radsec"} {
		a.St.DelSecret(ctx, tenantSecret(id, kind)+"_cert")
		a.St.DelSecret(ctx, tenantSecret(id, kind)+"_key")
	}
	// the tenant's identity provider, its service-provider key, and the accounts it created
	a.St.DB.Exec(ctx, `DELETE FROM settings WHERE key=$1`, "saml:"+id)
	a.St.DelSecret(ctx, "tenant:"+id+":saml_sp_cert")
	a.St.DelSecret(ctx, "tenant:"+id+":saml_sp_key")
	a.St.DB.Exec(ctx, `DELETE FROM users WHERE sso AND idp=$1`, id)
	a.caMu.Lock()
	delete(a.caCache, id+"/eap")
	delete(a.caCache, id+"/radsec")
	a.caMu.Unlock()
	return nil
}

func tenantSecret(tenantID, kind string) string { return "tenant:" + tenantID + ":" + kind + "_ca" }

// tenantCA returns (creating on first use) a tenant's private CA. kind is "eap" or "radsec".
func (a *App) tenantCA(ctx context.Context, tenantID, kind string) (*pki.CA, error) {
	key := tenantID + "/" + kind
	a.caMu.Lock()
	defer a.caMu.Unlock()
	if ca, ok := a.caCache[key]; ok {
		return ca, nil
	}
	cn := map[string]string{"eap": "EAP Server CA", "radsec": "RadSec AP CA"}[kind]
	var tname string
	if err := a.St.DB.QueryRow(ctx, `SELECT name FROM tenants WHERE id::text=$1`, tenantID).Scan(&tname); err != nil {
		return nil, err
	}
	ca, err := a.ensureCA(ctx, tenantSecret(tenantID, kind), tname+" "+cn)
	if err != nil {
		return nil, err
	}
	a.caCache[key] = ca
	return ca, nil
}

func (a *App) tenantCAPEM(ctx context.Context, tenantID, kind string) ([]byte, error) {
	ca, err := a.tenantCA(ctx, tenantID, kind)
	if err != nil {
		return nil, err
	}
	return pki.EncodeCert(ca.Cert.Raw), nil
}

// migrateTenancy upgrades a single-tenant database in place: legacy data moves into a "Default" tenant,
// legacy roles become platform/tenant roles, and the legacy global EAP/RadSec CAs become that tenant's CAs.
// It is idempotent and a no-op on fresh or already-migrated databases.
func (a *App) migrateTenancy(ctx context.Context) error {
	db := a.St.DB
	var legacyRole bool
	db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='role' AND table_schema=current_schema())`).Scan(&legacyRole)
	var orphans int
	db.QueryRow(ctx, `SELECT (SELECT count(*) FROM sites WHERE tenant_id IS NULL)+(SELECT count(*) FROM pki_profiles WHERE tenant_id IS NULL)+(SELECT count(*) FROM eap_certs WHERE tenant_id IS NULL)`).Scan(&orphans)

	if legacyRole || orphans > 0 {
		tx, err := db.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		needDefault := orphans > 0
		if legacyRole && !needDefault {
			var n int
			tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE role IN ('operator','viewer')`).Scan(&n)
			needDefault = n > 0
		}
		tid := ""
		if needDefault {
			err := tx.QueryRow(ctx, `SELECT id::text FROM tenants WHERE slug='default'`).Scan(&tid)
			if errors.Is(err, pgx.ErrNoRows) {
				err = tx.QueryRow(ctx, `INSERT INTO tenants(name,slug) VALUES('Default','default') RETURNING id::text`).Scan(&tid)
			}
			if err != nil {
				return err
			}
			for _, t := range []string{"sites", "pki_profiles", "eap_certs"} {
				if _, err := tx.Exec(ctx, fmt.Sprintf(`UPDATE %s SET tenant_id=$1::uuid WHERE tenant_id IS NULL`, t), tid); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE audit SET tenant_id=$1::uuid WHERE tenant_id IS NULL AND (action LIKE 'site.%' OR action LIKE 'ap.%' OR action LIKE 'node.%' OR action LIKE 'pki.%' OR action LIKE 'eapcert.%' OR action LIKE 'radsec.%' OR action LIKE 'policy.%')`, tid); err != nil {
				return err
			}
		}
		if legacyRole {
			// admin -> global administrator; operator -> tenant admin; viewer -> read-only (both in the Default tenant)
			if _, err := tx.Exec(ctx, `UPDATE users SET platform_role='global_admin' WHERE role='admin' AND platform_role=''`); err != nil {
				return err
			}
			if tid != "" {
				if _, err := tx.Exec(ctx, `INSERT INTO memberships(user_id,tenant_id,role) SELECT id,$1::uuid,'tenant_admin' FROM users WHERE role='operator' ON CONFLICT DO NOTHING`, tid); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO memberships(user_id,tenant_id,role) SELECT id,$1::uuid,'read_only' FROM users WHERE role='viewer' ON CONFLICT DO NOTHING`, tid); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `ALTER TABLE users DROP COLUMN role`); err != nil {
				return err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		if tid != "" {
			// the legacy global CAs become the Default tenant's CAs, so already-issued certificates keep validating
			for legacy, kind := range map[string]string{"eap_ca": "eap", "radsec_ca": "radsec"} {
				for _, suffix := range []string{"_cert", "_key"} {
					v, _ := a.St.GetSecret(ctx, legacy+suffix)
					if existing, _ := a.St.GetSecret(ctx, tenantSecret(tid, kind)+suffix); v != "" && existing == "" {
						if err := a.St.SetSecret(ctx, tenantSecret(tid, kind)+suffix, v); err != nil {
							return err
						}
					}
				}
			}
		}
	}

	// uniqueness is per tenant now
	stmts := []string{
		`ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_name_key`,
		`ALTER TABLE pki_profiles DROP CONSTRAINT IF EXISTS pki_profiles_name_key`,
		`CREATE UNIQUE INDEX IF NOT EXISTS sites_tenant_name ON sites(tenant_id, name)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS pki_tenant_name ON pki_profiles(tenant_id, name)`,
		`UPDATE events e SET tenant_id=s.tenant_id FROM sites s WHERE e.tenant_id IS NULL AND s.id=e.site_id`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(ctx, s); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}
	// tenant_id becomes mandatory once nothing is orphaned
	db.QueryRow(ctx, `SELECT (SELECT count(*) FROM sites WHERE tenant_id IS NULL)+(SELECT count(*) FROM pki_profiles WHERE tenant_id IS NULL)+(SELECT count(*) FROM eap_certs WHERE tenant_id IS NULL)`).Scan(&orphans)
	if orphans == 0 {
		for _, t := range []string{"sites", "pki_profiles", "eap_certs"} {
			if _, err := db.Exec(ctx, fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN tenant_id SET NOT NULL`, t)); err != nil {
				return err
			}
		}
	}
	return nil
}

// quotaExceeded returns a message when creating one more sites/nodes/aps would exceed the tenant's quota.
func (a *App) quotaExceeded(ctx context.Context, t *Tenant, what string) string {
	var limit int
	var q string
	switch what {
	case "sites":
		limit, q = t.MaxSites, `SELECT count(*) FROM sites WHERE tenant_id=$1::uuid`
	case "nodes":
		limit, q = t.MaxNodes, `SELECT count(*) FROM nodes n JOIN sites s ON s.id=n.site_id WHERE s.tenant_id=$1::uuid`
	case "aps":
		limit, q = t.MaxAPs, `SELECT count(*) FROM aps a JOIN sites s ON s.id=a.site_id WHERE s.tenant_id=$1::uuid`
	}
	if limit <= 0 {
		return ""
	}
	var n int
	a.St.DB.QueryRow(ctx, q, t.ID).Scan(&n)
	if n >= limit {
		return fmt.Sprintf("This tenant has reached its limit of %d %s. Contact your service provider to raise it.", limit, what)
	}
	return ""
}
