package manager

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Editions. One code base, one data model, one binary: "standalone" is the MSP engine running with a single implicit tenant
// and a simplified UI. Switching a standalone installation to MSP later just means changing the mode.
const (
	ModeMSP        = "msp"
	ModeStandalone = "standalone"
)

func (a *App) Standalone() bool { return a.Opt.Mode == ModeStandalone }

// initMode prepares the database for the chosen edition.
func (a *App) initMode(ctx context.Context) error {
	if !a.Standalone() {
		return nil
	}
	var n int
	a.St.DB.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&n)
	switch {
	case n == 0:
		t, err := a.CreateTenant(ctx, "Default")
		if err != nil {
			return fmt.Errorf("creating the standalone tenant: %w", err)
		}
		a.solo = t
	case n == 1:
		var id string
		a.St.DB.QueryRow(ctx, `SELECT id::text FROM tenants`).Scan(&id)
		t, err := a.loadTenant(ctx, id)
		if err != nil {
			return err
		}
		a.solo = t
	default:
		return fmt.Errorf("this database holds %d tenants, but standalone mode supports exactly one: start with %s=%s, or remove the extra tenants", n, "RADMAN_MODE", ModeMSP)
	}
	a.solo.Status = "active" // suspension and quotas are MSP concepts
	a.solo.MaxSites, a.solo.MaxNodes, a.solo.MaxAPs = 0, 0, 0
	// make sure the implicit tenant's CAs exist
	for _, kind := range []string{"eap", "radsec"} {
		if _, err := a.tenantCA(ctx, a.solo.ID, kind); err != nil {
			return err
		}
	}
	return nil
}

// ---- standalone edition: roles are Administrator / Operator / Read-only ----

const (
	soloAdmin    = "admin"
	soloOperator = "operator"
	soloReadOnly = "read_only"
)

// soloRoleOf derives the edition role from the stored platform role / membership.
func soloRoleOf(platform, membership string) string {
	switch {
	case platform == RoleGlobalAdmin:
		return soloAdmin
	case membership == RoleTenantAdmin:
		return soloOperator
	}
	return soloReadOnly
}

func soloLabel(role string) string {
	return map[string]string{soloAdmin: "Administrator", soloOperator: "Operator", soloReadOnly: "Read-only"}[role]
}

// soloTranslateIn converts the standalone SSO mapping vocabulary into the stored one.
func (a *App) soloTranslateIn(role string) string {
	switch role {
	case soloAdmin:
		return RoleGlobalAdmin
	case soloOperator:
		return RoleTenantAdmin + "@" + a.solo.Slug
	case soloReadOnly:
		return RoleReadOnly + "@" + a.solo.Slug
	}
	return ""
}

func (a *App) soloTranslateOut(role string) string {
	switch {
	case role == RoleGlobalAdmin:
		return soloAdmin
	case role == RoleTenantAdmin+"@"+a.solo.Slug:
		return soloOperator
	case role == RoleReadOnly+"@"+a.solo.Slug:
		return soloReadOnly
	}
	return role
}

type soloUserRow struct {
	ID, Email, Name, Role, RoleLabel string
	SSO, Disabled, TOTP              bool
	LastLogin                        *time.Time
}

func (s *server) soloUsers(w http.ResponseWriter, r *http.Request, u *User) {
	rows, err := s.a.St.DB.Query(r.Context(), `SELECT u.id::text, u.email, u.name, u.platform_role, COALESCE(m.role,''), u.sso, u.disabled, u.totp_enabled, u.last_login
		FROM users u LEFT JOIN memberships m ON m.user_id=u.id AND m.tenant_id=$1::uuid ORDER BY u.email`, s.a.solo.ID)
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	var users []soloUserRow
	for rows.Next() {
		var x soloUserRow
		var plat, mem string
		rows.Scan(&x.ID, &x.Email, &x.Name, &plat, &mem, &x.SSO, &x.Disabled, &x.TOTP, &x.LastLogin)
		x.Role = soloRoleOf(plat, mem)
		x.RoleLabel = soloLabel(x.Role)
		users = append(users, x)
	}
	rows.Close()
	s.render(w, r, u, "solo_users", page{"Title": "Users", "Users": users})
}

// setSoloRole stores an edition role as platform role / membership (never both).
func (a *App) setSoloRole(ctx context.Context, userID, role string) error {
	tx, err := a.St.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	plat := ""
	if role == soloAdmin {
		plat = RoleGlobalAdmin
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET platform_role=$2 WHERE id=$1::uuid`, userID, plat); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM memberships WHERE user_id=$1::uuid AND tenant_id=$2::uuid`, userID, a.solo.ID); err != nil {
		return err
	}
	mem := map[string]string{soloOperator: RoleTenantAdmin, soloReadOnly: RoleReadOnly}[role]
	if mem != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO memberships(user_id,tenant_id,role,source) VALUES($1::uuid,$2::uuid,$3,'manual')`, userID, a.solo.ID, mem); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func validSoloRole(r string) bool { return r == soloAdmin || r == soloOperator || r == soloReadOnly }

func (s *server) soloUserCreate(w http.ResponseWriter, r *http.Request, u *User) {
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	role := r.PostFormValue("role")
	if !strings.Contains(email, "@") || !validSoloRole(role) {
		s.back(w, r, "/users", "err", "A valid e-mail address and role are required.")
		return
	}
	hash, err := hashPassword(r.PostFormValue("password"))
	if err != nil {
		s.back(w, r, "/users", "err", err.Error())
		return
	}
	var id string
	if err := s.a.St.DB.QueryRow(r.Context(), `INSERT INTO users(email,name,password_hash) VALUES($1,$2,$3) RETURNING id::text`, email, r.PostFormValue("name"), hash).Scan(&id); err != nil {
		s.back(w, r, "/users", "err", "Could not create user (already exists?).")
		return
	}
	if err := s.a.setSoloRole(r.Context(), id, role); err != nil {
		s.fail(w, r, u, err)
		return
	}
	s.a.Audit(r.Context(), u.Email, "user.create", email+" "+role)
	s.back(w, r, "/users", "ok", "User created.")
}

func (s *server) soloUserUpdate(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	if !isUUID(id) {
		http.NotFound(w, r)
		return
	}
	var sso bool
	var plat string
	if err := s.a.St.DB.QueryRow(r.Context(), `SELECT sso, platform_role FROM users WHERE id=$1::uuid`, id).Scan(&sso, &plat); err != nil {
		http.NotFound(w, r)
		return
	}
	role, disabled := r.PostFormValue("role"), r.PostFormValue("disabled") == "1"
	if !sso && !validSoloRole(role) {
		s.back(w, r, "/users", "err", "Invalid role.")
		return
	}
	if plat == RoleGlobalAdmin && (disabled || (!sso && role != soloAdmin)) && s.globalAdminCount(r, id) == 0 {
		s.back(w, r, "/users", "err", "There must be at least one active administrator.")
		return
	}
	if !sso { // single sign-on users get their role from the identity provider's groups
		if err := s.a.setSoloRole(r.Context(), id, role); err != nil {
			s.fail(w, r, u, err)
			return
		}
	}
	s.a.St.DB.Exec(r.Context(), `UPDATE users SET disabled=$2 WHERE id=$1::uuid`, id, disabled)
	if pw := r.PostFormValue("password"); pw != "" && !sso {
		h, err := hashPassword(pw)
		if err != nil {
			s.back(w, r, "/users", "err", err.Error())
			return
		}
		s.a.St.DB.Exec(r.Context(), `UPDATE users SET password_hash=$2 WHERE id=$1::uuid`, id, h)
	}
	if disabled {
		s.a.St.DB.Exec(r.Context(), `DELETE FROM sessions WHERE user_id=$1::uuid`, id)
	}
	s.a.Audit(r.Context(), u.Email, "user.update", id+" role="+role)
	s.back(w, r, "/users", "ok", "User updated.")
}

func (s *server) soloUserDelete(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	if !isUUID(id) || id == u.ID || s.globalAdminCount(r, id) == 0 {
		s.back(w, r, "/users", "err", "You cannot delete yourself or the last administrator.")
		return
	}
	s.a.St.DB.Exec(r.Context(), `DELETE FROM users WHERE id=$1::uuid`, id)
	s.a.Audit(r.Context(), u.Email, "user.delete", id)
	s.back(w, r, "/users", "ok", "User deleted.")
}
