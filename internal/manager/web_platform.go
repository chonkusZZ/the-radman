package manager

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ---- home / tenant switching ----

func (s *server) home(w http.ResponseWriter, r *http.Request, u *User) {
	if s.a.Standalone() {
		if u.Tenant == nil {
			s.forbidden(w, r, u, "You do not have access to this installation.")
			return
		}
		s.tenantDashboard(w, r, u)
		return
	}
	if u.Tenant != nil {
		s.tenantDashboard(w, r, u)
		return
	}
	if u.IsGlobal() {
		s.platformHome(w, r, u)
		return
	}
	// a tenant user who belongs to several tenants (or none)
	s.render(w, r, u, "picker", page{"Title": "Choose a tenant", "Choices": s.a.accessibleTenants(r.Context(), u)})
}

func (s *server) tenantSwitch(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	id := r.PostFormValue("tenant")
	var arg any
	if id != "" {
		if !isUUID(id) || !u.CanRead(id) {
			s.forbidden(w, r, u, "You do not have access to that tenant.")
			return
		}
		arg = id
	} else if !u.IsGlobal() {
		s.back(w, r, "/", "err", "Choose a tenant.")
		return
	}
	c, _ := r.Cookie(cookieName)
	s.a.St.DB.Exec(ctx, `UPDATE sessions SET tenant_id=$2::uuid WHERE id=$1`, hashSID(c.Value), arg)
	dest := "/"
	if id == "" {
		dest = "/platform"
	} else if next := r.PostFormValue("next"); next == "/sso" || next == "/users" || next == "/sites" { // fixed allow-list, never an open redirect
		dest = next
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// ---- platform overview and tenants ----

type tenantRow struct {
	ID, Name, Slug, Status        string
	Sites, Nodes, Online, Members int
	Accepts24h, Rejects24h        int
	MaxSites, MaxNodes, MaxAPs    int
	APs                           int
	Created                       time.Time
}

func (s *server) tenantRows(ctx context.Context, q string, limit, offset int) ([]*tenantRow, int) {
	g := s.a.General(ctx)
	online := time.Duration(3*g.NodeIntervalSecs+15) * time.Second
	var total int
	s.a.St.DB.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE name ILIKE '%'||$1||'%' OR slug ILIKE '%'||$1||'%'`, q).Scan(&total)
	rows, err := s.a.St.DB.Query(ctx, `SELECT t.id::text, t.name, t.slug, t.status, t.max_sites, t.max_nodes, t.max_aps, t.created_at,
		(SELECT count(*) FROM sites WHERE tenant_id=t.id),
		(SELECT count(*) FROM aps a JOIN sites s ON s.id=a.site_id WHERE s.tenant_id=t.id),
		(SELECT count(*) FROM nodes n JOIN sites s ON s.id=n.site_id WHERE s.tenant_id=t.id),
		(SELECT count(*) FROM nodes n JOIN sites s ON s.id=n.site_id WHERE s.tenant_id=t.id AND n.status='active' AND n.last_seen > now() - make_interval(secs => $4)),
		(SELECT count(*) FROM memberships WHERE tenant_id=t.id)
		FROM tenants t WHERE t.name ILIKE '%'||$1||'%' OR t.slug ILIKE '%'||$1||'%' ORDER BY t.name LIMIT $2 OFFSET $3`, q, limit, offset, online.Seconds())
	if err != nil {
		return nil, 0
	}
	var out []*tenantRow
	for rows.Next() {
		t := &tenantRow{}
		rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.MaxSites, &t.MaxNodes, &t.MaxAPs, &t.Created, &t.Sites, &t.APs, &t.Nodes, &t.Online, &t.Members)
		out = append(out, t)
	}
	rows.Close()
	// 24h auth counts in one pass over the (partitioned, indexed) events table
	acc := map[string][2]int{}
	er, err := s.a.St.RO.Query(ctx, `SELECT tenant_id::text, count(*) FILTER (WHERE data->>'result'='accept'), count(*) FILTER (WHERE data->>'result'='reject')
		FROM events WHERE kind='auth' AND ts > now()-interval '24 hours' GROUP BY tenant_id`)
	if err == nil {
		for er.Next() {
			var id string
			var a, rj int
			er.Scan(&id, &a, &rj)
			acc[id] = [2]int{a, rj}
		}
		er.Close()
	}
	for _, t := range out {
		t.Accepts24h, t.Rejects24h = acc[t.ID][0], acc[t.ID][1]
	}
	return out, total
}

func (s *server) platformHome(w http.ResponseWriter, r *http.Request, u *User) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	pg, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if pg < 1 {
		pg = 1
	}
	const per = 50
	list, total := s.tenantRows(r.Context(), q, per, (pg-1)*per)
	sum := &tenantRow{}
	for _, t := range list {
		sum.Sites += t.Sites
		sum.Nodes += t.Nodes
		sum.Online += t.Online
		sum.Accepts24h += t.Accepts24h
		sum.Rejects24h += t.Rejects24h
	}
	var nodesTotal, nodesOnline int
	g := s.a.General(r.Context())
	s.a.St.DB.QueryRow(r.Context(), `SELECT count(*), count(*) FILTER (WHERE status='active' AND last_seen > now() - make_interval(secs => $1)) FROM nodes`, float64(3*g.NodeIntervalSecs+15)).Scan(&nodesTotal, &nodesOnline)
	var pending int
	s.a.St.DB.QueryRow(r.Context(), `SELECT count(*) FROM nodes WHERE status='pending'`).Scan(&pending)
	s.render(w, r, u, "platform", page{"Title": "Platform", "Tenants": list, "Total": total, "Q": q, "Page": pg, "Pages": (total + per - 1) / per,
		"NodesTotal": nodesTotal, "NodesOnline": nodesOnline, "Pending": pending, "Sum": sum})
}

func (s *server) tenantCreate(w http.ResponseWriter, r *http.Request, u *User) {
	t, err := s.a.CreateTenant(r.Context(), r.PostFormValue("name"))
	if err != nil {
		s.back(w, r, "/platform", "err", err.Error())
		return
	}
	s.a.Audit(withTenant(r.Context(), t.ID), u.Email, "tenant.create", t.Name)
	s.back(w, r, "/platform/tenants/"+t.ID, "ok", "Tenant created. Set quotas and add its administrators, then open it to build sites.")
}

func (s *server) tenantDetail(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	id := r.PathValue("id")
	if !isUUID(id) {
		http.NotFound(w, r)
		return
	}
	rows, _ := s.tenantRows(ctx, "", 1000000, 0)
	var row *tenantRow
	for _, t := range rows {
		if t.ID == id {
			row = t
		}
	}
	if row == nil {
		s.render(w, r, u, "error", page{"Title": "Not found", "Msg": "Tenant not found."}, 404)
		return
	}
	var notes string
	s.a.St.DB.QueryRow(ctx, `SELECT notes FROM tenants WHERE id=$1::uuid`, id).Scan(&notes)
	sso := s.a.TenantSSO(ctx, id)
	s.render(w, r, u, "tenant", page{"Title": row.Name, "T": row, "Notes": notes, "Members": s.members(ctx, id),
		"SSOOn": sso.Enabled && sso.configured(), "SSORequired": sso.RequireSSO, "SSODomains": strings.Join(s.a.tenantDomains(ctx, id), ", ")})
}

type memberRow struct {
	UserID, Email, Name, Role, Source string
	Platform                          string
	Disabled                          bool
	LastLogin                         *time.Time
}

func (s *server) members(ctx context.Context, tenantID string) []memberRow {
	rows, err := s.a.St.DB.Query(ctx, `SELECT u.id::text, u.email, u.name, m.role, m.source, u.platform_role, u.disabled, u.last_login
		FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.tenant_id=$1::uuid ORDER BY u.email`, tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []memberRow
	for rows.Next() {
		var m memberRow
		rows.Scan(&m.UserID, &m.Email, &m.Name, &m.Role, &m.Source, &m.Platform, &m.Disabled, &m.LastLogin)
		out = append(out, m)
	}
	return out
}

func (s *server) tenantUpdate(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	atoi := func(k string) int {
		n, _ := strconv.Atoi(r.PostFormValue(k))
		if n < 0 {
			n = 0
		}
		return n
	}
	status := "active"
	if r.PostFormValue("status") == "suspended" {
		status = "suspended"
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		s.back(w, r, "/platform/tenants/"+id, "err", "A name is required.")
		return
	}
	if _, err := s.a.St.DB.Exec(r.Context(), `UPDATE tenants SET name=$2, status=$3, max_sites=$4, max_nodes=$5, max_aps=$6, notes=$7 WHERE id=$1::uuid`,
		id, name, status, atoi("max_sites"), atoi("max_nodes"), atoi("max_aps"), r.PostFormValue("notes")); err != nil {
		s.back(w, r, "/platform/tenants/"+id, "err", "Could not save (is the name already used?).")
		return
	}
	s.a.Audit(withTenant(r.Context(), id), u.Email, "tenant.update", name+" status="+status)
	s.back(w, r, "/platform/tenants/"+id, "ok", "Tenant saved.")
}

func (s *server) tenantDelete(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	t, err := s.a.loadTenant(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if strings.TrimSpace(r.PostFormValue("confirm")) != t.Slug {
		s.back(w, r, "/platform/tenants/"+id, "err", "To delete a tenant, type its identifier ("+t.Slug+") in the confirmation box.")
		return
	}
	if err := s.a.DeleteTenant(r.Context(), id); err != nil {
		s.fail(w, r, u, err)
		return
	}
	s.a.Audit(r.Context(), u.Email, "tenant.delete", t.Name)
	s.back(w, r, "/platform", "ok", "Tenant "+t.Name+" and all of its data were deleted. Its nodes can no longer check in.")
}

// ---- membership (shared by the platform and tenant user pages) ----

var errMember = errors.New("invalid membership request")

// addMember grants a user a role in a tenant, creating a local account if the e-mail is new.
func (a *App) addMember(ctx context.Context, tenantID, email, name, password, role string) (created bool, err error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !strings.Contains(email, "@") || (role != RoleTenantAdmin && role != RoleReadOnly) {
		return false, errors.New("a valid e-mail address and role are required")
	}
	var uid string
	err = a.St.DB.QueryRow(ctx, `SELECT id::text FROM users WHERE email=$1`, email).Scan(&uid)
	if err != nil {
		hash, herr := hashPassword(password)
		if herr != nil {
			return false, errors.New("this e-mail has no account yet: set an initial password (" + herr.Error() + ")")
		}
		if err := a.St.DB.QueryRow(ctx, `INSERT INTO users(email,name,password_hash) VALUES($1,$2,$3) RETURNING id::text`, email, name, hash).Scan(&uid); err != nil {
			return false, err
		}
		created = true
	}
	_, err = a.St.DB.Exec(ctx, `INSERT INTO memberships(user_id,tenant_id,role,source) VALUES($1::uuid,$2::uuid,$3,'manual')
		ON CONFLICT (user_id,tenant_id) DO UPDATE SET role=EXCLUDED.role, source='manual'`, uid, tenantID, role)
	return created, err
}

func (s *server) memberAdd(w http.ResponseWriter, r *http.Request, u *User) {
	tid := r.PathValue("id")
	back := "/platform/tenants/" + tid
	created, err := s.a.addMember(r.Context(), tid, r.PostFormValue("email"), r.PostFormValue("name"), r.PostFormValue("password"), r.PostFormValue("role"))
	if err != nil {
		s.back(w, r, back, "err", err.Error())
		return
	}
	s.a.Audit(withTenant(r.Context(), tid), u.Email, "member.add", r.PostFormValue("email")+" "+r.PostFormValue("role"))
	msg := "Access granted."
	if created {
		msg = "User created and granted access."
	}
	s.back(w, r, back, "ok", msg)
}

func (s *server) memberRemove(w http.ResponseWriter, r *http.Request, u *User) {
	tid := r.PathValue("id")
	s.a.St.DB.Exec(r.Context(), `DELETE FROM memberships WHERE tenant_id=$1::uuid AND user_id=$2::uuid`, tid, r.PostFormValue("user"))
	s.a.Audit(withTenant(r.Context(), tid), u.Email, "member.remove", r.PostFormValue("user"))
	s.back(w, r, "/platform/tenants/"+tid, "ok", "Access removed.")
}

// ---- tenant administrators manage their own tenant's users ----

func (s *server) tenantUsers(w http.ResponseWriter, r *http.Request, u *User) {
	s.render(w, r, u, "tenant_users", page{"Title": "Users", "Members": s.members(r.Context(), u.Tenant.ID)})
}

func (s *server) tenantUserAdd(w http.ResponseWriter, r *http.Request, u *User) {
	created, err := s.a.addMember(r.Context(), u.Tenant.ID, r.PostFormValue("email"), r.PostFormValue("name"), r.PostFormValue("password"), r.PostFormValue("role"))
	if err != nil {
		s.back(w, r, "/users", "err", err.Error())
		return
	}
	s.a.Audit(r.Context(), u.Email, "member.add", r.PostFormValue("email")+" "+r.PostFormValue("role"))
	msg := "Access granted."
	if created {
		msg = "User created and granted access."
	}
	s.back(w, r, "/users", "ok", msg)
}

func (s *server) tenantUserUpdate(w http.ResponseWriter, r *http.Request, u *User) {
	uid, role := r.PostFormValue("user"), r.PostFormValue("role")
	if !isUUID(uid) {
		http.NotFound(w, r)
		return
	}
	if uid == u.ID && !u.IsGlobal() {
		s.back(w, r, "/users", "err", "You cannot change or remove your own access; ask another administrator.")
		return
	}
	if r.PostFormValue("remove") == "1" {
		s.a.St.DB.Exec(r.Context(), `DELETE FROM memberships WHERE tenant_id=$1::uuid AND user_id=$2::uuid`, u.Tenant.ID, uid)
		s.a.Audit(r.Context(), u.Email, "member.remove", uid)
		s.back(w, r, "/users", "ok", "Access removed.")
		return
	}
	if role != RoleTenantAdmin && role != RoleReadOnly {
		s.back(w, r, "/users", "err", "Invalid role.")
		return
	}
	s.a.St.DB.Exec(r.Context(), `UPDATE memberships SET role=$3, source='manual' WHERE tenant_id=$1::uuid AND user_id=$2::uuid`, u.Tenant.ID, uid, role)
	s.a.Audit(r.Context(), u.Email, "member.update", uid+" "+role)
	s.back(w, r, "/users", "ok", "Role updated.")
}

// ---- platform users ----

type userRow struct {
	ID, Email, Name, Platform string
	SSO, Disabled, TOTP       bool
	LastLogin                 *time.Time
	Tenants                   []string
}

func (s *server) platformUsers(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	rows, err := s.a.St.DB.Query(ctx, `SELECT u.id::text, u.email, u.name, u.platform_role, u.sso, u.disabled, u.totp_enabled, u.last_login,
		COALESCE((SELECT array_agg(t.name || ' (' || CASE m.role WHEN 'tenant_admin' THEN 'admin' ELSE 'read-only' END || ')' ORDER BY t.name) FROM memberships m JOIN tenants t ON t.id=m.tenant_id WHERE m.user_id=u.id),'{}')
		FROM users u WHERE u.email ILIKE '%'||$1||'%' OR u.name ILIKE '%'||$1||'%' ORDER BY u.email LIMIT 200`, q)
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	var users []userRow
	for rows.Next() {
		var x userRow
		rows.Scan(&x.ID, &x.Email, &x.Name, &x.Platform, &x.SSO, &x.Disabled, &x.TOTP, &x.LastLogin, &x.Tenants)
		users = append(users, x)
	}
	rows.Close()
	s.render(w, r, u, "platform_users", page{"Title": "Users", "Users": users, "Q": q})
}

func (s *server) platformUserCreate(w http.ResponseWriter, r *http.Request, u *User) {
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	role := r.PostFormValue("platform_role")
	if !strings.Contains(email, "@") || (role != "" && role != RoleGlobalAdmin && role != RoleGlobalReadonly) {
		s.back(w, r, "/platform/users", "err", "A valid e-mail address is required.")
		return
	}
	hash, err := hashPassword(r.PostFormValue("password"))
	if err != nil {
		s.back(w, r, "/platform/users", "err", err.Error())
		return
	}
	if _, err := s.a.St.DB.Exec(r.Context(), `INSERT INTO users(email,name,password_hash,platform_role) VALUES($1,$2,$3,$4)`, email, r.PostFormValue("name"), hash, role); err != nil {
		s.back(w, r, "/platform/users", "err", "Could not create user (already exists?).")
		return
	}
	s.a.Audit(r.Context(), u.Email, "user.create", email+" "+role)
	s.back(w, r, "/platform/users", "ok", "User created. Grant tenant access from the tenant's page.")
}

func (s *server) globalAdminCount(r *http.Request, excluding string) int {
	var n int
	s.a.St.DB.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE platform_role='global_admin' AND NOT disabled AND id::text<>$1`, excluding).Scan(&n)
	return n
}

func (s *server) platformUserUpdate(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	if !isUUID(id) {
		http.NotFound(w, r)
		return
	}
	role := r.PostFormValue("platform_role")
	disabled := r.PostFormValue("disabled") == "1"
	if role != "" && role != RoleGlobalAdmin && role != RoleGlobalReadonly {
		s.back(w, r, "/platform/users", "err", "Invalid role.")
		return
	}
	if (role != RoleGlobalAdmin || disabled) && s.globalAdminCount(r, id) == 0 {
		var current string
		s.a.St.DB.QueryRow(r.Context(), `SELECT platform_role FROM users WHERE id=$1::uuid`, id).Scan(&current)
		if current == RoleGlobalAdmin {
			s.back(w, r, "/platform/users", "err", "There must be at least one active global administrator.")
			return
		}
	}
	s.a.St.DB.Exec(r.Context(), `UPDATE users SET platform_role=$2, disabled=$3 WHERE id=$1::uuid`, id, role, disabled)
	if pw := r.PostFormValue("password"); pw != "" {
		h, err := hashPassword(pw)
		if err != nil {
			s.back(w, r, "/platform/users", "err", err.Error())
			return
		}
		s.a.St.DB.Exec(r.Context(), `UPDATE users SET password_hash=$2 WHERE id=$1::uuid AND NOT sso`, id, h)
	}
	if disabled || role == "" { // role changes take effect immediately
		s.a.St.DB.Exec(r.Context(), `UPDATE sessions SET expires_at=now() WHERE user_id=$1::uuid AND $2`, id, disabled)
	}
	s.a.Audit(r.Context(), u.Email, "user.update", id+" platform_role="+role)
	s.back(w, r, "/platform/users", "ok", "User updated.")
}

func (s *server) platformUserDelete(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	if !isUUID(id) || id == u.ID || s.globalAdminCount(r, id) == 0 {
		s.back(w, r, "/platform/users", "err", "You cannot delete yourself or the last global administrator.")
		return
	}
	s.a.St.DB.Exec(r.Context(), `DELETE FROM users WHERE id=$1::uuid`, id)
	s.a.Audit(r.Context(), u.Email, "user.delete", id)
	s.back(w, r, "/platform/users", "ok", "User deleted.")
}

func (s *server) platformAudit(w http.ResponseWriter, r *http.Request, u *User) {
	type row struct {
		Time                          time.Time
		Tenant, Actor, Action, Detail string
	}
	var out []row
	rows, _ := s.a.St.DB.Query(r.Context(), `SELECT a.ts, COALESCE(t.name,'(platform)'), a.actor, a.action, a.detail FROM audit a LEFT JOIN tenants t ON t.id=a.tenant_id ORDER BY a.id DESC LIMIT 500`)
	for rows.Next() {
		var x row
		rows.Scan(&x.Time, &x.Tenant, &x.Actor, &x.Action, &x.Detail)
		out = append(out, x)
	}
	rows.Close()
	s.render(w, r, u, "platform_audit", page{"Title": "Platform audit", "Rows": out})
}
