package manager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*.html
var tplFS embed.FS

//go:embed static/*
var staticFS embed.FS

const cookieName = "rh_sid"

type User struct {
	ID, Email, Name, Platform string
	TOTPEnabled, SSO          bool
	CSRF                      string
	Member                    map[string]string // tenant id -> tenant_admin | read_only
	Tenant                    *Tenant           // tenant context of this request (nil = platform view)
}

// RoleLabel is the user's headline role for display.
func (u *User) RoleLabel() string {
	switch u.Platform {
	case RoleGlobalAdmin:
		return "Global administrator"
	case RoleGlobalReadonly:
		return "Global read-only"
	}
	if u.Tenant != nil {
		return map[string]string{RoleTenantAdmin: "Tenant administrator", RoleReadOnly: "Read-only"}[u.Member[u.Tenant.ID]]
	}
	return "Tenant user"
}

type page map[string]any

func (a *App) templates() map[string]*template.Template {
	funcs := template.FuncMap{
		"fmtTime": func(t any) string {
			switch v := t.(type) {
			case time.Time:
				if v.IsZero() {
					return "—"
				}
				return v.Local().Format("2006-01-02 15:04:05")
			case *time.Time:
				if v == nil || v.IsZero() {
					return "—"
				}
				return v.Local().Format("2006-01-02 15:04:05")
			}
			return "—"
		},
		"ago": func(t *time.Time) string {
			if t == nil {
				return "never"
			}
			d := time.Since(*t)
			switch {
			case d < 90*time.Second:
				return fmt.Sprintf("%ds ago", int(d.Seconds()))
			case d < 90*time.Minute:
				return fmt.Sprintf("%dm ago", int(d.Minutes()))
			case d < 48*time.Hour:
				return fmt.Sprintf("%dh ago", int(d.Hours()))
			}
			return fmt.Sprintf("%dd ago", int(d.Hours()/24))
		},
		"join":      strings.Join,
		"hasPrefix": strings.HasPrefix,
		"daysUntil": func(t *time.Time) int {
			if t == nil {
				return 0
			}
			return int(time.Until(*t).Hours() / 24)
		},
		"add": func(a, b int) int { return a + b },
		"seq": func(n int) []int {
			out := make([]int, n)
			for i := range out {
				out[i] = i + 1
			}
			return out
		},
		"bytes": func(v any) string {
			var n float64
			switch x := v.(type) {
			case int64:
				n = float64(x)
			case *int64:
				if x != nil {
					n = float64(*x)
				}
			case int:
				n = float64(x)
			}
			for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
				if n < 1024 || u == "TB" {
					if u == "B" {
						return fmt.Sprintf("%.0f B", n)
					}
					return fmt.Sprintf("%.1f %s", n, u)
				}
				n /= 1024
			}
			return ""
		},
	}
	out := map[string]*template.Template{}
	base := template.Must(template.New("base").Funcs(funcs).ParseFS(tplFS, "templates/base.html"))
	entries, _ := fs.ReadDir(tplFS, "templates")
	for _, e := range entries {
		if e.Name() == "base.html" {
			continue
		}
		t := template.Must(template.Must(base.Clone()).ParseFS(tplFS, "templates/"+e.Name()))
		out[strings.TrimSuffix(e.Name(), ".html")] = t
	}
	return out
}

type server struct {
	a   *App
	tpl map[string]*template.Template
	mux *http.ServeMux
}

func (a *App) NewHandler() http.Handler {
	s := &server{a: a, tpl: a.templates(), mux: http.NewServeMux()}
	s.routes()
	sub, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(sub)))
	return securityHeaders(s.mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "same-origin")
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self' https:")
		hd.Set("Strict-Transport-Security", "max-age=31536000")
		h.ServeHTTP(w, r)
	})
}

// ---- sessions ----

func hashSID(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func (a *App) newSession(ctx context.Context, w http.ResponseWriter, userID string) error {
	sid := randToken(32)
	// a user with exactly one accessible tenant lands in it
	var only *string
	a.St.DB.QueryRow(ctx, `SELECT CASE WHEN (SELECT count(*) FROM memberships WHERE user_id::text=$1)=1 AND (SELECT platform_role FROM users WHERE id::text=$1)=''
		THEN (SELECT tenant_id::text FROM memberships WHERE user_id::text=$1) END`, userID).Scan(&only)
	_, err := a.St.DB.Exec(ctx, `INSERT INTO sessions(id,user_id,csrf,tenant_id,expires_at) VALUES($1,$2,$3,$4::uuid,now()+interval '12 hours')`, hashSID(sid), userID, randToken(18), only)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sid, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 12 * 3600})
	return nil
}

func (a *App) userFromRequest(r *http.Request) *User {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	u := &User{Member: map[string]string{}}
	var tid *string
	err = a.St.DB.QueryRow(r.Context(), `SELECT u.id::text, u.email, u.name, u.platform_role, u.totp_enabled, u.sso, s.csrf, s.tenant_id::text
		FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.expires_at>now() AND NOT u.disabled`, hashSID(c.Value)).
		Scan(&u.ID, &u.Email, &u.Name, &u.Platform, &u.TOTPEnabled, &u.SSO, &u.CSRF, &tid)
	if err != nil {
		return nil
	}
	rows, _ := a.St.DB.Query(r.Context(), `SELECT tenant_id::text, role FROM memberships WHERE user_id::text=$1`, u.ID)
	for rows.Next() {
		var t, role string
		rows.Scan(&t, &role)
		u.Member[t] = role
	}
	rows.Close()
	if a.Standalone() {
		// a single implicit tenant: no switching, no per-tenant states
		if u.CanRead(a.solo.ID) {
			t := *a.solo
			u.Tenant = &t
		}
		return u
	}
	if tid != nil && u.CanRead(*tid) {
		if t, err := a.loadTenant(r.Context(), *tid); err == nil {
			u.Tenant = t
		}
	}
	return u
}

type handler func(w http.ResponseWriter, r *http.Request, u *User)

// perm is the permission a route demands.
type perm int

const (
	pAny           perm = iota // any signed-in user
	pTenantRead                // read access in the current tenant
	pTenantWrite               // write access in the current tenant
	pPlatformRead              // global administrator or global read-only
	pPlatformWrite             // global administrator
)

// auth wraps a handler with login, permission and CSRF enforcement.
func (s *server) auth(p perm, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.a.Setup != "" {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		u := s.a.userFromRequest(r)
		if u == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			var perr error
			if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
				r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
				perr = r.ParseMultipartForm(1 << 20)
			} else {
				perr = r.ParseForm()
			}
			if perr != nil || subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(u.CSRF)) != 1 {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		if !s.permitted(w, r, u, p) {
			return
		}
		if u.Tenant != nil {
			r = r.WithContext(withTenant(r.Context(), u.Tenant.ID))
		}
		h(w, r, u)
	}
}

func (s *server) forbidden(w http.ResponseWriter, r *http.Request, u *User, msg string) {
	s.render(w, r, u, "error", page{"Title": "Forbidden", "Msg": msg}, http.StatusForbidden)
}

func (s *server) permitted(w http.ResponseWriter, r *http.Request, u *User, p perm) bool {
	switch p {
	case pAny:
		return true
	case pPlatformRead:
		if u.IsGlobal() {
			return true
		}
	case pPlatformWrite:
		if u.IsGlobalAdmin() {
			return true
		}
	case pTenantRead, pTenantWrite:
		if u.Tenant == nil {
			if s.a.Standalone() {
				s.forbidden(w, r, u, "You do not have access to this installation.")
				return false
			}
			s.back(w, r, "/", "err", "Choose a tenant first.")
			return false
		}
		if p == pTenantRead && u.CanRead(u.Tenant.ID) {
			return true
		}
		if p == pTenantWrite {
			if u.CanWrite(u.Tenant) {
				return true
			}
			if u.RoleIn(u.Tenant.ID) == RoleTenantAdmin && u.Tenant.Suspended() {
				s.forbidden(w, r, u, "This tenant is suspended; changes are disabled. Contact your service provider.")
				return false
			}
		}
	}
	s.forbidden(w, r, u, "You do not have permission to do that.")
	return false
}

// res protects routes addressed by a resource id ({id} in the path). The resource's tenant is looked up and the
// user's access to *that* tenant is checked, so an id from another tenant is indistinguishable from a missing one.
func (s *server) res(kind string, write bool, h handler) http.HandlerFunc {
	return s.auth(pAny, func(w http.ResponseWriter, r *http.Request, u *User) {
		id := r.PathValue("id")
		tid, err := s.a.resourceTenant(r.Context(), kind, id)
		if err != nil || !u.CanRead(tid) {
			s.render(w, r, u, "error", page{"Title": "Not found", "Msg": "Not found."}, http.StatusNotFound)
			return
		}
		t, err := s.a.loadTenant(r.Context(), tid)
		if err != nil {
			s.render(w, r, u, "error", page{"Title": "Not found", "Msg": "Not found."}, http.StatusNotFound)
			return
		}
		u.Tenant = t
		if write && !u.CanWrite(t) {
			msg := "You do not have permission to change this."
			if u.RoleIn(t.ID) == RoleTenantAdmin && t.Suspended() {
				msg = "This tenant is suspended; changes are disabled."
			}
			s.forbidden(w, r, u, msg)
			return
		}
		h(w, r.WithContext(withTenant(r.Context(), tid)), u)
	})
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func isUUID(s string) bool { return uuidRe.MatchString(s) }

// resourceTenant maps a resource id to its owning tenant.
func (a *App) resourceTenant(ctx context.Context, kind, id string) (string, error) {
	if !isUUID(id) {
		return "", pgx.ErrNoRows
	}
	q := map[string]string{
		"site":   `SELECT tenant_id::text FROM sites WHERE id=$1::uuid`,
		"ap":     `SELECT s.tenant_id::text FROM aps a JOIN sites s ON s.id=a.site_id WHERE a.id=$1::uuid`,
		"node":   `SELECT s.tenant_id::text FROM nodes n JOIN sites s ON s.id=n.site_id WHERE n.id=$1::uuid`,
		"pki":    `SELECT tenant_id::text FROM pki_profiles WHERE id=$1::uuid`,
		"eap":    `SELECT tenant_id::text FROM eap_certs WHERE id=$1::uuid`,
		"radsec": `SELECT s.tenant_id::text FROM radsec_certs c JOIN aps a ON a.id=c.ap_id JOIN sites s ON s.id=a.site_id WHERE c.id=$1::uuid`,
		"tenant": `SELECT id::text FROM tenants WHERE id=$1::uuid`,
	}[kind]
	var tid string
	err := a.St.DB.QueryRow(ctx, q, id).Scan(&tid)
	return tid, err
}

// ---- rendering ----

func (s *server) flash(w http.ResponseWriter, kind, msg string) {
	http.SetCookie(w, &http.Cookie{Name: "rh_flash", Value: kind + "|" + hex.EncodeToString([]byte(msg)), Path: "/", MaxAge: 30, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func (s *server) render(w http.ResponseWriter, r *http.Request, u *User, name string, d page, status ...int) {
	if d == nil {
		d = page{}
	}
	d["User"] = u
	d["Version"] = s.a.Opt.Version
	d["Standalone"] = s.a.Standalone()
	if b := s.a.Branding(r.Context()); b.SVG != "" {
		d["Logo"], d["LogoVer"] = true, b.Version
	}
	d["Path"] = r.URL.Path
	if u != nil {
		d["CSRF"] = u.CSRF
		d["CanWrite"] = u.CanWrite(u.Tenant)
		d["IsGlobalAdmin"] = u.IsGlobalAdmin()
		d["IsGlobal"] = u.IsGlobal()
		d["Tenant"] = u.Tenant
		d["RoleLabel"] = u.RoleLabel()
		if s.a.Standalone() {
			d["RoleLabel"] = soloLabel(soloRoleOf(u.Platform, u.Member[s.a.solo.ID]))
		}
		d["Suspended"] = u.Tenant.Suspended()
	}
	if c, err := r.Cookie("rh_flash"); err == nil {
		if k, m, ok := strings.Cut(c.Value, "|"); ok {
			if b, err := hex.DecodeString(m); err == nil {
				d["Flash"], d["FlashKind"] = string(b), k
			}
		}
		http.SetCookie(w, &http.Cookie{Name: "rh_flash", Path: "/", MaxAge: -1})
	}
	t, ok := s.tpl[name]
	if !ok {
		http.Error(w, "template missing: "+name, 500)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", d); err != nil {
		s.a.Log.Printf("render %s: %v", name, err)
		http.Error(w, "render error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if len(status) > 0 {
		w.WriteHeader(status[0])
	}
	w.Write(buf.Bytes())
}

func (s *server) fail(w http.ResponseWriter, r *http.Request, u *User, err error) {
	code := 500
	msg := "Something went wrong."
	if errors.Is(err, pgx.ErrNoRows) {
		code, msg = 404, "Not found."
	} else {
		s.a.Log.Printf("%s %s: %v", r.Method, r.URL.Path, err)
	}
	s.render(w, r, u, "error", page{"Title": "Error", "Msg": msg}, code)
}

// back redirects with a flash message.
func (s *server) back(w http.ResponseWriter, r *http.Request, to, kind, msg string) {
	s.flash(w, kind, msg)
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func checkPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func hashPassword(pw string) (string, error) {
	if len(pw) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

// ---- servers ----

// Run starts the HTTPS UI, optional HTTP redirect, QUIC node server and background jobs. Blocks until ctx ends.
func (a *App) Run(ctx context.Context) error {
	if err := a.ReloadWebTLS(ctx); err != nil {
		return err
	}
	go a.crlLoop(ctx)
	go a.maintenanceLoop(ctx)
	errc := make(chan error, 3)
	go func() { errc <- a.ServeNodes(ctx) }()

	h := a.NewHandler()
	srv := &http.Server{
		Addr: a.Opt.HTTPSAddr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 120 * time.Second,
		TLSConfig: &tls.Config{GetCertificate: a.web.GetCertificate, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1", acme.ALPNProto}},
	}
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	a.Log.Printf("web UI on https://%s", a.Opt.HTTPSAddr)
	if a.Opt.HTTPAddr != "" {
		redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a.web.mu.RLock()
			auto := a.web.auto
			a.web.mu.RUnlock()
			if auto != nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
				auto.HTTPHandler(nil).ServeHTTP(w, r)
				return
			}
			host := hostOnly(r.Host)
			target := "https://" + host
			if _, port, ok := strings.Cut(a.Opt.HTTPSAddr, ":"); ok && port != "443" {
				target += ":" + port
			}
			http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusMovedPermanently)
		})
		go func() {
			errc <- (&http.Server{Addr: a.Opt.HTTPAddr, Handler: redirect, ReadHeaderTimeout: 10 * time.Second}).ListenAndServe()
		}()
	}
	if a.Setup != "" {
		a.Log.Printf("FIRST RUN: open the web UI and complete setup with this one-time token: %s", a.Setup)
	}
	select {
	case <-ctx.Done():
		sc, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		return srv.Shutdown(sc)
	case err := <-errc:
		return err
	}
}

func (a *App) maintenanceLoop(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		// exactly one manager instance performs housekeeping at a time
		a.runExclusive(ctx, lockMaintenance, func(ctx context.Context) {
			days := a.General(ctx).EventRetentionDays
			if err := a.ensurePartitions(ctx); err != nil {
				a.Log.Printf("partitions: %v", err)
			}
			if dropped, err := a.dropOldPartitions(ctx, days); err != nil {
				a.Log.Printf("retention: %v", err)
			} else if len(dropped) > 0 {
				a.Log.Printf("retention: dropped %v", dropped)
			}
			a.purgeStats(ctx, a.General(ctx).StatsRetentionDays)
			a.St.DB.Exec(ctx, `DELETE FROM audit WHERE ts < now() - interval '365 days'`)
			a.St.DB.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
			a.renewInternalEAPCerts(ctx)
			a.cleanupLogBundles(ctx)
		})
		a.refreshQUICCert(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
