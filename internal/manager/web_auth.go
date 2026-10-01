package manager

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"image/png"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// ---- first-run setup ----

func (s *server) setupPage(w http.ResponseWriter, r *http.Request) {
	if s.a.Setup == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, nil, "setup", page{"Title": "Setup", "Host": hostOnly(r.Host)})
}

func (s *server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	a := s.a
	if a.Setup == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	redo := func(msg string) {
		s.render(w, r, nil, "setup", page{"Title": "Setup", "Host": r.PostFormValue("host"), "Err": msg, "Email": r.PostFormValue("email"), "Name": r.PostFormValue("name")})
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(r.PostFormValue("token"))), []byte(a.Setup)) != 1 {
		redo("Setup token is wrong. It is printed in the manager's console/log output.")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	host := strings.TrimSpace(r.PostFormValue("host"))
	if !strings.Contains(email, "@") || host == "" {
		redo("A valid e-mail and the public hostname are required.")
		return
	}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("password2") {
		redo("Passwords do not match.")
		return
	}
	hash, err := hashPassword(pw)
	if err != nil {
		redo(err.Error())
		return
	}
	ctx := r.Context()
	if _, err := a.St.DB.Exec(ctx, `INSERT INTO users(email,name,password_hash,platform_role) VALUES($1,$2,$3,'global_admin')`, email, r.PostFormValue("name"), hash); err != nil {
		redo("Could not create user: " + err.Error())
		return
	}
	g := a.General(ctx)
	g.PublicHost = host
	if err := a.SaveGeneral(ctx, g); err != nil {
		redo(err.Error())
		return
	}
	a.ReloadWebTLS(ctx)
	a.Setup = ""
	a.Audit(ctx, email, "setup.complete", "initial global administrator created")
	s.flash(w, "ok", "Setup complete. Sign in with your new administrator account.")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- login ----

var dummyHash, _ = hashPassword("dummy-password-for-timing")

func clientIP(r *http.Request) string {
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	return h
}

func (a *App) throttled(key string) bool {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	var keep []time.Time
	for _, t := range a.loginErr[key] {
		if time.Since(t) < 10*time.Minute {
			keep = append(keep, t)
		}
	}
	a.loginErr[key] = keep
	return len(keep) >= 5
}

func (a *App) noteFailure(key string) {
	a.loginMu.Lock()
	a.loginErr[key] = append(a.loginErr[key], time.Now())
	a.loginMu.Unlock()
}

func (s *server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.a.Setup != "" {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if s.a.userFromRequest(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, nil, "login", s.loginData(r, nil))
}

func (s *server) loginData(r *http.Request, extra page) page {
	sso := s.a.SAMLSettings(r.Context())
	d := page{"Title": "Sign in", "SSO": sso.Enabled && sso.configured(), "Local": !sso.Enabled || sso.AllowLocal}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

func (s *server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	a := s.a
	r.ParseForm()
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	key := email + "|" + clientIP(r)
	again := func(msg string, totp bool) {
		s.render(w, r, nil, "login", s.loginData(r, page{"Err": msg, "Email": email, "NeedTOTP": totp}), http.StatusUnauthorized)
	}
	if a.throttled(key) {
		again("Too many failed attempts. Try again in a few minutes.", false)
		return
	}
	sso := a.SAMLSettings(r.Context())
	if sso.Enabled && !sso.AllowLocal {
		again("Local sign-in is disabled; use single sign-on.", false)
		return
	}
	var id, hash, secret string
	var enabled, ssoUser, disabled bool
	err := a.St.DB.QueryRow(r.Context(), `SELECT id::text, password_hash, totp_secret, totp_enabled, sso, disabled FROM users WHERE email=$1`, email).Scan(&id, &hash, &secret, &enabled, &ssoUser, &disabled)
	if err != nil || ssoUser || disabled || hash == "" || !checkPassword(hash, r.PostFormValue("password")) {
		if err != nil {
			checkPassword(dummyHash, "x") // equalise timing between unknown users and wrong passwords
		}
		a.noteFailure(key)
		a.Audit(r.Context(), email, "login.failed", clientIP(r))
		again("Invalid e-mail or password.", false)
		return
	}
	if a.localLoginBlocked(r.Context(), id) {
		a.Audit(r.Context(), email, "login.blocked", "local sign-in disabled: organisation requires SSO")
		again("Your organisation requires single sign-on. Use your organisation's sign-in link.", false)
		return
	}
	if enabled {
		code := strings.TrimSpace(r.PostFormValue("code"))
		sec, _ := a.open(secret)
		if code == "" {
			again("Enter the 6-digit code from your authenticator app.", true)
			return
		}
		if !totp.Validate(code, sec) {
			a.noteFailure(key)
			again("Invalid authentication code.", true)
			return
		}
	}
	a.St.DB.Exec(r.Context(), `UPDATE users SET last_login=now() WHERE id=$1::uuid`, id)
	if err := a.newSession(r.Context(), w, id); err != nil {
		s.fail(w, r, nil, err)
		return
	}
	a.Audit(r.Context(), email, "login", clientIP(r))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request, u *User) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.a.St.DB.Exec(r.Context(), `DELETE FROM sessions WHERE id=$1`, hashSID(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- account ----

func (s *server) accountPage(w http.ResponseWriter, r *http.Request, u *User) {
	s.render(w, r, u, "account", page{"Title": "My account"})
}

func (s *server) accountPassword(w http.ResponseWriter, r *http.Request, u *User) {
	if u.SSO {
		s.back(w, r, "/account", "err", "Your password is managed by your identity provider.")
		return
	}
	var hash string
	s.a.St.DB.QueryRow(r.Context(), `SELECT password_hash FROM users WHERE id=$1::uuid`, u.ID).Scan(&hash)
	if !checkPassword(hash, r.PostFormValue("current")) {
		s.back(w, r, "/account", "err", "Current password is wrong.")
		return
	}
	if r.PostFormValue("new") != r.PostFormValue("new2") {
		s.back(w, r, "/account", "err", "New passwords do not match.")
		return
	}
	nh, err := hashPassword(r.PostFormValue("new"))
	if err != nil {
		s.back(w, r, "/account", "err", err.Error())
		return
	}
	s.a.St.DB.Exec(r.Context(), `UPDATE users SET password_hash=$2 WHERE id=$1::uuid`, u.ID, nh)
	s.a.Audit(r.Context(), u.Email, "account.password", "")
	s.back(w, r, "/account", "ok", "Password changed.")
}

func (s *server) totpEnable(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	if u.SSO {
		s.back(w, r, "/account", "err", "Two-factor is handled by your identity provider.")
		return
	}
	var enc string
	s.a.St.DB.QueryRow(ctx, `SELECT totp_secret FROM users WHERE id=$1::uuid`, u.ID).Scan(&enc)
	code := strings.TrimSpace(r.PostFormValue("code"))
	if code != "" && enc != "" {
		sec, _ := s.a.open(enc)
		if totp.Validate(code, sec) {
			s.a.St.DB.Exec(ctx, `UPDATE users SET totp_enabled=true WHERE id=$1::uuid`, u.ID)
			s.a.Audit(ctx, u.Email, "account.totp_enabled", "")
			s.back(w, r, "/account", "ok", "Two-factor authentication enabled.")
			return
		}
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "arc's The RadMAN", AccountName: u.Email})
	if enc != "" && code != "" { // wrong code: keep the same secret so the QR already scanned still works
		sec, _ := s.a.open(enc)
		key, err = otpFromSecret(u.Email, sec)
	} else if err == nil {
		s.a.St.DB.Exec(ctx, `UPDATE users SET totp_secret=$2 WHERE id=$1::uuid`, u.ID, s.a.seal(key.Secret()))
	}
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	img, _ := key.Image(200, 200)
	var buf bytes.Buffer
	png.Encode(&buf, img)
	d := page{"Title": "My account", "TOTPSetup": true, "Secret": key.Secret(), "QR": "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())}
	if code != "" {
		d["Flash"], d["FlashKind"] = "That code was not valid, try again.", "err"
	}
	s.render(w, r, u, "account", d)
}

func (s *server) totpDisable(w http.ResponseWriter, r *http.Request, u *User) {
	var hash string
	s.a.St.DB.QueryRow(r.Context(), `SELECT password_hash FROM users WHERE id=$1::uuid`, u.ID).Scan(&hash)
	if !checkPassword(hash, r.PostFormValue("current")) {
		s.back(w, r, "/account", "err", "Password is wrong.")
		return
	}
	s.a.St.DB.Exec(r.Context(), `UPDATE users SET totp_enabled=false, totp_secret='' WHERE id=$1::uuid`, u.ID)
	s.a.Audit(r.Context(), u.Email, "account.totp_disabled", "")
	s.back(w, r, "/account", "ok", "Two-factor authentication disabled.")
}
