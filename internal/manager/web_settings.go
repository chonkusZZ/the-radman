package manager

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"radman/internal/pki"
)

func (s *server) settingsPage(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "general"
	}
	d := page{"Title": "Settings", "Tab": tab, "General": s.a.General(ctx), "UDPPort": s.a.quicPort}
	switch tab {
	case "webtls":
		t := s.a.WebTLSSettings(ctx)
		d["TLS"] = t
		d["Domains"] = strings.Join(t.Domains, ", ")
		d["CSR"] = s.a.PendingCSR(ctx)
		sub, na, names := s.a.WebCertInfo(ctx)
		d["CertSubject"], d["CertNotAfter"], d["CertNames"] = sub, na, strings.Join(names, ", ")
		d["CertFP"] = ""
		d["PublicHost"] = s.a.General(ctx).PublicHost
	case "branding":
		b := s.a.Branding(ctx)
		d["HasLogo"], d["LogoURL"], d["LogoVer"] = b.SVG != "", b.SourceURL, b.Version
	case "sso":
		d["SSO"] = s.a.SAMLSettings(ctx)
		d["BaseURL"] = s.a.baseURL(ctx)
		d["SSOMap"] = s.a.MapText(s.a.SAMLSettings(ctx))
	case "database":
		d["DB"] = s.a.DBHealth(ctx)
	}
	s.render(w, r, u, "settings", d)
}

func (s *server) settingsGeneral(w http.ResponseWriter, r *http.Request, u *User) {
	g := s.a.General(r.Context())
	host := strings.TrimSpace(r.PostFormValue("public_host"))
	if host == "" || strings.ContainsAny(host, " /:") && !strings.Contains(host, "::") {
		s.back(w, r, "/settings?tab=general", "err", "Enter a hostname or IP address only (no scheme or port).")
		return
	}
	atoi := func(k string, def, lo, hi int) int {
		n, err := strconv.Atoi(r.PostFormValue(k))
		if err != nil || n < lo || n > hi {
			return def
		}
		return n
	}
	changed := host != g.PublicHost
	g.PublicHost = host
	g.NodeIntervalSecs = atoi("node_interval_secs", g.NodeIntervalSecs, 10, 3600)
	g.EventRetentionDays = atoi("event_retention_days", g.EventRetentionDays, 1, 3650)
	g.CRLIntervalMins = atoi("crl_interval_mins", g.CRLIntervalMins, 5, 1440)
	g.EnrollTokenHours = atoi("enroll_token_hours", g.EnrollTokenHours, 1, 720)
	g.NodeCertDays = atoi("node_cert_days", g.NodeCertDays, 7, 825)
	g.NodeGraceDays = atoi("node_grace_days", g.NodeGraceDays, 0, 90)
	g.StatsRetentionDays = atoi("stats_retention_days", g.StatsRetentionDays, 30, 3650)
	if tz := strings.TrimSpace(r.PostFormValue("timezone")); tz != "" {
		if _, err := time.LoadLocation(tz); err != nil {
			s.back(w, r, "/settings?tab=general", "err", "Unknown time zone "+tz+" (use a name like Europe/London or UTC).")
			return
		}
		g.Timezone = tz
	}
	if err := s.a.SaveGeneral(r.Context(), g); err != nil {
		s.fail(w, r, u, err)
		return
	}
	if changed {
		s.a.ReloadWebTLS(r.Context())
	}
	s.a.Audit(r.Context(), u.Email, "settings.general", "")
	msg := "Settings saved."
	if changed {
		msg += " Hostname changed: nodes already enrolled keep working only if they can still reach the old name; the manager's node-channel certificate was re-issued for the new name."
	}
	s.back(w, r, "/settings?tab=general", "ok", msg)
}

func (s *server) settingsWebTLS(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	t := s.a.WebTLSSettings(ctx)
	switch r.PostFormValue("action") {
	case "selfsigned":
		t.Mode = "selfsigned"
		if r.PostFormValue("regenerate") == "1" {
			s.a.St.SetJSON(ctx, "webtls", t)
			s.a.RegenerateSelfSigned(ctx)
			s.a.Audit(ctx, u.Email, "webtls.selfsigned", "regenerated")
			s.back(w, r, "/settings?tab=webtls", "ok", "New self-signed certificate generated.")
			return
		}
	case "uploaded":
		if cp, _, _ := s.a.getPEM(ctx, "web_uploaded"); cp == nil {
			s.back(w, r, "/settings?tab=webtls", "err", "Upload a certificate first.")
			return
		}
		t.Mode = "uploaded"
	case "letsencrypt":
		var doms []string
		for _, d := range strings.FieldsFunc(r.PostFormValue("domains"), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
			doms = append(doms, strings.ToLower(d))
		}
		if len(doms) == 0 {
			s.back(w, r, "/settings?tab=webtls", "err", "Enter at least one public DNS name.")
			return
		}
		t.Mode, t.Domains, t.Email, t.Staging = "letsencrypt", doms, strings.TrimSpace(r.PostFormValue("email")), r.PostFormValue("staging") == "1"
	default:
		http.NotFound(w, r)
		return
	}
	if err := s.a.St.SetJSON(ctx, "webtls", t); err != nil {
		s.fail(w, r, u, err)
		return
	}
	if err := s.a.ReloadWebTLS(ctx); err != nil {
		s.fail(w, r, u, err)
		return
	}
	s.a.Audit(ctx, u.Email, "webtls.mode", t.Mode)
	msg := "Web certificate mode set to " + t.Mode + "."
	if t.Mode == "letsencrypt" {
		msg += " The certificate is requested on the first HTTPS connection to the domain (TLS-ALPN-01), so the manager must be reachable on public port 443. Until then the self-signed certificate is served."
	}
	s.back(w, r, "/settings?tab=webtls", "ok", msg)
}

func (s *server) settingsWebCSR(w http.ResponseWriter, r *http.Request, u *User) {
	cn := strings.TrimSpace(r.PostFormValue("cn"))
	if cn == "" {
		s.back(w, r, "/settings?tab=webtls", "err", "Common name is required.")
		return
	}
	var sans []string
	for _, d := range strings.FieldsFunc(r.PostFormValue("sans"), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		sans = append(sans, d)
	}
	if _, err := s.a.CreateWebCSR(r.Context(), cn, sans); err != nil {
		s.fail(w, r, u, err)
		return
	}
	s.a.Audit(r.Context(), u.Email, "webtls.csr", cn)
	s.back(w, r, "/settings?tab=webtls", "ok", "Certificate request generated. Submit it to your CA, then upload the issued certificate below.")
}

func (s *server) settingsWebCSRDownload(w http.ResponseWriter, r *http.Request, u *User) {
	csr := s.a.PendingCSR(r.Context())
	if csr == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pkcs10")
	w.Header().Set("Content-Disposition", `attachment; filename="radman-web.csr"`)
	w.Write([]byte(csr))
}

func (s *server) settingsWebUpload(w http.ResponseWriter, r *http.Request, u *User) {
	cert, key := strings.TrimSpace(r.PostFormValue("cert")), strings.TrimSpace(r.PostFormValue("key"))
	if cert == "" {
		s.back(w, r, "/settings?tab=webtls", "err", "Paste the certificate (with chain).")
		return
	}
	if err := s.a.InstallWebCert(r.Context(), []byte(cert), []byte(key)); err != nil {
		s.back(w, r, "/settings?tab=webtls", "err", err.Error())
		return
	}
	s.a.Audit(r.Context(), u.Email, "webtls.upload", "")
	s.back(w, r, "/settings?tab=webtls", "ok", "Certificate installed and now served by the web UI.")
}

var _ = pki.Fingerprint
