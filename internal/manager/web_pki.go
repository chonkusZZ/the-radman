package manager

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"radman/internal/crl"
	"radman/internal/pki"
)

type pkiRow struct {
	ID, Name, Kind, StalePolicy string
	Sites                       int
	CAs                         []string
	URLs                        []string
}

type crlRow struct {
	URL, Err            string
	Fetched, NextUpdate *time.Time
	Revoked             int
	Stale               bool
}

func (s *server) pkiList(w http.ResponseWriter, r *http.Request, u *User) {
	rows, err := s.a.St.DB.Query(r.Context(), `SELECT p.id::text, p.name, p.kind, p.stale_policy, p.ca_pem, p.crl_urls, (SELECT count(*) FROM site_pki WHERE pki_id=p.id) FROM pki_profiles p WHERE p.tenant_id=$1::uuid ORDER BY p.name`, u.Tenant.ID)
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	var list []pkiRow
	for rows.Next() {
		var x pkiRow
		var pem string
		rows.Scan(&x.ID, &x.Name, &x.Kind, &x.StalePolicy, &pem, &x.URLs, &x.Sites)
		if cs, err := pki.ParseCerts([]byte(pem)); err == nil {
			for _, c := range cs {
				x.CAs = append(x.CAs, c.Subject.CommonName)
			}
		}
		list = append(list, x)
	}
	rows.Close()
	s.render(w, r, u, "pkis", page{"Title": "PKI profiles", "PKIs": list, "P": pkiRow{}, "PEM": "", "URLText": ""})
}

// parsePKIForm validates and normalises the PKI form fields.
func (s *server) parsePKIForm(r *http.Request) (name, kind, caPEM string, urls []string, stale string, grace int, err error) {
	name, kind = strings.TrimSpace(r.PostFormValue("name")), r.PostFormValue("kind")
	if kind != "azure" {
		kind = "generic"
	}
	caPEM = strings.TrimSpace(r.PostFormValue("ca_pem"))
	if name == "" {
		err = errMsg("A name is required.")
		return
	}
	cs, perr := pki.ParseCerts([]byte(caPEM))
	if perr != nil {
		err = errMsg("CA certificates: " + perr.Error())
		return
	}
	hasCA := false
	for _, c := range cs {
		if c.IsCA {
			hasCA = true
		}
	}
	if !hasCA {
		err = errMsg("None of the supplied certificates is a CA certificate. Paste the root and issuing CA certificates (public parts only).")
		return
	}
	caPEM = ""
	for _, c := range cs {
		caPEM += string(pki.EncodeCert(c.Raw))
	}
	for _, l := range strings.FieldsFunc(r.PostFormValue("crl_urls"), func(r rune) bool { return r == '\n' || r == ',' || r == ' ' || r == '\r' }) {
		if !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") {
			err = errMsg("CRL URLs must start with http:// or https://")
			return
		}
		urls = append(urls, l)
	}
	if sample := strings.TrimSpace(r.PostFormValue("sample_cert")); sample != "" {
		found, derr := crl.CDPFromPEM([]byte(sample))
		if derr != nil {
			err = errMsg("Sample certificate could not be read.")
			return
		}
		for _, f := range found {
			if strings.HasPrefix(f, "http") && !contains(urls, f) {
				urls = append(urls, f)
			}
		}
	}
	stale = r.PostFormValue("stale_policy")
	if stale != "fail_open" {
		stale = "fail_closed"
	}
	grace, _ = strconv.Atoi(r.PostFormValue("stale_grace_hours"))
	if grace < 0 || grace > 24*30 {
		grace = 24
	}
	return
}

type errMsg string

func (e errMsg) Error() string { return string(e) }

func (s *server) pkiCreate(w http.ResponseWriter, r *http.Request, u *User) {
	name, kind, ca, urls, stale, grace, err := s.parsePKIForm(r)
	if err != nil {
		s.back(w, r, "/pki", "err", err.Error())
		return
	}
	var id string
	if err := s.a.St.DB.QueryRow(r.Context(), `INSERT INTO pki_profiles(tenant_id,name,kind,ca_pem,crl_urls,stale_policy,stale_grace_hours) VALUES($1::uuid,$2,$3,$4,$5,$6,$7) RETURNING id::text`,
		u.Tenant.ID, name, kind, ca, urls, stale, grace).Scan(&id); err != nil {
		s.back(w, r, "/pki", "err", "Could not save (duplicate name?).")
		return
	}
	for _, url := range urls {
		go func(url string) { s.a.RefreshCRL(r.Context(), url) }(url)
	}
	s.a.Audit(r.Context(), u.Email, "pki.create", name)
	s.back(w, r, "/pki/"+id, "ok", "PKI profile created. Attach it to a site to start accepting its certificates.")
}

func (s *server) pkiDetail(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	id := r.PathValue("id")
	var x pkiRow
	var pem, notes string
	var grace int
	err := s.a.St.DB.QueryRow(ctx, `SELECT id::text, name, kind, stale_policy, ca_pem, crl_urls, stale_grace_hours, notes FROM pki_profiles WHERE id=$1::uuid`, id).
		Scan(&x.ID, &x.Name, &x.Kind, &x.StalePolicy, &pem, &x.URLs, &grace, &notes)
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	type caRow struct {
		Subject, Issuer, Serial, FP string
		NotAfter                    time.Time
		Root                        bool
	}
	var cas []caRow
	if cs, err := pki.ParseCerts([]byte(pem)); err == nil {
		for _, c := range cs {
			cas = append(cas, caRow{c.Subject.CommonName, c.Issuer.CommonName, pki.SerialHex(c), pki.Fingerprint(c), c.NotAfter, string(c.RawSubject) == string(c.RawIssuer)})
		}
	}
	var crls []crlRow
	for _, url := range x.URLs {
		c := crlRow{URL: url}
		s.a.St.DB.QueryRow(ctx, `SELECT fetched_at, next_update, revoked_count, last_error FROM crl_cache WHERE url=$1`, url).Scan(&c.Fetched, &c.NextUpdate, &c.Revoked, &c.Err)
		c.Stale = c.NextUpdate != nil && time.Now().After(*c.NextUpdate)
		crls = append(crls, c)
	}
	var sites []string
	rows, _ := s.a.St.DB.Query(ctx, `SELECT s.name FROM sites s JOIN site_pki sp ON sp.site_id=s.id WHERE sp.pki_id=$1::uuid AND s.tenant_id=$2::uuid ORDER BY s.name`, id, u.Tenant.ID)
	for rows.Next() {
		var n string
		rows.Scan(&n)
		sites = append(sites, n)
	}
	rows.Close()
	s.render(w, r, u, "pki", page{"Title": x.Name, "P": x, "CAs": cas, "CRLs": crls, "PEM": pem, "Grace": grace, "Sites": sites,
		"URLText": strings.Join(x.URLs, "\n")})
}

func (s *server) pkiUpdate(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	name, kind, ca, urls, stale, grace, err := s.parsePKIForm(r)
	if err != nil {
		s.back(w, r, "/pki/"+id, "err", err.Error())
		return
	}
	if _, err := s.a.St.DB.Exec(r.Context(), `UPDATE pki_profiles SET name=$2, kind=$3, ca_pem=$4, crl_urls=$5, stale_policy=$6, stale_grace_hours=$7 WHERE id=$1::uuid`,
		id, name, kind, ca, urls, stale, grace); err != nil {
		s.back(w, r, "/pki/"+id, "err", "Could not save: "+err.Error())
		return
	}
	for _, url := range urls {
		go s.a.RefreshCRL(context_bg(), url)
	}
	s.a.Audit(r.Context(), u.Email, "pki.update", name)
	s.back(w, r, "/pki/"+id, "ok", "PKI profile saved.")
}

func (s *server) pkiDelete(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	if _, err := s.a.St.DB.Exec(r.Context(), `DELETE FROM pki_profiles WHERE id=$1::uuid`, id); err != nil {
		s.back(w, r, "/pki/"+id, "err", "Profile is still used by a site. Detach it first.")
		return
	}
	s.a.Audit(r.Context(), u.Email, "pki.delete", id)
	s.back(w, r, "/pki", "ok", "PKI profile deleted.")
}

func (s *server) pkiRefresh(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	var urls []string
	s.a.St.DB.QueryRow(r.Context(), `SELECT crl_urls FROM pki_profiles WHERE id=$1::uuid`, id).Scan(&urls)
	var errs []string
	for _, url := range urls {
		if err := s.a.RefreshCRL(r.Context(), url); err != nil {
			errs = append(errs, url+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		s.back(w, r, "/pki/"+id, "err", strings.Join(errs, "; "))
		return
	}
	s.back(w, r, "/pki/"+id, "ok", "CRLs refreshed.")
}

// ---- EAP server certificates ----

func (s *server) eapList(w http.ResponseWriter, r *http.Request, u *User) {
	type row struct {
		ID, Name, Source string
		NotAfter         time.Time
		DNS              []string
		Sites            []string
	}
	var list []row
	rows, err := s.a.St.DB.Query(r.Context(), `SELECT id::text, name, source, not_after, dns_names FROM eap_certs WHERE tenant_id=$1::uuid ORDER BY name`, u.Tenant.ID)
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	for rows.Next() {
		var x row
		rows.Scan(&x.ID, &x.Name, &x.Source, &x.NotAfter, &x.DNS)
		list = append(list, x)
	}
	rows.Close()
	for i := range list {
		sr, _ := s.a.St.DB.Query(r.Context(), `SELECT name FROM sites WHERE eap_cert_id=$1::uuid`, list[i].ID)
		for sr.Next() {
			var n string
			sr.Scan(&n)
			list[i].Sites = append(list[i].Sites, n)
		}
		sr.Close()
	}
	caPEM, _ := s.a.tenantCAPEM(r.Context(), u.Tenant.ID, "eap")
	fp, _ := pki.FingerprintPEM(caPEM)
	s.render(w, r, u, "eapcerts", page{"Title": "Server certificates", "Certs": list, "CAFP": fp})
}

func (s *server) eapCAPEM(w http.ResponseWriter, r *http.Request, u *User) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="radman-eap-ca.pem"`)
	pem, err := s.a.tenantCAPEM(r.Context(), u.Tenant.ID, "eap")
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	w.Write(pem)
}

func (s *server) eapCreateInternal(w http.ResponseWriter, r *http.Request, u *User) {
	name, cn := strings.TrimSpace(r.PostFormValue("name")), strings.TrimSpace(r.PostFormValue("cn"))
	if name == "" || cn == "" {
		s.back(w, r, "/eapcerts", "err", "Name and server name are required.")
		return
	}
	var dns []string
	for _, d := range strings.FieldsFunc(r.PostFormValue("dns"), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		dns = append(dns, d)
	}
	dns = append([]string{cn}, dns...)
	if _, err := s.a.CreateInternalEAPCert(r.Context(), u.Tenant.ID, name, cn, dns); err != nil {
		s.back(w, r, "/eapcerts", "err", err.Error())
		return
	}
	s.a.Audit(r.Context(), u.Email, "eapcert.create", name)
	s.back(w, r, "/eapcerts", "ok", "Certificate issued by the internal EAP CA.")
}

func (s *server) eapUpload(w http.ResponseWriter, r *http.Request, u *User) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	certPEM, keyPEM := strings.TrimSpace(r.PostFormValue("cert")), strings.TrimSpace(r.PostFormValue("key"))
	if name == "" {
		s.back(w, r, "/eapcerts", "err", "A name is required.")
		return
	}
	if _, err := tlsPair(certPEM, keyPEM); err != nil {
		s.back(w, r, "/eapcerts", "err", "Certificate/key problem: "+err.Error())
		return
	}
	na, dns, _ := certExpiry([]byte(certPEM))
	if dns == nil {
		dns = []string{}
	}
	// normalise the key to PKCS#8
	k, _ := pki.ParseKey([]byte(keyPEM))
	kp, _ := pki.EncodeKey(k)
	if _, err := s.a.St.DB.Exec(r.Context(), `INSERT INTO eap_certs(tenant_id,name,source,cert_pem,key_enc,not_after,dns_names) VALUES($1::uuid,$2,'uploaded',$3,$4,$5,$6)`,
		u.Tenant.ID, name, certPEM, s.a.seal(string(kp)), na, dns); err != nil {
		s.back(w, r, "/eapcerts", "err", err.Error())
		return
	}
	s.a.Audit(r.Context(), u.Email, "eapcert.upload", name)
	s.back(w, r, "/eapcerts", "ok", "Certificate uploaded. Include the full chain in the certificate field so supplicants can validate it.")
}

func (s *server) eapDelete(w http.ResponseWriter, r *http.Request, u *User) {
	if _, err := s.a.St.DB.Exec(r.Context(), `DELETE FROM eap_certs WHERE id=$1::uuid AND NOT EXISTS (SELECT 1 FROM sites WHERE eap_cert_id=$1::uuid)`, r.PathValue("id")); err != nil {
		s.fail(w, r, u, err)
		return
	}
	s.back(w, r, "/eapcerts", "ok", "If the certificate was not assigned to a site, it has been deleted.")
}

var _ = json.Marshal
