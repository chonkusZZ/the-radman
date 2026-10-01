package manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"radman/internal/pki"
)

type radsecCertRow struct {
	ID, Serial, Subject, Algo, CreatedBy string
	NotAfter, Created                    time.Time
	Revoked                              *time.Time
	Expired                              bool
}

func (s *server) radsecPage(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	id := r.PathValue("id")
	var apName, addr, siteName, siteID string
	var port int
	if err := s.a.St.DB.QueryRow(ctx, `SELECT a.name, a.addr, s.name, s.id::text, s.radsec_port FROM aps a JOIN sites s ON s.id=a.site_id WHERE a.id=$1::uuid`, id).
		Scan(&apName, &addr, &siteName, &siteID, &port); err != nil {
		s.fail(w, r, u, err)
		return
	}
	var certs []radsecCertRow
	rows, _ := s.a.St.DB.Query(ctx, `SELECT id::text, serial, subject, algo, created_by, not_after, created_at, revoked_at FROM radsec_certs WHERE ap_id=$1::uuid ORDER BY created_at DESC`, id)
	for rows.Next() {
		var c radsecCertRow
		rows.Scan(&c.ID, &c.Serial, &c.Subject, &c.Algo, &c.CreatedBy, &c.NotAfter, &c.Created, &c.Revoked)
		c.Expired = time.Now().After(c.NotAfter)
		certs = append(certs, c)
	}
	rows.Close()
	s.render(w, r, u, "radsec", page{"Title": "RadSEC · " + apName, "APID": id, "AP": apName, "Addr": addr, "Site": siteName, "SiteID": siteID,
		"Port": port, "Enabled": port > 0, "Certs": certs, "Public": s.a.General(ctx).PublicHost})
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// radsecSign signs a CSR generated in the administrator's browser. The private key never reaches the server.
func (s *server) radsecSign(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	id := r.PathValue("id")
	fail := func(code int, msg string) { jsonOut(w, code, map[string]string{"error": msg}) }

	var apName, eapPEM string
	var port int
	if err := s.a.St.DB.QueryRow(ctx, `SELECT a.name, s.radsec_port, COALESCE(e.cert_pem,'') FROM aps a JOIN sites s ON s.id=a.site_id LEFT JOIN eap_certs e ON e.id=s.eap_cert_id WHERE a.id=$1::uuid AND s.tenant_id=$2::uuid`, id, u.Tenant.ID).
		Scan(&apName, &port, &eapPEM); err != nil {
		fail(404, "access point not found")
		return
	}
	if port == 0 {
		fail(409, "RadSEC is not enabled for this site")
		return
	}
	rsCA, err := s.a.tenantCA(ctx, u.Tenant.ID, "radsec")
	if err != nil {
		fail(500, "tenant CA unavailable")
		return
	}
	csr, err := pki.ParseCSR([]byte(r.PostFormValue("csr")))
	if err != nil {
		fail(400, "invalid certificate request: "+err.Error())
		return
	}
	var algo string
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			fail(400, "unsupported EC curve (use P-256 or P-384)")
			return
		}
		algo = "EC " + k.Curve.Params().Name
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			fail(400, "RSA keys must be at least 2048 bits")
			return
		}
		algo = fmt.Sprintf("RSA %d", k.N.BitLen())
	default:
		fail(400, "unsupported key type")
		return
	}
	days, _ := strconv.Atoi(r.PostFormValue("days"))
	if days < 1 || days > 1825 {
		days = 730
	}
	// the subject is chosen by the manager, not the browser
	cn := apName
	certPEM, c, err := rsCA.Sign(csr.PublicKey, pki.SignOpts{CommonName: cn, Validity: time.Duration(days) * 24 * time.Hour, Client: true})
	if err != nil {
		fail(500, "signing failed")
		return
	}
	if _, err := s.a.St.DB.Exec(ctx, `INSERT INTO radsec_certs(ap_id,serial,subject,algo,not_after,created_by) VALUES($1,$2,$3,$4,$5,$6)`,
		id, pki.SerialHex(c), cn, algo, c.NotAfter, u.Email); err != nil {
		fail(500, "could not record certificate")
		return
	}
	s.a.Audit(ctx, u.Email, "radsec.issue", fmt.Sprintf("%s serial=%s %s", apName, pki.SerialHex(c), algo))

	// what the AP must trust to validate the node: the issuer chain of the site's server certificate
	serverCA := ""
	if certs, err := pki.ParseCerts([]byte(eapPEM)); err == nil && len(certs) > 1 {
		for _, cc := range certs[1:] {
			serverCA += string(pki.EncodeCert(cc.Raw))
		}
	}
	jsonOut(w, 200, map[string]string{"cert": string(certPEM), "server_ca": serverCA, "serial": pki.SerialHex(c), "not_after": c.NotAfter.Format("2006-01-02")})
}

func (s *server) radsecRevoke(w http.ResponseWriter, r *http.Request, u *User) {
	var ap, serial string
	err := s.a.St.DB.QueryRow(r.Context(), `UPDATE radsec_certs SET revoked_at=now() WHERE id=$1::uuid AND revoked_at IS NULL RETURNING ap_id::text, serial`, r.PathValue("id")).Scan(&ap, &serial)
	if err != nil {
		s.back(w, r, "/sites", "err", "Certificate not found or already revoked.")
		return
	}
	s.a.Audit(r.Context(), u.Email, "radsec.revoke", "serial="+serial)
	s.back(w, r, "/aps/"+ap+"/radsec", "ok", "Certificate revoked. Nodes drop it at their next check-in (within about a minute).")
}

var _ = strings.TrimSpace
