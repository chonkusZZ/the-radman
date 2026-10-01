package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"radman/internal/proto"
)

// BuildSiteConfig assembles the configuration of a site (using the site's server certificate).
func (a *App) BuildSiteConfig(ctx context.Context, siteID string) (*proto.SiteConfig, error) {
	return a.BuildNodeConfig(ctx, siteID, "")
}

// BuildNodeConfig is the configuration pushed to one node: the site's settings, with the node's own server certificate
// (names chosen at node creation) in place of the site's when it has one.
func (a *App) BuildNodeConfig(ctx context.Context, siteID, nodeID string) (*proto.SiteConfig, error) {
	cfg := &proto.SiteConfig{SiteID: siteID}
	var polJSON []byte
	var eapID *string
	var tenantID string
	err := a.St.DB.QueryRow(ctx, `SELECT name, policy, auth_port, acct_port, radsec_port, eap_cert_id::text, tenant_id::text FROM sites WHERE id=$1::uuid`, siteID).
		Scan(&cfg.SiteName, &polJSON, &cfg.AuthPort, &cfg.AcctPort, &cfg.RadSecPort, &eapID, &tenantID)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(polJSON, &cfg.Policy); err != nil {
		return nil, err
	}
	cfg.IntervalSeconds = a.General(ctx).NodeIntervalSecs
	var certPEM, keyEnc string
	if nodeID != "" {
		a.St.DB.QueryRow(ctx, `SELECT eap_cert_pem, eap_key_enc FROM nodes WHERE id=$1::uuid AND site_id=$2::uuid AND eap_cert_pem <> ''`, nodeID, siteID).Scan(&certPEM, &keyEnc)
	}
	if certPEM == "" {
		if eapID == nil {
			return nil, errors.New("site has no EAP server certificate assigned")
		}
		if err := a.St.DB.QueryRow(ctx, `SELECT cert_pem, key_enc FROM eap_certs WHERE id=$1::uuid AND tenant_id=$2::uuid`, *eapID, tenantID).Scan(&certPEM, &keyEnc); err != nil {
			return nil, err
		}
	}
	key, err := a.open(keyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypting EAP key: %w", err)
	}
	cfg.EAPCert, cfg.EAPKey = certPEM, key
	if cfg.RadSecPort > 0 {
		pemCA, err := a.tenantCAPEM(ctx, tenantID, "radsec")
		if err != nil {
			return nil, err
		}
		cfg.RadSecCA = string(pemCA)
	}

	rows, err := a.St.DB.Query(ctx, `SELECT a.name, a.addr, a.secret_enc,
		COALESCE((SELECT array_agg(c.serial ORDER BY c.serial) FROM radsec_certs c WHERE c.ap_id=a.id AND c.revoked_at IS NULL AND c.not_after > now()), '{}')
		FROM aps a WHERE a.site_id=$1::uuid ORDER BY a.name`, siteID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ap proto.AP
		var enc string
		if err := rows.Scan(&ap.Name, &ap.Addr, &enc, &ap.RadSecSerials); err != nil {
			rows.Close()
			return nil, err
		}
		if ap.Secret, err = a.open(enc); err != nil {
			rows.Close()
			return nil, err
		}
		cfg.APs = append(cfg.APs, ap)
	}
	rows.Close()

	prows, err := a.St.DB.Query(ctx, `SELECT p.id::text, p.name, p.ca_pem, p.crl_urls, p.stale_policy, p.stale_grace_hours
		FROM pki_profiles p JOIN site_pki sp ON sp.pki_id=p.id WHERE sp.site_id=$1::uuid AND p.tenant_id=$2::uuid ORDER BY p.name`, siteID, tenantID)
	if err != nil {
		return nil, err
	}
	defer prows.Close()
	for prows.Next() {
		var p proto.PKI
		if err := prows.Scan(&p.ID, &p.Name, &p.CAs, &p.CRLURLs, &p.StalePolicy, &p.StaleGraceHours); err != nil {
			return nil, err
		}
		cfg.PKI = append(cfg.PKI, p)
	}
	prows.Close()
	for i := range cfg.PKI {
		for _, u := range cfg.PKI[i].CRLURLs {
			var der []byte
			a.St.DB.QueryRow(ctx, `SELECT der FROM crl_cache WHERE url=$1`, u).Scan(&der)
			if len(der) > 0 {
				if cfg.PKI[i].CRLs == nil {
					cfg.PKI[i].CRLs = map[string][]byte{}
				}
				cfg.PKI[i].CRLs[u] = der
			}
		}
	}
	return cfg, nil
}
