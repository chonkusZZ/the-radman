package manager

import (
	"context"
	_ "embed"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"radman/internal/crypt"
	"radman/internal/pki"
)

//go:embed testdata/legacy_schema.sql
var legacySchema string

// TestUpgradeFromSingleTenant builds a database exactly as the single-tenant product left it and upgrades it in place.
func TestUpgradeFromSingleTenant(t *testing.T) {
	admin := os.Getenv("RADMAN_TEST_DB")
	if admin == "" {
		t.Skip("set RADMAN_TEST_DB")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	name := "radman_mig_" + strings.ToLower(randHex(4))
	conn.Exec(ctx, "CREATE DATABASE "+name)
	defer func() { conn.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)"); conn.Close(ctx) }()
	u, _ := url.Parse(admin)
	u.Path = "/" + name
	dbURL := u.String()

	legacy, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(ctx, legacySchema); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	key, _ := crypt.LoadOrCreateKey(filepath.Join(dir, "master.key"))
	box, _ := crypt.New(key)
	// the single-tenant product's global EAP and RadSec CAs, and a server certificate issued by the EAP CA
	eapCert, eapKey, _ := pki.NewCA("RadMAN EAP Server CA", time.Hour*24*365)
	rsCert, rsKey, _ := pki.NewCA("RadMAN RadSec AP CA", time.Hour*24*365)
	put := func(k string, v []byte) {
		legacy.Exec(ctx, `INSERT INTO secrets(key,value) VALUES($1,$2)`, k, box.Seal(v))
	}
	put("eap_ca_cert", eapCert)
	put("eap_ca_key", eapKey)
	put("radsec_ca_cert", rsCert)
	put("radsec_ca_key", rsKey)
	eapCA, _ := pki.LoadCA(eapCert, eapKey)
	k, _ := pki.GenerateKey()
	srvPEM, _, _ := eapCA.Sign(&k.PublicKey, pki.SignOpts{CommonName: "radius.legacy", Validity: time.Hour, Server: true})
	srvKey, _ := pki.EncodeKey(k)

	var eapID, siteID, nodeID, apID string
	legacy.QueryRow(ctx, `INSERT INTO eap_certs(name,source,cert_pem,key_enc,not_after) VALUES('srv','internal',$1,$2,now()+interval '1 year') RETURNING id::text`, string(srvPEM), box.Seal(srvKey)).Scan(&eapID)
	legacy.QueryRow(ctx, `INSERT INTO sites(name,eap_cert_id) VALUES('Head Office',$1) RETURNING id::text`, eapID).Scan(&siteID)
	legacy.QueryRow(ctx, `INSERT INTO aps(site_id,name,addr,secret_enc) VALUES($1,'ap1','10.0.0.1',$2) RETURNING id::text`, siteID, box.Seal([]byte("secretsecret"))).Scan(&apID)
	legacy.QueryRow(ctx, `INSERT INTO nodes(site_id,name,status) VALUES($1,'n1','active') RETURNING id::text`, siteID).Scan(&nodeID)
	caPEM, _, _ := pki.NewCA("Cust CA", time.Hour)
	legacy.Exec(ctx, `INSERT INTO pki_profiles(name,ca_pem) VALUES('Cust PKI',$1)`, string(caPEM))
	for email, role := range map[string]string{"boss@x": "admin", "tech@x": "operator", "view@x": "viewer"} {
		legacy.Exec(ctx, `INSERT INTO users(email,password_hash,role) VALUES($1,'x',$2)`, email, role)
	}
	for i := 0; i < 50; i++ {
		ts := time.Now().AddDate(0, -(i % 4), -i)
		legacy.Exec(ctx, `INSERT INTO events(node_id,site_id,seq,ts,kind,data) VALUES($1,$2,$3,$4,'auth','{"result":"accept"}')`, nodeID, siteID, i+1, ts)
	}
	legacy.Exec(ctx, `INSERT INTO audit(actor,action,detail) VALUES('boss@x','site.create','Head Office'),('boss@x','settings.general','x')`)
	legacy.Close(ctx)

	// ---- upgrade ----
	a, err := New(ctx, Options{DatabaseURL: dbURL, DataDir: dir, UDPAddr: "127.0.0.1:0", Version: "test", Mode: ModeMSP}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer a.St.DB.Close()
	count := func(q string, args ...any) int {
		var n int
		if err := a.St.DB.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	var tid string
	if err := a.St.DB.QueryRow(ctx, `SELECT id::text FROM tenants WHERE slug='default'`).Scan(&tid); err != nil {
		t.Fatal("no Default tenant created:", err)
	}
	if count(`SELECT count(*) FROM sites WHERE tenant_id=$1::uuid`, tid) != 1 || count(`SELECT count(*) FROM pki_profiles WHERE tenant_id=$1::uuid`, tid) != 1 || count(`SELECT count(*) FROM eap_certs WHERE tenant_id=$1::uuid`, tid) != 1 {
		t.Error("legacy data not adopted by the Default tenant")
	}
	if count(`SELECT count(*) FROM users WHERE email='boss@x' AND platform_role='global_admin'`) != 1 {
		t.Error("legacy admin did not become a global administrator")
	}
	if count(`SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.email='tech@x' AND m.role='tenant_admin' AND m.tenant_id=$1::uuid`, tid) != 1 ||
		count(`SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.email='view@x' AND m.role='read_only' AND m.tenant_id=$1::uuid`, tid) != 1 {
		t.Error("legacy operator/viewer roles not converted to tenant memberships")
	}
	if count(`SELECT count(*) FROM information_schema.columns WHERE table_name='users' AND column_name='role' AND table_schema=current_schema()`) != 0 {
		t.Error("legacy role column should be gone")
	}
	if count(`SELECT count(*) FROM events WHERE tenant_id=$1::uuid`, tid) != 50 {
		t.Errorf("events not migrated/backfilled: %d", count(`SELECT count(*) FROM events`))
	}
	if count(`SELECT count(*) FROM pg_partitioned_table pt JOIN pg_class c ON c.oid=pt.partrelid WHERE c.relname='events'`) != 1 {
		t.Error("events table is not partitioned")
	}
	if count(`SELECT count(*) FROM events_default`) != 0 {
		t.Error("migrated events should all land in dated partitions")
	}
	if count(`SELECT count(*) FROM audit WHERE tenant_id=$1::uuid AND action='site.create'`, tid) != 1 || count(`SELECT count(*) FROM audit WHERE tenant_id IS NULL AND action='settings.general'`) != 1 {
		t.Error("audit rows not attributed correctly")
	}
	// the legacy CAs became the Default tenant's CAs, so the old server certificate still chains
	ca, err := a.tenantCA(ctx, tid, "eap")
	if err != nil || pki.Fingerprint(ca.Cert) != func() string { f, _ := pki.FingerprintPEM(eapCert); return f }() {
		t.Fatalf("legacy EAP CA was not carried over: %v", err)
	}
	cfg, err := a.BuildSiteConfig(ctx, siteID)
	if err != nil || len(cfg.APs) != 1 || cfg.APs[0].Secret != "secretsecret" || len(cfg.PKI) != 0 {
		t.Fatalf("legacy site config: %v %+v", err, cfg)
	}
	leaf, _ := pki.ParseCert([]byte(cfg.EAPCert))
	if leaf.CheckSignatureFrom(ca.Cert) != nil {
		t.Error("server certificate no longer verifies against the carried-over CA")
	}
	// same site name can now exist in another tenant
	other, _ := a.CreateTenant(ctx, "Other")
	if _, err := a.St.DB.Exec(ctx, `INSERT INTO sites(tenant_id,name) VALUES($1::uuid,'Head Office')`, other.ID); err != nil {
		t.Errorf("site names should be unique per tenant only: %v", err)
	}
	// idempotent: starting again changes nothing
	a.St.DB.Close()
	a2, err := New(ctx, Options{DatabaseURL: dbURL, DataDir: dir, UDPAddr: "127.0.0.1:0", Version: "test", Mode: ModeMSP}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	defer a2.St.DB.Close()
	var n int
	a2.St.DB.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&n)
	if n != 2 {
		t.Errorf("restart created extra tenants: %d", n)
	}
	a2.St.DB.QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&n)
	if n != 50 {
		t.Errorf("restart changed events: %d", n)
	}
}
