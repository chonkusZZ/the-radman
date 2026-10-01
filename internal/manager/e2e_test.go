package manager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"layeh.com/radius"

	"radman/internal/eaptest"
	"radman/internal/nodeagent"
	"radman/internal/pki"
	"radman/internal/proto"
)

func freeUDPPort(t *testing.T) int {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func waitFor(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestHubAndSpoke exercises manager + node over the real QUIC channel:
// token enrollment, config sync, local EAP-TLS auth, event upload, cert renewal, revocation.
func TestHubAndSpoke(t *testing.T) {
	a := testApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port := freeUDPPort(t)
	a.Opt.UDPAddr = net.JoinHostPort("127.0.0.1", itoa(port))
	a.quicPort = port
	g := a.General(ctx)
	g.PublicHost, g.NodeIntervalSecs, g.NodeCertDays = "127.0.0.1", 10, 20 // short-lived node certs force a renewal
	if err := a.SaveGeneral(ctx, g); err != nil {
		t.Fatal(err)
	}
	nodeagent.RenewalThreshold = func(*x509.Certificate) time.Duration { return 365 * 24 * time.Hour }
	defer func() { nodeagent.RenewalThreshold = nodeagent.DefaultRenewalThreshold }()
	go a.ServeNodes(ctx)
	time.Sleep(300 * time.Millisecond)

	// customer PKI + site
	caPEM, caKey, _ := pki.NewCA("Customer CA", 24*time.Hour)
	ca, _ := pki.LoadCA(caPEM, caKey)
	var pkiID, siteID, nodeID string
	tn, err := a.CreateTenant(ctx, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	a.St.DB.QueryRow(ctx, `INSERT INTO pki_profiles(tenant_id,name,ca_pem) VALUES($1::uuid,'cust',$2) RETURNING id::text`, tn.ID, string(caPEM)).Scan(&pkiID)
	eap, err := a.CreateInternalEAPCert(ctx, tn.ID, "srv", "radius.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.St.DB.QueryRow(ctx, `INSERT INTO sites(tenant_id,name,eap_cert_id,auth_port,acct_port) VALUES($1::uuid,'hq',$2::uuid,$3,$4) RETURNING id::text`, tn.ID, eap, freeUDPPort(t), freeUDPPort(t)).Scan(&siteID)
	authPort := 0
	a.St.DB.QueryRow(ctx, `SELECT auth_port FROM sites WHERE id::text=$1`, siteID).Scan(&authPort)
	a.St.DB.Exec(ctx, `INSERT INTO site_pki VALUES($1,$2)`, siteID, pkiID)
	a.St.DB.Exec(ctx, `INSERT INTO aps(site_id,name,addr,secret_enc) VALUES($1,'ap1','127.0.0.0/8',$2)`, siteID, a.seal("secretsecret"))
	tok := "tok-" + randToken(16)
	a.St.DB.QueryRow(ctx, `INSERT INTO nodes(site_id,name,token_hash,token_enc,token_expires) VALUES($1,'n1',$2,$3,now()+interval '1 hour') RETURNING id::text`,
		siteID, hashToken(tok), a.seal(tok)).Scan(&nodeID)

	// the node gets its own server certificate names (CN + SANs); devices must be able to validate "node.test" and the IP
	if err := a.setNodeServerNames(ctx, tn.ID, nodeID, []string{"node.test", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}

	// node
	dir := t.TempDir()
	fp, _ := pki.FingerprintPEM(a.NodeCAPEM())
	b, _ := json.Marshal(nodeagent.EnrollConfig{Manager: a.Opt.UDPAddr, CAFP: fp, Token: tok}) // CA learned via pinned fingerprint
	os.WriteFile(filepath.Join(dir, "enroll.json"), b, 0o600)
	agent := nodeagent.New(dir, log.New(io.Discard, "", 0))
	go agent.Run(ctx)

	waitFor(t, "node enrollment + config", 15*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(dir, "config.json"))
		return err == nil
	})
	if _, err := os.Stat(filepath.Join(dir, "enroll.json")); err == nil {
		t.Fatal("single-use enroll.json should be deleted after enrollment")
	}
	var status string
	a.St.DB.QueryRow(ctx, `SELECT status FROM nodes WHERE id::text=$1`, nodeID).Scan(&status)
	if status != "active" {
		t.Fatalf("node status %q", status)
	}
	// enrolling twice with the same token must fail
	if _, err := a.enroll(ctx, nil2enroll(tok), "x"); err == nil {
		t.Fatal("token reuse accepted")
	}

	// device authenticates against the node (node is autonomous: works regardless of manager)
	k, _ := pki.GenerateKey()
	cpem, _, _ := ca.Sign(&k.PublicKey, pki.SignOpts{CommonName: "device-1", Validity: time.Hour, Client: true})
	kpem, _ := pki.EncodeKey(k)
	devCert, _ := tls.X509KeyPair(cpem, kpem)
	srvRoots := x509.NewCertPool()
	eapCA, _ := a.tenantCAPEM(ctx, tn.ID, "eap")
	srvRoots.AppendCertsFromPEM(eapCA)
	tc := &tls.Config{Certificates: []tls.Certificate{devCert}, RootCAs: srvRoots, ServerName: "node.test", MinVersion: tls.VersionTLS12} // would fail if the node served the site certificate (radius.test)
	res, err := eaptest.Authenticate("127.0.0.1:"+itoa(authPort), "secretsecret", "device-1", tc)
	if err != nil || res.Code != radius.CodeAccessAccept {
		t.Fatalf("auth: %v %+v", err, res)
	}

	// auth event reaches the manager on a later check-in
	waitFor(t, "auth event upload", 20*time.Second, func() bool {
		var n int
		a.St.DB.QueryRow(ctx, `SELECT count(*) FROM events WHERE tenant_id=$1::uuid AND kind='auth' AND data->>'subject'='device-1' AND data->>'result'='accept'`, tn.ID).Scan(&n)
		return n == 1
	})

	// forced renewal: new cert issued, previous serial retained: previous serial retained
	waitFor(t, "client certificate renewal", 15*time.Second, func() bool {
		var prev string
		a.St.DB.QueryRow(ctx, `SELECT prev_cert_serial FROM nodes WHERE id::text=$1`, nodeID).Scan(&prev)
		return prev != ""
	})

	// config change propagates: add an AP with a new secret, then use it
	a.St.DB.Exec(ctx, `UPDATE aps SET secret_enc=$2 WHERE site_id::text=$1`, siteID, a.seal("changed-secret"))
	waitFor(t, "config sync", 25*time.Second, func() bool {
		cfg, err := a.BuildNodeConfig(ctx, siteID, nodeID)
		if err != nil {
			return false
		}
		nb, _ := os.ReadFile(filepath.Join(dir, "config.json")) // what the node applied and persisted
		var nc proto.SiteConfig
		return json.Unmarshal(nb, &nc) == nil && proto.HashConfig(&nc) == proto.HashConfig(cfg)
	})
	if r, err := eaptest.Authenticate("127.0.0.1:"+itoa(authPort), "changed-secret", "device-1", tc); err != nil || r.Code != radius.CodeAccessAccept {
		t.Fatalf("auth with new secret: %v", err)
	}

	// revoke: node can no longer check in
	a.St.DB.Exec(ctx, `UPDATE nodes SET status='revoked', cert_serial='', prev_cert_serial='' WHERE id::text=$1`, nodeID)
	_, err = a.authenticateTestCert(ctx, dir)
	if err == nil {
		t.Fatal("revoked node still authenticates to the manager")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func nil2enroll(tok string) *proto.EnrollReq {
	csr, _, _ := pki.NewCSR("x", nil)
	return &proto.EnrollReq{Token: tok, CSR: string(csr)}
}

// authenticateTestCert checks the node's current client certificate against the manager's rules.
func (a *App) authenticateTestCert(ctx context.Context, dir string) (*nodeIdentity, error) {
	b, err := os.ReadFile(filepath.Join(dir, "node.crt"))
	if err != nil {
		return nil, err
	}
	cs, err := pki.ParseCerts(b)
	if err != nil {
		return nil, err
	}
	return a.authenticate(ctx, cs)
}
