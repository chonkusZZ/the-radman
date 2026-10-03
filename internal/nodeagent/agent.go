// Package nodeagent is the site node: RADIUS/EAP-TLS service plus manager check-in.
package nodeagent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"radman/internal/crl"
	"radman/internal/netguard"
	"radman/internal/nodelog"
	"radman/internal/pki"
	"radman/internal/proto"
)

var Version = "dev"

// crlClient fetches CRLs. A node runs on the site's own network, where an on-prem CA's CRL distribution
// point legitimately sits on a private address, so private ranges are allowed here (unlike the manager's
// tenant-facing fetch) — but loopback and link-local addresses are still refused, so a CRL URL can never
// be turned into a probe of the node's own local services.
var crlClient = netguard.Client(true)

const renewBefore = 30 * 24 * time.Hour

// EnrollConfig is the small file shipped inside the node download.
type EnrollConfig struct {
	Manager string `json:"manager"` // host:port (UDP)
	CAPEM   string `json:"ca_pem"`  // manager's internal CA
	CAFP    string `json:"ca_sha256"`
	Token   string `json:"token"`
}

type managerInfo struct {
	Manager string `json:"manager"`
	CAPEM   string `json:"ca_pem"`
	NodeID  string `json:"node_id"`
}

type Agent struct {
	Dir     string
	Log     *nodelog.Logger
	q       *Queue
	started time.Time

	mu       sync.Mutex
	mgr      managerInfo
	cert     *tls.Certificate
	leaf     *x509.Certificate
	srv      *Server
	ports    [3]int
	interval time.Duration

	collecting int32 // 1 while a log bundle upload is in progress
}

func New(dir string, l *nodelog.Logger) *Agent {
	return &Agent{Dir: dir, Log: l, started: time.Now(), interval: 60 * time.Second}
}

func (a *Agent) path(n string) string { return filepath.Join(a.Dir, n) }

func (a *Agent) Run(ctx context.Context) error {
	if err := os.MkdirAll(a.Dir, 0o700); err != nil {
		return err
	}
	q, err := OpenQueue(a.Dir)
	if err != nil {
		return err
	}
	a.q = q

	// 1. Start serving from the last-known-good config, even before the manager is reachable.
	if b, err := os.ReadFile(a.path("config.json")); err == nil {
		var cfg proto.SiteConfig
		if json.Unmarshal(b, &cfg) == nil {
			if err := a.applyConfig(&cfg, false); err != nil {
				a.Log.Errorf("cached config unusable: %v", err)
			} else {
				a.Log.Infof("serving cached site config %q", cfg.SiteName)
			}
		}
	}

	go a.crlRefresher(ctx)
	go a.logPruner(ctx)

	// 2. Enrol if needed, then check in forever.
	for ctx.Err() == nil {
		if err := a.loadIdentity(); err != nil {
			if err := a.enroll(ctx); err != nil {
				a.Log.Errorf("enrollment: %v (retrying in 30s)", err)
				sleep(ctx, 30*time.Second)
				continue
			}
		}
		break
	}
	fails := 0
	for ctx.Err() == nil {
		err := a.checkin(ctx)
		wait := a.interval
		if err != nil {
			fails++
			a.Log.Warnf("check-in failed (%d): %v - continuing standalone", fails, err)
			wait = time.Duration(min(fails, 6)) * 30 * time.Second
			if wait > 5*time.Minute {
				wait = 5 * time.Minute
			}
			if wait < a.interval {
				wait = a.interval
			}
		} else {
			fails = 0
		}
		sleep(ctx, wait+time.Duration(rand.Intn(5000))*time.Millisecond)
	}
	a.mu.Lock()
	if a.srv != nil {
		a.srv.Shutdown()
	}
	a.mu.Unlock()
	return nil
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func (a *Agent) loadIdentity() error {
	b, err := os.ReadFile(a.path("manager.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &a.mgr); err != nil {
		return err
	}
	c, err := tls.LoadX509KeyPair(a.path("node.crt"), a.path("node.key"))
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.cert, a.leaf = &c, leaf
	a.mu.Unlock()
	return nil
}

func (a *Agent) findEnrollFile() string {
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	for _, d := range []string{a.Dir, filepath.Dir(exe), cwd} {
		p := filepath.Join(d, "enroll.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (a *Agent) dial(ctx context.Context, withCert bool) (*quic.Conn, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(a.mgr.CAPEM)) {
		return nil, errors.New("manager CA is invalid")
	}
	host, _, err := net.SplitHostPort(a.mgr.Manager)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{RootCAs: pool, ServerName: host, NextProtos: []string{proto.ALPN}, MinVersion: tls.VersionTLS13}
	if withCert {
		a.mu.Lock()
		c := a.cert
		a.mu.Unlock()
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return c, nil }
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return quic.DialAddr(dctx, a.mgr.Manager, tc, &quic.Config{MaxIdleTimeout: 30 * time.Second, HandshakeIdleTimeout: 10 * time.Second})
}

func (a *Agent) roundTrip(ctx context.Context, withCert bool, req *proto.Request) (*proto.Response, error) {
	conn, err := a.dial(ctx, withCert)
	if err != nil {
		return nil, err
	}
	defer conn.CloseWithError(0, "bye")
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	st.SetDeadline(time.Now().Add(60 * time.Second))
	if err := proto.Write(st, req); err != nil {
		return nil, err
	}
	st.Close()
	var resp proto.Response
	if err := proto.Read(st, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("manager: %s", resp.Error)
	}
	return &resp, nil
}

func (a *Agent) enroll(ctx context.Context) error {
	p := a.findEnrollFile()
	if p == "" {
		return errors.New("no enroll.json found (download the node package from the manager)")
	}
	var ec EnrollConfig
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &ec); err != nil {
		return err
	}
	if ec.CAPEM != "" {
		if fp, err := pki.FingerprintPEM([]byte(ec.CAPEM)); err != nil || (ec.CAFP != "" && fp != ec.CAFP) {
			return errors.New("manager CA fingerprint mismatch in enroll.json")
		}
	} else if ec.CAFP == "" {
		return errors.New("enroll.json needs ca_pem or ca_sha256")
	}
	if ec.CAPEM == "" { // manual enrollment: learn the CA from the handshake, pinned by fingerprint
		pem, err := discoverCA(ctx, ec.Manager, ec.CAFP)
		if err != nil {
			return err
		}
		ec.CAPEM = pem
	}
	a.mgr = managerInfo{Manager: ec.Manager, CAPEM: ec.CAPEM}
	csrPEM, keyPEM, err := pki.NewCSR("radman-node", nil)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	resp, err := a.roundTrip(ctx, false, &proto.Request{Type: "enroll", Enroll: &proto.EnrollReq{
		Token: ec.Token, CSR: string(csrPEM), Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH, Version: Version,
	}})
	if err != nil {
		return err
	}
	a.mgr.NodeID = resp.Enroll.NodeID
	mb, _ := json.Marshal(a.mgr)
	if err := os.WriteFile(a.path("node.key"), keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(a.path("node.crt"), []byte(resp.Enroll.Cert), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(a.path("manager.json"), mb, 0o600); err != nil {
		return err
	}
	os.Remove(p) // the single-use token is now spent
	a.Log.Infof("enrolled as node %s", a.mgr.NodeID)
	return a.loadIdentity()
}

func (a *Agent) checkin(ctx context.Context) error {
	host, _ := os.Hostname()
	req := &proto.CheckinReq{Version: Version, OS: runtime.GOOS, Hostname: host}
	a.mu.Lock()
	srv := a.srv
	leaf := a.leaf
	a.mu.Unlock()
	var rt *Runtime
	if srv != nil {
		rt = srv.Runtime()
		req.ConfigHash = rt.Hash
		req.Stats = proto.Stats{Accepts: srv.Accepts.Load(), Rejects: srv.Rejects.Load()}
		for _, st := range rt.PKIs {
			req.CRLStatus = append(req.CRLStatus, st.Status()...)
		}
	}
	req.Stats.UptimeSeconds = int64(time.Since(a.started).Seconds())
	req.Stats.QueueDepth = a.q.Len()
	a.logStats(&req.Stats)
	events := a.q.Peek(500)
	req.Events = events

	var newKey []byte
	if time.Until(leaf.NotAfter) < RenewalThreshold(leaf) {
		csr, key, err := pki.NewCSR("radman-node", nil)
		if err == nil {
			req.RenewCSR, newKey = string(csr), key
		}
	}
	resp, err := a.roundTrip(ctx, true, &proto.Request{Type: "checkin", Checkin: &proto.CheckinReq{
		Version: req.Version, OS: req.OS, Hostname: req.Hostname, ConfigHash: req.ConfigHash, RenewCSR: req.RenewCSR,
		Events: req.Events, Stats: req.Stats, CRLStatus: req.CRLStatus,
	}})
	if err != nil {
		return err
	}
	r := resp.Checkin
	a.q.Ack(r.AckedSeq)
	if r.IntervalSeconds >= 10 {
		a.interval = time.Duration(r.IntervalSeconds) * time.Second
	}
	if r.Cert != "" && newKey != nil {
		os.WriteFile(a.path("node.key"), newKey, 0o600)
		os.WriteFile(a.path("node.crt"), []byte(r.Cert), 0o600)
		if err := a.loadIdentity(); err != nil {
			return fmt.Errorf("installing renewed certificate: %w", err)
		}
		a.Log.Infof("client certificate renewed, expires %s", a.leaf.NotAfter.Format(time.RFC3339))
	}
	if r.Config != nil {
		if err := a.applyConfig(r.Config, true); err != nil {
			return fmt.Errorf("applying new config: %w", err)
		}
		a.Log.Infof("applied new site config (hash %.12s)", a.srv.Runtime().Hash)
	}
	if r.CollectLogs != "" {
		a.startLogCollection(ctx, r.CollectLogs)
	}
	return nil
}

func (a *Agent) applyConfig(cfg *proto.SiteConfig, persist bool) error {
	a.applyLogSettings(cfg)
	rt, err := BuildRuntime(cfg)
	if err != nil {
		return err
	}
	auth, acct := cfg.AuthPort, cfg.AcctPort
	if auth == 0 {
		auth = 1812
	}
	if acct == 0 {
		acct = 1813
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.srv != nil && a.ports == [3]int{auth, acct, cfg.RadSecPort} {
		a.srv.SetRuntime(rt)
	} else {
		if a.srv != nil {
			a.srv.Shutdown()
		}
		srv := NewServer(a.q.Add, a.Log)
		srv.SetRuntime(rt)
		radsec := ""
		if cfg.RadSecPort > 0 {
			radsec = fmt.Sprintf(":%d", cfg.RadSecPort)
		}
		if err := srv.ListenAndServeRadSec(fmt.Sprintf(":%d", auth), fmt.Sprintf(":%d", acct), radsec); err != nil {
			return err
		}
		a.srv, a.ports = srv, [3]int{auth, acct, cfg.RadSecPort}
	}
	if cfg.IntervalSeconds >= 10 {
		a.interval = time.Duration(cfg.IntervalSeconds) * time.Second
	}
	if persist {
		b, _ := json.Marshal(cfg)
		tmp := a.path("config.json.tmp")
		if err := os.WriteFile(tmp, b, 0o600); err == nil {
			os.Rename(tmp, a.path("config.json"))
		}
	}
	return nil
}

// crlRefresher fetches CRLs directly when the manager copy is getting old,
// so the node keeps working if it cannot reach the manager but can reach the CDP.
func (a *Agent) crlRefresher(ctx context.Context) {
	for {
		sleep(ctx, 2*time.Minute)
		if ctx.Err() != nil {
			return
		}
		a.mu.Lock()
		srv := a.srv
		a.mu.Unlock()
		if srv == nil {
			continue
		}
		for _, st := range srv.Runtime().PKIs {
			for _, u := range st.NeedsRefresh() {
				der, rl, err := crl.Fetch(u, crlClient)
				if err != nil {
					continue
				}
				st.SetCRL(u, der, rl, "direct")
				a.Log.Infof("refreshed CRL directly: %s", u)
			}
		}
	}
}

// discoverCA connects to the manager and returns the CA certificate (PEM) whose SHA-256 matches fp,
// provided the server certificate chains to it for the manager's name.
func discoverCA(ctx context.Context, addr, fp string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	var found string
	tc := &tls.Config{
		InsecureSkipVerify: true, // verified below against the pinned CA
		NextProtos:         []string{proto.ALPN},
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			var certs []*x509.Certificate
			for _, r := range raw {
				c, err := x509.ParseCertificate(r)
				if err != nil {
					return err
				}
				certs = append(certs, c)
			}
			for _, c := range certs {
				if pki.Fingerprint(c) == fp && c.IsCA {
					pool := x509.NewCertPool()
					pool.AddCert(c)
					if _, err := certs[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: host}); err != nil {
						return err
					}
					found = string(pki.EncodeCert(c.Raw))
					return nil
				}
			}
			return errors.New("manager did not present a CA matching the pinned fingerprint")
		},
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(dctx, addr, tc, &quic.Config{HandshakeIdleTimeout: 10 * time.Second})
	if err != nil {
		return "", err
	}
	conn.CloseWithError(0, "")
	return found, nil
}

// EnrollNow performs enrollment immediately (used by the "enroll" command).
func (a *Agent) EnrollNow(ctx context.Context) error {
	if err := os.MkdirAll(a.Dir, 0o700); err != nil {
		return err
	}
	return a.enroll(ctx)
}

// RenewalThreshold returns the remaining lifetime below which a node asks for a new certificate:
// 30 days, or a third of the lifetime for short-lived certificates. A variable so tests can force renewal.
var RenewalThreshold = DefaultRenewalThreshold

func DefaultRenewalThreshold(c *x509.Certificate) time.Duration {
	t := c.NotAfter.Sub(c.NotBefore) / 3
	if t > renewBefore {
		t = renewBefore
	}
	return t
}
