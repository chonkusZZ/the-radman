// Package manager implements the RadMAN manager: web UI, node (QUIC) server and background jobs.
package manager

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"radman/internal/crypt"
	"radman/internal/pki"
	"radman/internal/store"
)

type Options struct {
	DatabaseURL   string
	DatabaseROURL string // optional streaming replica for log/dashboard queries
	DataDir       string
	Mode          string // "msp" (multi-tenant, default) or "standalone" (one implicit tenant, simplified UI)
	HTTPSAddr     string
	HTTPAddr      string
	UDPAddr       string
	NodeBinDir    string
	Version       string
}

// General holds the editable global settings.
type General struct {
	PublicHost         string `json:"public_host"`
	NodeIntervalSecs   int    `json:"node_interval_secs"`
	EventRetentionDays int    `json:"event_retention_days"`
	CRLIntervalMins    int    `json:"crl_interval_mins"`
	EnrollTokenHours   int    `json:"enroll_token_hours"`
	NodeCertDays       int    `json:"node_cert_days"`
	NodeGraceDays      int    `json:"node_grace_days"`
	StatsRetentionDays int    `json:"stats_retention_days"` // rollups behind the Stats graphs and client history
	Timezone           string `json:"timezone"`             // IANA zone used to bucket Stats by day/month and to label reports
}

func defaultGeneral() General {
	return General{NodeIntervalSecs: 60, EventRetentionDays: 90, CRLIntervalMins: 60, EnrollTokenHours: 24, NodeCertDays: 90, NodeGraceDays: 14, StatsRetentionDays: 400, Timezone: "UTC"}
}

type App struct {
	Opt   Options
	St    *store.Store
	Box   *crypt.Box
	Log   *log.Logger
	Setup string // one-time setup token while no admin exists

	solo *Tenant // the one tenant of a standalone installation (nil in MSP mode)

	nodeCA *pki.CA // platform-wide: identifies site nodes (CN = node id); tenants never see it

	caMu    sync.Mutex
	caCache map[string]*pki.CA // "<tenant>/eap" | "<tenant>/radsec" -> per-tenant CAs

	quicCert atomic.Pointer[tls.Certificate]
	quicPort int

	mu    sync.Mutex
	gen   *General
	brand *Branding

	web      *webTLS
	loginMu  sync.Mutex
	loginErr map[string][]time.Time
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func New(ctx context.Context, opt Options, l *log.Logger) (*App, error) {
	if err := os.MkdirAll(opt.DataDir, 0o700); err != nil {
		return nil, err
	}
	key, err := crypt.LoadKey(filepath.Join(opt.DataDir, "master.key"))
	if err != nil {
		return nil, err
	}
	box, err := crypt.New(key)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, opt.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	if opt.DatabaseROURL != "" {
		if err := st.AttachReplica(ctx, opt.DatabaseROURL); err != nil {
			return nil, fmt.Errorf("read replica: %w", err)
		}
	}
	if opt.Mode == "" {
		opt.Mode = ModeMSP
	}
	if opt.Mode != ModeMSP && opt.Mode != ModeStandalone {
		return nil, fmt.Errorf("unknown mode %q (use %q or %q)", opt.Mode, ModeMSP, ModeStandalone)
	}
	a := &App{Opt: opt, St: st, Box: box, Log: l, loginErr: map[string][]time.Time{}, caCache: map[string]*pki.CA{}}
	if _, port, err := net.SplitHostPort(opt.UDPAddr); err == nil {
		fmt.Sscan(port, &a.quicPort)
	}
	if a.nodeCA, err = a.ensureCA(ctx, "node_ca", "RadMAN Node CA"); err != nil {
		return nil, err
	}
	if err := a.migrateTenancy(ctx); err != nil {
		return nil, fmt.Errorf("tenancy migration: %w", err)
	}
	if err := a.migrateEvents(ctx); err != nil {
		return nil, fmt.Errorf("events migration: %w", err)
	}
	if err := a.refreshQUICCert(ctx); err != nil {
		return nil, err
	}
	if err := a.initMode(ctx); err != nil {
		return nil, err
	}
	if err := a.backfillStats(ctx); err != nil {
		return nil, fmt.Errorf("statistics backfill: %w", err)
	}
	var n int
	a.St.DB.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	if n == 0 {
		a.Setup = randToken(12)
	}
	return a, nil
}

func (a *App) General(ctx context.Context) General {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.gen == nil {
		g := defaultGeneral()
		a.St.GetJSON(ctx, "general", &g)
		a.gen = &g
	}
	return *a.gen
}

func (a *App) SaveGeneral(ctx context.Context, g General) error {
	if err := a.St.SetJSON(ctx, "general", g); err != nil {
		return err
	}
	a.mu.Lock()
	a.gen = &g
	a.mu.Unlock()
	return a.refreshQUICCert(ctx)
}

func (a *App) seal(s string) string          { return a.Box.Seal([]byte(s)) }
func (a *App) open(s string) (string, error) { b, err := a.Box.Open(s); return string(b), err }

func (a *App) putPEM(ctx context.Context, name string, cert, key []byte) error {
	if err := a.St.SetSecret(ctx, name+"_cert", a.seal(string(cert))); err != nil {
		return err
	}
	return a.St.SetSecret(ctx, name+"_key", a.seal(string(key)))
}

func (a *App) getPEM(ctx context.Context, name string) (cert, key []byte, err error) {
	c, err := a.St.GetSecret(ctx, name+"_cert")
	if err != nil || c == "" {
		return nil, nil, err
	}
	k, err := a.St.GetSecret(ctx, name+"_key")
	if err != nil || k == "" {
		return nil, nil, err
	}
	cp, err := a.open(c)
	if err != nil {
		return nil, nil, err
	}
	kp, err := a.open(k)
	return []byte(cp), []byte(kp), err
}

func (a *App) ensureCA(ctx context.Context, name, cn string) (*pki.CA, error) {
	c, k, err := a.getPEM(ctx, name)
	if err != nil {
		return nil, err
	}
	if c == nil {
		if c, k, err = pki.NewCA(cn, 10*365*24*time.Hour); err != nil {
			return nil, err
		}
		if err := a.putPEM(ctx, name, c, k); err != nil {
			return nil, err
		}
	}
	return pki.LoadCA(c, k)
}

func (a *App) NodeCAPEM() []byte { return pki.EncodeCert(a.nodeCA.Cert.Raw) }

// refreshQUICCert (re)issues the node-channel server certificate when the public host changed or it nears expiry.
func (a *App) refreshQUICCert(ctx context.Context) error {
	host := a.General(ctx).PublicHost
	if host == "" {
		host = "localhost"
	}
	if cp, kp, _ := a.getPEM(ctx, "quic"); cp != nil {
		if c, err := pki.ParseCert(cp); err == nil && time.Until(c.NotAfter) > 30*24*time.Hour && c.VerifyHostname(host) == nil {
			if tc, err := tls.X509KeyPair(append(cp, a.NodeCAPEM()...), kp); err == nil {
				a.quicCert.Store(&tc)
				return nil
			}
		}
	}
	k, err := pki.GenerateKey()
	if err != nil {
		return err
	}
	so := pki.SignOpts{CommonName: host, Validity: 365 * 24 * time.Hour, Server: true}
	if ip := net.ParseIP(host); ip != nil {
		so.IPs = []net.IP{ip}
	} else {
		so.DNSNames = []string{host}
	}
	if host != "localhost" {
		so.DNSNames = append(so.DNSNames, "localhost")
	}
	so.IPs = append(so.IPs, net.ParseIP("127.0.0.1"))
	cp, _, err := a.nodeCA.Sign(&k.PublicKey, so)
	if err != nil {
		return err
	}
	kp, _ := pki.EncodeKey(k)
	if err := a.putPEM(ctx, "quic", cp, kp); err != nil {
		return err
	}
	tc, err := tls.X509KeyPair(append(cp, a.NodeCAPEM()...), kp) // CA included so nodes can pin it by fingerprint
	if err != nil {
		return err
	}
	a.quicCert.Store(&tc)
	return nil
}

// Audit records an administrative action.
func (a *App) Audit(ctx context.Context, actor, action, detail string) {
	var tid any
	if t := tenantFrom(ctx); t != "" {
		tid = t
	}
	if _, err := a.St.DB.Exec(context.WithoutCancel(ctx), `INSERT INTO audit(tenant_id,actor,action,detail) VALUES($1::uuid,$2,$3,$4)`, tid, actor, action, detail); err != nil {
		a.Log.Printf("audit: %v", err)
	}
}

func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return strings.TrimSpace(s)
}

var errBadRequest = errors.New("bad request")

func certExpiry(pemBytes []byte) (time.Time, []string, error) {
	c, err := pki.ParseCert(pemBytes)
	if err != nil {
		return time.Time{}, nil, err
	}
	return c.NotAfter, c.DNSNames, nil
}

var _ = x509.NewCertPool
