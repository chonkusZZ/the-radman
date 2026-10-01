package manager

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"radman/internal/pki"
	"radman/internal/proto"
)

func hashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

// ServeNodes runs the single UDP (QUIC) listener that all site nodes use.
func (a *App) ServeNodes(ctx context.Context) error {
	tc := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		NextProtos:     []string{proto.ALPN},
		ClientAuth:     tls.RequestClientCert, // verified manually so we can apply a renewal grace period
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return a.quicCert.Load(), nil },
	}
	l, err := quic.ListenAddr(a.Opt.UDPAddr, tc, &quic.Config{MaxIdleTimeout: 30 * time.Second, MaxIncomingStreams: 4, HandshakeIdleTimeout: 10 * time.Second})
	if err != nil {
		return err
	}
	a.Log.Printf("node channel (QUIC/UDP) listening on %s", a.Opt.UDPAddr)
	go func() { <-ctx.Done(); l.Close() }()
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			return nil
		}
		go a.handleConn(ctx, conn)
	}
}

type nodeIdentity struct {
	ID       string
	SiteID   string
	TenantID string
	Name     string
	Expired  bool
}

// authenticate maps the presented client certificate to a node record.
func (a *App) authenticate(ctx context.Context, certs []*x509.Certificate) (*nodeIdentity, error) {
	if len(certs) == 0 {
		return nil, nil // anonymous: enrollment only
	}
	leaf := certs[0]
	pool := x509.NewCertPool()
	pool.AddCert(a.nodeCA.Cert)
	grace := time.Duration(a.General(ctx).NodeGraceDays) * 24 * time.Hour
	now := time.Now()
	expired := false
	if now.After(leaf.NotAfter) {
		if now.After(leaf.NotAfter.Add(grace)) {
			return nil, errors.New("client certificate expired beyond grace period; re-enrollment required")
		}
		expired = true
		now = leaf.NotAfter.Add(-time.Second)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fmt.Errorf("client certificate rejected: %w", err)
	}
	id := &nodeIdentity{ID: leaf.Subject.CommonName, Expired: expired}
	serial := pki.SerialHex(leaf)
	var status, cur, prev string
	err := a.St.DB.QueryRow(ctx, `SELECT n.site_id::text, s.tenant_id::text, n.name, n.status, n.cert_serial, n.prev_cert_serial FROM nodes n JOIN sites s ON s.id=n.site_id WHERE n.id::text=$1`, id.ID).
		Scan(&id.SiteID, &id.TenantID, &id.Name, &status, &cur, &prev)
	if err != nil {
		return nil, errors.New("unknown node")
	}
	if status != "active" {
		return nil, fmt.Errorf("node is %s", status)
	}
	if serial != cur && serial != prev {
		return nil, errors.New("certificate has been superseded")
	}
	if serial == cur && prev != "" {
		a.St.DB.Exec(ctx, `UPDATE nodes SET prev_cert_serial='' WHERE id::text=$1`, id.ID) // new cert proven in use
	}
	return id, nil
}

func (a *App) handleConn(ctx context.Context, conn *quic.Conn) {
	defer conn.CloseWithError(0, "")
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	st, err := conn.AcceptStream(cctx)
	if err != nil {
		return
	}
	defer st.Close()
	st.SetDeadline(time.Now().Add(90 * time.Second))
	var req proto.Request
	if err := proto.Read(st, &req); err != nil {
		return
	}
	remote := hostOnly(conn.RemoteAddr().String())
	resp := a.dispatch(cctx, conn.ConnectionState().TLS.PeerCertificates, remote, &req)
	if err := proto.Write(st, resp); err != nil {
		return
	}
	st.Close()
	// closing the connection immediately would discard unacknowledged response data; let the node hang up first
	select {
	case <-conn.Context().Done():
	case <-time.After(5 * time.Second):
	}
}

func (a *App) dispatch(ctx context.Context, certs []*x509.Certificate, remote string, req *proto.Request) *proto.Response {
	fail := func(err error) *proto.Response {
		a.Log.Printf("node request from %s (%s): %v", remote, req.Type, err)
		return &proto.Response{Error: err.Error()}
	}
	switch req.Type {
	case "enroll":
		if req.Enroll == nil {
			return fail(errBadRequest)
		}
		r, err := a.enroll(ctx, req.Enroll, remote)
		if err != nil {
			return fail(err)
		}
		return &proto.Response{OK: true, Enroll: r}
	case "checkin":
		id, err := a.authenticate(ctx, certs)
		if err != nil {
			return fail(err)
		}
		if id == nil || req.Checkin == nil {
			return fail(errors.New("client certificate required"))
		}
		r, err := a.checkin(ctx, id, req.Checkin, remote)
		if err != nil {
			return fail(err)
		}
		return &proto.Response{OK: true, Checkin: r}
	}
	return fail(errBadRequest)
}

func (a *App) signNodeCert(nodeID, csrPEM string) (certPEM string, serial string, notAfter time.Time, err error) {
	csr, err := pki.ParseCSR([]byte(csrPEM))
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("invalid CSR: %w", err)
	}
	days := a.General(context.Background()).NodeCertDays
	p, c, err := a.nodeCA.Sign(csr.PublicKey, pki.SignOpts{CommonName: nodeID, Validity: time.Duration(days) * 24 * time.Hour, Client: true})
	if err != nil {
		return "", "", time.Time{}, err
	}
	return string(p), pki.SerialHex(c), c.NotAfter, nil
}

func (a *App) enroll(ctx context.Context, r *proto.EnrollReq, remote string) (*proto.EnrollResp, error) {
	if r.Token == "" {
		return nil, errors.New("missing enrollment token")
	}
	var id string
	var exp *time.Time
	err := a.St.DB.QueryRow(ctx, `SELECT id::text, token_expires FROM nodes WHERE token_hash=$1 AND status='pending'`, hashToken(r.Token)).Scan(&id, &exp)
	if err != nil || exp == nil || time.Now().After(*exp) {
		return nil, errors.New("enrollment token invalid or expired")
	}
	cert, serial, na, err := a.signNodeCert(id, r.CSR)
	if err != nil {
		return nil, err
	}
	tag, err := a.St.DB.Exec(ctx, `UPDATE nodes SET status='active', token_hash='', token_enc='', token_expires=NULL, cert_serial=$2, prev_cert_serial='',
		cert_not_after=$3, hostname=$4, os=$5, version=$6, last_addr=$7, last_seen=now() WHERE id::text=$1 AND status='pending'`,
		id, serial, na, r.Hostname, r.OS+"/"+r.Arch, r.Version, remote)
	if err != nil || tag.RowsAffected() == 0 {
		return nil, errors.New("enrollment failed")
	}
	a.Audit(ctx, "node:"+id, "node.enroll", fmt.Sprintf("host=%s os=%s/%s from %s", r.Hostname, r.OS, r.Arch, remote))
	return &proto.EnrollResp{NodeID: id, Cert: cert}, nil
}

func (a *App) checkin(ctx context.Context, id *nodeIdentity, r *proto.CheckinReq, remote string) (*proto.CheckinResp, error) {
	resp := &proto.CheckinResp{ServerTime: time.Now().UTC()}
	g := a.General(ctx)
	resp.IntervalSeconds = g.NodeIntervalSecs

	if len(r.Events) > 0 {
		acked, err := a.storeEvents(ctx, id, r.Events)
		if err != nil {
			return nil, fmt.Errorf("storing events: %w", err)
		}
		resp.AckedSeq = acked
	}

	var newSerial string
	var newNotAfter time.Time
	if r.RenewCSR != "" {
		cert, serial, na, err := a.signNodeCert(id.ID, r.RenewCSR)
		if err != nil {
			return nil, err
		}
		resp.Cert, newSerial, newNotAfter = cert, serial, na
	}

	cfg, cfgErr := a.BuildNodeConfig(ctx, id.SiteID, id.ID)
	if cfgErr == nil {
		resp.ConfigHash = proto.HashConfig(cfg)
		if resp.ConfigHash != r.ConfigHash {
			resp.Config = cfg
		}
	}

	stats, _ := json.Marshal(r.Stats)
	crls, _ := json.Marshal(r.CRLStatus)
	_, err := a.St.DB.Exec(ctx, `UPDATE nodes SET last_seen=now(), last_addr=$2, version=$3, os=COALESCE(NULLIF($4,''),os), hostname=$5, config_hash=$6, stats=$7, crl_status=$8 WHERE id::text=$1`,
		id.ID, remote, r.Version, r.OS, r.Hostname, r.ConfigHash, stats, crls)
	if err != nil {
		return nil, err
	}
	if newSerial != "" {
		_, err = a.St.DB.Exec(ctx, `UPDATE nodes SET prev_cert_serial=cert_serial, cert_serial=$2, cert_not_after=$3 WHERE id::text=$1`, id.ID, newSerial, newNotAfter)
		if err != nil {
			return nil, err
		}
		a.Audit(ctx, "node:"+id.ID, "node.cert_renewed", "client certificate renewed, expires "+newNotAfter.Format("2006-01-02"))
	}
	if cfgErr != nil {
		a.Log.Printf("node %s: cannot build config: %v", id.ID, cfgErr)
	}
	return resp, nil
}

var _ = net.IP{}
