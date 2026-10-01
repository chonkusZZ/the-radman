package nodeagent

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/vendors/microsoft"

	"radman/internal/crl"
	"radman/internal/eaptls"
	"radman/internal/pki"
)

// EventSink receives auth/accounting events.
type EventSink func(kind string, data map[string]string)

type authSession struct {
	mu       sync.Mutex
	eap      *eaptls.Session
	rt       *Runtime
	identity string
	started  time.Time
	touched  time.Time
	// filled by the TLS verify callback
	leaf   *x509.Certificate
	dec    crl.Decision
	verr   error
	apName string
}

// Server is the RADIUS auth+acct endpoint of a node.
type Server struct {
	rt          atomic.Pointer[Runtime]
	sink        EventSink
	sessions    sync.Map // state -> *authSession
	Accepts     atomic.Uint64
	Rejects     atomic.Uint64
	servers     []*radius.PacketServer
	radsecLn    net.Listener
	radsecConns sync.Map // net.Conn -> certificate serial
	stop        chan struct{}
	log         *log.Logger
	AuthAddr    net.Addr
}

func NewServer(sink EventSink, l *log.Logger) *Server {
	return &Server{sink: sink, stop: make(chan struct{}), log: l}
}

func (s *Server) SetRuntime(rt *Runtime) {
	s.rt.Store(rt)
	// drop RadSec connections whose AP certificate was revoked or removed by this config
	s.radsecConns.Range(func(k, v any) bool {
		if _, ok := rt.radsecSerials[v.(string)]; !ok {
			k.(net.Conn).Close()
		}
		return true
	})
}
func (s *Server) Runtime() *Runtime { return s.rt.Load() }

type secretSource struct{ s *Server }

func (ss secretSource) RADIUSSecret(ctx context.Context, a net.Addr) ([]byte, error) {
	rt := ss.s.rt.Load()
	if rt == nil {
		return nil, nil
	}
	udp, ok := a.(*net.UDPAddr)
	if !ok {
		return nil, nil
	}
	if ap := rt.LookupAP(udp.IP); ap != nil {
		return ap.secret, nil
	}
	ss.s.log.Printf("dropping packet from unknown AP %s", udp.IP)
	return nil, nil
}

// ListenAndServe starts auth and accounting listeners. It returns once both are bound.
func (s *Server) ListenAndServe(authAddr, acctAddr string) error {
	return s.ListenAndServeRadSec(authAddr, acctAddr, "")
}

// ListenAndServeRadSec additionally starts a RadSec (RADIUS over TLS, TCP) listener when radsecAddr is set.
func (s *Server) ListenAndServeRadSec(authAddr, acctAddr, radsecAddr string) error {
	authConn, err := net.ListenPacket("udp", authAddr)
	if err != nil {
		return err
	}
	acctConn, err := net.ListenPacket("udp", acctAddr)
	if err != nil {
		authConn.Close()
		return err
	}
	s.AuthAddr = authConn.LocalAddr()
	auth := &radius.PacketServer{SecretSource: secretSource{s}, Handler: radius.HandlerFunc(s.handleAuth), ErrorLog: s.log}
	acct := &radius.PacketServer{SecretSource: secretSource{s}, Handler: radius.HandlerFunc(s.handleAcct), ErrorLog: s.log}
	s.servers = []*radius.PacketServer{auth, acct}
	go auth.Serve(authConn)
	go acct.Serve(acctConn)
	go s.reaper()
	s.log.Printf("RADIUS listening: auth %s, acct %s", authAddr, acctAddr)
	if radsecAddr != "" {
		if err := s.listenRadSec(radsecAddr); err != nil {
			s.Shutdown()
			return err
		}
	}
	return nil
}

func (s *Server) Shutdown() {
	close(s.stop)
	if s.radsecLn != nil {
		s.radsecLn.Close()
	}
	for _, sv := range s.servers {
		sv.Shutdown(context.Background())
	}
}

func (s *Server) reaper() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.sessions.Range(func(k, v any) bool {
				as := v.(*authSession)
				as.mu.Lock()
				old := time.Since(as.touched) > 60*time.Second
				as.mu.Unlock()
				if old {
					as.eap.Close()
					s.sessions.Delete(k)
				}
				return true
			})
		}
	}
}

func verifyMA(p *radius.Packet, secret []byte) bool {
	got := rfc2869.MessageAuthenticator_Get(p)
	if got == nil {
		return false
	}
	q := &radius.Packet{Code: p.Code, Identifier: p.Identifier, Authenticator: p.Authenticator}
	for _, avp := range p.Attributes {
		a := avp.Attribute
		if avp.Type == rfc2869.MessageAuthenticator_Type {
			a = make(radius.Attribute, 16)
		}
		q.Attributes = append(q.Attributes, &radius.AVP{Type: avp.Type, Attribute: a})
	}
	b, err := q.MarshalBinary()
	if err != nil {
		return false
	}
	m := hmac.New(md5.New, secret)
	m.Write(b)
	return hmac.Equal(m.Sum(nil), got)
}

// send finalises Message-Authenticator and writes the response.
func send(w radius.ResponseWriter, resp *radius.Packet) {
	rfc2869.MessageAuthenticator_Set(resp, make([]byte, 16))
	b, err := resp.MarshalBinary() // authenticator == request authenticator
	if err == nil {
		m := hmac.New(md5.New, resp.Secret)
		m.Write(b)
		rfc2869.MessageAuthenticator_Set(resp, m.Sum(nil))
	}
	w.Write(resp)
}

func (s *Server) tlsConfig(rt *Runtime, as *authSession) *tls.Config {
	return &tls.Config{
		Certificates:           []tls.Certificate{rt.Cert},
		MinVersion:             tls.VersionTLS12,
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			err := s.verifyClient(rt, as, raw)
			as.verr = err
			return err
		},
	}
}

func (s *Server) verifyClient(rt *Runtime, as *authSession, raw [][]byte) error {
	if len(raw) == 0 {
		return errors.New("no client certificate presented")
	}
	var certs []*x509.Certificate
	for _, r := range raw {
		c, err := x509.ParseCertificate(r)
		if err != nil {
			return fmt.Errorf("unparseable client certificate: %w", err)
		}
		certs = append(certs, c)
	}
	leaf := certs[0]
	as.leaf = leaf
	if len(rt.PKIs) == 0 {
		return errors.New("no PKI profile configured for this site")
	}
	var errs []string
	for _, st := range rt.PKIs {
		if _, err := st.Verify(leaf, certs[1:], time.Now()); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", st.Cfg.Name, err))
			continue
		}
		d := crl.Evaluate(rt.Cfg.Policy, leaf, st.Cfg.Name)
		as.dec = d
		if !d.Allow {
			return errors.New(d.Reason)
		}
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}

func (s *Server) handleAuth(w radius.ResponseWriter, r *radius.Request) {
	rt := s.rt.Load()
	if rt == nil {
		return
	}
	p := r.Packet
	secret := p.Secret
	if p.Code != radius.CodeAccessRequest {
		return
	}
	eapRaw := rfc2869.EAPMessage_Get(p)
	if eapRaw == nil {
		s.reject(w, p, nil, "only EAP-TLS is supported")
		return
	}
	if !verifyMA(p, secret) {
		s.log.Printf("bad Message-Authenticator from %s", r.RemoteAddr)
		return
	}
	apName, _ := r.Context().Value(apNameKey).(string)
	if apName == "" {
		if ap := rt.LookupAP(ipOf(r.RemoteAddr)); ap != nil {
			apName = ap.name
		}
	}
	ep, err := eaptls.ParsePacket(eapRaw)
	if err != nil {
		return
	}

	var as *authSession
	if st := rfc2865.State_Get(p); len(st) > 0 {
		if v, ok := s.sessions.Load(string(st)); ok {
			as = v.(*authSession)
		}
	}

	if ep.Code == eaptls.CodeResponse && ep.Type == eaptls.TypeIdentity {
		if as != nil {
			as.eap.Close()
		}
		as = &authSession{rt: rt, started: time.Now(), apName: apName, identity: string(ep.Data)}
		as.eap = eaptls.NewSession(s.tlsConfig(rt, as))
		sid := make([]byte, 16)
		rand.Read(sid)
		s.sessions.Store(string(sid), as)
		as.touched = time.Now()
		resp := p.Response(radius.CodeAccessChallenge)
		rfc2869.EAPMessage_Set(resp, as.eap.Start(ep.ID+1))
		rfc2865.State_Set(resp, sid)
		send(w, resp)
		return
	}
	if as == nil {
		s.reject(w, p, nil, "unknown or expired session")
		return
	}

	as.mu.Lock()
	defer as.mu.Unlock()
	as.touched = time.Now()
	out, state, serr := as.eap.Step(eapRaw)
	if out == nil && state == eaptls.Continue {
		return // duplicate; drop
	}
	switch state {
	case eaptls.Continue:
		resp := p.Response(radius.CodeAccessChallenge)
		rfc2869.EAPMessage_Set(resp, out)
		rfc2865.State_Set(resp, rfc2865.State_Get(p))
		send(w, resp)
	case eaptls.Success:
		resp := p.Response(radius.CodeAccessAccept)
		rfc2869.EAPMessage_Set(resp, out)
		msk := as.eap.Res.MSK
		microsoft.MSMPPERecvKey_Add(resp, msk[:32])
		microsoft.MSMPPESendKey_Add(resp, msk[32:64])
		if rfc2865.UserName_Get(p) != nil {
			rfc2865.UserName_Set(resp, rfc2865.UserName_Get(p))
		}
		if v := as.dec.VLAN; v != "" {
			rfc2868.TunnelType_Set(resp, 0, rfc2868.TunnelType(13))
			rfc2868.TunnelMediumType_Set(resp, 0, rfc2868.TunnelMediumType_Value_IEEE802)
			rfc2868.TunnelPrivateGroupID_SetString(resp, 0, v)
		}
		send(w, resp)
		s.Accepts.Add(1)
		s.record(as, p, "accept", "", r)
		as.eap.Close()
		s.sessions.Range(func(k, v any) bool {
			if v == as {
				s.sessions.Delete(k)
			}
			return true
		})
	case eaptls.Failure:
		reason := ""
		if as.verr != nil {
			reason = as.verr.Error()
		} else if serr != nil {
			reason = serr.Error()
		}
		resp := p.Response(radius.CodeAccessReject)
		rfc2869.EAPMessage_Set(resp, out)
		send(w, resp)
		s.Rejects.Add(1)
		s.record(as, p, "reject", reason, r)
		as.eap.Close()
		s.sessions.Range(func(k, v any) bool {
			if v == as {
				s.sessions.Delete(k)
			}
			return true
		})
	}
}

func (s *Server) reject(w radius.ResponseWriter, p *radius.Packet, as *authSession, reason string) {
	resp := p.Response(radius.CodeAccessReject)
	rfc2869.EAPMessage_Set(resp, []byte{eaptls.CodeFailure, 0, 0, 4})
	send(w, resp)
	s.Rejects.Add(1)
}

func (s *Server) record(as *authSession, p *radius.Packet, result, reason string, r *radius.Request) {
	d := map[string]string{
		"result":      result,
		"reason":      reason,
		"identity":    as.identity,
		"ap":          as.apName,
		"nas_ip":      ipOf(r.RemoteAddr).String(),
		"client_mac":  rfc2865.CallingStationID_GetString(p),
		"ssid":        rfc2865.CalledStationID_GetString(p),
		"vlan":        as.dec.VLAN,
		"rule":        as.dec.Rule,
		"pki":         as.dec.PKI,
		"duration_ms": fmt.Sprint(time.Since(as.started).Milliseconds()),
	}
	if as.leaf != nil {
		d["subject"] = as.leaf.Subject.CommonName
		d["serial"] = pki.SerialHex(as.leaf)
		d["issuer"] = as.leaf.Issuer.CommonName
		d["san"] = strings.Join(crl.SANs(as.leaf), ",")
	}
	s.sink("auth", d)
}

func (s *Server) handleAcct(w radius.ResponseWriter, r *radius.Request) {
	p := r.Packet
	if p.Code != radius.CodeAccountingRequest {
		return
	}
	d := map[string]string{
		"status":        rfc2866.AcctStatusType_Get(p).String(),
		"session_id":    rfc2866.AcctSessionID_GetString(p),
		"user":          rfc2865.UserName_GetString(p),
		"client_mac":    rfc2865.CallingStationID_GetString(p),
		"ssid":          rfc2865.CalledStationID_GetString(p),
		"nas_ip":        ipOf(r.RemoteAddr).String(),
		"session_time":  fmt.Sprint(rfc2866.AcctSessionTime_Get(p)),
		"in_octets":     fmt.Sprint(rfc2866.AcctInputOctets_Get(p)),
		"out_octets":    fmt.Sprint(rfc2866.AcctOutputOctets_Get(p)),
		"in_gigawords":  fmt.Sprint(rfc2869.AcctInputGigawords_Get(p)),
		"out_gigawords": fmt.Sprint(rfc2869.AcctOutputGigawords_Get(p)),
		"terminate":     rfc2866.AcctTerminateCause_Get(p).String(),
	}
	if name, _ := r.Context().Value(apNameKey).(string); name != "" {
		d["ap"] = name
	} else if rt := s.rt.Load(); rt != nil {
		if ap := rt.LookupAP(ipOf(r.RemoteAddr)); ap != nil {
			d["ap"] = ap.name
		}
	}
	s.sink("acct", d)
	w.Write(p.Response(radius.CodeAccountingResponse))
}
