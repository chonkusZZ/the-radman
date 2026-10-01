package nodeagent

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"layeh.com/radius"

	"radman/internal/eaptest"
	"radman/internal/pki"
	"radman/internal/proto"
)

func TestRadSec(t *testing.T) {
	e := newEnv(t, proto.Policy{DefaultAction: "allow", DefaultVLAN: "5"}, nil)

	// RadSec CA + AP certificates
	cap, ckp, _ := pki.NewCA("RadSec CA", time.Hour)
	rsCA, _ := pki.LoadCA(cap, ckp)
	apCert := func(ca *pki.CA) (tls.Certificate, string) {
		k, _ := pki.GenerateKey()
		cp, c, err := ca.Sign(&k.PublicKey, pki.SignOpts{CommonName: "ap-hall", Validity: time.Hour, Client: true})
		if err != nil {
			t.Fatal(err)
		}
		kp, _ := pki.EncodeKey(k)
		tc, _ := tls.X509KeyPair(cp, kp)
		return tc, pki.SerialHex(c)
	}
	good, goodSerial := apCert(rsCA)
	revoked, _ := apCert(rsCA) // valid chain but serial not in the active list
	otherCAPem, otherKey, _ := pki.NewCA("Other CA", time.Hour)
	otherCA, _ := pki.LoadCA(otherCAPem, otherKey)
	stranger, _ := apCert(otherCA)

	cfg := *e.srv.Runtime().Cfg
	cfg.RadSecPort = 1
	cfg.RadSecCA = string(cap)
	cfg.APs = []proto.AP{{Name: "Hall AP", Addr: "192.0.2.1", Secret: "x", RadSecSerials: []string{goodSerial}}}
	rt, err := BuildRuntime(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetRuntime(rt)
	if err := e.srv.listenRadSec("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	addr := e.srv.radsecLn.Addr().String()

	dev, _ := e.clientCert(t, e.ca, "phone-1")
	supp := e.tlsClient(dev, tls.VersionTLS13)
	serverRoots := e.serverRoots() // AP trusts the node's server certificate chain
	apTLS := func(c tls.Certificate) *tls.Config {
		return &tls.Config{Certificates: []tls.Certificate{c}, RootCAs: serverRoots, ServerName: "radius.test", MinVersion: tls.VersionTLS12}
	}

	// valid AP: full EAP-TLS over RadSec, VLAN returned, AP identified by its certificate (the source IP is irrelevant)
	res, err := eaptest.AuthenticateRadSec(addr, "phone-1", apTLS(good), supp)
	if err != nil || res.Code != radius.CodeAccessAccept {
		t.Fatalf("RadSec auth: %v %+v", err, res)
	}
	e.mu.Lock()
	ev := e.events[len(e.events)-1]
	e.mu.Unlock()
	if ev["ap"] != "Hall AP" || ev["result"] != "accept" || ev["vlan"] != "5" {
		t.Fatalf("event: %+v", ev)
	}

	// certificates not in the active list, or from another CA, never get past the handshake.
	// (TLS 1.3 reports client-certificate failures on the first read, so exercise a request.)
	for name, c := range map[string]tls.Certificate{"revoked/unregistered": revoked, "foreign CA": stranger} {
		if r, err := eaptest.AuthenticateRadSec(addr, "x", apTLS(c), supp); err == nil {
			t.Fatalf("%s AP certificate accepted: %+v", name, r)
		}
	}
	_ = x509.NewCertPool
}
