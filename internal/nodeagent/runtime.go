package nodeagent

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"

	"radman/internal/crl"
	"radman/internal/proto"
)

type apEntry struct {
	name   string
	ip     net.IP
	net    *net.IPNet
	secret []byte
}

// Runtime is a compiled, immutable snapshot of the site configuration.
type Runtime struct {
	Cfg  *proto.SiteConfig
	Hash string
	PKIs []*crl.PKIState
	Cert tls.Certificate
	aps  []apEntry

	radsecPool    *x509.CertPool
	radsecSerials map[string]string // active AP certificate serial -> AP name
}

func HashConfig(c *proto.SiteConfig) string { return proto.HashConfig(c) }

func BuildRuntime(cfg *proto.SiteConfig) (*Runtime, error) {
	rt := &Runtime{Cfg: cfg, Hash: HashConfig(cfg)}
	cert, err := tls.X509KeyPair([]byte(cfg.EAPCert), []byte(cfg.EAPKey))
	if err != nil {
		return nil, fmt.Errorf("EAP server certificate: %w", err)
	}
	rt.Cert = cert
	for _, p := range cfg.PKI {
		st, err := crl.Compile(p)
		if err != nil {
			return nil, err
		}
		rt.PKIs = append(rt.PKIs, st)
	}
	if cfg.RadSecPort > 0 {
		rt.radsecPool = x509.NewCertPool()
		if !rt.radsecPool.AppendCertsFromPEM([]byte(cfg.RadSecCA)) {
			return nil, fmt.Errorf("RadSec CA certificate is invalid")
		}
		rt.radsecSerials = map[string]string{}
		for _, ap := range cfg.APs {
			for _, sn := range ap.RadSecSerials {
				rt.radsecSerials[strings.ToLower(sn)] = ap.Name
			}
		}
	}
	for _, ap := range cfg.APs {
		e := apEntry{name: ap.Name, secret: []byte(ap.Secret)}
		addr := strings.TrimSpace(ap.Addr)
		if strings.Contains(addr, "/") {
			_, n, err := net.ParseCIDR(addr)
			if err != nil {
				return nil, fmt.Errorf("AP %q: %w", ap.Name, err)
			}
			e.net = n
		} else if e.ip = net.ParseIP(addr); e.ip == nil {
			return nil, fmt.Errorf("AP %q: invalid address %q", ap.Name, addr)
		}
		rt.aps = append(rt.aps, e)
	}
	return rt, nil
}

// LookupAP returns the AP entry for a source address (exact IP beats CIDR; longest prefix wins).
func (rt *Runtime) LookupAP(ip net.IP) *apEntry {
	var best *apEntry
	bestBits := -1
	for i := range rt.aps {
		e := &rt.aps[i]
		if e.ip != nil && e.ip.Equal(ip) {
			return e
		}
		if e.net != nil && e.net.Contains(ip) {
			if ones, _ := e.net.Mask.Size(); ones > bestBits {
				best, bestBits = e, ones
			}
		}
	}
	return best
}
