// Package netguard provides an HTTP client that refuses to connect to the local network, for
// fetching URLs that administrators (who may not be fully trusted, e.g. a tenant admin in an MSP
// deployment) supply: SAML IdP metadata, CRL distribution points. Without this guard, such a URL
// is a server-side request forgery vector into whatever network the fetching process sits on.
package netguard

import (
	"errors"
	"net"
	"syscall"
	"time"

	"net/http"
)

// Client returns an http.Client whose dialer refuses loopback, link-local and (unless allowPrivate)
// RFC1918/CGNAT addresses. The check runs against the address actually dialed (post-DNS-resolution),
// so it cannot be bypassed by DNS rebinding.
func Client(allowPrivate bool) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, _ := net.SplitHostPort(address)
		return Blocked(net.ParseIP(host), allowPrivate)
	}}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DialContext: d.DialContext}}
}

// Blocked decides whether an outbound connection to ip should be refused.
func Blocked(ip net.IP, allowPrivate bool) error {
	if ip == nil {
		return errors.New("refusing to connect")
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("refusing to fetch from a loopback/link-local address")
	}
	if !allowPrivate {
		if ip.IsPrivate() {
			return errors.New("refusing to fetch from a private network address")
		}
		if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 { // 100.64.0.0/10 carrier-grade NAT
			return errors.New("refusing to fetch from a private network address")
		}
	}
	return nil
}
