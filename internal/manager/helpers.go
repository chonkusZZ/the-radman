package manager

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/url"

	"github.com/pquerna/otp"
	"regexp"
	"strings"
)

func pkiParseAddr(a string) bool {
	if strings.Contains(a, "/") {
		_, _, err := net.ParseCIDR(a)
		return err == nil
	}
	return net.ParseIP(a) != nil
}

func compileCheck(expr string) error { _, err := regexp.Compile(expr); return err }

func otpFromSecret(email, secret string) (*otp.Key, error) {
	return otp.NewKeyFromURL("otpauth://totp/RadMAN:" + url.PathEscape(email) + "?secret=" + secret + "&issuer=RadMAN")
}

func context_bg() context.Context { return context.Background() }

func tlsPair(certPEM, keyPEM string) (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
}

func jsonOf(v any) []byte { b, _ := json.Marshal(v); return b }
