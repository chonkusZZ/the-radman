package manager

import (
	"net"
	"testing"
)

func TestValidateSVG(t *testing.T) {
	ok := []string{
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#14f2af"/></svg>`,
		`<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg xmlns="http://www.w3.org/2000/svg"><style>.a{fill:red}</style><use href="#a"/></svg>`,
	}
	bad := map[string]string{
		"script":        `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`,
		"onload":        `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`,
		"js href":       `<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><rect/></a></svg>`,
		"external href": `<svg xmlns="http://www.w3.org/2000/svg"><image href="http://evil.example/x.png"/></svg>`,
		"foreignObject": `<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div/></foreignObject></svg>`,
		"entity":        `<!DOCTYPE svg [<!ENTITY x "y">]><svg xmlns="http://www.w3.org/2000/svg"/>`,
		"not svg":       `<html><body/></html>`,
		"not xml":       `GIF89a`,
		"animate":       `<svg xmlns="http://www.w3.org/2000/svg"><a><animate attributeName="href" values="javascript:alert(1)"/></a></svg>`,
	}
	for i, s := range ok {
		if err := validateSVG([]byte(s)); err != nil {
			t.Errorf("valid #%d rejected: %v", i, err)
		}
	}
	for name, s := range bad {
		if err := validateSVG([]byte(s)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestOutboundAddressGuard(t *testing.T) {
	cases := []struct {
		ip      string
		private bool // allowPrivate
		blocked bool
	}{
		{"127.0.0.1", true, true}, {"::1", true, true}, {"169.254.169.254", true, true}, {"0.0.0.0", true, true}, {"224.0.0.1", true, true},
		{"10.1.2.3", false, true}, {"172.16.0.9", false, true}, {"192.168.1.1", false, true}, {"100.64.0.1", false, true}, {"fd00::1", false, true},
		{"10.1.2.3", true, false}, {"192.168.1.1", true, false},
		{"93.184.216.34", false, false}, {"2606:2800:220:1:248:1893:25c8:1946", false, false},
	}
	for _, c := range cases {
		err := blockedAddr(net.ParseIP(c.ip), c.private)
		if (err != nil) != c.blocked {
			t.Errorf("%s allowPrivate=%v: blocked=%v want %v (%v)", c.ip, c.private, err != nil, c.blocked, err)
		}
	}
	if blockedAddr(nil, true) == nil {
		t.Error("unparseable address must be refused")
	}
}
