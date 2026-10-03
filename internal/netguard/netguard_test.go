package netguard

import (
	"net"
	"testing"
)

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
		err := Blocked(net.ParseIP(c.ip), c.private)
		if (err != nil) != c.blocked {
			t.Errorf("%s allowPrivate=%v: blocked=%v want %v (%v)", c.ip, c.private, err != nil, c.blocked, err)
		}
	}
	if Blocked(nil, true) == nil {
		t.Error("unparseable address must be refused")
	}
}
