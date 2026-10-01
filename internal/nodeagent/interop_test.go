package nodeagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"radman/internal/proto"
)

// TestInteropServe starts a server for manual interop testing against eapol_test:
//
//	RADMAN_INTEROP_DIR=/tmp/x go test -run TestInteropServe ./internal/nodeagent
func TestInteropServe(t *testing.T) {
	dir := os.Getenv("RADMAN_INTEROP_DIR")
	if dir == "" {
		t.Skip("set RADMAN_INTEROP_DIR to run")
	}
	testAP, testListen = "0.0.0.0/0", "0.0.0.0:18120"
	defer func() { testAP, testListen = "127.0.0.0/8", "127.0.0.1:0" }()
	e := newEnv(t, proto.Policy{DefaultAction: "allow", DefaultVLAN: "30"}, nil)
	cert, _ := e.clientCert(t, e.ca, "interop-laptop")
	_ = cert
	k, _ := os.ReadFile("/dev/null")
	_ = k
	// write PEMs for the supplicant
	cpem, kpem := e.issuePEM(t, "interop-laptop")
	os.WriteFile(filepath.Join(dir, "client.crt"), cpem, 0o600)
	os.WriteFile(filepath.Join(dir, "client.key"), kpem, 0o600)
	// trust anchor for server cert = the EAP CA (last cert in srvCert bundle)
	idx := strings.LastIndex(string(e.srvCert), "-----BEGIN CERTIFICATE-----")
	os.WriteFile(filepath.Join(dir, "eapca.pem"), e.srvCert[idx:], 0o600)
	os.WriteFile(filepath.Join(dir, "ready"), nil, 0o600)
	time.Sleep(90 * time.Second)
}
