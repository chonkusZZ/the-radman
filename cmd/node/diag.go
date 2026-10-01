package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"

	"layeh.com/radius"

	"radman/internal/eaptest"
)

// runEAPTest performs one EAP-TLS authentication against a RADIUS server, acting as a supplicant.
func runEAPTest(args []string) {
	fs := flag.NewFlagSet("eaptest", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:1812", "RADIUS server")
	secret := fs.String("secret", "", "shared secret")
	certF := fs.String("cert", "", "client certificate PEM (with chain)")
	keyF := fs.String("key", "", "client key PEM")
	caF := fs.String("ca", "", "CA PEM that signed the RADIUS server certificate (omit to skip server validation)")
	id := fs.String("identity", "eaptest", "EAP identity")
	fs.Parse(args)
	if *secret == "" || *certF == "" || *keyF == "" {
		fs.Usage()
		os.Exit(2)
	}
	cert, err := tls.LoadX509KeyPair(*certF, *keyF)
	check(err)
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, InsecureSkipVerify: *caF == ""}
	if *caF != "" {
		pem, err := os.ReadFile(*caF)
		check(err)
		tc.RootCAs = x509.NewCertPool()
		tc.RootCAs.AppendCertsFromPEM(pem)
		tc.ServerName = "" // verified by chain only; names are the operator's concern here
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			inter := x509.NewCertPool()
			for _, r := range raw[1:] {
				if c, err := x509.ParseCertificate(r); err == nil {
					inter.AddCert(c)
				}
			}
			_, err = leaf.Verify(x509.VerifyOptions{Roots: tc.RootCAs, Intermediates: inter})
			return err
		}
	}
	res, err := eaptest.Authenticate(*server, *secret, *id, tc)
	check(err)
	defer res.Client.Close()
	fmt.Println("result:", res.Code)
	if res.Code != radius.CodeAccessAccept {
		os.Exit(1)
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
