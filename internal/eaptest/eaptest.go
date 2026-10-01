// Package eaptest is a minimal EAP-TLS supplicant + RADIUS client for diagnostics and tests.
package eaptest

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"

	"radman/internal/eaptls"
)

// Result of one authentication.
type Result struct {
	Code   radius.Code
	Final  *radius.Packet
	Client *eaptls.Client
}

// transport sends one encoded RADIUS request and returns the encoded response.
type transport func(wire []byte) ([]byte, error)

// Authenticate performs a full EAP-TLS exchange against a UDP RADIUS server (host:port).
func Authenticate(server, secret, identity string, tc *tls.Config) (*Result, error) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return run([]byte(secret), identity, tc, func(wire []byte) ([]byte, error) {
		if _, err := conn.Write(wire); err != nil {
			return nil, err
		}
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		return buf[:n], err
	})
}

// AuthenticateRadSec does the same over RADIUS/TLS (RadSec) using apTLS as the access point's identity.
func AuthenticateRadSec(server, identity string, apTLS, tc *tls.Config) (*Result, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", server, apTLS)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return run([]byte("radsec"), identity, tc, func(wire []byte) ([]byte, error) {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(wire); err != nil {
			return nil, err
		}
		var hdr [4]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return nil, err
		}
		buf := make([]byte, binary.BigEndian.Uint16(hdr[2:4]))
		copy(buf, hdr[:])
		_, err := io.ReadFull(conn, buf[4:])
		return buf, err
	})
}

func run(sec []byte, identity string, tc *tls.Config, send transport) (*Result, error) {
	cl := eaptls.NewClient(tc)
	exchange := func(eap, state []byte) (*radius.Packet, error) {
		p := radius.New(radius.CodeAccessRequest, sec)
		rfc2865.UserName_SetString(p, identity)
		rfc2865.CallingStationID_SetString(p, "02-00-00-00-00-01")
		rfc2865.CalledStationID_SetString(p, "00-11-22-33-44-55:corp")
		rfc2869.EAPMessage_Set(p, eap)
		if state != nil {
			rfc2865.State_Set(p, state)
		}
		rfc2869.MessageAuthenticator_Set(p, make([]byte, 16))
		b, _ := p.MarshalBinary()
		m := hmac.New(md5.New, sec)
		m.Write(b)
		rfc2869.MessageAuthenticator_Set(p, m.Sum(nil))
		wire, _ := p.Encode()
		resp, err := send(wire)
		if err != nil {
			return nil, err
		}
		if !radius.IsAuthenticResponse(resp, wire, sec) {
			return nil, errors.New("invalid response authenticator (shared secret mismatch?)")
		}
		return radius.Parse(resp, sec)
	}

	resp, err := exchange(eaptls.Marshal(eaptls.CodeResponse, 1, eaptls.TypeIdentity, []byte(identity)), nil)
	for i := 0; err == nil && i < 64 && resp.Code == radius.CodeAccessChallenge; i++ {
		out, st, cerr := cl.Step(rfc2869.EAPMessage_Get(resp))
		if out == nil {
			cl.Close()
			if cerr == nil {
				cerr = errors.New("supplicant stopped in state " + map[eaptls.State]string{eaptls.Continue: "continue", eaptls.Success: "success", eaptls.Failure: "failure"}[st])
			}
			return nil, cerr
		}
		resp, err = exchange(out, rfc2865.State_Get(resp))
	}
	if err != nil {
		cl.Close()
		return nil, err
	}
	return &Result{Code: resp.Code, Final: resp, Client: cl}, nil
}
