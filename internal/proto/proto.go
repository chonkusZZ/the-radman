// Package proto defines the manager<->node wire protocol (JSON over QUIC streams).
package proto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const (
	ALPN        = "radman/1"
	MaxMsgBytes = 16 << 20
)

// Request is sent by a node on a fresh bidirectional stream.
type Request struct {
	Type    string      `json:"type"` // "enroll" | "checkin"
	Enroll  *EnrollReq  `json:"enroll,omitempty"`
	Checkin *CheckinReq `json:"checkin,omitempty"`
}

type Response struct {
	OK      bool         `json:"ok"`
	Error   string       `json:"error,omitempty"`
	Enroll  *EnrollResp  `json:"enroll,omitempty"`
	Checkin *CheckinResp `json:"checkin,omitempty"`
}

type EnrollReq struct {
	Token    string `json:"token"`
	CSR      string `json:"csr"` // PEM
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
}

type EnrollResp struct {
	NodeID string `json:"node_id"`
	Cert   string `json:"cert"` // PEM
}

type CheckinReq struct {
	Version    string      `json:"version"`
	OS         string      `json:"os"`
	Hostname   string      `json:"hostname"`
	ConfigHash string      `json:"config_hash"` // hash of the config the node is running
	RenewCSR   string      `json:"renew_csr,omitempty"`
	Events     []Event     `json:"events,omitempty"`
	Stats      Stats       `json:"stats"`
	CRLStatus  []CRLStatus `json:"crl_status,omitempty"`
}

type CheckinResp struct {
	Config          *SiteConfig `json:"config,omitempty"` // present only if hash differs
	ConfigHash      string      `json:"config_hash"`
	Cert            string      `json:"cert,omitempty"` // renewed client cert
	AckedSeq        uint64      `json:"acked_seq"`
	IntervalSeconds int         `json:"interval_seconds"`
	ServerTime      time.Time   `json:"server_time"`
}

type Stats struct {
	UptimeSeconds int64  `json:"uptime_seconds"`
	Accepts       uint64 `json:"accepts"`
	Rejects       uint64 `json:"rejects"`
	QueueDepth    int    `json:"queue_depth"`
}

type CRLStatus struct {
	URL        string    `json:"url"`
	NextUpdate time.Time `json:"next_update"`
	Source     string    `json:"source"` // "manager" | "direct"
}

// Event is an auth result or accounting record collected by a node.
type Event struct {
	Seq  uint64            `json:"seq"`
	Time time.Time         `json:"time"`
	Kind string            `json:"kind"` // "auth" | "acct"
	Data map[string]string `json:"data"`
}

// SiteConfig is everything a node needs to operate autonomously.
type SiteConfig struct {
	SiteID          string `json:"site_id"`
	SiteName        string `json:"site_name"`
	APs             []AP   `json:"aps"`
	EAPCert         string `json:"eap_cert"` // PEM chain presented to supplicants
	EAPKey          string `json:"eap_key"`
	PKI             []PKI  `json:"pki"`
	Policy          Policy `json:"policy"`
	RadSecPort      int    `json:"radsec_port,omitempty"` // 0 = RadSec disabled
	RadSecCA        string `json:"radsec_ca,omitempty"`   // PEM: CA that signs AP client certificates
	AuthPort        int    `json:"auth_port"`
	AcctPort        int    `json:"acct_port"`
	IntervalSeconds int    `json:"interval_seconds"`
}

type AP struct {
	Name          string   `json:"name"`
	Addr          string   `json:"addr"` // IP or CIDR
	Secret        string   `json:"secret"`
	RadSecSerials []string `json:"radsec_serials,omitempty"` // active AP client certificates (hex serials)
}

type PKI struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	CAs             string            `json:"cas"` // PEM bundle (roots + intermediates)
	CRLURLs         []string          `json:"crl_urls"`
	CRLs            map[string][]byte `json:"crls,omitempty"` // url -> DER, fetched by manager
	StalePolicy     string            `json:"stale_policy"`   // "fail_closed" | "fail_open"
	StaleGraceHours int               `json:"stale_grace_hours"`
}

type Policy struct {
	DefaultAction string `json:"default_action"` // "allow" | "deny"
	DefaultVLAN   string `json:"default_vlan"`
	Rules         []Rule `json:"rules"`
}

type Rule struct {
	Name   string `json:"name"`
	Field  string `json:"field"` // subject_cn | san | issuer_cn | pki
	Op     string `json:"op"`    // equals | contains | regex
	Value  string `json:"value"`
	Action string `json:"action"` // allow | deny
	VLAN   string `json:"vlan,omitempty"`
}

func Write(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxMsgBytes {
		return errors.New("message too large")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func Read(r io.Reader, v any) error {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n > MaxMsgBytes {
		return errors.New("message too large")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// HashConfig returns a stable hash of a site config; manager and node must agree on it.
func HashConfig(c *SiteConfig) string {
	b, _ := json.Marshal(c)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
