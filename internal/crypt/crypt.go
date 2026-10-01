// Package crypt provides AES-GCM encryption of secrets at rest.
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"strings"
)

type Box struct{ aead cipher.AEAD }

// LoadKey returns the master key: from RADMAN_MASTER_KEY (base64, 32 bytes) if set - handy for secret managers and for
// running several manager instances against one database - otherwise from the key file, creating it on first use.
func LoadKey(path string) ([]byte, error) {
	if v := strings.TrimSpace(os.Getenv("RADMAN_MASTER_KEY")); v != "" {
		k, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(k) != 32 {
			return nil, errors.New("RADMAN_MASTER_KEY must be 32 bytes, base64 encoded")
		}
		return k, nil
	}
	return LoadOrCreateKey(path)
}

// LoadOrCreateKey reads a 32-byte base64 key from path or creates one (0600).
func LoadOrCreateKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) != 32 {
			return nil, errors.New("master key file is corrupt")
		}
		return k, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(k)), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func New(key []byte) (*Box, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Box{g}, nil
}

func (b *Box) Seal(plain []byte) string {
	n := make([]byte, b.aead.NonceSize())
	rand.Read(n)
	return base64.StdEncoding.EncodeToString(b.aead.Seal(n, n, plain, nil))
}

func (b *Box) Open(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) < b.aead.NonceSize() {
		return nil, errors.New("bad ciphertext")
	}
	return b.aead.Open(nil, raw[:b.aead.NonceSize()], raw[b.aead.NonceSize():], nil)
}
