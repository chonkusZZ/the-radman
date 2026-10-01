package manager

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"

	"radman/internal/crypt"
)

func keyFromEnv() bool { return strings.TrimSpace(os.Getenv("RADMAN_MASTER_KEY")) != "" }

// KeyKit is the recovery file for the master key. Database backups are useless without it, because CA keys,
// AP secrets and server keys are encrypted with it. The kit is encrypted with an operator-chosen passphrase.
type KeyKit struct {
	Format  string `json:"format"`
	Created string `json:"created"`
	KDF     string `json:"kdf"`
	N, R, P int
	Salt    string `json:"salt"`
	Nonce   string `json:"nonce"`
	Data    string `json:"data"`
}

func deriveKitKey(pass string, salt []byte, n, r, p int) ([]byte, error) {
	return scrypt.Key([]byte(pass), salt, n, r, p, 32)
}

// SealKeyKit encrypts the master key with a passphrase (scrypt + AES-256-GCM).
func SealKeyKit(masterKey []byte, passphrase string) ([]byte, error) {
	if len(passphrase) < 12 {
		return nil, errors.New("the passphrase must be at least 12 characters")
	}
	salt, nonce := make([]byte, 16), make([]byte, 12)
	rand.Read(salt)
	rand.Read(nonce)
	k := &KeyKit{Format: "radman-keykit-1", Created: time.Now().UTC().Format(time.RFC3339), KDF: "scrypt", N: 1 << 15, R: 8, P: 1,
		Salt: base64.StdEncoding.EncodeToString(salt), Nonce: base64.StdEncoding.EncodeToString(nonce)}
	key, err := deriveKitKey(passphrase, salt, k.N, k.R, k.P)
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	k.Data = base64.StdEncoding.EncodeToString(g.Seal(nil, nonce, masterKey, []byte(k.Format)))
	return json.MarshalIndent(k, "", "  ")
}

// OpenKeyKit recovers the master key from a kit file.
func OpenKeyKit(raw []byte, passphrase string) ([]byte, error) {
	var k KeyKit
	if err := json.Unmarshal(raw, &k); err != nil || k.Format != "radman-keykit-1" {
		return nil, errors.New("not a key kit file")
	}
	salt, _ := base64.StdEncoding.DecodeString(k.Salt)
	nonce, _ := base64.StdEncoding.DecodeString(k.Nonce)
	data, _ := base64.StdEncoding.DecodeString(k.Data)
	key, err := deriveKitKey(passphrase, salt, k.N, k.R, k.P)
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	mk, err := g.Open(nil, nonce, data, []byte(k.Format))
	if err != nil {
		return nil, errors.New("wrong passphrase or damaged kit")
	}
	return mk, nil
}

// keyKit lets a global administrator download the encrypted master-key recovery kit (re-authenticating first).
func (s *server) keyKit(w http.ResponseWriter, r *http.Request, u *User) {
	back := func(msg string) { s.back(w, r, "/settings?tab=database", "err", msg) }
	var hash string
	s.a.St.DB.QueryRow(r.Context(), `SELECT password_hash FROM users WHERE id=$1::uuid`, u.ID).Scan(&hash)
	if u.SSO || hash == "" {
		back("SSO accounts cannot export the key kit; use a local global administrator account.")
		return
	}
	if !checkPassword(hash, r.PostFormValue("password")) {
		s.a.Audit(r.Context(), u.Email, "keykit.denied", "wrong password")
		back("Password is wrong.")
		return
	}
	pass := r.PostFormValue("passphrase")
	if subtle.ConstantTimeCompare([]byte(pass), []byte(r.PostFormValue("passphrase2"))) != 1 {
		back("The passphrases do not match.")
		return
	}
	mk, err := crypt.LoadKey(s.a.Opt.DataDir + "/master.key")
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	kit, err := SealKeyKit(mk, pass)
	if err != nil {
		back(err.Error())
		return
	}
	s.a.Audit(r.Context(), u.Email, "keykit.export", "")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="radman-key-kit-%s.json"`, time.Now().Format("20060102")))
	w.Header().Set("Cache-Control", "no-store")
	bytes.NewReader(kit).WriteTo(w)
}
