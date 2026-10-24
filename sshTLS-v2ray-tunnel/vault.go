package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/scrypt"
)

var errVaultLocked = errors.New("profile vault is locked; unlock it before saving or using credentials")

type vaultKeyStore interface {
	Get(string) (string, error)
	Set(string, string) error
}
type systemKeyStore struct{}

func (systemKeyStore) Get(account string) (string, error) { return keyring.Get("TunnelNest", account) }
func (systemKeyStore) Set(account, value string) error {
	return keyring.Set("TunnelNest", account, value)
}

type profileVault struct {
	mu      sync.RWMutex
	key     []byte
	db      *sql.DB
	store   vaultKeyStore
	account string
	mode    string
}

func newProfileVault(db *sql.DB, path string, store vaultKeyStore) (*profileVault, error) {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS vault_metadata(id INTEGER PRIMARY KEY CHECK(id=1),mode TEXT NOT NULL,salt TEXT NOT NULL,check_value TEXT NOT NULL)`); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(path))
	v := &profileVault{db: db, store: store, account: hex.EncodeToString(digest[:]), mode: "locked"}
	var mode, salt, check string
	err := db.QueryRow(`SELECT mode,salt,check_value FROM vault_metadata WHERE id=1`).Scan(&mode, &salt, &check)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if mode == "password" {
		v.mode = mode
		return v, nil
	}
	encoded, keyErr := store.Get(v.account)
	if keyErr == nil {
		key, err := base64.RawStdEncoding.DecodeString(encoded)
		if err == nil && len(key) == 32 {
			v.key = key
			v.mode = "keychain"
			if mode == "" {
				err = v.saveMetadata("keychain", "", key)
			} else {
				_, err = v.open(check)
			}
			if err == nil {
				return v, nil
			}
			v.key = nil
		}
	}
	if mode != "" {
		v.mode = mode
		return v, nil
	}
	// Never replace a lost key or silently fall back to plaintext.
	if keyErr != nil && !errors.Is(keyErr, keyring.ErrNotFound) {
		return v, nil
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return nil, err
	}
	if err = store.Set(v.account, base64.RawStdEncoding.EncodeToString(key)); err != nil {
		return v, nil
	}
	v.key = key
	v.mode = "keychain"
	if err = v.saveMetadata("keychain", "", key); err != nil {
		return nil, err
	}
	return v, nil
}
func (v *profileVault) saveMetadata(mode, salt string, key []byte) error {
	sealed, err := sealVault(key, []byte("TunnelNest vault v1"))
	if err != nil {
		return err
	}
	_, err = v.db.Exec(`INSERT INTO vault_metadata(id,mode,salt,check_value) VALUES(1,?,?,?)`, mode, salt, sealed)
	return err
}
func sealVault(key, raw []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	encrypted := aead.Seal(nonce, nonce, raw, []byte("TunnelNest profile v1"))
	return "vault1." + base64.RawStdEncoding.EncodeToString(encrypted), nil
}
func openVault(key []byte, value string) ([]byte, error) {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "vault1."))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, fmt.Errorf("invalid encrypted profile")
	}
	return aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte("TunnelNest profile v1"))
}
func (v *profileVault) open(value string) ([]byte, error) {
	if len(v.key) != 32 {
		return nil, errVaultLocked
	}
	return openVault(v.key, value)
}
func (v *profileVault) locked() bool { v.mu.RLock(); defer v.mu.RUnlock(); return len(v.key) != 32 }
func (v *profileVault) encode(args []string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(v.key) != 32 {
		return "", errVaultLocked
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	return sealVault(v.key, raw)
}
func (v *profileVault) decode(raw string) ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(v.key) != 32 {
		return nil, errVaultLocked
	}
	var data []byte
	var err error
	if strings.HasPrefix(raw, "vault1.") {
		data, err = v.open(raw)
	} else {
		data = []byte(raw)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt saved profile")
	}
	var args []string
	err = json.Unmarshal(data, &args)
	return args, err
}
func (v *profileVault) unlock(password string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.key) == 32 {
		return nil
	}
	var mode, salt, check string
	err := v.db.QueryRow(`SELECT mode,salt,check_value FROM vault_metadata WHERE id=1`).Scan(&mode, &salt, &check)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if mode == "keychain" {
		encoded, err := v.store.Get(v.account)
		if err != nil {
			return fmt.Errorf("OS credential vault is unavailable; restore access to the original keychain")
		}
		key, err := base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return err
		}
		plain, err := openVault(key, check)
		if err != nil || string(plain) != "TunnelNest vault v1" {
			return fmt.Errorf("OS vault key does not match saved profiles")
		}
		v.key = key
		return nil
	}
	if len(password) < 12 || len(password) > 1024 {
		return fmt.Errorf("vault password must contain 12–1024 bytes")
	}
	var saltBytes []byte
	if mode == "" {
		saltBytes = make([]byte, 16)
		if _, err = rand.Read(saltBytes); err != nil {
			return err
		}
	} else {
		saltBytes, err = base64.RawStdEncoding.DecodeString(salt)
		if err != nil {
			return err
		}
	}
	key, err := scrypt.Key([]byte(password), saltBytes, 32768, 8, 1, 32)
	if err != nil {
		return err
	}
	if mode != "" {
		plain, err := openVault(key, check)
		if err != nil || string(plain) != "TunnelNest vault v1" {
			return fmt.Errorf("incorrect vault password")
		}
	} else {
		if err = v.saveMetadata("password", base64.RawStdEncoding.EncodeToString(saltBytes), key); err != nil {
			return err
		}
	}
	v.key = key
	v.mode = "password"
	return nil
}
func (s *profileStore) migrateSecrets() error {
	if s.vault.locked() {
		return nil
	}
	rows, err := s.db.Query(`SELECT id,args FROM profiles WHERE args NOT LIKE 'vault1.%'`)
	if err != nil {
		return err
	}
	type row struct {
		id  int64
		raw string
	}
	var old []row
	for rows.Next() {
		var r row
		if err = rows.Scan(&r.id, &r.raw); err != nil {
			rows.Close()
			return err
		}
		old = append(old, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range old {
		args, err := s.vault.decode(r.raw)
		if err != nil {
			return err
		}
		sealed, err := s.vault.encode(args)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE profiles SET args=? WHERE id=?`, sealed, r.id); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if len(old) > 0 {
		_, err = s.db.Exec(`VACUUM`)
	}
	return err
}

func (v *profileVault) status() map[string]interface{} {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return map[string]interface{}{"locked": len(v.key) != 32, "mode": v.mode}
}
