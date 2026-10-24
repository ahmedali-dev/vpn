package main

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

type memoryKeys map[string]string

func (m memoryKeys) Get(k string) (string, error) {
	v, ok := m[k]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}
func (m memoryKeys) Set(k, v string) error { m[k] = v; return nil }

type unavailableKeys struct{}

func (unavailableKeys) Get(string) (string, error) { return "", errors.New("no desktop keychain") }
func (unavailableKeys) Set(string, string) error   { return errors.New("no desktop keychain") }
func testVault(t *testing.T) *profileVault {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return &profileVault{key: key}
}
func TestVaultEncryptionAndPasswordRestart(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	v, err := newProfileVault(db, "test", unavailableKeys{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.encode([]string{"-p", "secret"}); !errors.Is(err, errVaultLocked) {
		t.Fatal("locked vault saved credentials")
	}
	if err = v.unlock("test master password"); err != nil {
		t.Fatal(err)
	}
	sealed, err := v.encode([]string{"-p", "never plaintext"})
	if err != nil || strings.Contains(sealed, "never plaintext") {
		t.Fatalf("encryption failed: %v", err)
	}
	fresh, err := newProfileVault(db, "test", unavailableKeys{})
	if err != nil {
		t.Fatal(err)
	}
	if err = fresh.unlock("wrong password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if err = fresh.unlock("test master password"); err != nil {
		t.Fatal(err)
	}
	args, err := fresh.decode(sealed)
	if err != nil || args[1] != "never plaintext" {
		t.Fatal("restart lost credentials")
	}
	sealed = sealed[:len(sealed)-3] + "abc"
	if _, err = fresh.decode(sealed); err == nil {
		t.Fatal("tamper accepted")
	}
}
func TestKeychainVaultPersistsAndDoesNotReplaceMissingKey(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keys := memoryKeys{}
	v, err := newProfileVault(db, "test", keys)
	if err != nil || v.locked() {
		t.Fatalf("keychain vault: %v", err)
	}
	sealed, _ := v.encode([]string{"credential"})
	fresh, err := newProfileVault(db, "test", keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fresh.decode(sealed); err != nil {
		t.Fatal(err)
	}
	lost, err := newProfileVault(db, "test", memoryKeys{})
	if err != nil || !lost.locked() {
		t.Fatal("missing key silently replaced")
	}
}

func TestLegacyProfilesMigrateOnlyAfterUnlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE profiles(id INTEGER PRIMARY KEY,name TEXT,mode TEXT,args TEXT,updated_at TEXT,session_only INTEGER DEFAULT 0); INSERT INTO profiles VALUES(1,'Legacy','ssh','["-p","legacy-secret"]','',0)`)
	if err != nil {
		t.Fatal(err)
	}
	v, err := newProfileVault(db, path, unavailableKeys{})
	if err != nil {
		t.Fatal(err)
	}
	store := &profileStore{db: db, vault: v}
	if err = store.migrateSecrets(); err != nil {
		t.Fatal(err)
	}
	list, err := store.list()
	if err != nil || len(list) != 1 || !list[0].Locked || len(list[0].Args) != 0 {
		t.Fatalf("locked legacy profile exposed credentials: %#v %v", list, err)
	}
	if err = v.unlock("a long master password"); err != nil {
		t.Fatal(err)
	}
	if err = store.migrateSecrets(); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err = db.QueryRow("SELECT args FROM profiles WHERE id=1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "vault1.") || strings.Contains(raw, "legacy-secret") {
		t.Fatal("legacy plaintext was not migrated")
	}
	args, err := v.decode(raw)
	if err != nil || len(args) != 2 || args[1] != "legacy-secret" {
		t.Fatal("migration lost original credentials")
	}
}
