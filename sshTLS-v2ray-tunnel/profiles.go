package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type savedProfile struct {
	SessionOnly      bool     `json:"sessionOnly,omitempty"`
	NeedsCredentials bool     `json:"needsCredentials,omitempty"`
	Locked           bool     `json:"locked,omitempty"`
	SchemaVersion    int      `json:"schemaVersion"`
	ID               int64    `json:"id"`
	Name             string   `json:"name"`
	Mode             string   `json:"mode"`
	Args             []string `json:"args"`
	UpdatedAt        string   `json:"updatedAt"`
}

type profileStore struct {
	sessionMu sync.Mutex
	session   map[int64][]string
	db        *sql.DB
	vault     *profileVault
}

func openProfileStore() (*profileStore, error) { return openProfileStoreWithKeys(systemKeyStore{}) }
func openProfileStoreWithKeys(keys vaultKeyStore) (*profileStore, error) {
	dir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "TunnelDesktop")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create profile directory: %w", err)
	}
	path := filepath.Join(dir, "profiles.sqlite3")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open profiles database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA secure_delete=ON`); err != nil {
		db.Close()
		return nil, err
	}
	store := &profileStore{db: db}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        mode TEXT NOT NULL,
        args TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        session_only INTEGER NOT NULL DEFAULT 0
    )`); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize profiles database: %w", err)
	}
	columns, err := db.Query(`PRAGMA table_info(profiles)`)
	if err != nil {
		db.Close()
		return nil, err
	}
	found := false
	for columns.Next() {
		var cid, notNull, pk int
		var name, kind string
		var defaultValue interface{}
		if err = columns.Scan(&cid, &name, &kind, &notNull, &defaultValue, &pk); err != nil {
			columns.Close()
			db.Close()
			return nil, err
		}
		if name == "session_only" {
			found = true
		}
	}
	if err = columns.Err(); err != nil {
		columns.Close()
		db.Close()
		return nil, err
	}
	columns.Close()
	if !found {
		if _, err = db.Exec(`ALTER TABLE profiles ADD COLUMN session_only INTEGER NOT NULL DEFAULT 0`); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := os.Chmod(path, 0600); err != nil && runtime.GOOS != "windows" {
		db.Close()
		return nil, fmt.Errorf("protect profiles database: %w", err)
	}
	store.vault, err = newProfileVault(db, path, keys)
	if err != nil {
		db.Close()
		return nil, err
	}
	if err = store.migrateSecrets(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *profileStore) close() {
	if s != nil && s.db != nil {
		if s.vault != nil {
			s.vault.mu.Lock()
			for i := range s.vault.key {
				s.vault.key[i] = 0
			}
			s.vault.key = nil
			s.vault.mu.Unlock()
		}
		s.sessionMu.Lock()
		clear(s.session)
		s.sessionMu.Unlock()
		_ = s.db.Close()
	}
}

func (s *profileStore) list() ([]savedProfile, error) {
	rows, err := s.db.Query(`SELECT id,name,mode,args,updated_at,session_only FROM profiles ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []savedProfile
	for rows.Next() {
		var p savedProfile
		var raw string
		if err := rows.Scan(&p.ID, &p.Name, &p.Mode, &raw, &p.UpdatedAt, &p.SessionOnly); err != nil {
			return nil, err
		}
		if !s.vault.locked() {
			if p.Args, err = s.vault.decode(raw); err != nil {
				return nil, fmt.Errorf("decode profile %q: %w", p.Name, err)
			}
		} else {
			p.Locked = true
		}
		p.SchemaVersion = 1
		if !p.Locked {
			s.restoreSession(&p)
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

func (s *profileStore) save(p savedProfile) (savedProfile, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 100 {
		return p, fmt.Errorf("profile name must be 1-100 characters")
	}
	if len(p.Args) == 0 || len(p.Args) > 128 {
		return p, fmt.Errorf("profile arguments are invalid")
	}
	storedArgs := p.Args
	if p.SessionOnly {
		storedArgs = credentialsRemoved(p.Args)
	}
	raw, err := s.vault.encode(storedArgs)
	if err != nil {
		return p, err
	}
	p.SchemaVersion = 1
	p.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if p.ID > 0 {
		var result sql.Result
		result, err = s.db.Exec(`UPDATE profiles SET name=?,mode=?,args=?,updated_at=?,session_only=? WHERE id=?`, p.Name, p.Mode, raw, p.UpdatedAt, p.SessionOnly, p.ID)
		if err == nil {
			if n, _ := result.RowsAffected(); n == 0 {
				err = fmt.Errorf("profile not found")
			}
		}
	} else {
		res, execErr := s.db.Exec(`INSERT INTO profiles(name,mode,args,updated_at,session_only) VALUES(?,?,?,?,?)`, p.Name, p.Mode, raw, p.UpdatedAt, p.SessionOnly)
		err = execErr
		if err == nil {
			p.ID, err = res.LastInsertId()
		}
	}
	if err == nil {
		s.cacheProfile(p)
	}
	return p, err
}

func (s *profileStore) delete(id int64) error {
	if id < 1 {
		return fmt.Errorf("invalid profile id")
	}
	result, err := s.db.Exec(`DELETE FROM profiles WHERE id=?`, id)
	if err != nil {
		return err
	}
	s.sessionMu.Lock()
	delete(s.session, id)
	s.sessionMu.Unlock()
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return fmt.Errorf("profile not found")
	}
	return err
}
