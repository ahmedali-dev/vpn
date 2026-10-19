package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type savedProfile struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Mode      string   `json:"mode"`
	Args      []string `json:"args"`
	UpdatedAt string   `json:"updatedAt"`
}

type profileStore struct{ db *sql.DB }

func openProfileStore() (*profileStore, error) {
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
	store := &profileStore{db: db}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        mode TEXT NOT NULL,
        args TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )`); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize profiles database: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil && runtime.GOOS != "windows" {
		db.Close()
		return nil, fmt.Errorf("protect profiles database: %w", err)
	}
	return store, nil
}

func (s *profileStore) close() {
	if s != nil && s.db != nil {
		_ = s.db.Close()
	}
}

func (s *profileStore) list() ([]savedProfile, error) {
	rows, err := s.db.Query(`SELECT id,name,mode,args,updated_at FROM profiles ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []savedProfile
	for rows.Next() {
		var p savedProfile
		var raw string
		if err := rows.Scan(&p.ID, &p.Name, &p.Mode, &raw, &p.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &p.Args); err != nil {
			return nil, fmt.Errorf("decode profile %q: %w", p.Name, err)
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
	raw, err := json.Marshal(p.Args)
	if err != nil {
		return p, err
	}
	p.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if p.ID > 0 {
		_, err = s.db.Exec(`UPDATE profiles SET name=?,mode=?,args=?,updated_at=? WHERE id=?`, p.Name, p.Mode, raw, p.UpdatedAt, p.ID)
	} else {
		res, execErr := s.db.Exec(`INSERT INTO profiles(name,mode,args,updated_at) VALUES(?,?,?,?)`, p.Name, p.Mode, raw, p.UpdatedAt)
		err = execErr
		if err == nil {
			p.ID, err = res.LastInsertId()
		}
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
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return fmt.Errorf("profile not found")
	}
	return err
}
