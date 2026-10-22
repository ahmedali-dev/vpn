package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

const sharePrefix = "TN1."
const maxShareCode = 24 * 1024
const maxSharePayload = 64 * 1024

// A password-derived key is never included in the share code. AES-GCM checks
// the password and authenticates both the ciphertext and the format version.
type sharedProfile struct {
	Name string   `json:"n"`
	Mode string   `json:"m"`
	Args []string `json:"a"`
}

var shareValueFlags = map[string]bool{
	"-mode": true, "-H": true, "-P": true, "-u": true, "-p": true, "-S": true,
	"-socks-port": true, "-pac-port": true, "-max-conns": true, "-tls-version": true,
	"-ssh-host-key": true, "-ssh-cert-sha256": true, "-proxy": true, "-payload-stage": true,
	"-v2ray-link": true, "-v2ray-sni": true, "-v2ray-cert-sha256": true,
	"-v2ray-protocol": true, "-v2ray-uuid": true, "-v2ray-addr": true, "-v2ray-port": true,
	"-v2ray-network": true, "-v2ray-security": true, "-v2ray-path": true,
	"-v2ray-host": true, "-v2ray-service": true,
}

func validateSharedProfile(p sharedProfile) (sharedProfile, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 100 || !utf8.ValidString(p.Name) {
		return p, fmt.Errorf("shared profile name must be 1–100 bytes")
	}
	if len(p.Args) == 0 || len(p.Args) > 128 {
		return p, fmt.Errorf("invalid shared profile arguments")
	}
	seen := map[string]bool{}
	for i := 0; i < len(p.Args); i++ {
		flag := p.Args[i]
		if seen[flag] {
			return p, fmt.Errorf("duplicate profile option %s", flag)
		}
		seen[flag] = true
		if flag == "-tun" || flag == "-auto-route" || flag == "-ssh-trust-on-first-use" {
			continue
		}
		if !shareValueFlags[flag] {
			return p, fmt.Errorf("option %s cannot be imported", flag)
		}
		i++
		if i >= len(p.Args) || len(p.Args[i]) > 8192 || !utf8.ValidString(p.Args[i]) {
			return p, fmt.Errorf("invalid value for %s", flag)
		}
	}
	cfg, err := parseConfig(p.Args)
	if err != nil {
		return p, fmt.Errorf("invalid shared configuration: %w", err)
	}
	if (p.Mode != "ssh" && p.Mode != "xray" && p.Mode != "v2ray") || (p.Mode == "ssh") != (cfg.Mode == ModeSSH) {
		return p, fmt.Errorf("shared profile mode does not match its configuration")
	}
	p.Mode = string(cfg.Mode)
	return p, nil
}

func portableProfile(p savedProfile) (sharedProfile, error) {
	args := make([]string, 0, len(p.Args))
	for i := 0; i < len(p.Args); i++ {
		flag := p.Args[i]
		switch flag {
		case "-v2ray-binary", "-tun-binary":
			if i+1 >= len(p.Args) {
				return sharedProfile{}, fmt.Errorf("missing binary path")
			}
			i++
			continue
		case "-payload-file", "-tls-ca", "-ssh-known-hosts", "-v2ray-config":
			return sharedProfile{}, fmt.Errorf("this profile uses local files (%s); remove file references before sharing", flag)
		}
		args = append(args, flag)
		if flag != "-tun" && flag != "-auto-route" && flag != "-ssh-trust-on-first-use" {
			if i+1 >= len(p.Args) {
				return sharedProfile{}, fmt.Errorf("missing value for %s", flag)
			}
			i++
			args = append(args, p.Args[i])
		}
	}
	return validateSharedProfile(sharedProfile{Name: p.Name, Mode: p.Mode, Args: args})
}

func shareCipher(password string, salt []byte) (cipher.AEAD, error) {
	if len(password) < 8 || len(password) > 1024 {
		return nil, fmt.Errorf("share password must contain 8–1024 bytes")
	}
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encodeLegacyProfileShare(p savedProfile, password string) (string, error) {
	portable, err := portableProfile(p)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(portable)
	if err != nil {
		return "", err
	}
	if len(raw) > maxSharePayload {
		return "", fmt.Errorf("profile is too large to share")
	}
	var compressed bytes.Buffer
	writer, _ := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
	if _, err = writer.Write(raw); err != nil {
		return "", err
	}
	if err = writer.Close(); err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return "", err
	}
	aead, err := shareCipher(password, salt)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	envelope := append(salt, nonce...)
	envelope = aead.Seal(envelope, nonce, compressed.Bytes(), []byte(sharePrefix))
	code := sharePrefix + base64.RawURLEncoding.EncodeToString(envelope)
	if len(code) > maxShareCode {
		return "", fmt.Errorf("profile is too large to share")
	}
	return code, nil
}

func decodeLegacyProfileShare(code, password string) (savedProfile, error) {
	code = strings.TrimSpace(code)
	if len(code) > maxShareCode || !strings.HasPrefix(code, sharePrefix) {
		return savedProfile{}, fmt.Errorf("invalid or unsupported TunnelNest share code")
	}
	envelope, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, sharePrefix))
	if err != nil || len(envelope) < 16+12+16 {
		return savedProfile{}, fmt.Errorf("invalid TunnelNest share code")
	}
	aead, err := shareCipher(password, envelope[:16])
	if err != nil {
		return savedProfile{}, err
	}
	compressed, err := aead.Open(nil, envelope[16:28], envelope[28:], []byte(sharePrefix))
	if err != nil {
		return savedProfile{}, fmt.Errorf("incorrect password or damaged share code")
	}
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return savedProfile{}, fmt.Errorf("invalid compressed profile")
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, maxSharePayload+1))
	if err != nil || len(raw) > maxSharePayload {
		return savedProfile{}, fmt.Errorf("invalid or oversized profile")
	}
	var p sharedProfile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&p); err != nil {
		return savedProfile{}, fmt.Errorf("invalid shared profile data")
	}
	if err = decoder.Decode(new(interface{})); err != io.EOF {
		return savedProfile{}, fmt.Errorf("unexpected shared profile data")
	}
	p, err = validateSharedProfile(p)
	if err != nil {
		return savedProfile{}, err
	}
	return savedProfile{Name: p.Name, Mode: p.Mode, Args: p.Args}, nil
}

func (s *profileStore) get(id int64) (savedProfile, error) {
	var p savedProfile
	var raw string
	err := s.db.QueryRow(`SELECT id,name,mode,args,updated_at,session_only FROM profiles WHERE id=?`, id).Scan(&p.ID, &p.Name, &p.Mode, &raw, &p.UpdatedAt, &p.SessionOnly)
	if err != nil {
		return p, fmt.Errorf("profile not found")
	}
	if p.Args, err = s.vault.decode(raw); err != nil {
		return p, err
	}
	s.restoreSession(&p)
	if p.NeedsCredentials {
		return p, fmt.Errorf("profile credentials were not saved; enter them in the editor first")
	}
	return p, nil
}

// Conflict-safe insertion always creates a new row; importing never updates a
// saved profile even when the sender used the same name.
func (s *profileStore) saveImported(p savedProfile) (savedProfile, error) {
	p.ID = 0
	raw, err := s.vault.encode(p.Args)
	if err != nil {
		return p, err
	}
	base := p.Name
	p.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	for n := 1; n <= 1000; n++ {
		suffix := ""
		if n > 1 {
			suffix = " (" + strconv.Itoa(n) + ")"
		}
		name := base
		for len(name)+len(suffix) > 100 {
			_, size := utf8.DecodeLastRuneInString(name)
			name = name[:len(name)-size]
		}
		p.Name = name + suffix
		result, err := s.db.Exec(`INSERT INTO profiles(name,mode,args,updated_at) VALUES(?,?,?,?) ON CONFLICT(name) DO NOTHING`, p.Name, p.Mode, raw, p.UpdatedAt)
		if err != nil {
			return p, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return p, err
		}
		if count == 1 {
			p.ID, err = result.LastInsertId()
			return p, err
		}
	}
	return p, fmt.Errorf("too many profiles with this name; rename one before importing")
}
