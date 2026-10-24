package main

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func testShareProfile() savedProfile {
	return savedProfile{Name: "Office", Mode: "ssh", Args: []string{"-mode", "ssh", "-H", "server.example.com", "-P", "443", "-u", "share-test-user", "-p", "share-test-secret", "-S", "tls.example.com", "-socks-port", "1082"}}
}
func testShareStore(t *testing.T) *profileStore {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE profiles(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE,mode TEXT NOT NULL,args TEXT NOT NULL,updated_at TEXT NOT NULL,session_only INTEGER NOT NULL DEFAULT 0)`)
	if err != nil {
		t.Fatal(err)
	}
	store := &profileStore{db: db, vault: testVault(t)}
	t.Cleanup(store.close)
	return store
}
func TestProfileShareRoundTrip(t *testing.T) {
	profiles := []savedProfile{testShareProfile(), {Name: "VMess", Mode: "xray", Args: []string{"-mode", "xray", "-v2ray-link", "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"example.com","port":"443","id":"test-id","net":"ws","tls":"tls","host":"web.whatsapp.com"}`)), "-tls-version", "tls1.2"}}}
	for _, profile := range profiles {
		t.Run(profile.Mode, func(t *testing.T) {
			code, err := encodeProfileShare(profile, "test password")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(code, protectedSharePrefix) || strings.Contains(code, "share-test-secret") {
				t.Fatal("invalid or plaintext share code")
			}
			decoded, err := decodeProfileShare(code, "test password")
			if err != nil {
				t.Fatal(err)
			}
			if decoded.ID != 0 || decoded.Name != profile.Name || !reflect.DeepEqual(decoded.Args, profile.Args) {
				t.Fatal("shared settings changed")
			}
			other, err := encodeProfileShare(profile, "test password")
			if err != nil {
				t.Fatal(err)
			}
			if other == code {
				t.Fatal("sharing did not use fresh randomness")
			}
		})
	}
}
func TestProfileShareRejectsWrongPasswordAndTampering(t *testing.T) {
	code, err := encodeProfileShare(testShareProfile(), "test password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeProfileShare(code, "wrong password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	envelope, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, protectedSharePrefix))
	envelope[len(envelope)/2] ^= 1
	if _, err = decodeProfileShare(protectedSharePrefix+base64.RawURLEncoding.EncodeToString(envelope), "test password"); err == nil {
		t.Fatal("tampering accepted")
	}
	for _, bad := range []string{"TN2.invalid", "TN1.", "not a code", strings.Repeat("a", maxShareCode+1)} {
		if _, err = decodeProfileShare(bad, "test password"); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	if _, err = encodeProfileShare(testShareProfile(), "short"); err == nil {
		t.Fatal("short password accepted")
	}
}
func TestSharedProfileRejectsUnsafeOptions(t *testing.T) {
	for _, flag := range []string{"-ui", "-ui-ready-file", "-v2ray-binary", "-tun-binary", "-payload-file", "-tls-ca", "-ssh-known-hosts", "-v2ray-config"} {
		p := testShareProfile()
		p.Args = append(p.Args, flag, "/untrusted/path")
		if _, err := validateSharedProfile(sharedProfile{Name: p.Name, Mode: p.Mode, Args: p.Args}); err == nil {
			t.Fatalf("accepted %s", flag)
		}
	}
	p := testShareProfile()
	p.Args = append(p.Args, "-mode", "ssh")
	if _, err := portableProfile(p); err == nil {
		t.Fatal("duplicate flags accepted")
	}
	p = testShareProfile()
	p.Mode = "xray"
	if _, err := portableProfile(p); err == nil {
		t.Fatal("mode mismatch accepted")
	}
	p = testShareProfile()
	p.Args = append(p.Args, "-v2ray-binary", "/local/xray", "-tun-binary", "/local/sing-box")
	portable, err := portableProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(portable.Args, testShareProfile().Args) {
		t.Fatal("local executable paths were not omitted")
	}
}
func TestSharedProfileInflateLimit(t *testing.T) {
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	_, _ = writer.Write(bytes.Repeat([]byte("a"), maxSharePayload+1))
	_ = writer.Close()
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	aead, err := shareCipher("test password", salt)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	envelope := append(salt, nonce...)
	envelope = aead.Seal(envelope, nonce, compressed.Bytes(), []byte(sharePrefix))
	if _, err = decodeProfileShare(sharePrefix+base64.RawURLEncoding.EncodeToString(envelope), "test password"); err == nil {
		t.Fatal("oversized decompressed data accepted")
	}
}
func TestSharedProfileAPIValidatesBeforeSaving(t *testing.T) {
	store := testShareStore(t)
	original, err := store.save(testShareProfile())
	if err != nil {
		t.Fatal(err)
	}
	manager := &controlManager{profiles: store}
	handler := controlHandler("127.0.0.1:12345", "secret", manager)
	call := func(path string, body interface{}, token string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:12345/api/"+path, bytes.NewReader(raw))
		req.Header.Set("X-Tunnel-Token", token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	response := call("profiles/share", map[string]interface{}{"id": original.ID, "password": "test password"}, "secret")
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	var shared struct {
		Code string `json:"code"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &shared); err != nil {
		t.Fatal(err)
	}
	if response = call("profiles/import-shared", map[string]string{"code": shared.Code, "password": "wrong password"}, "secret"); response.Code != 400 {
		t.Fatal("wrong password import accepted")
	}
	if response = call("profiles/import-shared", map[string]string{"code": shared.Code, "password": "test password"}, "wrong token"); response.Code != 401 {
		t.Fatal("unauthorized import accepted")
	}
	profiles, err := store.list()
	if err != nil || len(profiles) != 1 {
		t.Fatal("invalid import changed stored profiles")
	}
	for i := 0; i < 2; i++ {
		response = call("profiles/import-shared", map[string]string{"code": shared.Code, "password": "test password"}, "secret")
		if response.Code != 200 {
			t.Fatal(response.Body.String())
		}
	}
	profiles, err = store.list()
	if err != nil || len(profiles) != 3 {
		t.Fatal("imports did not create separate profiles")
	}
	unchanged, err := store.get(original.ID)
	if err != nil || !reflect.DeepEqual(unchanged.Args, original.Args) {
		t.Fatal("original profile overwritten")
	}
	if manager.client != nil {
		t.Fatal("import started a connection")
	}
}

func TestCompactShareOptionalPasswordAndLegacyImport(t *testing.T) {
	profile := testShareProfile()
	code, err := encodeProfileShare(profile, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(code, compactSharePrefix) {
		t.Fatal("empty password did not select the open compact format")
	}
	decoded, err := decodeProfileShare(code, "")
	if err != nil || !reflect.DeepEqual(decoded.Args, profile.Args) {
		t.Fatal("open compact profile did not round trip")
	}
	envelope, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, compactSharePrefix))
	envelope[len(envelope)-1] ^= 1
	if _, err = decodeProfileShare(compactSharePrefix+base64.RawURLEncoding.EncodeToString(envelope), ""); err == nil {
		t.Fatal("damaged open code accepted")
	}
	legacy, err := encodeLegacyProfileShare(profile, "test password")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = decodeProfileShare(legacy, "test password")
	if err != nil || !reflect.DeepEqual(decoded.Args, profile.Args) {
		t.Fatal("legacy code import broke")
	}
	compactProtected, err := encodeProfileShare(profile, "test password")
	if err != nil {
		t.Fatal(err)
	}
	if len(code) >= len(legacy) || len(compactProtected) >= len(legacy) {
		t.Fatal("compact encoding did not shorten the reference profile")
	}
	t.Logf("Reference SSH profile: open %d, protected %d, previous protected format %d characters", len(code), len(compactProtected), len(legacy))
}

func TestCompactVMessRemovesNestedBase64WithoutChangingSettings(t *testing.T) {
	raw := []byte(`{"add":"example.com","port":"443","id":"00000000-0000-4000-8000-000000000001","net":"ws","host":"web.whatsapp.com","path":"/socket","tls":"tls","ps":"Sample profile"}`)
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		profile := savedProfile{Name: "Sample", Mode: "xray", Args: []string{"-mode", "xray", "-v2ray-link", "vmess://" + encoding.EncodeToString(raw), "-tls-version", "tls1.3"}}
		code, err := encodeProfileShare(profile, "")
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeProfileShare(code, "")
		if err != nil || !reflect.DeepEqual(decoded.Args, profile.Args) {
			t.Fatal("VMess representation changed")
		}
	}
}

func TestCompactDecodeBoundsAndFlagValidation(t *testing.T) {
	for _, data := range [][]byte{{}, {255}, {0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127}, {0, 1, 'x', 255}, {0, 1, 'x', 0, 0, 128}} {
		if _, err := unpackProfileShare(data); err == nil {
			t.Fatal("invalid compact payload accepted")
		}
	}
	if _, err := inflateShare([]byte{0, 1}); err != nil {
		t.Fatal(err)
	}
	var large bytes.Buffer
	writer, _ := flate.NewWriter(&large, flate.BestCompression)
	_, _ = writer.Write(bytes.Repeat([]byte("x"), maxSharePayload+1))
	_ = writer.Close()
	if _, err := inflateShare(append([]byte{1}, large.Bytes()...)); err == nil {
		t.Fatal("compact decompression bomb accepted")
	}
}
