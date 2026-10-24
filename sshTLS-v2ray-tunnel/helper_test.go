package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHelperRejectsProfilesAndAcceptsLease(t *testing.T) {
	m := &controlManager{helperOnly: true}
	token := strings.Repeat("a", 64)
	handler := controlHandler("127.0.0.1:12345", token, m)
	for _, tc := range []struct {
		path, method string
		status       int
	}{{"/api/profiles", "GET", 403}, {"/api/vault/unlock", "POST", 403}, {"/", "GET", 404}, {"/api/lease", "POST", 200}} {
		req := httptest.NewRequest(tc.method, "http://127.0.0.1:12345"+tc.path, nil)
		req.Header.Set("X-Tunnel-Token", token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
	}
	if m.lastLease.Load() == 0 {
		t.Fatal("lease was not refreshed")
	}
}
func TestHelperURLValidation(t *testing.T) {
	for _, raw := range []string{"http://evil.example/#" + strings.Repeat("a", 64), "https://127.0.0.1:1/#" + strings.Repeat("a", 64), "http://127.0.0.1:1/#invalid"} {
		if _, err := newHelperClient(raw); err == nil {
			t.Fatal("untrusted helper address accepted")
		}
	}
}
func TestHelperLeaseExpires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var last atomic.Int64
	last.Store(time.Now().Add(-helperLeaseTimeout - time.Second).UnixNano())
	go watchHelperLease(ctx, cancel, &last)
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("orphan helper did not stop")
	}
}
func TestAttachHelperKeepsUserProfileStore(t *testing.T) {
	root := &controlManager{helperOnly: true}
	token := strings.Repeat("a", 64)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { controlHandler(r.Host, token, root).ServeHTTP(w, r) }))
	defer server.Close()
	user := &controlManager{profiles: testShareStore(t)}
	defer user.detachHelper()
	if _, err := user.profiles.save(testShareProfile()); err != nil {
		t.Fatal(err)
	}
	if err := user.attachHelper(server.URL + "/#" + token); err != nil {
		t.Fatal(err)
	}
	profiles, err := user.profiles.list()
	if err != nil || len(profiles) != 1 {
		t.Fatal("elevation switched profile stores")
	}
	if root.profiles != nil {
		t.Fatal("privileged helper opened a profile database")
	}
}
