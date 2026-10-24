package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestSessionCredentialsNeverPersist(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"HOME", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"} {
		t.Setenv(name, home)
	}
	keys := memoryKeys{}
	store, err := openProfileStoreWithKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	args := []string{"-mode", "ssh", "-H", "server.example", "-u", "private-user", "-p", "secret-password", "-proxy", "http://proxy-user:proxy-password@localhost:8888", "-tun", "-max-conns", "5"}
	p, err := store.save(savedProfile{Name: "Temporary credentials", Mode: "ssh", Args: args, SessionOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	if err = store.db.QueryRow("SELECT args FROM profiles WHERE id=?", p.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	diskArgs, err := store.vault.decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-user", "secret-password", "proxy-user", "proxy-password"} {
		if strings.Contains(strings.Join(diskArgs, " "), secret) || strings.Contains(raw, secret) {
			t.Fatalf("credential persisted: %s", secret)
		}
	}
	got, err := store.get(p.ID)
	if err != nil || !reflect.DeepEqual(got.Args, args) {
		t.Fatalf("session credentials missing: %v", err)
	}
	store.close()
	if len(store.session) != 0 {
		t.Fatal("session cache retained after close")
	}
	reopened, err := openProfileStoreWithKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	list, err := reopened.list()
	if err != nil || len(list) != 1 || !list[0].NeedsCredentials {
		t.Fatalf("restart should request credentials: %#v %v", list, err)
	}
	if _, err = reopened.get(p.ID); err == nil {
		t.Fatal("sharing accepted missing credentials")
	}
}

func TestRemoveProtocolCredentials(t *testing.T) {
	got := credentialsRemoved([]string{"-mode", "v2ray", "-v2ray-link", "vmess://secret", "-v2ray-uuid", "secret-id", "-tun", "-max-conns", "5"})
	want := []string{"-mode", "v2ray", "-v2ray-link", "", "-v2ray-uuid", "", "-tun", "-max-conns", "5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected redaction: %v", got)
	}
}
