package main

import (
	"path/filepath"
	"testing"
)

func TestProfileStoreRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("APPDATA", home)
	t.Setenv("LOCALAPPDATA", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	store, err := openProfileStoreWithKeys(memoryKeys{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	saved, err := store.save(savedProfile{Name: "Office", Mode: "v2ray", Args: []string{"-mode", "v2ray", "-v2ray-link", "vmess://example"}})
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := store.list()
	if err != nil || len(profiles) != 1 || profiles[0].Name != saved.Name {
		t.Fatalf("unexpected profiles: %#v, %v", profiles, err)
	}
	if err := store.delete(saved.ID); err != nil {
		t.Fatal(err)
	}
	profiles, err = store.list()
	if err != nil || len(profiles) != 0 {
		t.Fatalf("profile was not deleted: %#v, %v", profiles, err)
	}
}
