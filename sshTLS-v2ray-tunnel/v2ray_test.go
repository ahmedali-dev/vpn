package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testCore(t *testing.T, body string) (*V2RayClient, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake core uses a POSIX shell")
	}
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	binary := filepath.Join(dir, "fake-core")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return &V2RayClient{config: V2RayConfig{BinaryPath: binary, Protocol: "vmess", Address: "example.com", Port: 443, UUID: "00000000-0000-4000-8000-000000000001", Network: "tcp", Security: "tls", SNI: "example.com"}}, dir
}

func assertNoGeneratedConfig(t *testing.T, dir string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "v2ray-config-*.json"))
	if err != nil || len(files) != 0 {
		t.Fatalf("generated configs not cleaned up: %v (%v)", files, err)
	}
}

func TestCoreStartupFailure(t *testing.T) {
	core, dir := testCore(t, "echo 'invalid configuration' >&2\nexit 7")
	err := core.Start(1080)
	if err == nil || !strings.Contains(err.Error(), "exit status 7") {
		t.Fatalf("startup failure was not reported: %v", err)
	}
	if core.IsRunning() {
		t.Fatal("exited process reported as running")
	}
	assertNoGeneratedConfig(t, dir)
	// A failed start must leave the client reusable.
	if err := core.Start(1080); err == nil {
		t.Fatal("second failed startup reported success")
	}
	if err := core.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestCoreStopsAndRetainsUserConfig(t *testing.T) {
	core, dir := testCore(t, "exec sleep 30")
	config := filepath.Join(dir, "custom.json")
	if err := os.WriteFile(config, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	core.config.ConfigPath = config
	if err := core.Start(1080); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Stop() })
	if !core.IsRunning() {
		t.Fatal("core should be running")
	}
	if err := core.Stop(); err != nil {
		t.Fatal(err)
	}
	if core.IsRunning() {
		t.Fatal("stopped core still reported as running")
	}
	if _, err := os.Stat(config); err != nil {
		t.Fatalf("user config removed: %v", err)
	}
}

func TestCoreExitAfterStartup(t *testing.T) {
	core, dir := testCore(t, "sleep 3\nexit 9")
	if err := core.Start(1080); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Stop() })
	select {
	case <-core.done:
	case <-time.After(5 * time.Second):
		t.Fatal("core exit was not collected")
	}
	if core.IsRunning() {
		t.Fatal("crashed core still reported as running; restart monitor cannot detect it")
	}
	assertNoGeneratedConfig(t, dir)
}

func TestGeneratedTLSConfig(t *testing.T) {
	core := &V2RayClient{config: V2RayConfig{Protocol: "vmess", Address: "example.com", Port: 2053, UUID: "00000000-0000-4000-8000-000000000001", Network: "tcp", Security: "tls", SNI: "example.com"}}
	config, err := core.generateV2RayConfig(1080)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(config), &parsed); err != nil {
		t.Fatal(err)
	}
	tls := parsed["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})["tlsSettings"].(map[string]interface{})
	if _, ok := tls["allowInsecure"]; ok {
		t.Fatal("removed allowInsecure option is emitted")
	}
	if tls["serverName"] != "example.com" {
		t.Fatal("TLS server name lost")
	}
	binary, err := exec.LookPath("xray")
	if err != nil {
		t.Skip("Xray not installed; JSON assertions passed")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(binary, "run", "-test", "-c", path).CombinedOutput()
	if err != nil {
		t.Fatalf("installed Xray rejected generated config: %v\n%s", err, output)
	}
	t.Log(string(output))
}

func TestGeneratedRoutingDoesNotBlockSites(t *testing.T) {
	core := &V2RayClient{config: V2RayConfig{Protocol: "vmess", Address: "example.com", Port: 443, UUID: "test-id", Network: "tcp", Security: "tls", SNI: "example.com"}}
	generated, err := core.generateV2RayConfig(1080)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(generated, "category-ads-all") || strings.Contains(generated, "blackhole") {
		t.Fatal("generated routing still blocks sites by default")
	}
}

func TestCoreCancellationDuringStartup(t *testing.T) {
	core, _ := testCore(t, "exec sleep 30")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	core.ctx = ctx
	done := make(chan error, 1)
	go func() { done <- core.Start(1082) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected canceled startup, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("startup did not cancel promptly")
	}
	if core.IsRunning() {
		t.Fatal("canceled core left running")
	}
}
