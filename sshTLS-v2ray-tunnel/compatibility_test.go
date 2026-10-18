package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestCompatibilityIsExplicitAndTLSOnly(t *testing.T) {
	base := []string{"-mode", "xray", "-v2ray-link", "vless://test@example.com:443?security=tls"}
	cfg, err := parseConfig(base)
	if err != nil || !cfg.V2Ray.AutoPin || cfg.V2Ray.UnverifiedPin {
		t.Fatalf("verification default changed: %v", err)
	}
	cfg, err = parseConfig(append(base, "-v2ray-cert-sha256", "insecure"))
	if err != nil || !cfg.V2Ray.UnverifiedPin || cfg.V2Ray.AutoPin {
		t.Fatalf("explicit compatibility mode unavailable: %v", err)
	}
	for _, args := range [][]string{
		{"-mode", "xray", "-v2ray-link", "vless://test@example.com:443?security=none", "-v2ray-cert-sha256", "insecure"},
		{"-mode", "xray", "-v2ray-config", "custom.json", "-v2ray-cert-sha256", "insecure"},
	} {
		if _, err := parseConfig(args); err == nil {
			t.Fatal("compatibility accepted outside generated TLS configuration")
		}
	}
}

func TestCompatibilityPinsObservedCertificateForSession(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	address := server.Listener.Addr().String()
	host, port, _ := net.SplitHostPort(address)
	n, _ := strconv.Atoi(port)
	core := &V2RayClient{config: V2RayConfig{Address: host, Port: n, SNI: "wrong.example", Security: "tls", UnverifiedPin: true}}
	sum := sha256.Sum256(server.Certificate().Raw)
	server.CloseClientConnections()
	if err := core.resolveAutomaticPin(context.Background()); err != nil {
		server.Close()
		t.Fatal(err)
	}
	server.Close()
	if core.config.PeerCertSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("observed pin was not used")
	}
	// With the server gone, a core restart must retain the session pin rather
	// than opening another unauthenticated discovery connection.
	if err := core.resolveAutomaticPin(context.Background()); err != nil {
		t.Fatalf("session pin was rediscovered: %v", err)
	}
	generated, err := core.generateV2RayConfig(1082)
	if err != nil || !strings.Contains(generated, core.config.PeerCertSHA256) || strings.Contains(generated, "allowInsecure") {
		t.Fatalf("modern core did not receive session pin: %v", err)
	}
}
