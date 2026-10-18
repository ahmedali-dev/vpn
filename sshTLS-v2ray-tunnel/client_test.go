package main

import (
	"net"
	"strings"
	"testing"
)

func TestOccupiedPortRejectedBeforeCoreLaunch(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	client := NewVPNClient(Config{Mode: ModeXray, SOCKSPort: port, V2Ray: V2RayConfig{Enabled: true, BinaryPath: "/nonexistent/core"}})
	defer client.cancel()
	err = client.Start()
	if err == nil || !strings.Contains(err.Error(), "cannot use local port") {
		t.Fatalf("expected port conflict before core launch, got %v", err)
	}
	if client.v2rayClient.cmd != nil {
		t.Fatal("core launched despite occupied port")
	}
}
