package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifiedPinRejectsUntrustedAndWrongHostname(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	address := server.Listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pin, err := verifiedCertificatePin(ctx, address, "example.com", roots)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(server.Certificate().Raw)
	if pin != hex.EncodeToString(sum[:]) {
		t.Fatal("wrong certificate pin")
	}
	if _, err := verifiedCertificatePin(ctx, address, "invalid.example.org", roots); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	if _, err := verifiedCertificatePin(ctx, address, "example.com", x509.NewCertPool()); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestSSHHostKeyVerification(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	client := NewVPNClient(Config{SSHHostKey: ssh.FingerprintSHA256(signer.PublicKey())})
	defer client.cancel()
	callback, err := client.sshHostKeyCallback()
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	if err := callback("example.com", remote, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(other)
	if err := callback("example.com", remote, otherSigner.PublicKey()); err == nil {
		t.Fatal("wrong SSH host key accepted")
	}
	client.config.SSHHostKey = ""
	client.config.SSHKnownHosts = t.TempDir() + "/missing"
	if _, err := client.sshHostKeyCallback(); err == nil {
		t.Fatal("missing trusted host keys silently accepted")
	}
	cfg, err := sshTLSConfig(Config{SNIHostname: "example.com"})
	if err != nil || cfg.InsecureSkipVerify {
		t.Fatal("SSH TLS verification disabled")
	}
}

func TestSSHCompatibilityAcceptsSessionHostKey(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	client := NewVPNClient(Config{SSHUnverifiedPin: true})
	defer client.cancel()
	callback, err := client.sshHostKeyCallback()
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	if err := callback("example.com", remote, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := callback("example.com", remote, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(other)
	if err := callback("example.com", remote, otherSigner.PublicKey()); err == nil {
		t.Fatal("changed SSH host key accepted in one session")
	}
}

func TestCONNECTPreservesBufferedTunnelData(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	finished := make(chan error, 1)
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(server))
		if err == nil && req.Host != "example.com:443" {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = io.WriteString(server, "HTTP/1.1 200 Connection established\r\n\r\nSSH-BANNER")
		}
		finished <- err
	}()
	conn, err := httpConnect(client, "example.com:443", "", "")
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len("SSH-BANNER"))
	if _, err = io.ReadFull(conn, b); err != nil || string(b) != "SSH-BANNER" {
		t.Fatalf("buffered tunnel data lost: %q %v", b, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestCONNECTRejectsProxyAuthenticationFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(server))
		_, _ = io.WriteString(server, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
	}()
	if _, err := httpConnect(client, "example.com:443", "", ""); err == nil || !strings.Contains(err.Error(), "407") {
		t.Fatalf("expected 407 error, got %v", err)
	}
}

func TestPayloadPlaceholdersAndProxyAuth(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	observed := make(chan *http.Request, 1)
	go func() {
		req, _ := http.ReadRequest(bufio.NewReader(server))
		observed <- req
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\n\r\n")
	}()
	_, err := httpConnect(client, "example.com:443", "CONNECT [host_port] [protocol][crlf]Host: [host][crlf][proxy_auth][crlf]", "dXNlcjpwYXNz")
	if err != nil {
		t.Fatal(err)
	}
	req := <-observed
	if req == nil || req.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" || req.Host != "example.com:443" {
		t.Fatal("invalid custom payload/auth")
	}
}
