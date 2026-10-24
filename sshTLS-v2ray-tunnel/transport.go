package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Discover pins only after PKI and hostname verification. An unverified
// certificate observed on the wire is never silently trusted.
func verifiedCertificatePin(ctx context.Context, address, name string, roots *x509.CertPool) (string, error) {
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: ConnectionTimeout}, Config: &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS12}}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", fmt.Errorf("cannot obtain a verified certificate for %s: %w", name, err)
	}
	defer conn.Close()
	cert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
	digest := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(digest[:]), nil
}

// observedCertificatePin is used ONLY when the user explicitly selects insecure
// compatibility mode. It authenticates neither the hostname nor the certificate
// chain. The resulting leaf pin is held in memory for this connection session.
func observedCertificatePin(ctx context.Context, address, name string) (string, error) {
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: ConnectionTimeout}, Config: &tls.Config{
		ServerName: name, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, // Explicit insecure compatibility mode only.
		NextProtos: []string{"http/1.1"},
	}}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", fmt.Errorf("cannot obtain compatibility certificate: %w", err)
	}
	defer conn.Close()
	cert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
	digest := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(digest[:]), nil
}

func (v *V2RayClient) resolveAutomaticPin(ctx context.Context) error {
	if v.config.UnverifiedPin {
		if v.config.ConfigPath != "" || v.config.Security != "tls" {
			return fmt.Errorf("unverified session pin requires a generated TLS config")
		}
		// Retain the pin across core restarts; never silently accept a changed certificate.
		if v.config.PeerCertSHA256 != "" {
			return nil
		}
		dialHost := v.config.Address
		if v.config.DialAddress != "" {
			dialHost = v.config.DialAddress
		}
		v.coreLogf("[!] INSECURE compatibility: certificate expiry, hostname and CA trust are not verified. The initial connection may be impersonated.\n")
		pin, err := observedCertificatePin(ctx, net.JoinHostPort(dialHost, strconv.Itoa(v.config.Port)), v.config.SNI)
		if err != nil {
			return err
		}
		v.config.PeerCertSHA256 = pin
		v.coreLogf("[!] Unverified session certificate SHA-256: %s (not a trusted identity).\n", pin)
		return nil
	}

	if !v.config.AutoPin || v.config.ConfigPath != "" || v.config.Security != "tls" || v.config.SNI == v.config.Address {
		return nil
	}
	dialHost := v.config.Address
	if v.config.DialAddress != "" {
		dialHost = v.config.DialAddress
	}
	pin, err := verifiedCertificatePin(ctx, net.JoinHostPort(dialHost, strconv.Itoa(v.config.Port)), v.config.Address, nil)
	if err != nil {
		return err
	}
	v.config.PeerCertSHA256 = pin
	v.coreLogf("[+] Verified server certificate automatically; SHA-256: %s\n", pin)
	return nil
}

func (v *VPNClient) sshHostKeyCallback() (ssh.HostKeyCallback, error) {
	if pin := v.config.SSHHostKey; pin != "" {
		if !strings.HasPrefix(pin, "SHA256:") {
			return nil, fmt.Errorf("SSH host-key pin must use SHA256: format")
		}
		return func(host string, remote net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != pin {
				return fmt.Errorf("SSH host-key mismatch for %s", host)
			}
			return nil
		}, nil
	}
	if v.config.SSHTrustOnFirstUse {
		// Compatibility mode uses session-scoped TOFU for the SSH host key. This
		// lets legacy servers work without a known_hosts file while still
		// rejecting a key change during the same handshake/session.
		return func(host string, remote net.Addr, key ssh.PublicKey) error {
			v.trustMu.Lock()
			defer v.trustMu.Unlock()
			current := ssh.FingerprintSHA256(key)
			if v.observedSSHKey == "" {
				v.observedSSHKey = current
				v.logf("[!] SSH compatibility mode: accepting session host key %s; configure Trusted SSH fingerprint for persistent verification.\n", current)
				return nil
			}
			if v.observedSSHKey != current {
				return fmt.Errorf("SSH host-key changed during session for %s", host)
			}
			return nil
		}, nil
	}
	callback, err := knownhosts.New(v.config.SSHKnownHosts)
	if err != nil {
		return nil, fmt.Errorf("load trusted SSH keys: %w; supply -ssh-known-hosts or -ssh-host-key from your server operator", err)
	}
	return callback, nil
}

func sshTLSConfig(cfg Config) (*tls.Config, error) {
	result := &tls.Config{ServerName: cfg.SNIHostname, MinVersion: tls.VersionTLS12}
	if cfg.TLSVersion == "tls1.2" {
		result.MinVersion, result.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	} else if cfg.TLSVersion == "tls1.3" {
		result.MinVersion, result.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	}
	if cfg.TLSCA != "" {
		pem, err := os.ReadFile(cfg.TLSCA)
		if err != nil {
			return nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("TLS CA file contains no certificates")
		}
		result.RootCAs = roots
	}
	return result, nil
}

func parseProxyURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("proxy must be an http:// or https:// URL")
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("proxy URL must not contain a path, query, or fragment")
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid proxy port")
		}
	}
	return u, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// HTTP CONNECT responses can share a packet with TLS/SSH bytes. Preserve all
// bytes read ahead rather than throwing away the buffered reader.
func httpConnect(conn net.Conn, target, template, auth string) (net.Conn, error) {
	if template == "" {
		template = "CONNECT [host_port] HTTP/1.1[crlf]Host: [host_port][crlf][proxy_auth]Proxy-Connection: Keep-Alive[crlf][crlf]"
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	authHeader := ""
	if auth != "" {
		authHeader = "Proxy-Authorization: Basic " + auth + "\r\n"
	}
	payload := strings.NewReplacer("[host_port]", target, "[host]", host, "[port]", port, "[protocol]", "HTTP/1.1", "[crlf]", "\r\n", "[cr]", "\r", "[lf]", "\n", "[ua]", "Tunnel/1.0", "[proxy_auth]", authHeader).Replace(template)
	for _, part := range strings.Split(payload, "[split]") {
		if _, err := io.WriteString(conn, part); err != nil {
			return nil, err
		}
	}
	reader := bufio.NewReader(conn)
	var header bytes.Buffer
	for header.Len() < 64*1024 {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("CONNECT response: %w", err)
		}
		header.WriteByte(b)
		if bytes.HasSuffix(header.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}
	if !bytes.HasSuffix(header.Bytes(), []byte("\r\n\r\n")) {
		return nil, fmt.Errorf("CONNECT response headers exceed 64 KiB")
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(header.Bytes())), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("invalid CONNECT response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream CONNECT rejected: HTTP %d", resp.StatusCode)
	}
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

func (v *VPNClient) dialSSHTransport() (net.Conn, error) {
	target := net.JoinHostPort(v.config.Host, strconv.Itoa(v.config.Port))
	address := target
	if v.config.DialAddress != "" {
		address = net.JoinHostPort(v.config.DialAddress, strconv.Itoa(v.config.Port))
	}
	var proxy *url.URL
	var err error
	if v.config.ProxyURL != "" {
		proxy, err = parseProxyURL(v.config.ProxyURL)
		if err != nil {
			return nil, err
		}
		port := proxy.Port()
		if port == "" {
			port = "80"
			if proxy.Scheme == "https" {
				port = "443"
			}
		}
		proxyHost := proxy.Hostname()
		if v.config.ProxyDialAddress != "" {
			proxyHost = v.config.ProxyDialAddress
		}
		address = net.JoinHostPort(proxyHost, port)
	}
	conn, err := (&net.Dialer{Timeout: ConnectionTimeout, KeepAlive: 30 * time.Second}).DialContext(v.ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	baseConn := conn
	stopCancellation := context.AfterFunc(v.ctx, func() { baseConn.Close() })
	defer stopCancellation()
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(ConnectionTimeout))
	if proxy != nil && proxy.Scheme == "https" {
		secure := tls.Client(conn, &tls.Config{ServerName: proxy.Hostname(), MinVersion: tls.VersionTLS12})
		if err = secure.HandshakeContext(v.ctx); err != nil {
			return nil, err
		}
		conn = secure
	}
	payloadBefore := v.config.Payload != "" && v.config.PayloadStage == "before-tls"
	if proxy != nil || payloadBefore {
		template := ""
		if payloadBefore {
			template = v.config.Payload
		}
		auth := ""
		if proxy != nil && proxy.User != nil {
			password, _ := proxy.User.Password()
			auth = base64.StdEncoding.EncodeToString([]byte(proxy.User.Username() + ":" + password))
		}
		conn, err = httpConnect(conn, target, template, auth)
		if err != nil {
			return nil, err
		}
	}
	tlsConfig, err := sshTLSConfig(v.config)
	if err != nil {
		return nil, err
	}
	pin := v.config.SSHCertPin
	if v.config.SSHAutoPin && v.config.SNIHostname != v.config.Host {
		dialHost := v.config.Host
		if v.config.DialAddress != "" {
			dialHost = v.config.DialAddress
		}
		pin, err = verifiedCertificatePin(v.ctx, net.JoinHostPort(dialHost, strconv.Itoa(v.config.Port)), v.config.Host, tlsConfig.RootCAs)
		if err != nil {
			return nil, err
		}
	}
	if v.config.SSHUnverifiedPin && pin == "" {
		dialHost := v.config.Host
		if v.config.DialAddress != "" {
			dialHost = v.config.DialAddress
		}
		pin, err = observedCertificatePin(v.ctx, net.JoinHostPort(dialHost, strconv.Itoa(v.config.Port)), v.config.SNIHostname)
		if err != nil {
			return nil, err
		}
		v.config.SSHCertPin = pin
		v.logf("[!] SSH compatibility mode: certificate expiry, hostname, and CA trust are not verified. Session SHA-256: %s\n", pin)
	}
	if pin != "" {
		// Verification is replaced by comparison to an explicitly trusted or
		// previously PKI-verified certificate, not disabled.
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("missing TLS peer certificate")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].Raw)
			if hex.EncodeToString(sum[:]) != pin {
				return fmt.Errorf("SSH TLS certificate pin mismatch")
			}
			return nil
		}
	}
	secure := tls.Client(conn, tlsConfig)
	if err = secure.HandshakeContext(v.ctx); err != nil {
		return nil, fmt.Errorf("SSH TLS handshake: %w", err)
	}
	conn = secure
	if v.config.Payload != "" && v.config.PayloadStage == "after-tls" {
		conn, err = httpConnect(conn, target, v.config.Payload, "")
		if err != nil {
			return nil, err
		}
	}
	conn.SetDeadline(time.Time{})
	ok = true
	return conn, nil
}

func waitForSOCKS(ctx context.Context, port int) error {
	deadline := time.Now().Add(6 * time.Second)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		conn, err := (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, err = conn.Write([]byte{5, 1, 0})
			reply := make([]byte, 2)
			if err == nil {
				_, err = io.ReadFull(conn, reply)
			}
			conn.Close()
			if err == nil && reply[0] == 5 && reply[1] == 0 {
				return nil
			}
		}
		if !sleepContext(ctx, 100*time.Millisecond) {
			break
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("core did not provide a working SOCKS5 listener on port %d", port)
}
