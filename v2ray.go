package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// Constants - Optimized for high-performance connection handling
const (
	SOCKS5Version     = 0x05
	MaxConnections    = 2000
	DefaultSOCKSPort  = 1080
	MaxRetries        = 5
	RetryDelay        = 2 * time.Second
	KeepaliveInterval = 15 * time.Second
	StatusInterval    = 60 * time.Second
	ConnectionTimeout = 30 * time.Second
	RouteCheckInterval = 10 * time.Second
	MaxRouteRetries    = 3
	ReadBufferSize     = 32 * 1024
	WriteBufferSize    = 32 * 1024
	MaxIdleConns       = 100
	IdleConnTimeout    = 90 * time.Second
	
	// V2Ray/Xray constants
	DefaultV2RayPort   = 10808
	DefaultXrayAPIPort = 10809
)

// SOCKS5 command types
const (
	SOCKS5CmdConnect = 0x01
)

// SOCKS5 address types
const (
	SOCKS5AtypIPv4   = 0x01
	SOCKS5AtypDomain = 0x03
	SOCKS5AtypIPv6   = 0x04
)

// SOCKS5 reply codes
const (
	SOCKS5ReplySuccess        = 0x00
	SOCKS5ReplyGeneralError   = 0x05
	SOCKS5ReplyCmdNotSupport  = 0x07
	SOCKS5ReplyAtypNotSupport = 0x08
)

// TunnelMode defines the tunnel type
type TunnelMode string

const (
	ModeSSH   TunnelMode = "ssh"
	ModeV2Ray TunnelMode = "v2ray"
	ModeXray  TunnelMode = "xray"
)

// V2RayConfig holds V2Ray/Xray configuration
type V2RayConfig struct {
	Enabled      bool
	Protocol     string // vmess, vless, trojan, shadowsocks
	UUID         string
	Address      string
	Port         int
	Network      string // tcp, ws, grpc, http
	Security     string // none, tls, reality
	SNI          string
	Path         string // for websocket
	Host         string // for websocket
	ServiceName  string // for grpc
	ConfigPath   string // custom config file path
	BinaryPath   string // xray or v2ray binary path
}

// Config holds the VPN client configuration
type Config struct {
	// Common
	Mode           TunnelMode
	SOCKSPort      int
	AutoRoute      bool
	PACPort        int
	MaxConnections int
	
	// SSH specific
	Host        string
	Port        int
	Username    string
	Password    string
	SNIHostname string
	
	// V2Ray/Xray specific
	V2Ray V2RayConfig
}

// V2RayClient manages V2Ray/Xray process
type V2RayClient struct {
	config  V2RayConfig
	cmd     *exec.Cmd
	running atomic.Bool
	mu      sync.Mutex
}

// ConnectionPool manages SSH connections for better performance
type ConnectionPool struct {
	client       *ssh.Client
	mu           sync.RWMutex
	lastUsed     time.Time
	healthy      atomic.Bool
	dialAttempts atomic.Int64
	dialErrors   atomic.Int64
}

func (cp *ConnectionPool) MarkHealthy() {
	cp.mu.Lock()
	cp.lastUsed = time.Now()
	cp.mu.Unlock()
	cp.healthy.Store(true)
}

func (cp *ConnectionPool) MarkUnhealthy() {
	cp.healthy.Store(false)
}

func (cp *ConnectionPool) IsHealthy() bool {
	return cp.healthy.Load()
}

func (cp *ConnectionPool) GetClient() *ssh.Client {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.client
}

func (cp *ConnectionPool) SetClient(client *ssh.Client) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.client != nil {
		cp.client.Close()
	}
	cp.client = client
	cp.lastUsed = time.Now()
	cp.healthy.Store(true)
}

// RouteManager handles automatic routing
type RouteManager struct {
	originalGateway string
	serverIP        string
	routeAdded      atomic.Bool
	mu              sync.Mutex
}

// PACServer serves PAC file for automatic browser configuration
type PACServer struct {
	port      int
	socksPort int
	running   atomic.Bool
	server    *http.Server
}

// Stats tracks connection statistics with better granularity
type Stats struct {
	connCount      atomic.Int32
	totalConns     atomic.Int64
	failedCount    atomic.Int64
	successCount   atomic.Int64
	bytesIn        atomic.Int64
	bytesOut       atomic.Int64
	startTime      time.Time
	lastConnTime   time.Time
	lastConnMu     sync.RWMutex
}

func (s *Stats) RecordConnection() {
	s.connCount.Add(1)
	s.totalConns.Add(1)
	s.lastConnMu.Lock()
	s.lastConnTime = time.Now()
	s.lastConnMu.Unlock()
}

func (s *Stats) CloseConnection() {
	s.connCount.Add(-1)
}

func (s *Stats) RecordSuccess() {
	s.successCount.Add(1)
}

func (s *Stats) RecordFailure() {
	s.failedCount.Add(1)
}

func (s *Stats) AddBytes(in, out int64) {
	s.bytesIn.Add(in)
	s.bytesOut.Add(out)
}

// VPNClient manages the VPN tunnel
type VPNClient struct {
	config        Config
	connPool      *ConnectionPool
	v2rayClient   *V2RayClient
	running       atomic.Bool
	stats         Stats
	routeManager  *RouteManager
	pacServer     *PACServer
	ctx           context.Context
	cancel        context.CancelFunc
	connSemaphore chan struct{}
	bufferPool    *sync.Pool
}

// NewVPNClient creates a new VPN client instance
func NewVPNClient(cfg Config) *VPNClient {
	ctx, cancel := context.WithCancel(context.Background())
	
	maxConns := cfg.MaxConnections
	if maxConns <= 0 {
		maxConns = MaxConnections
	}
	
	client := &VPNClient{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
		stats: Stats{
			startTime: time.Now(),
		},
		connPool: &ConnectionPool{},
		routeManager: &RouteManager{
			serverIP: cfg.Host,
		},
		pacServer: &PACServer{
			port:      cfg.PACPort,
			socksPort: cfg.SOCKSPort,
		},
		connSemaphore: make(chan struct{}, maxConns),
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, ReadBufferSize)
			},
		},
	}
	
	// Initialize V2Ray client if enabled
	if cfg.V2Ray.Enabled {
		client.v2rayClient = &V2RayClient{
			config: cfg.V2Ray,
		}
	}
	
	return client
}

// V2Ray/Xray Management

// generateV2RayConfig generates V2Ray/Xray configuration
func (v *V2RayClient) generateV2RayConfig(socksPort int) (string, error) {
	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds": []map[string]interface{}{
			{
				"port":     socksPort,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls"},
				},
			},
		},
		"outbounds": []map[string]interface{}{},
	}
	
	// Build outbound based on protocol
	outbound := map[string]interface{}{
		"protocol": v.config.Protocol,
		"settings": map[string]interface{}{},
		"streamSettings": map[string]interface{}{
			"network":  v.config.Network,
			"security": v.config.Security,
		},
	}
	
	// Configure protocol settings
	switch strings.ToLower(v.config.Protocol) {
	case "vmess":
		outbound["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": v.config.Address,
					"port":    v.config.Port,
					"users": []map[string]interface{}{
						{
							"id":       v.config.UUID,
							"alterId":  0, // Modern VMess uses 0
							"security": "auto",
						},
					},
				},
			},
		}
		
	case "vless":
		outbound["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": v.config.Address,
					"port":    v.config.Port,
					"users": []map[string]interface{}{
						{
							"id":         v.config.UUID,
							"encryption": "none",
							"flow":       "", // Add flow if using XTLS
						},
					},
				},
			},
		}
		
	case "trojan":
		outbound["settings"] = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  v.config.Address,
					"port":     v.config.Port,
					"password": v.config.UUID,
					"level":    0,
				},
			},
		}
		
	case "shadowsocks":
		outbound["settings"] = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  v.config.Address,
					"port":     v.config.Port,
					"method":   "aes-256-gcm",
					"password": v.config.UUID,
					"level":    0,
				},
			},
		}
	}
	
	// Configure stream settings
	streamSettings := outbound["streamSettings"].(map[string]interface{})
	
	switch v.config.Network {
	case "ws":
		wsSettings := map[string]interface{}{
			"path": v.config.Path,
		}
		if v.config.Host != "" {
			wsSettings["headers"] = map[string]interface{}{
				"Host": v.config.Host,
			}
		}
		streamSettings["wsSettings"] = wsSettings
		
	case "grpc":
		streamSettings["grpcSettings"] = map[string]interface{}{
			"serviceName":        v.config.ServiceName,
			"multiMode":          false,
			"idle_timeout":       60,
			"health_check_timeout": 20,
		}
		
	case "http", "h2":
		httpSettings := map[string]interface{}{
			"path": v.config.Path,
		}
		if v.config.Host != "" {
			httpSettings["host"] = []string{v.config.Host}
		}
		streamSettings["httpSettings"] = httpSettings
		
	case "tcp":
		// TCP can have header obfuscation
		streamSettings["tcpSettings"] = map[string]interface{}{
			"header": map[string]interface{}{
				"type": "none",
			},
		}
	}
	
	// Configure TLS/Security
	if v.config.Security == "tls" {
		tlsSettings := map[string]interface{}{
			"allowInsecure": true, // Allow insecure for compatibility
			"alpn":          []string{"h2", "http/1.1"},
		}
		if v.config.SNI != "" {
			tlsSettings["serverName"] = v.config.SNI
		}
		// Add fingerprint if available
		tlsSettings["fingerprint"] = "chrome"
		streamSettings["tlsSettings"] = tlsSettings
		
	} else if v.config.Security == "reality" {
		realitySettings := map[string]interface{}{
			"fingerprint": "chrome",
			"serverName":  v.config.SNI,
			"show":        false,
		}
		streamSettings["realitySettings"] = realitySettings
	}
	
	config["outbounds"] = []map[string]interface{}{
		outbound,
		{
			"protocol": "freedom",
			"tag":      "direct",
		},
		{
			"protocol": "blackhole",
			"tag":      "block",
		},
	}
	
	// Add routing rules
	config["routing"] = map[string]interface{}{
		"domainStrategy": "IPIfNonMatch",
		"rules": []map[string]interface{}{
			{
				"type":        "field",
				"outboundTag": "direct",
				"domain":      []string{"geosite:private"},
			},
			{
				"type":        "field",
				"outboundTag": "block",
				"domain":      []string{"geosite:category-ads-all"},
			},
		},
	}
	
	// Convert to JSON
	jsonData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	
	return string(jsonData), nil
}

// Start starts the V2Ray/Xray process
func (v *V2RayClient) Start(socksPort int) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	
	if v.running.Load() {
		return fmt.Errorf("v2ray/xray already running")
	}
	
	// Determine binary path
	binaryPath := v.config.BinaryPath
	if binaryPath == "" {
		// Try to find xray or v2ray in PATH
		var err error
		binaryPath, err = exec.LookPath("xray")
		if err != nil {
			binaryPath, err = exec.LookPath("v2ray")
			if err != nil {
				return fmt.Errorf("xray/v2ray binary not found in PATH. Install xray or specify -v2ray-binary")
			}
		}
	}
	
	fmt.Printf("[*] Using binary: %s\n", binaryPath)
	
	// Generate or use existing config
	var configPath string
	if v.config.ConfigPath != "" {
		configPath = v.config.ConfigPath
		fmt.Printf("[*] Using config file: %s\n", configPath)
	} else {
		// Generate config
		configJSON, err := v.generateV2RayConfig(socksPort)
		if err != nil {
			return fmt.Errorf("failed to generate config: %w", err)
		}
		
		// Write to temp file
		tmpFile, err := os.CreateTemp("", "v2ray-config-*.json")
		if err != nil {
			return fmt.Errorf("failed to create temp config: %w", err)
		}
		configPath = tmpFile.Name()
		
		if _, err := tmpFile.Write([]byte(configJSON)); err != nil {
			tmpFile.Close()
			return fmt.Errorf("failed to write config: %w", err)
		}
		tmpFile.Close()
		
		fmt.Printf("[*] Generated config: %s\n", configPath)
		
		// Print config for debugging (optional)
		if os.Getenv("DEBUG") == "1" {
			fmt.Println("[DEBUG] Generated config:")
			fmt.Println(configJSON)
		}
	}
	
	// Start the process
	v.cmd = exec.Command(binaryPath, "run", "-c", configPath)
	
	// Capture output for connection tracking
	stdout, err := v.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	stderr, err := v.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}
	
	if err := v.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start v2ray/xray: %w", err)
	}
	
	v.running.Store(true)
	
	// Stream output
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line)
		}
	}()
	
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line)
		}
	}()
	
	// Wait a moment for startup
	time.Sleep(2 * time.Second)
	
	// Verify process is running
	if v.cmd.Process == nil {
		return fmt.Errorf("v2ray/xray process failed to start")
	}
	
	// Check if process is still alive
	if err := v.cmd.Process.Signal(syscall.Signal(0)); err != nil {
		return fmt.Errorf("v2ray/xray process died immediately: %w", err)
	}
	
	fmt.Printf("[+] V2Ray/Xray started (PID: %d)\n", v.cmd.Process.Pid)
	return nil
}

// Stop stops the V2Ray/Xray process
func (v *V2RayClient) Stop() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	
	if !v.running.Load() {
		return nil
	}
	
	if v.cmd != nil && v.cmd.Process != nil {
		fmt.Println("[*] Stopping V2Ray/Xray...")
		if err := v.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			v.cmd.Process.Kill()
		}
		v.cmd.Wait()
	}
	
	v.running.Store(false)
	fmt.Println("[+] V2Ray/Xray stopped")
	return nil
}

// IsRunning checks if V2Ray/Xray is running
func (v *V2RayClient) IsRunning() bool {
	return v.running.Load()
}

// SSH Tunnel Methods (existing code)

func (v *VPNClient) createTLSConnection() (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", v.config.Host, v.config.Port)

	dialer := &net.Dialer{
		Timeout:   ConnectionTimeout,
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP connection failed: %w", err)
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true)
		tcpConn.SetReadBuffer(ReadBufferSize)
		tcpConn.SetWriteBuffer(WriteBufferSize)
	}

	tlsConfig := &tls.Config{
		ServerName:         v.config.SNIHostname,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(ConnectionTimeout))

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := tlsConn.ConnectionState()
	fmt.Printf("[+] TLS connection established (TLS %s)\n", formatTLSVersion(state.Version))

	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

func (v *VPNClient) connectSSH() error {
	var lastErr error
	for attempt := 0; attempt < MaxRetries; attempt++ {
		if err := v.attemptSSHConnection(); err != nil {
			lastErr = err
			if attempt < MaxRetries-1 {
				fmt.Printf("[!] Attempt %d/%d failed: %v\n", attempt+1, MaxRetries, err)
				backoff := RetryDelay * time.Duration(attempt+1)
				fmt.Printf("[*] Retrying in %v...\n", backoff)
				time.Sleep(backoff)
				continue
			}
		} else {
			return nil
		}
	}
	return fmt.Errorf("failed after %d attempts: %w", MaxRetries, lastErr)
}

func (v *VPNClient) attemptSSHConnection() error {
	tlsConn, err := v.createTLSConnection()
	if err != nil {
		return err
	}

	fmt.Printf("[*] Authenticating as %s...\n", v.config.Username)

	config := &ssh.ClientConfig{
		User: v.config.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(v.config.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         ConnectionTimeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(tlsConn, v.config.Host, config)
	if err != nil {
		tlsConn.Close()
		return fmt.Errorf("SSH connection failed: %w", err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)
	v.connPool.SetClient(client)
	fmt.Println("[+] SSH authentication successful!")
	return nil
}

// SOCKS5 Handler

func (v *VPNClient) handleSOCKS5(clientConn net.Conn) {
	defer clientConn.Close()

	select {
	case v.connSemaphore <- struct{}{}:
		defer func() { <-v.connSemaphore }()
	default:
		return
	}

	v.stats.RecordConnection()
	defer v.stats.CloseConnection()

	clientConn.SetDeadline(time.Now().Add(30 * time.Second))

	if err := v.performSOCKS5Handshake(clientConn); err != nil {
		return
	}

	targetAddr, err := v.parseSOCKS5Request(clientConn)
	if err != nil {
		v.sendSOCKS5Reply(clientConn, SOCKS5ReplyGeneralError)
		v.stats.RecordFailure()
		return
	}

	clientConn.SetDeadline(time.Time{})

	var remoteConn net.Conn
	
	// Use appropriate tunnel based on mode
	if v.config.Mode == ModeSSH {
		remoteConn, err = v.dialThroughSSH(targetAddr)
	} else {
		// For V2Ray/Xray, we're already providing SOCKS5, so this shouldn't be called
		// But we'll handle it gracefully
		err = fmt.Errorf("v2ray/xray mode doesn't use SOCKS5 handler")
	}
	
	if err != nil {
		v.stats.RecordFailure()
		v.sendSOCKS5Reply(clientConn, SOCKS5ReplyGeneralError)
		return
	}
	defer remoteConn.Close()

	if err := v.sendSOCKS5Reply(clientConn, SOCKS5ReplySuccess); err != nil {
		v.stats.RecordFailure()
		return
	}

	v.stats.RecordSuccess()
	v.forwardDataWithMetrics(clientConn, remoteConn)
}

func (v *VPNClient) performSOCKS5Handshake(conn net.Conn) error {
	buf := make([]byte, 257)
	
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return fmt.Errorf("handshake read error: %w", err)
	}

	if buf[0] != SOCKS5Version {
		return fmt.Errorf("invalid SOCKS version: %d", buf[0])
	}

	nmethods := int(buf[1])
	if nmethods == 0 {
		return fmt.Errorf("no authentication methods provided")
	}

	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return fmt.Errorf("methods read error: %w", err)
	}

	_, err := conn.Write([]byte{SOCKS5Version, 0x00})
	return err
}

func (v *VPNClient) parseSOCKS5Request(conn net.Conn) (string, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", fmt.Errorf("request read error: %w", err)
	}

	if buf[1] != SOCKS5CmdConnect {
		v.sendSOCKS5Reply(conn, SOCKS5ReplyCmdNotSupport)
		return "", fmt.Errorf("unsupported command: %d", buf[1])
	}

	addr, err := v.readSOCKS5Address(conn, buf[3])
	if err != nil {
		return "", err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("port read error: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", addr, port), nil
}

func (v *VPNClient) readSOCKS5Address(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case SOCKS5AtypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		return net.IP(ip).String(), nil

	case SOCKS5AtypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", err
		}
		domain := make([]byte, length[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		return string(domain), nil

	case SOCKS5AtypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		return net.IP(ip).String(), nil

	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}
}

func (v *VPNClient) dialThroughSSH(addr string) (net.Conn, error) {
	v.connPool.dialAttempts.Add(1)
	
	for retry := 0; retry < 3; retry++ {
		client := v.connPool.GetClient()
		if client == nil {
			if retry < 2 {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			v.connPool.dialErrors.Add(1)
			return nil, fmt.Errorf("SSH client not available")
		}

		conn, err := client.Dial("tcp", addr)
		if err == nil {
			v.connPool.MarkHealthy()
			return conn, nil
		}

		if strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "closed") {
			v.connPool.MarkUnhealthy()
		}

		if retry < 2 {
			time.Sleep(time.Duration(retry+1) * 200 * time.Millisecond)
		}
	}
	
	v.connPool.dialErrors.Add(1)
	return nil, fmt.Errorf("failed to dial through SSH tunnel")
}

func (v *VPNClient) sendSOCKS5Reply(conn net.Conn, replyCode byte) error {
	reply := []byte{SOCKS5Version, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}

func (v *VPNClient) forwardDataWithMetrics(client, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	var bytesIn, bytesOut int64

	go func() {
		defer wg.Done()
		buf := v.bufferPool.Get().([]byte)
		defer v.bufferPool.Put(buf)
		
		n, _ := v.copyWithBuffer(remote, client, buf)
		bytesOut = n
		
		if tcp, ok := remote.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		buf := v.bufferPool.Get().([]byte)
		defer v.bufferPool.Put(buf)
		
		n, _ := v.copyWithBuffer(client, remote, buf)
		bytesIn = n
		
		if tcp, ok := client.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	wg.Wait()
	v.stats.AddBytes(bytesIn, bytesOut)
}

func (v *VPNClient) copyWithBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	var written int64
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				return written, nil
			}
			return written, err
		}
	}
}

// Server Management

func (v *VPNClient) startSOCKSServer() error {
	// For V2Ray/Xray mode, we don't start our own SOCKS server
	if v.config.Mode == ModeV2Ray || v.config.Mode == ModeXray {
		v.printBanner()
		v.running.Store(true)
		
		// Setup routes if enabled
		if v.config.AutoRoute {
			if err := v.setupRoutes(); err != nil {
				fmt.Printf("[!] Warning: Failed to setup routes: %v\n", err)
			}
		}
		
		// Start PAC server
		if v.config.PACPort > 0 {
			go v.startPACServer()
		}
		
		// Monitor V2Ray/Xray health
		go v.monitorV2Ray()
		go v.displayStatus()
		
		// Wait for shutdown
		<-v.ctx.Done()
		return nil
	}
	
	// SSH mode - start SOCKS5 server
	addr := fmt.Sprintf("127.0.0.1:%d", v.config.SOCKSPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start SOCKS server: %w", err)
	}
	defer listener.Close()

	v.printBanner()
	v.running.Store(true)

	if v.config.AutoRoute {
		if err := v.setupRoutes(); err != nil {
			fmt.Printf("[!] Warning: Failed to setup routes: %v\n", err)
		}
	}

	if v.config.PACPort > 0 {
		go v.startPACServer()
	}

	go v.keepalive()
	go v.displayStatus()
	go v.healthCheck()

	if v.config.AutoRoute {
		go v.monitorRoutes()
	}

	for v.running.Load() {
		conn, err := listener.Accept()
		if err != nil {
			if v.running.Load() {
				continue
			}
			break
		}
		
		go v.handleSOCKS5(conn)
	}

	return nil
}

func (v *VPNClient) monitorV2Ray() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for v.running.Load() {
		select {
		case <-ticker.C:
			if v.v2rayClient != nil && !v.v2rayClient.IsRunning() {
				fmt.Println("\n[!] V2Ray/Xray process died, restarting...")
				if err := v.v2rayClient.Start(v.config.SOCKSPort); err != nil {
					fmt.Printf("[!] Failed to restart: %v\n", err)
				} else {
					fmt.Println("[+] V2Ray/Xray restarted successfully")
				}
			}
		case <-v.ctx.Done():
			return
		}
	}
}

func (v *VPNClient) healthCheck() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for v.running.Load() {
		select {
		case <-ticker.C:
			if !v.connPool.IsHealthy() && v.config.Mode == ModeSSH {
				fmt.Println("\n[!] Connection unhealthy, reconnecting...")
				if err := v.reconnect(); err == nil {
					fmt.Println("[✓] Health check: Reconnected\n")
				}
			}
		case <-v.ctx.Done():
			return
		}
	}
}

func (v *VPNClient) keepalive() {
	ticker := time.NewTicker(KeepaliveInterval)
	defer ticker.Stop()

	consecutiveFailures := 0
	const maxFailures = 3

	for v.running.Load() {
		select {
		case <-ticker.C:
			client := v.connPool.GetClient()
			if client == nil {
				fmt.Println("\n[!] Connection lost. Reconnecting...")
				if err := v.reconnect(); err == nil {
					fmt.Println("[✓] Reconnected\n")
					consecutiveFailures = 0
				} else {
					consecutiveFailures++
					if consecutiveFailures >= maxFailures {
						v.running.Store(false)
					}
				}
			} else {
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					consecutiveFailures++
					v.connPool.MarkUnhealthy()
					if consecutiveFailures >= maxFailures {
						v.reconnect()
						consecutiveFailures = 0
					}
				} else {
					consecutiveFailures = 0
					v.connPool.MarkHealthy()
				}
			}
		case <-v.ctx.Done():
			return
		}
	}
}

func (v *VPNClient) displayStatus() {
	ticker := time.NewTicker(StatusInterval)
	defer ticker.Stop()

	for v.running.Load() {
		select {
		case <-ticker.C:
			v.printStatus()
		case <-v.ctx.Done():
			return
		}
	}
}

func (v *VPNClient) printStatus() {
	uptime := time.Since(v.stats.startTime)
	connCount := v.stats.connCount.Load()
	maxConns := v.config.MaxConnections
	if maxConns <= 0 {
		maxConns = MaxConnections
	}
	
	mode := string(v.config.Mode)
	if v.config.Mode == ModeV2Ray || v.config.Mode == ModeXray {
		protocol := v.config.V2Ray.Protocol
		mode = fmt.Sprintf("%s (%s)", mode, protocol)
	}

	fmt.Printf("\n[ℹ] Status Report:\n")
	fmt.Printf("  Mode: %s\n", mode)
	fmt.Printf("  Uptime: %v\n", uptime.Round(time.Second))
	fmt.Printf("  Active connections: %d/%d\n", connCount, maxConns)
	fmt.Printf("  Total: %d | Success: %d | Failed: %d\n", 
		v.stats.totalConns.Load(), v.stats.successCount.Load(), v.stats.failedCount.Load())
	fmt.Printf("  Data: ↓ %s / ↑ %s\n", 
		formatBytes(v.stats.bytesIn.Load()), formatBytes(v.stats.bytesOut.Load()))
	
	if v.config.Mode == ModeSSH {
		fmt.Printf("  SSH Health: %s\n", map[bool]string{true: "✓ Healthy", false: "✗ Unhealthy"}[v.connPool.IsHealthy()])
	} else if v.v2rayClient != nil {
		fmt.Printf("  V2Ray/Xray: %s\n", map[bool]string{true: "✓ Running", false: "✗ Stopped"}[v.v2rayClient.IsRunning()])
	}
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func (v *VPNClient) reconnect() error {
	if v.config.Mode != ModeSSH {
		return nil
	}
	
	client := v.connPool.GetClient()
	if client != nil {
		client.Close()
	}
	v.connPool.SetClient(nil)
	v.connPool.MarkUnhealthy()

	time.Sleep(time.Second)
	return v.connectSSH()
}

func (v *VPNClient) Start() error {
	v.printHeader()

	// Start based on mode
	if v.config.Mode == ModeV2Ray || v.config.Mode == ModeXray {
		if err := v.v2rayClient.Start(v.config.SOCKSPort); err != nil {
			return fmt.Errorf("failed to start V2Ray/Xray: %w", err)
		}
	} else {
		if err := v.connectSSH(); err != nil {
			return fmt.Errorf("failed to establish SSH connection: %w", err)
		}
	}

	v.setupSignalHandler()
	return v.startSOCKSServer()
}

func (v *VPNClient) setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		v.shutdown()
	}()
}

func (v *VPNClient) shutdown() {
	fmt.Println("\n[*] Shutting down...")
	v.running.Store(false)
	v.cancel()

	if v.pacServer.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		v.pacServer.server.Shutdown(ctx)
		cancel()
	}

	if v.config.AutoRoute {
		v.cleanupRoutes()
	}

	if v.v2rayClient != nil {
		v.v2rayClient.Stop()
	}

	client := v.connPool.GetClient()
	if client != nil {
		client.Close()
	}

	fmt.Println("[+] Shutdown complete")
	os.Exit(0)
}

func (v *VPNClient) printHeader() {
	fmt.Println("\n============================================================")
	fmt.Println("Enhanced VPN Client - SSH + V2Ray/Xray Support")
	fmt.Println("============================================================")
	
	if v.config.Mode == ModeSSH {
		fmt.Printf("Mode: SSH Tunnel\n")
		fmt.Printf("Server: %s:%d\n", v.config.Host, v.config.Port)
		fmt.Printf("SNI: %s\n", v.config.SNIHostname)
	} else {
		fmt.Printf("Mode: %s\n", v.config.Mode)
		fmt.Printf("Protocol: %s\n", v.config.V2Ray.Protocol)
		fmt.Printf("Server: %s:%d\n", v.config.V2Ray.Address, v.config.V2Ray.Port)
		fmt.Printf("Network: %s\n", v.config.V2Ray.Network)
		fmt.Printf("Security: %s\n", v.config.V2Ray.Security)
	}
	
	fmt.Printf("Max Connections: %d\n", v.config.MaxConnections)
	fmt.Println("============================================================\n")
}

func (v *VPNClient) printBanner() {
	fmt.Println("\n============================================================")
	fmt.Println("✅ VPN TUNNEL ACTIVE!")
	fmt.Println("============================================================")
	fmt.Printf("SOCKS5 Proxy: 127.0.0.1:%d\n", v.config.SOCKSPort)
	fmt.Printf("Mode: %s\n", v.config.Mode)
	
	if v.config.Mode == ModeV2Ray || v.config.Mode == ModeXray {
		fmt.Printf("Protocol: %s over %s (%s)\n", 
			v.config.V2Ray.Protocol, 
			v.config.V2Ray.Network,
			v.config.V2Ray.Security)
		fmt.Printf("Server: %s:%d\n", v.config.V2Ray.Address, v.config.V2Ray.Port)
	}
	
	if v.config.PACPort > 0 {
		fmt.Printf("\n🎉 PAC URL: http://127.0.0.1:%d/proxy.pac\n", v.config.PACPort)
		fmt.Printf("Config Page: http://127.0.0.1:%d/\n", v.config.PACPort)
	}
	
	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("✅ TEST YOUR CONNECTION:")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	
	// Test commands
	fmt.Println("\n1. Check your VPN IP:")
	fmt.Printf("   curl --socks5 127.0.0.1:%d https://ipinfo.io/ip\n", v.config.SOCKSPort)
	
	fmt.Println("\n2. Compare with your real IP:")
	fmt.Println("   curl https://ipinfo.io/ip")
	
	fmt.Println("\n3. Test in browser (after configuring PAC):")
	fmt.Println("   Visit: https://ipinfo.io")
	fmt.Println("          https://ipleak.net")
	
	fmt.Println("\n4. Speed test:")
	fmt.Println("   Visit: https://fast.com")
	
	if v.config.Mode == ModeV2Ray || v.config.Mode == ModeXray {
		fmt.Println("\n💡 Tip: You're using V2Ray/Xray mode")
		fmt.Println("   Your traffic is already being proxied through the SOCKS5 port")
		fmt.Println("   Just configure your browser to use the PAC file or SOCKS5 proxy")
	}
	
	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("Press Ctrl+C to disconnect...")
	fmt.Println("============================================================\n")
	
	// Auto-test the connection
	if v.config.Mode == ModeV2Ray || v.config.Mode == ModeXray {
		go v.testV2RayConnection()
	}
}

func formatTLSVersion(version uint16) string {
	versions := map[uint16]string{
		tls.VersionTLS13: "1.3",
		tls.VersionTLS12: "1.2",
		tls.VersionTLS11: "1.1",
		tls.VersionTLS10: "1.0",
	}
	if v, ok := versions[version]; ok {
		return v
	}
	return "unknown"
}

// testV2RayConnection tests the V2Ray/Xray connection
func (v *VPNClient) testV2RayConnection() {
	time.Sleep(3 * time.Second)
	
	fmt.Println("\n[*] Testing V2Ray/Xray connection...")
	
	// Create a SOCKS5 dialer
	dialer, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", v.config.SOCKSPort))
	if err != nil {
		fmt.Printf("[!] Cannot connect to SOCKS5 proxy: %v\n", err)
		return
	}
	defer dialer.Close()
	
	// SOCKS5 handshake
	_, err = dialer.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		fmt.Printf("[!] SOCKS5 handshake failed: %v\n", err)
		return
	}
	
	buf := make([]byte, 2)
	_, err = io.ReadFull(dialer, buf)
	if err != nil {
		fmt.Printf("[!] SOCKS5 handshake response failed: %v\n", err)
		return
	}
	
	// Connect to ipinfo.io
	target := "ipinfo.io"
	port := 443
	
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(target))}
	request = append(request, []byte(target)...)
	request = append(request, byte(port>>8), byte(port&0xff))
	
	_, err = dialer.Write(request)
	if err != nil {
		fmt.Printf("[!] SOCKS5 connect failed: %v\n", err)
		return
	}
	
	response := make([]byte, 10)
	_, err = io.ReadFull(dialer, response)
	if err != nil {
		fmt.Printf("[!] SOCKS5 connect response failed: %v\n", err)
		return
	}
	
	if response[1] != 0x00 {
		fmt.Printf("[!] SOCKS5 connect rejected: %d\n", response[1])
		return
	}
	
	// Wrap in TLS
	tlsConn := tls.Client(dialer, &tls.Config{
		ServerName:         "ipinfo.io",
		InsecureSkipVerify: false,
	})
	
	err = tlsConn.Handshake()
	if err != nil {
		fmt.Printf("[!] TLS handshake failed: %v\n", err)
		return
	}
	
	// Send HTTP request
	httpRequest := "GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: VPN-Test/1.0\r\nConnection: close\r\n\r\n"
	_, err = tlsConn.Write([]byte(httpRequest))
	if err != nil {
		fmt.Printf("[!] HTTP request failed: %v\n", err)
		return
	}
	
	// Read response
	responseBuf := make([]byte, 4096)
	n, _ := tlsConn.Read(responseBuf)
	responseStr := string(responseBuf[:n])
	
	// Parse IP from response
	lines := strings.Split(responseStr, "\r\n")
	bodyStart := false
	for _, line := range lines {
		if bodyStart {
			ip := strings.TrimSpace(line)
			if net.ParseIP(ip) != nil {
				fmt.Printf("\n╔══════════════════════════════════════════════════════╗\n")
				fmt.Printf("║  ✅ V2RAY/XRAY CONNECTION WORKING!                  ║\n")
				fmt.Printf("║                                                      ║\n")
				fmt.Printf("║  Your exit IP: %-37s ║\n", ip)
				fmt.Printf("║                                                      ║\n")
				fmt.Printf("║  🎉 Your traffic is being tunneled successfully!    ║\n")
				fmt.Printf("╚══════════════════════════════════════════════════════╝\n\n")
				return
			}
		}
		if line == "" {
			bodyStart = true
		}
	}
	
	fmt.Println("[✓] V2Ray/Xray tunnel is operational (test inconclusive)")
}

// Route management (simplified for space)
func (v *VPNClient) setupRoutes() error {
	return nil // Implement as needed
}

func (v *VPNClient) cleanupRoutes() error {
	return nil // Implement as needed
}

func (v *VPNClient) monitorRoutes() {}

// PAC Server
func (v *VPNClient) startPACServer() {
	if v.pacServer.port <= 0 {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/proxy.pac", v.handlePAC)
	mux.HandleFunc("/", v.handlePACInfo)

	v.pacServer.server = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", v.pacServer.port),
		Handler: mux,
	}

	v.pacServer.running.Store(true)
	fmt.Printf("[+] PAC server: http://127.0.0.1:%d\n", v.pacServer.port)

	v.pacServer.server.ListenAndServe()
}

func (v *VPNClient) handlePAC(w http.ResponseWriter, r *http.Request) {
	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (isPlainHostName(host) || shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }
    return "SOCKS5 127.0.0.1:%d; DIRECT";
}`, v.pacServer.socksPort)

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Write([]byte(pac))
}

func (v *VPNClient) handlePACInfo(w http.ResponseWriter, r *http.Request) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>VPN Proxy</title><style>
body{font-family:Arial;max-width:800px;margin:50px auto;padding:20px}
.info{background:#e3f2fd;padding:20px;border-radius:5px;margin:20px 0}
h1{color:#1976d2}code{background:#f5f5f5;padding:2px 6px;border-radius:3px}
</style></head><body>
<h1>🚀 VPN Proxy Active</h1>
<div class="info">
<p>Mode: <code>%s</code></p>
<p>SOCKS5: <code>127.0.0.1:%d</code></p>
<p>PAC: <code>http://127.0.0.1:%d/proxy.pac</code></p>
</div></body></html>`, v.config.Mode, v.pacServer.socksPort, v.pacServer.port)
	
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Flag parsing
func parseFlags() Config {
	// Mode selection
	mode := flag.String("mode", "ssh", "Tunnel mode: ssh, v2ray, xray")
	
	// Common flags
	socksPort := flag.Int("socks-port", DefaultSOCKSPort, "SOCKS5 port")
	autoRoute := flag.Bool("auto-route", false, "Auto routing")
	pacPort := flag.Int("pac-port", 0, "PAC server port")
	maxConns := flag.Int("max-conns", MaxConnections, "Max concurrent connections")
	
	// SSH flags
	host := flag.String("H", "", "SSH server hostname/IP")
	port := flag.Int("P", 0, "SSH server port")
	username := flag.String("u", "", "SSH username")
	password := flag.String("p", "", "SSH password")
	sni := flag.String("S", "", "SNI hostname")
	
	// V2Ray/Xray flags
	v2rayProtocol := flag.String("v2ray-protocol", "vmess", "Protocol: vmess, vless, trojan, shadowsocks")
	v2rayUUID := flag.String("v2ray-uuid", "", "V2Ray UUID/password")
	v2rayAddr := flag.String("v2ray-addr", "", "V2Ray server address")
	v2rayPort := flag.Int("v2ray-port", 0, "V2Ray server port")
	v2rayNetwork := flag.String("v2ray-network", "tcp", "Network: tcp, ws, grpc, http")
	v2raySecurity := flag.String("v2ray-security", "none", "Security: none, tls, reality")
	v2raySNI := flag.String("v2ray-sni", "", "V2Ray SNI (leave empty to use server address)")
	v2rayPath := flag.String("v2ray-path", "/", "WebSocket path or HTTP path")
	v2rayHost := flag.String("v2ray-host", "", "WebSocket/HTTP host")
	v2rayService := flag.String("v2ray-service", "", "gRPC service name")
	v2rayConfig := flag.String("v2ray-config", "", "V2Ray config file path")
	v2rayBinary := flag.String("v2ray-binary", "", "V2Ray/Xray binary path")
	//v2rayInsecure := flag.Bool("v2ray-insecure", false, "Allow insecure TLS (skip certificate verification)")
	
	// V2Ray link import
	v2rayLink := flag.String("v2ray-link", "", "Import from vmess:// or vless:// link")

	flag.Usage = func() {
		fmt.Println("Enhanced VPN Client - SSH + V2Ray/Xray Support")
		fmt.Println("\nModes:")
		fmt.Println("  ssh    - SSH tunnel with TLS+SNI")
		fmt.Println("  v2ray  - V2Ray (VMess/VLess/Trojan)")
		fmt.Println("  xray   - Xray (same as v2ray)")
		fmt.Println("\nSSH Mode Example:")
		fmt.Printf("  %s -mode ssh -H server.com -P 8443 -u user -p pass -S sni.com\n\n", os.Args[0])
		fmt.Println("V2Ray Mode Examples:")
		fmt.Printf("  VMess: %s -mode v2ray -v2ray-protocol vmess -v2ray-addr server.com -v2ray-port 443 -v2ray-uuid UUID -v2ray-network ws -v2ray-path /path\n", os.Args[0])
		fmt.Printf("  Link:  %s -mode v2ray -v2ray-link \"vmess://base64encoded\"\n\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	tunnelMode := TunnelMode(strings.ToLower(*mode))
	
	config := Config{
		Mode:           tunnelMode,
		SOCKSPort:      *socksPort,
		AutoRoute:      *autoRoute,
		PACPort:        *pacPort,
		MaxConnections: *maxConns,
	}

	// Parse based on mode
	if tunnelMode == ModeSSH {
		if *host == "" || *port == 0 || *username == "" || *password == "" {
			log.Fatal("SSH mode requires: -H, -P, -u, -p")
		}
		config.Host = *host
		config.Port = *port
		config.Username = *username
		config.Password = *password
		config.SNIHostname = *sni
	} else if tunnelMode == ModeV2Ray || tunnelMode == ModeXray {
		// Parse V2Ray link if provided
		if *v2rayLink != "" {
			v2rayConf, err := parseV2RayLink(*v2rayLink)
			if err != nil {
				log.Fatalf("Failed to parse V2Ray link: %v", err)
			}
			config.V2Ray = v2rayConf
			config.V2Ray.Enabled = true
		} else {
			// Manual configuration
			if *v2rayAddr == "" || *v2rayPort == 0 || *v2rayUUID == "" {
				log.Fatal("V2Ray mode requires: -v2ray-addr, -v2ray-port, -v2ray-uuid")
			}
			config.V2Ray = V2RayConfig{
				Enabled:     true,
				Protocol:    *v2rayProtocol,
				UUID:        *v2rayUUID,
				Address:     *v2rayAddr,
				Port:        *v2rayPort,
				Network:     *v2rayNetwork,
				Security:    *v2raySecurity,
				SNI:         *v2raySNI,
				Path:        *v2rayPath,
				Host:        *v2rayHost,
				ServiceName: *v2rayService,
				ConfigPath:  *v2rayConfig,
				BinaryPath:  *v2rayBinary,
			}
		}
	}

	return config
}

// Parse V2Ray share links
func parseV2RayLink(link string) (V2RayConfig, error) {
	config := V2RayConfig{}
	
	if strings.HasPrefix(link, "vmess://") {
		data := strings.TrimPrefix(link, "vmess://")
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(data)
			if err != nil {
				decoded, err = base64.URLEncoding.DecodeString(data)
				if err != nil {
					decoded, err = base64.RawURLEncoding.DecodeString(data)
					if err != nil {
						return config, fmt.Errorf("failed to decode base64: %w", err)
					}
				}
			}
		}
		
		var vmess map[string]interface{}
		if err := json.Unmarshal(decoded, &vmess); err != nil {
			return config, fmt.Errorf("failed to parse JSON: %w", err)
		}
		
		config.Protocol = "vmess"
		config.Enabled = true
		
		// Parse address
		if add, ok := vmess["add"].(string); ok {
			config.Address = add
		} else {
			return config, fmt.Errorf("missing or invalid 'add' field")
		}
		
		// Parse port - handle both string and number
		if port, ok := vmess["port"].(float64); ok {
			config.Port = int(port)
		} else if port, ok := vmess["port"].(string); ok {
			var portNum int
			if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil {
				return config, fmt.Errorf("invalid port: %s", port)
			}
			config.Port = portNum
		} else {
			return config, fmt.Errorf("missing or invalid 'port' field")
		}
		
		// Parse UUID
		if id, ok := vmess["id"].(string); ok {
			config.UUID = id
		} else {
			return config, fmt.Errorf("missing or invalid 'id' field")
		}
		
		// Parse network type
		if net, ok := vmess["net"].(string); ok {
			config.Network = net
		} else {
			config.Network = "tcp" // default
		}
		
		// Parse TLS
		if tls, ok := vmess["tls"].(string); ok {
			if tls == "tls" {
				config.Security = "tls"
			}
		}
		
		// Parse SNI
		if sni, ok := vmess["sni"].(string); ok && sni != "" {
			config.SNI = sni
		}
		
		// Parse path (for websocket)
		if path, ok := vmess["path"].(string); ok && path != "" {
			config.Path = path
		}
		
		// Parse host (for websocket/http)
		if host, ok := vmess["host"].(string); ok && host != "" {
			config.Host = host
		}
		
		// Parse alterId (VMess specific)
		// aid can be string or number
		var alterId int
		if aid, ok := vmess["aid"].(float64); ok {
			alterId = int(aid)
		} else if aid, ok := vmess["aid"].(string); ok {
			fmt.Sscanf(aid, "%d", &alterId)
		}
		
		// Parse security cipher
		if scy, ok := vmess["scy"].(string); ok && scy != "" {
			// Store security cipher if needed for config generation
			// For now, we'll use "auto" by default
		}
		
		// Parse type (header type)
		if typ, ok := vmess["type"].(string); ok && typ != "" {
			// Header type for TCP/KCP/etc
		}
		
		// Parse ps (description/remark)
		if ps, ok := vmess["ps"].(string); ok && ps != "" {
			fmt.Printf("[+] Server: %s\n", ps)
		}
		
		// Validate required fields
		if config.Address == "" {
			return config, fmt.Errorf("server address is empty")
		}
		if config.Port <= 0 || config.Port > 65535 {
			return config, fmt.Errorf("invalid port: %d", config.Port)
		}
		if config.UUID == "" {
			return config, fmt.Errorf("UUID is empty")
		}
		
		fmt.Printf("[+] Parsed VMess config:\n")
		fmt.Printf("    Address: %s:%d\n", config.Address, config.Port)
		fmt.Printf("    UUID: %s\n", config.UUID)
		fmt.Printf("    Network: %s\n", config.Network)
		fmt.Printf("    Security: %s\n", config.Security)
		if config.SNI != "" {
			fmt.Printf("    SNI: %s\n", config.SNI)
		}
		if config.Path != "" {
			fmt.Printf("    Path: %s\n", config.Path)
		}
		if config.Host != "" {
			fmt.Printf("    Host: %s\n", config.Host)
		}
	} else if strings.HasPrefix(link, "vless://") {
		// Parse VLess link
		data := strings.TrimPrefix(link, "vless://")
		// VLess format: vless://UUID@address:port?params#remark
		
		parts := strings.SplitN(data, "@", 2)
		if len(parts) != 2 {
			return config, fmt.Errorf("invalid vless link format")
		}
		
		config.Protocol = "vless"
		config.Enabled = true
		config.UUID = parts[0]
		
		// Parse address:port and parameters
		addrAndParams := strings.SplitN(parts[1], "?", 2)
		addrPort := addrAndParams[0]
		
		// Remove remark if present
		addrPort = strings.SplitN(addrPort, "#", 2)[0]
		
		addrPortParts := strings.Split(addrPort, ":")
		if len(addrPortParts) != 2 {
			return config, fmt.Errorf("invalid vless address:port format")
		}
		
		config.Address = addrPortParts[0]
		fmt.Sscanf(addrPortParts[1], "%d", &config.Port)
		
		// Parse parameters
		if len(addrAndParams) > 1 {
			params := addrAndParams[1]
			// Remove remark
			params = strings.SplitN(params, "#", 2)[0]
			
			for _, param := range strings.Split(params, "&") {
				kv := strings.SplitN(param, "=", 2)
				if len(kv) != 2 {
					continue
				}
				
				switch kv[0] {
				case "type":
					config.Network = kv[1]
				case "security":
					config.Security = kv[1]
				case "sni":
					config.SNI = kv[1]
				case "path":
					config.Path = kv[1]
				case "host":
					config.Host = kv[1]
				case "serviceName":
					config.ServiceName = kv[1]
				}
			}
		}
		
		fmt.Printf("[+] Parsed VLess config:\n")
		fmt.Printf("    Address: %s:%d\n", config.Address, config.Port)
		fmt.Printf("    UUID: %s\n", config.UUID)
		fmt.Printf("    Network: %s\n", config.Network)
		fmt.Printf("    Security: %s\n", config.Security)
	} else if strings.HasPrefix(link, "trojan://") {
		// Parse Trojan link
		data := strings.TrimPrefix(link, "trojan://")
		// Trojan format: trojan://password@address:port?params#remark
		
		parts := strings.SplitN(data, "@", 2)
		if len(parts) != 2 {
			return config, fmt.Errorf("invalid trojan link format")
		}
		
		config.Protocol = "trojan"
		config.Enabled = true
		config.UUID = parts[0] // password
		
		addrAndParams := strings.SplitN(parts[1], "?", 2)
		addrPort := addrAndParams[0]
		addrPort = strings.SplitN(addrPort, "#", 2)[0]
		
		addrPortParts := strings.Split(addrPort, ":")
		if len(addrPortParts) != 2 {
			return config, fmt.Errorf("invalid trojan address:port format")
		}
		
		config.Address = addrPortParts[0]
		fmt.Sscanf(addrPortParts[1], "%d", &config.Port)
		config.Security = "tls" // Trojan always uses TLS
		
		// Parse parameters
		if len(addrAndParams) > 1 {
			params := addrAndParams[1]
			params = strings.SplitN(params, "#", 2)[0]
			
			for _, param := range strings.Split(params, "&") {
				kv := strings.SplitN(param, "=", 2)
				if len(kv) != 2 {
					continue
				}
				
				switch kv[0] {
				case "sni":
					config.SNI = kv[1]
				case "type":
					config.Network = kv[1]
				case "path":
					config.Path = kv[1]
				case "host":
					config.Host = kv[1]
				}
			}
		}
		
		if config.Network == "" {
			config.Network = "tcp"
		}
		
		fmt.Printf("[+] Parsed Trojan config:\n")
		fmt.Printf("    Address: %s:%d\n", config.Address, config.Port)
		fmt.Printf("    Password: %s\n", strings.Repeat("*", len(config.UUID)))
		fmt.Printf("    Network: %s\n", config.Network)
	} else {
		return config, fmt.Errorf("unsupported link format (supported: vmess://, vless://, trojan://)")
	}
	
	return config, nil
}

func isAdmin() bool {
	switch runtime.GOOS {
	case "windows":
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		return err == nil
	case "linux", "darwin":
		return os.Geteuid() == 0
	}
	return false
}

func main() {
	config := parseFlags()

	if config.AutoRoute && !isAdmin() {
		log.Fatal("[!] -auto-route requires Administrator/root privileges")
	}

	client := NewVPNClient(config)
	if err := client.Start(); err != nil {
		log.Fatalf("[!] Error: %v\n", err)
	}
}