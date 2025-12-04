package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
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
	MaxConnections    = 2000 // Up to 2000 concurrent connections (configurable)
	DefaultSOCKSPort  = 1080
	MaxRetries        = 5
	RetryDelay        = 2 * time.Second
	KeepaliveInterval = 15 * time.Second // More frequent keepalive
	StatusInterval    = 60 * time.Second
	ConnectionTimeout = 30 * time.Second
	RouteCheckInterval = 10 * time.Second
	MaxRouteRetries    = 3
	ReadBufferSize     = 32 * 1024 // 32KB buffer for better performance
	WriteBufferSize    = 32 * 1024
	MaxIdleConns       = 100
	IdleConnTimeout    = 90 * time.Second
	
	// Protocol support: SOCKS5 tunnels ALL TCP protocols
	// ✅ HTTP, HTTPS, FTP, SSH, SMTP, POP3, IMAP, etc.
	// The tunnel is protocol-agnostic - it forwards raw TCP streams
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

// Config holds the VPN client configuration
type Config struct {
	Host           string
	Port           int
	Username       string
	Password       string
	SNIHostname    string
	SOCKSPort      int
	AutoRoute      bool
	PACPort        int
	MaxConnections int // Configurable connection limit
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
	config       Config
	connPool     *ConnectionPool
	running      atomic.Bool
	stats        Stats
	routeManager *RouteManager
	pacServer    *PACServer
	ctx          context.Context
	cancel       context.CancelFunc
	connSemaphore chan struct{} // Semaphore for connection limiting
	bufferPool    *sync.Pool    // Buffer pool for better memory management
}

// NewVPNClient creates a new VPN client instance
func NewVPNClient(cfg Config) *VPNClient {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Use configured max connections or default
	maxConns := cfg.MaxConnections
	if maxConns <= 0 {
		maxConns = MaxConnections
	}
	
	return &VPNClient{
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
}

// createTLSConnection establishes a TLS connection with SNI and optimizations
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

	// Set TCP optimizations
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true) // Disable Nagle's algorithm for lower latency
		tcpConn.SetReadBuffer(ReadBufferSize)
		tcpConn.SetWriteBuffer(WriteBufferSize)
	}

	tlsConfig := &tls.Config{
		ServerName:         v.config.SNIHostname,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}

	tlsConn := tls.Client(conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(ConnectionTimeout))

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := tlsConn.ConnectionState()
	fmt.Printf("[+] TLS connection established (TLS %s)\n", formatTLSVersion(state.Version))
	fmt.Printf("[+] SNI: %s\n", v.config.SNIHostname)

	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// connectSSH establishes an SSH connection over TLS with retry logic
func (v *VPNClient) connectSSH() error {
	var lastErr error
	for attempt := 0; attempt < MaxRetries; attempt++ {
		if err := v.attemptSSHConnection(); err != nil {
			lastErr = err
			if attempt < MaxRetries-1 {
				fmt.Printf("[!] Connection attempt %d/%d failed: %v\n", attempt+1, MaxRetries, err)
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

// attemptSSHConnection tries to establish a single SSH connection
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

// handleSOCKS5 processes a SOCKS5 client connection with improved error handling
func (v *VPNClient) handleSOCKS5(clientConn net.Conn) {
	defer clientConn.Close()

	// Acquire semaphore
	select {
	case v.connSemaphore <- struct{}{}:
		defer func() { <-v.connSemaphore }()
	default:
		fmt.Println("[!] Connection limit reached, rejecting connection")
		return
	}

	v.stats.RecordConnection()
	defer v.stats.CloseConnection()

	// Set connection deadline for initial handshake
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

	// Remove deadline after handshake
	clientConn.SetDeadline(time.Time{})

	remoteConn, err := v.dialThroughSSH(targetAddr)
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

// performSOCKS5Handshake handles the SOCKS5 authentication phase
func (v *VPNClient) performSOCKS5Handshake(conn net.Conn) error {
	buf := make([]byte, 257) // Max size for version + nmethods + methods
	
	// Read version and nmethods
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

	// Read methods
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return fmt.Errorf("methods read error: %w", err)
	}

	// Send "no authentication required" response
	_, err := conn.Write([]byte{SOCKS5Version, 0x00})
	return err
}

// parseSOCKS5Request parses the SOCKS5 connection request
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

// readSOCKS5Address reads the target address based on address type
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

// dialThroughSSH establishes a connection through the SSH tunnel with retry
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

		// Mark as unhealthy and trigger reconnection
		if strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "closed") {
			v.connPool.MarkUnhealthy()
		}

		if retry < 2 {
			time.Sleep(time.Duration(retry+1) * 200 * time.Millisecond)
		}
	}
	
	v.connPool.dialErrors.Add(1)
	return nil, fmt.Errorf("failed to dial through SSH tunnel after retries")
}

// sendSOCKS5Reply sends a SOCKS5 reply message
func (v *VPNClient) sendSOCKS5Reply(conn net.Conn, replyCode byte) error {
	reply := []byte{SOCKS5Version, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}

// forwardDataWithMetrics performs bidirectional data forwarding with metrics
func (v *VPNClient) forwardDataWithMetrics(client, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	var bytesIn, bytesOut int64

	// Client -> Remote
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

	// Remote -> Client
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

// copyWithBuffer copies data using a provided buffer
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

// startSOCKSServer starts the SOCKS5 proxy server
func (v *VPNClient) startSOCKSServer() error {
	addr := fmt.Sprintf("127.0.0.1:%d", v.config.SOCKSPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start SOCKS server: %w", err)
	}
	defer listener.Close()

	v.printBanner()
	v.running.Store(true)

	// Setup automatic routing if enabled
	if v.config.AutoRoute {
		if err := v.setupRoutes(); err != nil {
			fmt.Printf("[!] Warning: Failed to setup routes: %v\n", err)
			fmt.Println("[!] Continuing without automatic routing...")
		}
	}

	// Start PAC server if port is specified
	if v.config.PACPort > 0 {
		go v.startPACServer()
	}

	// Start background tasks
	go v.keepalive()
	go v.displayStatus()
	go v.healthCheck()

	// Monitor routes if auto-route is enabled
	if v.config.AutoRoute {
		go v.monitorRoutes()
	}

	// Accept connections
	for v.running.Load() {
		conn, err := listener.Accept()
		if err != nil {
			if v.running.Load() {
				continue
			}
			break
		}
		
		// Handle each connection in a goroutine
		go v.handleSOCKS5(conn)
	}

	return nil
}

// healthCheck monitors connection health and triggers reconnection
func (v *VPNClient) healthCheck() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for v.running.Load() {
		select {
		case <-ticker.C:
			if !v.connPool.IsHealthy() {
				fmt.Println("\n[!] Connection unhealthy, triggering reconnection...")
				if err := v.reconnect(); err == nil {
					fmt.Println("[✓] Health check: Reconnected successfully\n")
				}
			}
		case <-v.ctx.Done():
			return
		}
	}
}

// keepalive maintains the SSH connection with improved logic
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
					fmt.Println("[✓] Reconnected successfully\n")
					consecutiveFailures = 0
				} else {
					consecutiveFailures++
					fmt.Printf("[!] Reconnection failed (%d/%d): %v\n", consecutiveFailures, maxFailures, err)
					if consecutiveFailures >= maxFailures {
						fmt.Println("[!] Maximum reconnection attempts reached")
						v.running.Store(false)
					}
				}
			} else {
				// Send keepalive
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					consecutiveFailures++
					v.connPool.MarkUnhealthy()
					fmt.Printf("[!] Keepalive failed (%d/%d): %v\n", consecutiveFailures, maxFailures, err)
					
					if consecutiveFailures >= maxFailures {
						fmt.Println("\n[!] Multiple keepalive failures, reconnecting...")
						if err := v.reconnect(); err == nil {
							fmt.Println("[✓] Reconnected successfully\n")
							consecutiveFailures = 0
						}
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

// displayStatus shows periodic status updates with enhanced metrics
func (v *VPNClient) displayStatus() {
	ticker := time.NewTicker(StatusInterval)
	defer ticker.Stop()

	for v.running.Load() {
		select {
		case <-ticker.C:
			if v.connPool.GetClient() != nil && v.running.Load() {
				v.printStatus()
			}
		case <-v.ctx.Done():
			return
		}
	}
}

// printStatus displays current connection statistics
func (v *VPNClient) printStatus() {
	uptime := time.Since(v.stats.startTime)
	connCount := v.stats.connCount.Load()
	totalConns := v.stats.totalConns.Load()
	success := v.stats.successCount.Load()
	failed := v.stats.failedCount.Load()
	bytesIn := v.stats.bytesIn.Load()
	bytesOut := v.stats.bytesOut.Load()
	dialAttempts := v.connPool.dialAttempts.Load()
	dialErrors := v.connPool.dialErrors.Load()

	fmt.Printf("\n[ℹ] Status Report:\n")
	fmt.Printf("  Uptime: %v\n", uptime.Round(time.Second))
	fmt.Printf("  Active connections: %d/%d\n", connCount, MaxConnections)
	fmt.Printf("  Total connections: %d (Success: %d, Failed: %d)\n", totalConns, success, failed)
	fmt.Printf("  Data transferred: ↓ %s / ↑ %s\n", formatBytes(bytesIn), formatBytes(bytesOut))
	fmt.Printf("  Dial attempts: %d (Errors: %d)\n", dialAttempts, dialErrors)
	fmt.Printf("  Health: %s\n", map[bool]string{true: "✓ Healthy", false: "✗ Unhealthy"}[v.connPool.IsHealthy()])
}

// formatBytes formats bytes into human-readable format
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

// reconnect attempts to re-establish the SSH connection
func (v *VPNClient) reconnect() error {
	client := v.connPool.GetClient()
	if client != nil {
		client.Close()
	}
	v.connPool.SetClient(nil)
	v.connPool.MarkUnhealthy()

	// Brief delay before reconnection
	time.Sleep(time.Second)
	
	return v.connectSSH()
}

// Start initializes and runs the VPN client
func (v *VPNClient) Start() error {
	v.printHeader()

	if err := v.connectSSH(); err != nil {
		return fmt.Errorf("failed to establish VPN connection: %w", err)
	}

	v.setupSignalHandler()
	return v.startSOCKSServer()
}

// setupSignalHandler handles graceful shutdown
func (v *VPNClient) setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		v.shutdown()
	}()
}

// shutdown gracefully stops the VPN client
func (v *VPNClient) shutdown() {
	fmt.Println("\n[*] Shutting down gracefully...")
	v.running.Store(false)
	v.cancel()

	// Stop PAC server
	if v.pacServer.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		v.pacServer.server.Shutdown(ctx)
		cancel()
	}

	// Cleanup routes if they were added
	if v.config.AutoRoute {
		if err := v.cleanupRoutes(); err != nil {
			fmt.Printf("[!] Warning: Failed to cleanup routes: %v\n", err)
		}
	}

	// Close SSH connection
	client := v.connPool.GetClient()
	if client != nil {
		client.Close()
	}

	fmt.Println("[+] VPN tunnel closed")
	fmt.Println("[+] Final statistics:")
	v.printStatus()
	os.Exit(0)
}

// printHeader displays initial connection information
func (v *VPNClient) printHeader() {
	fmt.Println("\n============================================================")
	fmt.Println("SSH + TLS + SNI VPN Client (Go) - Enhanced Edition")
	fmt.Println("============================================================")
	fmt.Printf("Server: %s:%d\n", v.config.Host, v.config.Port)
	fmt.Printf("SNI: %s\n", v.config.SNIHostname)
	fmt.Printf("Username: %s\n", v.config.Username)
	fmt.Printf("Max Connections: %d\n", MaxConnections)
	fmt.Println("============================================================\n")
}

// printBanner displays the active tunnel information
func (v *VPNClient) printBanner() {
	fmt.Println("\n============================================================")
	fmt.Println("✅ VPN TUNNEL ACTIVE!")
	fmt.Println("============================================================")
	fmt.Printf("SOCKS5 Proxy: 127.0.0.1:%d\n", v.config.SOCKSPort)

	if v.config.AutoRoute {
		fmt.Println("\n🔀 Automatic Routing: ENABLED")
		fmt.Printf("   Server Route: %s via %s\n", v.routeManager.serverIP, v.routeManager.originalGateway)
		fmt.Println("   ⚠️  You must configure applications to use the SOCKS5 proxy")
	}

	if v.config.PACPort > 0 {
		fmt.Println("\n╔═══════════════════════════════════════════════════════════╗")
		fmt.Println("║  🎉 AUTOMATIC BROWSER CONFIGURATION ENABLED!             ║")
		fmt.Println("╚═══════════════════════════════════════════════════════════╝")
		fmt.Printf("\nPAC URL: http://127.0.0.1:%d/proxy.pac\n", v.config.PACPort)
		fmt.Printf("Config Page: http://127.0.0.1:%d/\n", v.config.PACPort)
	}

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("✅ TEST YOUR CONNECTION:")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("\n   curl --socks5 127.0.0.1:%d https://ipinfo.io/ip\n", v.config.SOCKSPort)
	fmt.Println("\n   OR visit: https://ipinfo.io")
	fmt.Println("\nPress Ctrl+C to disconnect...")
	fmt.Println("============================================================\n")

	// Test connection in background
	go v.testConnection()
}

// formatTLSVersion converts TLS version to string
func formatTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return "unknown"
	}
}

// Route management functions

func (v *VPNClient) setupRoutes() error {
	rm := v.routeManager
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.routeAdded.Load() {
		return nil
	}

	fmt.Println("[*] Setting up automatic routing...")
	fmt.Printf("[*] Platform: %s\n", runtime.GOOS)

	if !isAdmin() {
		return fmt.Errorf("insufficient privileges - run as Administrator/root")
	}
	fmt.Println("[+] Running with elevated privileges")

	serverIP, err := v.resolveServerIP()
	if err != nil {
		return fmt.Errorf("failed to resolve server IP: %w", err)
	}
	rm.serverIP = serverIP
	fmt.Printf("[+] Server IP: %s\n", serverIP)

	gateway, err := v.getDefaultGateway()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}
	rm.originalGateway = gateway
	fmt.Printf("[+] Original gateway: %s\n", gateway)

	fmt.Printf("[*] Adding route: %s via %s\n", serverIP, gateway)
	if err := v.addServerRoute(serverIP, gateway); err != nil {
		return fmt.Errorf("failed to add server route: %w", err)
	}

	time.Sleep(time.Second)
	exists, _ := v.checkServerRoute(serverIP)
	if exists {
		fmt.Println("[+] Route verified successfully!")
		rm.routeAdded.Store(true)
		return nil
	}

	fmt.Println("[!] Warning: Route added but verification failed")
	rm.routeAdded.Store(true)
	return nil
}

func (v *VPNClient) cleanupRoutes() error {
	rm := v.routeManager
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.routeAdded.Load() {
		return nil
	}

	fmt.Println("[*] Cleaning up routes...")
	if err := v.deleteServerRoute(rm.serverIP); err != nil {
		fmt.Printf("[!] Failed to remove server route: %v\n", err)
	}

	rm.routeAdded.Store(false)
	fmt.Println("[+] Routes cleaned up")
	return nil
}

func (v *VPNClient) monitorRoutes() {
	ticker := time.NewTicker(RouteCheckInterval)
	defer ticker.Stop()

	for v.running.Load() {
		select {
		case <-ticker.C:
			if v.routeManager.routeAdded.Load() {
				exists, _ := v.checkServerRoute(v.routeManager.serverIP)
				if !exists {
					fmt.Println("\n[!] Route lost, restoring...")
					v.routeManager.routeAdded.Store(false)
					if err := v.setupRoutes(); err != nil {
						fmt.Printf("[!] Failed to restore routes: %v\n", err)
					} else {
						fmt.Println("[+] Routes restored")
					}
				}
			}
		case <-v.ctx.Done():
			return
		}
	}
}

func (v *VPNClient) resolveServerIP() (string, error) {
	if net.ParseIP(v.config.Host) != nil {
		return v.config.Host, nil
	}

	ips, err := net.LookupIP(v.config.Host)
	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	return ips[0].String(), nil
}

func (v *VPNClient) getDefaultGateway() (string, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ip", "route", "show", "default")
		output, err := cmd.CombinedOutput()
		if err == nil {
			return v.parseLinuxGateway(string(output))
		}
		cmd = exec.Command("route", "-n")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return "", err
		}
		return v.parseLinuxRouteGateway(string(output))

	case "darwin":
		cmd = exec.Command("route", "-n", "get", "default")

	case "windows":
		cmd = exec.Command("route", "PRINT", "0.0.0.0")

	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	switch runtime.GOOS {
	case "darwin":
		return v.parseDarwinGateway(string(output))
	case "windows":
		return v.parseWindowsGateway(string(output))
	}

	return "", fmt.Errorf("unsupported OS")
}

func (v *VPNClient) parseLinuxGateway(output string) (string, error) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "default") && strings.Contains(line, "via") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "via" && i+1 < len(fields) {
					if net.ParseIP(fields[i+1]) != nil {
						return fields[i+1], nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("gateway not found")
}

func (v *VPNClient) parseLinuxRouteGateway(output string) (string, error) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "0.0.0.0" {
			if net.ParseIP(fields[1]) != nil {
				return fields[1], nil
			}
		}
	}
	return "", fmt.Errorf("gateway not found")
}

func (v *VPNClient) parseDarwinGateway(output string) (string, error) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "gateway:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && net.ParseIP(fields[1]) != nil {
				return fields[1], nil
			}
		}
	}
	return "", fmt.Errorf("gateway not found")
}

func (v *VPNClient) parseWindowsGateway(output string) (string, error) {
	lines := strings.Split(output, "\n")
	inRouteTable := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "IPv4 Route Table") || strings.Contains(line, "Active Routes:") {
			inRouteTable = true
			continue
		}
		if !inRouteTable || strings.Contains(line, "Persistent Routes:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			if net.ParseIP(fields[2]) != nil && fields[2] != "0.0.0.0" {
				return fields[2], nil
			}
		}
	}
	return "", fmt.Errorf("gateway not found")
}

func (v *VPNClient) addServerRoute(serverIP, gateway string) error {
	cmd := v.getAddRouteCommand(serverIP, gateway)
	if cmd == nil {
		return fmt.Errorf("unsupported platform")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		lowerOutput := strings.ToLower(string(output))
		if strings.Contains(lowerOutput, "exist") || strings.Contains(lowerOutput, "already") {
			return nil
		}
		return err
	}
	return nil
}

func (v *VPNClient) deleteServerRoute(serverIP string) error {
	cmd := v.getDeleteRouteCommand(serverIP)
	if cmd == nil {
		return nil
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		lowerOutput := strings.ToLower(string(output))
		if strings.Contains(lowerOutput, "not found") || strings.Contains(lowerOutput, "no such") {
			return nil
		}
	}
	return err
}

func (v *VPNClient) checkServerRoute(serverIP string) (bool, error) {
	cmd := v.getCheckRouteCommand(serverIP)
	if cmd == nil {
		return false, nil
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}

	return strings.Contains(string(output), serverIP), nil
}

func (v *VPNClient) getAddRouteCommand(serverIP, gateway string) *exec.Cmd {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("ip"); err == nil {
			return exec.Command("ip", "route", "add", serverIP+"/32", "via", gateway)
		}
		return exec.Command("route", "add", "-host", serverIP, "gw", gateway)
	case "darwin":
		return exec.Command("route", "-n", "add", "-host", serverIP, gateway)
	case "windows":
		return exec.Command("route", "ADD", serverIP, "MASK", "255.255.255.255", gateway, "METRIC", "1")
	}
	return nil
}

func (v *VPNClient) getDeleteRouteCommand(serverIP string) *exec.Cmd {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("ip"); err == nil {
			return exec.Command("ip", "route", "del", serverIP)
		}
		return exec.Command("route", "del", "-host", serverIP)
	case "darwin":
		return exec.Command("route", "-n", "delete", "-host", serverIP)
	case "windows":
		return exec.Command("route", "DELETE", serverIP)
	}
	return nil
}

func (v *VPNClient) getCheckRouteCommand(serverIP string) *exec.Cmd {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("ip"); err == nil {
			return exec.Command("ip", "route", "get", serverIP)
		}
		return exec.Command("route", "-n", "get", serverIP)
	case "darwin":
		return exec.Command("route", "-n", "get", serverIP)
	case "windows":
		return exec.Command("route", "PRINT")
	}
	return nil
}

func (v *VPNClient) testConnection() {
	time.Sleep(2 * time.Second)
	fmt.Println("\n[*] Testing connection...")

	client := v.connPool.GetClient()
	if client == nil {
		fmt.Println("[!] SSH client not ready yet")
		return
	}

	testConn, err := client.Dial("tcp", "ipinfo.io:80")
	if err != nil {
		fmt.Printf("[!] Connection test failed: %v\n", err)
		return
	}
	defer testConn.Close()

	request := "GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\nConnection: close\r\n\r\n"
	testConn.SetDeadline(time.Now().Add(10 * time.Second))
	testConn.Write([]byte(request))

	buf := make([]byte, 4096)
	n, _ := testConn.Read(buf)
	response := string(buf[:n])

	lines := strings.Split(response, "\r\n")
	bodyStart := false
	for _, line := range lines {
		if bodyStart {
			ip := strings.TrimSpace(line)
			if net.ParseIP(ip) != nil {
				fmt.Printf("\n[✓] Tunnel working! Exit IP: %s\n\n", ip)
				return
			}
		}
		if line == "" {
			bodyStart = true
		}
	}
	fmt.Println("[✓] Tunnel is operational")
}

// PAC Server

func (v *VPNClient) startPACServer() {
	if v.pacServer.port <= 0 {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/proxy.pac", v.handlePAC)
	mux.HandleFunc("/", v.handlePACInfo)

	v.pacServer.server = &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", v.pacServer.port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	v.pacServer.running.Store(true)
	fmt.Printf("[+] PAC server: http://127.0.0.1:%d\n", v.pacServer.port)

	if err := v.pacServer.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		if v.running.Load() {
			fmt.Printf("[!] PAC server error: %v\n", err)
		}
	}
}

func (v *VPNClient) handlePAC(w http.ResponseWriter, r *http.Request) {
	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }
    return "SOCKS5 127.0.0.1:%d; SOCKS 127.0.0.1:%d; DIRECT";
}`, v.pacServer.socksPort, v.pacServer.socksPort)

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
<p>SOCKS5: <code>127.0.0.1:%d</code></p>
<p>PAC URL: <code>http://127.0.0.1:%d/proxy.pac</code></p>
<p>Test: <a href="https://ipinfo.io" target="_blank">ipinfo.io</a></p>
</div></body></html>`, v.pacServer.socksPort, v.pacServer.port)
	
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Main and utility functions

func parseFlags() Config {
	host := flag.String("H", "", "Server hostname/IP (required)")
	port := flag.Int("P", 0, "Server port (required)")
	username := flag.String("u", "", "SSH username (required)")
	password := flag.String("p", "", "SSH password (required)")
	sni := flag.String("S", "", "SNI hostname (required)")
	socksPort := flag.Int("socks-port", DefaultSOCKSPort, "SOCKS5 port")
	autoRoute := flag.Bool("auto-route", false, "Auto routing (requires admin)")
	pacPort := flag.Int("pac-port", 0, "PAC server port")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Enhanced SSH+TLS+SNI VPN Client\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s -H host -P port -u user -p pass -S sni [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  %s -H vpn.example.com -P 8443 -u user -p pass -S web.whatsapp.com -pac-port 8080\n\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if *host == "" || *port == 0 || *username == "" || *password == "" || *sni == "" {
		flag.Usage()
		os.Exit(1)
	}

	return Config{
		Host:        *host,
		Port:        *port,
		Username:    *username,
		Password:    *password,
		SNIHostname: *sni,
		SOCKSPort:   *socksPort,
		AutoRoute:   *autoRoute,
		PACPort:     *pacPort,
	}
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
		log.Fatal("[!] Error: -auto-route requires Administrator/root privileges")
	}

	client := NewVPNClient(config)
	if err := client.Start(); err != nil {
		log.Fatalf("[!] Error: %v\n", err)
	}
}