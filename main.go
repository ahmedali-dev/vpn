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

// Constants
const (
	SOCKS5Version     = 0x05
	MaxConnections    = 40
	DefaultSOCKSPort  = 1080
	MaxRetries        = 3
	RetryDelay        = 3 * time.Second
	KeepaliveInterval = 30 * time.Second
	StatusInterval    = 60 * time.Second
	ConnectionTimeout = 30 * time.Second
	RouteCheckInterval = 5 * time.Second
	MaxRouteRetries    = 3
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
	SOCKS5ReplySuccess       = 0x00
	SOCKS5ReplyGeneralError  = 0x05
	SOCKS5ReplyCmdNotSupport = 0x07
	SOCKS5ReplyAtypNotSupport = 0x08
)

// Config holds the VPN client configuration
type Config struct {
	Host        string
	Port        int
	Username    string
	Password    string
	SNIHostname string
	SOCKSPort   int
	AutoRoute   bool
	PACPort     int
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
}

// Stats tracks connection statistics
type Stats struct {
	connCount   atomic.Int32
	failedCount atomic.Int64
	startTime   time.Time
}

// VPNClient manages the VPN tunnel
type VPNClient struct {
	config       Config
	sshClient    *ssh.Client
	running      atomic.Bool
	stats        Stats
	routeManager *RouteManager
	pacServer    *PACServer
	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewVPNClient creates a new VPN client instance
func NewVPNClient(cfg Config) *VPNClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &VPNClient{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
		stats: Stats{
			startTime: time.Now(),
		},
		routeManager: &RouteManager{
			serverIP: cfg.Host,
		},
		pacServer: &PACServer{
			port:      cfg.PACPort,
			socksPort: cfg.SOCKSPort,
		},
	}
}

// createTLSConnection establishes a TLS connection with SNI
func (v *VPNClient) createTLSConnection() (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", v.config.Host, v.config.Port)
	fmt.Printf("[*] Connecting to %s...\n", addr)

	dialer := &net.Dialer{
		Timeout: ConnectionTimeout,
	}
	
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP connection failed: %w", err)
	}

	tlsConfig := &tls.Config{
		ServerName:         v.config.SNIHostname,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
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
	fmt.Printf("[+] SNI: %s\n", v.config.SNIHostname)

	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// connectSSH establishes an SSH connection over TLS
func (v *VPNClient) connectSSH() error {
	for attempt := 0; attempt < MaxRetries; attempt++ {
		if err := v.attemptSSHConnection(); err != nil {
			if attempt < MaxRetries-1 {
				fmt.Printf("[!] %v\n", err)
				fmt.Printf("[*] Retrying... (%d/%d)\n", attempt+2, MaxRetries)
				time.Sleep(RetryDelay)
				continue
			}
			return fmt.Errorf("failed after %d attempts: %w", MaxRetries, err)
		}
		return nil
	}
	return fmt.Errorf("failed after %d attempts", MaxRetries)
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

	v.sshClient = ssh.NewClient(sshConn, chans, reqs)
	fmt.Println("[+] SSH authentication successful!")
	return nil
}

// handleSOCKS5 processes a SOCKS5 client connection
func (v *VPNClient) handleSOCKS5(clientConn net.Conn) {
	defer clientConn.Close()

	if !v.checkConnectionLimit() {
		return
	}
	defer v.stats.connCount.Add(-1)

	if err := v.performSOCKS5Handshake(clientConn); err != nil {
		return
	}

	targetAddr, err := v.parseSOCKS5Request(clientConn)
	if err != nil {
		v.sendSOCKS5Reply(clientConn, SOCKS5ReplyGeneralError)
		return
	}

	remoteConn, err := v.dialThroughSSH(targetAddr)
	if err != nil {
		v.stats.failedCount.Add(1)
		v.sendSOCKS5Reply(clientConn, SOCKS5ReplyGeneralError)
		return
	}
	defer remoteConn.Close()

	if err := v.sendSOCKS5Reply(clientConn, SOCKS5ReplySuccess); err != nil {
		return
	}

	v.forwardData(clientConn, remoteConn)
}

// checkConnectionLimit enforces the maximum connection limit
func (v *VPNClient) checkConnectionLimit() bool {
	current := v.stats.connCount.Add(1)
	return current <= MaxConnections
}

// performSOCKS5Handshake handles the SOCKS5 authentication phase
func (v *VPNClient) performSOCKS5Handshake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != SOCKS5Version {
		return fmt.Errorf("invalid SOCKS version: %d", buf[0])
	}

	nmethods := buf[1]
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Send "no authentication required" response
	_, err := conn.Write([]byte{SOCKS5Version, 0x00})
	return err
}

// parseSOCKS5Request parses the SOCKS5 connection request
func (v *VPNClient) parseSOCKS5Request(conn net.Conn) (string, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
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
		return "", err
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

// dialThroughSSH establishes a connection through the SSH tunnel
func (v *VPNClient) dialThroughSSH(addr string) (net.Conn, error) {
	for retry := 0; retry < 3; retry++ {
		if v.sshClient == nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		conn, err := v.sshClient.Dial("tcp", addr)
		if err == nil {
			return conn, nil
		}

		if retry < 2 {
			time.Sleep(500 * time.Millisecond)
		}
	}
	return nil, fmt.Errorf("failed to dial through SSH tunnel")
}

// sendSOCKS5Reply sends a SOCKS5 reply message
func (v *VPNClient) sendSOCKS5Reply(conn net.Conn, replyCode byte) error {
	reply := []byte{SOCKS5Version, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}

// forwardData performs bidirectional data forwarding
func (v *VPNClient) forwardData(client, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(remote, client)
		if tcp, ok := remote.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, remote)
		if tcp, ok := client.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	wg.Wait()
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

	go v.keepalive()
	go v.displayStatus()
	
	// Monitor routes if auto-route is enabled
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

// keepalive maintains the SSH connection
func (v *VPNClient) keepalive() {
	ticker := time.NewTicker(KeepaliveInterval)
	defer ticker.Stop()

	for v.running.Load() {
		select {
		case <-ticker.C:
			v.performKeepalive()
		case <-v.ctx.Done():
			return
		}
	}
}

// performKeepalive checks and maintains the connection
func (v *VPNClient) performKeepalive() {
	if v.sshClient == nil {
		fmt.Println("\n[!] Connection lost. Reconnecting...")
		if err := v.reconnect(); err == nil {
			fmt.Println("[✓] Reconnected! VPN active again.\n")
		} else {
			fmt.Printf("[!] Reconnection failed: %v\n", err)
			fmt.Println("[!] Please restart the VPN.")
			v.running.Store(false)
		}
	} else {
		v.sshClient.SendRequest("keepalive@openssh.com", true, nil)
	}
}

// displayStatus shows periodic status updates
func (v *VPNClient) displayStatus() {
	ticker := time.NewTicker(StatusInterval)
	defer ticker.Stop()

	for v.running.Load() {
		select {
		case <-ticker.C:
			if v.sshClient != nil && v.running.Load() {
				v.printStatus()
			}
		case <-v.ctx.Done():
			return
		}
	}
}

// printStatus displays current connection statistics
func (v *VPNClient) printStatus() {
	uptime := int(time.Since(v.stats.startTime).Minutes())
	connCount := v.stats.connCount.Load()
	failed := v.stats.failedCount.Load()

	status := fmt.Sprintf("[ℹ] Active | Connections: %d/%d | Uptime: %dm",
		connCount, MaxConnections, uptime)
	if failed > 0 {
		status += fmt.Sprintf(" | Failed: %d", failed)
	}
	fmt.Println(status)
}

// reconnect attempts to re-establish the SSH connection
func (v *VPNClient) reconnect() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.sshClient != nil {
		v.sshClient.Close()
		v.sshClient = nil
	}

	time.Sleep(2 * time.Second)
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
	fmt.Println("\n[*] Disconnecting...")
	v.running.Store(false)
	v.cancel()
	
	// Cleanup routes if they were added
	if v.config.AutoRoute {
		if err := v.cleanupRoutes(); err != nil {
			fmt.Printf("[!] Warning: Failed to cleanup routes: %v\n", err)
		}
	}
	
	if v.sshClient != nil {
		v.sshClient.Close()
	}
	
	fmt.Println("[+] VPN tunnel closed")
	os.Exit(0)
}

// printHeader displays initial connection information
func (v *VPNClient) printHeader() {
	fmt.Println("\n============================================================")
	fmt.Println("SSH + TLS + SNI VPN Client (Go)")
	fmt.Println("============================================================")
	fmt.Printf("Server: %s:%d\n", v.config.Host, v.config.Port)
	fmt.Printf("SNI: %s\n", v.config.SNIHostname)
	fmt.Printf("Username: %s\n", v.config.Username)
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
		fmt.Println("   ⚠️  NOTE: Auto-route only ensures VPN server connectivity")
		fmt.Println("   ⚠️  You MUST configure applications to use the SOCKS5 proxy below")
	}
	
	if v.config.PACPort > 0 {
		fmt.Println("\n╔═══════════════════════════════════════════════════════════╗")
		fmt.Println("║  🎉 AUTOMATIC BROWSER CONFIGURATION ENABLED!             ║")
		fmt.Println("╚═══════════════════════════════════════════════════════════╝")
		fmt.Printf("\nPAC URL: http://127.0.0.1:%d/proxy.pac\n", v.config.PACPort)
		
		fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("📋 AUTOMATIC CONFIGURATION (Easiest Method)")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		
		if runtime.GOOS == "windows" {
			fmt.Println("\n🔧 Windows System-Wide (All Apps):")
			fmt.Println("   1. Settings → Network & Internet → Proxy")
			fmt.Println("   2. Automatic proxy setup → Use setup script: ON")
			fmt.Printf("   3. Script address: http://127.0.0.1:%d/proxy.pac\n", v.config.PACPort)
			fmt.Println("   4. Click 'Save'")
			fmt.Println("   ✅ All browsers will now use the VPN automatically!")
		}
		
		fmt.Println("\n🔧 Firefox:")
		fmt.Println("   1. Settings → General → Network Settings → Settings")
		fmt.Println("   2. Select: 'Automatic proxy configuration URL'")
		fmt.Printf("   3. URL: http://127.0.0.1:%d/proxy.pac\n", v.config.PACPort)
		fmt.Println("   4. Click 'OK'")
		
		fmt.Println("\n🔧 Chrome/Edge:")
		fmt.Println("   1. Settings → System → Open proxy settings")
		fmt.Println("   2. LAN settings → Use automatic configuration script")
		fmt.Printf("   3. Address: http://127.0.0.1:%d/proxy.pac\n", v.config.PACPort)
		fmt.Println("   4. Click 'OK'")
		
		fmt.Println("\n💡 Benefits:")
		fmt.Println("   • No manual proxy configuration needed")
		fmt.Println("   • Works automatically when VPN is running")
		fmt.Println("   • Direct connection when VPN is off")
		fmt.Println("   • All traffic goes through VPN")
		
	} else {
		fmt.Println("\n╔═══════════════════════════════════════════════════════════╗")
		fmt.Println("║  ⚠️  CRITICAL: MANUAL CONFIGURATION REQUIRED!            ║")
		fmt.Println("║                                                           ║")
		fmt.Println("║  This is a SOCKS5 PROXY, not an automatic VPN!           ║")
		fmt.Println("║  Your IP will NOT change until you configure apps!       ║")
		fmt.Println("╚═══════════════════════════════════════════════════════════╝")
		
		fmt.Println("\n💡 TIP: Use -pac-port flag for automatic configuration!")
		fmt.Printf("   Example: %s ... -pac-port 8080\n", os.Args[0])
		
		fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("📋 MANUAL CONFIGURATION: Firefox")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("\n1. Settings → General → Network Settings → Settings")
		fmt.Println("2. Select: 'Manual proxy configuration'")
		fmt.Println("3. SOCKS Host: 127.0.0.1")
		fmt.Printf("4. Port: %d\n", v.config.SOCKSPort)
		fmt.Println("5. Select: 'SOCKS v5'")
		fmt.Println("6. ✅ CHECK: 'Proxy DNS when using SOCKS v5'")
		fmt.Println("7. Click 'OK'")
	}
	
	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("✅ TEST YOUR CONNECTION:")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("\n   curl --socks5 127.0.0.1:%d https://ipinfo.io/ip\n", v.config.SOCKSPort)
	fmt.Println("\n   OR visit in configured browser: https://ipinfo.io")
	fmt.Println("   Your IP should show the VPN server's IP")
	
	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("Status: Connection active, auto-reconnect enabled")
	fmt.Println("Press Ctrl+C to disconnect...")
	fmt.Println("============================================================\n")
	
	// Test the connection automatically
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

// setupRoutes configures routing to direct traffic through VPN
func (v *VPNClient) setupRoutes() error {
	rm := v.routeManager
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.routeAdded.Load() {
		return nil
	}

	fmt.Println("[*] Preparing automatic routing...")
	fmt.Printf("[*] Platform: %s\n", runtime.GOOS)
	
	// Check privileges
	if !isAdmin() {
		return fmt.Errorf("insufficient privileges - run as Administrator/root")
	}
	fmt.Println("[+] Running with elevated privileges")

	// Resolve server IP first
	serverIP, err := v.resolveServerIP()
	if err != nil {
		return fmt.Errorf("failed to resolve server IP: %w", err)
	}
	rm.serverIP = serverIP
	fmt.Printf("[+] Server IP: %s\n", serverIP)

	// Get original default gateway
	gateway, err := v.getDefaultGateway()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}
	rm.originalGateway = gateway
	fmt.Printf("[+] Original gateway: %s\n", gateway)

	// Add route for VPN server through original gateway
	fmt.Printf("[*] Adding route: %s via %s\n", serverIP, gateway)
	if err := v.addServerRoute(serverIP, gateway); err != nil {
		return fmt.Errorf("failed to add server route: %w", err)
	}

	// Verify route was added with longer timeout
	fmt.Println("[*] Verifying route installation...")
	time.Sleep(1 * time.Second)
	
	exists, err := v.checkServerRoute(serverIP)
	if err != nil {
		fmt.Printf("[!] Route verification error: %v\n", err)
	}
	
	if exists {
		fmt.Println("[+] Route verified successfully!")
		rm.routeAdded.Store(true)
		return nil
	}

	fmt.Println("[!] Warning: Route added but verification failed")
	fmt.Println("[!] This may be OK - route commands vary by platform")
	fmt.Println("[!] Test manually with:")
	
	switch runtime.GOOS {
	case "windows":
		fmt.Println("[!]   route PRINT")
	case "linux":
		fmt.Println("[!]   ip route show")
	case "darwin":
		fmt.Println("[!]   netstat -nr")
	}
	
	rm.routeAdded.Store(true)
	return nil
}

// cleanupRoutes removes added routes
func (v *VPNClient) cleanupRoutes() error {
	rm := v.routeManager
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.routeAdded.Load() {
		return nil
	}

	fmt.Println("[*] Cleaning up routes...")

	// Remove server route
	if err := v.deleteServerRoute(rm.serverIP); err != nil {
		fmt.Printf("[!] Failed to remove server route: %v\n", err)
		// On Windows, try force delete
		if runtime.GOOS == "windows" {
			fmt.Println("[*] Attempting force delete...")
			v.forceDeleteWindowsRoute(rm.serverIP)
		}
	}

	rm.routeAdded.Store(false)
	fmt.Println("[+] Routes cleaned up")
	return nil
}

// forceDeleteWindowsRoute attempts to forcefully remove a route on Windows
func (v *VPNClient) forceDeleteWindowsRoute(serverIP string) {
	// Try deleting without specifying gateway
	cmd := exec.Command("route", "DELETE", serverIP)
	cmd.Run()
}

// monitorRoutes periodically checks and maintains routes
func (v *VPNClient) monitorRoutes() {
	ticker := time.NewTicker(RouteCheckInterval)
	defer ticker.Stop()

	for v.running.Load() {
		select {
		case <-ticker.C:
			v.checkAndFixRoutes()
		case <-v.ctx.Done():
			return
		}
	}
}

// checkAndFixRoutes verifies routes are still in place
func (v *VPNClient) checkAndFixRoutes() {
	if !v.routeManager.routeAdded.Load() {
		return
	}

	// Check if server route exists
	exists, err := v.checkServerRoute(v.routeManager.serverIP)
	if err != nil {
		return
	}

	if !exists {
		fmt.Println("\n[!] Route lost, attempting to restore...")
		v.routeManager.routeAdded.Store(false)
		
		if err := v.setupRoutes(); err != nil {
			fmt.Printf("[!] Failed to restore routes: %v\n", err)
		} else {
			fmt.Println("[+] Routes restored successfully")
		}
	}
}

// getDefaultGateway retrieves the system's default gateway
func (v *VPNClient) getDefaultGateway() (string, error) {
	// Implementation varies by OS
	// This is a cross-platform approach using external commands
	
	// Try to get gateway from routing table
	gateway, err := v.parseDefaultGateway()
	if err != nil {
		return "", err
	}
	
	return gateway, nil
}

// testConnection tests the SOCKS5 proxy connection
func (v *VPNClient) testConnection() {
	time.Sleep(3 * time.Second) // Wait for server to be ready
	
	fmt.Println("\n[*] Testing SOCKS5 proxy connection...")
	
	// Simple connection test
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", v.config.SOCKSPort), 5*time.Second)
	if err != nil {
		fmt.Printf("[!] Cannot connect to SOCKS proxy: %v\n", err)
		fmt.Println("[!] The proxy server might not be running properly")
		return
	}
	conn.Close()
	fmt.Println("[✓] SOCKS5 proxy is listening on port", v.config.SOCKSPort)
	
	// Test through SSH tunnel
	if v.sshClient == nil {
		fmt.Println("[!] SSH connection not established yet")
		return
	}
	
	fmt.Println("[*] Testing SSH tunnel connectivity...")
	testConn, err := v.sshClient.Dial("tcp", "ipinfo.io:80")
	if err != nil {
		fmt.Printf("[!] SSH tunnel test failed: %v\n", err)
		fmt.Println("[!] Your SSH connection may have issues")
		return
	}
	defer testConn.Close()
	
	// Send HTTP request
	request := "GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: VPN-Test\r\nConnection: close\r\n\r\n"
	testConn.SetDeadline(time.Now().Add(10 * time.Second))
	
	if _, err := testConn.Write([]byte(request)); err != nil {
		fmt.Printf("[!] Failed to send request: %v\n", err)
		return
	}
	
	// Read response
	buf := make([]byte, 8192)
	n, err := testConn.Read(buf)
	if err != nil && err != io.EOF {
		fmt.Printf("[!] Failed to read response: %v\n", err)
		return
	}
	
	response := string(buf[:n])
	
	// Parse IP from response
	lines := strings.Split(response, "\r\n")
	var ip string
	
	// Find body
	bodyStart := false
	for _, line := range lines {
		if bodyStart {
			ip = strings.TrimSpace(line)
			if net.ParseIP(ip) != nil {
				break
			}
		}
		if line == "" {
			bodyStart = true
		}
	}
	
	if ip != "" && net.ParseIP(ip) != nil {
		fmt.Printf("\n╔══════════════════════════════════════════════════════╗\n")
		fmt.Printf("║  ✅ SSH TUNNEL IS WORKING!                          ║\n")
		fmt.Printf("║                                                      ║\n")
		fmt.Printf("║  Your exit IP through tunnel: %-22s ║\n", ip)
		fmt.Printf("║                                                      ║\n")
		fmt.Printf("║  ⚠️  BUT you must configure your browser!           ║\n")
		fmt.Printf("║  The proxy does NOT work automatically!             ║\n")
		fmt.Printf("╚══════════════════════════════════════════════════════╝\n\n")
	} else {
		fmt.Println("[✓] SSH tunnel is responding (configure your browser to see IP change)")
	}
}

// resolveServerIP resolves hostname to IP address
func (v *VPNClient) resolveServerIP() (string, error) {
	// Check if already an IP
	if net.ParseIP(v.config.Host) != nil {
		return v.config.Host, nil
	}

	// Resolve hostname
	ips, err := net.LookupIP(v.config.Host)
	if err != nil {
		return "", err
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for host")
	}

	// Prefer IPv4
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	return ips[0].String(), nil
}

// addServerRoute adds a route for the VPN server
func (v *VPNClient) addServerRoute(serverIP, gateway string) error {
	cmd := v.getAddRouteCommand(serverIP, gateway)
	if cmd == nil {
		return fmt.Errorf("unsupported platform for automatic routing")
	}

	fmt.Printf("[*] Executing: %s\n", strings.Join(cmd.Args, " "))
	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))
	
	if err != nil {
		// Check if route already exists (not an error on most platforms)
		lowerOutput := strings.ToLower(outputStr)
		if strings.Contains(lowerOutput, "exist") || 
		   strings.Contains(lowerOutput, "already") ||
		   strings.Contains(outputStr, "File exists") {
			fmt.Println("[+] Route already exists (OK)")
			return nil
		}
		
		// Log detailed error
		fmt.Printf("[!] Command failed with error: %v\n", err)
		if len(outputStr) > 0 {
			fmt.Printf("[!] Command output:\n%s\n", outputStr)
		}
		return fmt.Errorf("failed to add route: %w", err)
	}

	if len(outputStr) > 0 {
		fmt.Printf("[DEBUG] Command output: %s\n", outputStr)
	}
	
	fmt.Printf("[+] Route added successfully: %s via %s\n", serverIP, gateway)
	return nil
}

// deleteServerRoute removes the VPN server route
func (v *VPNClient) deleteServerRoute(serverIP string) error {
	cmd := v.getDeleteRouteCommand(serverIP)
	if cmd == nil {
		return fmt.Errorf("unsupported platform")
	}

	fmt.Printf("[*] Executing: %s\n", strings.Join(cmd.Args, " "))
	fmt.Printf("[*] Removing route for %s\n", serverIP)
	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))
	
	if err != nil {
		// Ignore errors if route doesn't exist
		lowerOutput := strings.ToLower(outputStr)
		if strings.Contains(lowerOutput, "not found") ||
		   strings.Contains(lowerOutput, "no such") ||
		   strings.Contains(lowerOutput, "not in table") {
			fmt.Println("[+] Route already removed or never existed")
			return nil
		}
		
		// Log detailed error
		fmt.Printf("[!] Command failed with error: %v\n", err)
		if len(outputStr) > 0 {
			fmt.Printf("[!] Command output:\n%s\n", outputStr)
		}
		return fmt.Errorf("failed to delete route: %w", err)
	}

	if len(outputStr) > 0 {
		fmt.Printf("[DEBUG] Command output: %s\n", outputStr)
	}
	
	fmt.Println("[+] Route removed successfully")
	return nil
}

// checkServerRoute verifies if the server route exists
func (v *VPNClient) checkServerRoute(serverIP string) (bool, error) {
	cmd := v.getCheckRouteCommand(serverIP)
	if cmd == nil {
		return false, fmt.Errorf("unsupported platform")
	}

	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	
	// Parse output based on platform
	switch runtime.GOOS {
	case "linux":
		// ip route get returns the route for the specific IP
		// Look for the server IP in the output
		if err != nil {
			return false, nil
		}
		return strings.Contains(outputStr, serverIP), nil
		
	case "darwin":
		// route -n get returns route details
		// Look for "destination:" or "gateway:" containing our IP
		if err != nil {
			return false, nil
		}
		return strings.Contains(outputStr, serverIP), nil
		
	case "windows":
		// route PRINT shows all routes
		// Parse the IPv4 Route Table section
		if err != nil {
			// Command may succeed even with no route
			fmt.Printf("[DEBUG] route PRINT error: %v\n", err)
		}
		
		// Look for the server IP in the active routes section
		inRouteTable := false
		lines := strings.Split(outputStr, "\n")
		
		for _, line := range lines {
			line = strings.TrimSpace(line)
			
			// Find the IPv4 Route Table section
			if strings.Contains(line, "IPv4 Route Table") || 
			   strings.Contains(line, "Active Routes:") {
				inRouteTable = true
				continue
			}
			
			// Skip until we're in the route table
			if !inRouteTable {
				continue
			}
			
			// Stop at the next section
			if strings.Contains(line, "Persistent Routes:") ||
			   strings.Contains(line, "IPv6 Route Table") {
				break
			}
			
			// Check if this line contains our server IP as destination
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				// First field should be the destination
				if strings.HasPrefix(fields[0], serverIP) {
					fmt.Printf("[DEBUG] Found route in output: %s\n", line)
					return true, nil
				}
			}
		}
		
		return false, nil
		
	default:
		return false, fmt.Errorf("unsupported platform")
	}
}

// getAddRouteCommand returns the OS-specific command to add a route
func (v *VPNClient) getAddRouteCommand(serverIP, gateway string) *exec.Cmd {
	switch runtime.GOOS {
	case "linux":
		// Check if system uses ip or route command
		if _, err := exec.LookPath("ip"); err == nil {
			// Use /32 for host route
			return exec.Command("ip", "route", "add", serverIP+"/32", "via", gateway)
		}
		return exec.Command("route", "add", "-host", serverIP, "gw", gateway)
		
	case "darwin":
		return exec.Command("route", "-n", "add", "-host", serverIP, gateway)
		
	case "windows":
		// Windows route: destination mask gateway metric
		// MASK 255.255.255.255 ensures it's a /32 host route
		return exec.Command("route", "ADD", serverIP, "MASK", "255.255.255.255", gateway, "METRIC", "1")
		
	default:
		return nil
	}
}

// getDeleteRouteCommand returns the OS-specific command to delete a route
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
		
	default:
		return nil
	}
}

// getCheckRouteCommand returns the OS-specific command to check if a route exists
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
		// Windows: route PRINT (without IP) shows all routes
		return exec.Command("route", "PRINT")
		
	default:
		return nil
	}
}

// parseDefaultGateway extracts the default gateway from routing table
func (v *VPNClient) parseDefaultGateway() (string, error) {
	var cmd *exec.Cmd
	var parser func(string) (string, error)
	
	switch runtime.GOOS {
	case "linux":
		// Try ip route first
		cmd = exec.Command("ip", "route", "show", "default")
		parser = v.parseLinuxGateway
		
		output, err := cmd.CombinedOutput()
		if err == nil {
			gateway, err := parser(string(output))
			if err == nil {
				return gateway, nil
			}
		}
		
		// Fallback to route command
		cmd = exec.Command("route", "-n")
		parser = v.parseLinuxRouteGateway
		
	case "darwin":
		cmd = exec.Command("route", "-n", "get", "default")
		parser = v.parseDarwinGateway
		
	case "windows":
		cmd = exec.Command("route", "PRINT", "0.0.0.0")
		parser = v.parseWindowsGateway
		
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get routing table: %w\nOutput: %s", err, string(output))
	}

	return parser(string(output))
}

// parseLinuxGateway parses gateway from 'ip route' output
func (v *VPNClient) parseLinuxGateway(output string) (string, error) {
	// Output: default via 192.168.1.1 dev eth0
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "default") && strings.Contains(line, "via") {
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "via" && i+1 < len(fields) {
					gateway := fields[i+1]
					if net.ParseIP(gateway) != nil {
						return gateway, nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("could not parse gateway from ip route output")
}

// parseLinuxRouteGateway parses gateway from 'route -n' output
func (v *VPNClient) parseLinuxRouteGateway(output string) (string, error) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "0.0.0.0" {
			gateway := fields[1]
			if net.ParseIP(gateway) != nil {
				return gateway, nil
			}
		}
	}
	return "", fmt.Errorf("could not parse gateway from route output")
}

// parseDarwinGateway parses gateway from macOS route output
func (v *VPNClient) parseDarwinGateway(output string) (string, error) {
	// Output contains: gateway: 192.168.1.1
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				gateway := fields[1]
				if net.ParseIP(gateway) != nil {
					return gateway, nil
				}
			}
		}
	}
	return "", fmt.Errorf("could not parse gateway from route output")
}

// parseWindowsGateway parses gateway from Windows route output
func (v *VPNClient) parseWindowsGateway(output string) (string, error) {
	lines := strings.Split(output, "\n")
	inRouteTable := false
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Find the IPv4 Route Table section
		if strings.Contains(line, "IPv4 Route Table") || 
		   strings.Contains(line, "Active Routes:") {
			inRouteTable = true
			continue
		}
		
		// Skip header lines
		if strings.Contains(line, "Network Destination") || 
		   strings.Contains(line, "=====") {
			continue
		}
		
		// Stop at next section
		if strings.Contains(line, "Persistent Routes:") ||
		   strings.Contains(line, "IPv6 Route Table") {
			break
		}
		
		if !inRouteTable {
			continue
		}
		
		// Look for default route (0.0.0.0)
		fields := strings.Fields(line)
		
		// Format: Network_Destination Netmask Gateway Interface Metric
		// Example: 0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100  25
		if len(fields) >= 3 {
			destination := fields[0]
			netmask := fields[1]
			gateway := fields[2]
			
			// Look for default route (0.0.0.0 with 0.0.0.0 netmask)
			if destination == "0.0.0.0" && netmask == "0.0.0.0" {
				// Validate gateway is a valid IP and not 0.0.0.0
				if net.ParseIP(gateway) != nil && gateway != "0.0.0.0" {
					fmt.Printf("[DEBUG] Found default gateway in route table: %s\n", gateway)
					return gateway, nil
				}
			}
		}
	}
	
	return "", fmt.Errorf("could not parse default gateway from Windows route table")
}

// parseFlags parses command line arguments
func parseFlags() Config {
	host := flag.String("H", "", "Server IP/hostname (required)")
	port := flag.Int("P", 0, "Server port (required)")
	username := flag.String("u", "", "SSH username (required)")
	password := flag.String("p", "", "SSH password (required)")
	sni := flag.String("S", "", "SNI hostname (required)")
	socksPort := flag.Int("socks-port", DefaultSOCKSPort, "SOCKS5 port (default: 1080)")
	autoRoute := flag.Bool("auto-route", false, "Automatically configure routing (requires admin/root)")
	pacPort := flag.Int("pac-port", 0, "PAC server port for automatic browser config (e.g., 8080)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SSH + TLS + SNI VPN Client (Go)\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s -H host -P port -u user -p pass -S sni [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  Basic:\n")
		fmt.Fprintf(os.Stderr, "    %s -H 51.159.125.86 -P 8443 -u user -p pass -S web.whatsapp.com\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  With automatic browser configuration (RECOMMENDED):\n")
		fmt.Fprintf(os.Stderr, "    %s -H 51.159.125.86 -P 8443 -u user -p pass -S web.whatsapp.com -pac-port 8080\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  With auto-route:\n")
		fmt.Fprintf(os.Stderr, "    %s -H 51.159.125.86 -P 8443 -u user -p pass -S web.whatsapp.com -auto-route -pac-port 8080\n\n", os.Args[0])
		
		if runtime.GOOS == "windows" {
			fmt.Fprintf(os.Stderr, "Windows Users:\n")
			fmt.Fprintf(os.Stderr, "  • Use -pac-port for automatic browser configuration (easiest!)\n")
			fmt.Fprintf(os.Stderr, "  • Run as Administrator for -auto-route feature\n")
			fmt.Fprintf(os.Stderr, "  • After starting, configure PAC URL in Windows proxy settings\n\n")
		}
		
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		
		fmt.Fprintf(os.Stderr, "\nFeatures:\n")
		fmt.Fprintf(os.Stderr, "  -pac-port: Starts a PAC server for automatic proxy configuration\n")
		fmt.Fprintf(os.Stderr, "             Browsers can auto-configure using: http://127.0.0.1:<pac-port>/proxy.pac\n")
		fmt.Fprintf(os.Stderr, "             This is the EASIEST way to configure browsers!\n\n")
		
		if runtime.GOOS == "windows" {
			fmt.Fprintf(os.Stderr, "  -auto-route: Requires Administrator privileges (Run as Administrator)\n")
		} else {
			fmt.Fprintf(os.Stderr, "  -auto-route: Requires root privileges (run with sudo)\n")
		}
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

func main() {
	config := parseFlags()
	
	// Check for admin privileges if auto-route is enabled
	if config.AutoRoute {
		if !isAdmin() {
			if runtime.GOOS == "windows" {
				log.Fatal("[!] Error: -auto-route requires Administrator privileges\n" +
					"       Right-click the program and select 'Run as Administrator'\n" +
					"       Or run from an Administrator Command Prompt/PowerShell\n\n" +
					"       To test route commands manually:\n" +
					"       1. Open Command Prompt as Administrator\n" +
					"       2. Run: route PRINT\n" +
					"       3. Run: route ADD <server_ip> MASK 255.255.255.255 <gateway> METRIC 1\n")
			} else {
				log.Fatal("[!] Error: -auto-route requires root privileges\n" +
					"       Run with: sudo " + os.Args[0] + "\n\n" +
					"       To test route commands manually:\n" +
					"       Linux: sudo ip route add <server_ip>/32 via <gateway>\n" +
					"       macOS: sudo route -n add -host <server_ip> <gateway>\n")
			}
		}
		fmt.Println("[+] Running with elevated privileges")
	}
	
	client := NewVPNClient(config)

	if err := client.Start(); err != nil {
		log.Fatalf("[!] Error: %v\n", err)
	}
}

// isAdmin checks if the program is running with admin/root privileges
func isAdmin() bool {
	switch runtime.GOOS {
	case "windows":
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		return err == nil
	case "linux", "darwin":
		return os.Geteuid() == 0
	default:
		return false
	}
}

// startPACServer starts the PAC file server for automatic proxy configuration
func (v *VPNClient) startPACServer() {
	if v.pacServer.port <= 0 {
		return
	}

	addr := fmt.Sprintf("127.0.0.1:%d", v.pacServer.port)
	
	http.HandleFunc("/proxy.pac", func(w http.ResponseWriter, r *http.Request) {
		pacContent := v.generatePACFile()
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Write([]byte(pacContent))
	})
	
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>VPN Proxy Configuration</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .info { background: #e3f2fd; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .success { background: #c8e6c9; padding: 20px; border-radius: 5px; margin: 20px 0; }
        h1 { color: #1976d2; }
        code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
        .step { margin: 10px 0; padding-left: 20px; }
    </style>
</head>
<body>
    <h1>🚀 VPN Proxy Server</h1>
    <div class="success">
        <h2>✅ Server is Running!</h2>
        <p>SOCKS5 Proxy: <code>127.0.0.1:%d</code></p>
        <p>PAC URL: <code>http://127.0.0.1:%d/proxy.pac</code></p>
    </div>
    
    <div class="info">
        <h2>📋 How to Configure Your Browser:</h2>
        
        <h3>Windows System-Wide:</h3>
        <div class="step">1. Settings → Network & Internet → Proxy</div>
        <div class="step">2. Automatic proxy setup → Use setup script: ON</div>
        <div class="step">3. Script address: <code>http://127.0.0.1:%d/proxy.pac</code></div>
        <div class="step">4. Click 'Save'</div>
        
        <h3>Firefox:</h3>
        <div class="step">1. Settings → Network Settings</div>
        <div class="step">2. Automatic proxy configuration URL</div>
        <div class="step">3. URL: <code>http://127.0.0.1:%d/proxy.pac</code></div>
        
        <h3>Chrome/Edge:</h3>
        <div class="step">1. Settings → System → Open proxy settings</div>
        <div class="step">2. Use automatic configuration script</div>
        <div class="step">3. Address: <code>http://127.0.0.1:%d/proxy.pac</code></div>
    </div>
    
    <div class="info">
        <h2>🧪 Test Your Connection:</h2>
        <p>Visit: <a href="https://ipinfo.io" target="_blank">https://ipinfo.io</a></p>
        <p>Your IP should show the VPN server's IP address.</p>
    </div>
</body>
</html>`, v.pacServer.socksPort, v.pacServer.port, v.pacServer.port, v.pacServer.port, v.pacServer.port)
			w.Write([]byte(html))
		} else {
			http.NotFound(w, r)
		}
	})
	
	v.pacServer.running.Store(true)
	fmt.Printf("[+] PAC server started on http://127.0.0.1:%d\n", v.pacServer.port)
	fmt.Printf("[+] Configuration page: http://127.0.0.1:%d/\n", v.pacServer.port)
	
	if err := http.ListenAndServe(addr, nil); err != nil {
		if v.running.Load() {
			fmt.Printf("[!] PAC server error: %v\n", err)
		}
	}
}

// generatePACFile creates a PAC file content
func (v *VPNClient) generatePACFile() string {
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
    // VPN Proxy Auto-Configuration
    // All traffic goes through SOCKS5 proxy
    
    // Localhost and local network - direct connection
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }
    
    // Everything else goes through SOCKS5 proxy
    return "SOCKS5 127.0.0.1:%d; SOCKS 127.0.0.1:%d; DIRECT";
}`, v.pacServer.socksPort, v.pacServer.socksPort)
}
