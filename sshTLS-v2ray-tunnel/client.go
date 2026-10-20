package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// Constants - Optimized for high-performance connection handling
const (
	SOCKS5Version      = 0x05
	MaxConnections     = 2000
	DefaultSOCKSPort   = 1080
	MaxRetries         = 5
	RetryDelay         = 2 * time.Second
	KeepaliveInterval  = 15 * time.Second
	StatusInterval     = 60 * time.Second
	ConnectionTimeout  = 30 * time.Second
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
	DialAddress      string
	Enabled          bool
	Protocol         string // vmess, vless, trojan, shadowsocks
	UUID             string
	Address          string
	Port             int
	Network          string // tcp, ws, grpc, http
	Security         string // none, tls, reality
	TLSVersion       string // auto, tls1.2, tls1.3
	SNI              string
	SNISource        string // link, host, or server fallback
	PeerCertSHA256   string
	AutoPin          bool
	UnverifiedPin    bool
	Fingerprint      string
	ALPN             []string
	Cipher           string
	Flow             string
	RealityPublicKey string
	RealityShortID   string
	Path             string // for websocket
	Host             string // for websocket
	ServiceName      string // for grpc
	ConfigPath       string // custom config file path
	BinaryPath       string // xray or v2ray binary path
}

// Config holds the VPN client configuration
type Config struct {
	UIReadyFile      string
	DialAddress      string
	ProxyDialAddress string
	// Common
	Mode           TunnelMode
	SOCKSPort      int
	AutoRoute      bool
	PACPort        int
	MaxConnections int

	UI            bool
	UINoBrowser   bool
	UIPort        int
	TUN           bool
	TUNBinary     string
	ProxyURL      string
	PayloadFile   string
	Payload       string
	PayloadStage  string
	SSHKnownHosts string
	SSHHostKey    string
	TLSCA         string
	Output        io.Writer `json:"-"`

	SSHCertPin       string
	SSHAutoPin       bool
	SSHUnverifiedPin bool
	// SSH specific
	Host        string
	Port        int
	Username    string
	Password    string
	SNIHostname string
	TLSVersion  string // auto, tls1.2, tls1.3

	// V2Ray/Xray specific
	V2Ray V2RayConfig
}

// V2RayClient manages V2Ray/Xray process
type V2RayClient struct {
	config  V2RayConfig
	output  io.Writer
	ctx     context.Context
	cmd     *exec.Cmd
	done    chan struct{}
	exitErr error
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
	connCount    atomic.Int32
	totalConns   atomic.Int64
	failedCount  atomic.Int64
	successCount atomic.Int64
	bytesIn      atomic.Int64
	bytesOut     atomic.Int64
	startTime    time.Time
	lastConnTime time.Time
	lastConnMu   sync.RWMutex
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
	tunProcess    *tunProcess
	tunExcluded   []string
	lifecycle     sync.Mutex
	reconnectMu   sync.Mutex
	stopped       bool
	listener      net.Listener
	workers       sync.WaitGroup
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
			output: cfg.Output, ctx: ctx,
		}
	}

	return client
}

// Server Management

func (v *VPNClient) startSOCKSServer() error {
	if v.config.Mode == ModeSSH {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", v.config.SOCKSPort))
		if err != nil {
			return err
		}
		v.listener = listener
		v.workers.Add(1)
		go func() {
			defer v.workers.Done()
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go v.handleSOCKS5(conn)
			}
		}()
	}
	if v.config.PACPort > 0 {
		if err := v.startPACServer(); err != nil {
			return err
		}
	}
	if v.config.TUN {
		if err := v.startTUN(v.tunExcluded); err != nil {
			return err
		}
	}
	v.running.Store(true)
	v.printBanner()
	if v.config.Mode == ModeSSH {
		v.workers.Add(1)
		go func() { defer v.workers.Done(); v.keepalive() }()
	} else {
		v.workers.Add(1)
		go func() { defer v.workers.Done(); v.monitorV2Ray() }()
	}
	go v.displayStatus()
	<-v.ctx.Done()
	return nil
}

func (v *VPNClient) monitorV2Ray() {
	failures := 0
	for sleepContext(v.ctx, time.Second) {
		if v.v2rayClient.IsRunning() {
			failures = 0
			continue
		}
		delay := time.Second * time.Duration(1<<min(failures, 5))
		if !sleepContext(v.ctx, delay) {
			return
		}
		v.reconnectMu.Lock()
		if v.ctx.Err() != nil {
			v.reconnectMu.Unlock()
			return
		}
		v.logf("[!] Core exited; restart attempt %d\n", failures+1)
		err := v.v2rayClient.Start(v.config.SOCKSPort)
		v.reconnectMu.Unlock()
		if err != nil {
			v.logf("[!] Restart failed: %v\n", err)
			failures++
		} else {
			failures = 0
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
				v.logln("\n[!] Connection unhealthy, reconnecting...")
				if err := v.reconnect(); err == nil {
					v.logln("[✓] Health check: Reconnected")
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
				v.logln("\n[!] Connection lost. Reconnecting...")
				if err := v.reconnect(); err == nil {
					v.logln("[✓] Reconnected")
					consecutiveFailures = 0
				} else {
					consecutiveFailures++
					if consecutiveFailures >= maxFailures {
						v.cancel()
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

	v.logf("\n[ℹ] Status Report:\n")
	v.logf("  Mode: %s\n", mode)
	v.logf("  Uptime: %v\n", uptime.Round(time.Second))
	v.logf("  Active connections: %d/%d\n", connCount, maxConns)
	v.logf("  Total: %d | Success: %d | Failed: %d\n",
		v.stats.totalConns.Load(), v.stats.successCount.Load(), v.stats.failedCount.Load())
	v.logf("  Data: ↓ %s / ↑ %s\n",
		formatBytes(v.stats.bytesIn.Load()), formatBytes(v.stats.bytesOut.Load()))

	if v.config.Mode == ModeSSH {
		v.logf("  SSH Health: %s\n", map[bool]string{true: "✓ Healthy", false: "✗ Unhealthy"}[v.connPool.IsHealthy()])
	} else if v.v2rayClient != nil {
		v.logf("  V2Ray/Xray: %s\n", map[bool]string{true: "✓ Running", false: "✗ Stopped"}[v.v2rayClient.IsRunning()])
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
	v.reconnectMu.Lock()
	defer v.reconnectMu.Unlock()
	if v.ctx.Err() != nil {
		return v.ctx.Err()
	}
	if v.config.Mode != ModeSSH {
		return nil
	}

	client := v.connPool.GetClient()
	if client != nil {
		client.Close()
	}
	v.connPool.SetClient(nil)
	v.connPool.MarkUnhealthy()

	if !sleepContext(v.ctx, time.Second) {
		return v.ctx.Err()
	}
	return v.connectSSH()
}

func (v *VPNClient) Start() error {
	defer v.Stop()
	if v.ctx.Err() != nil {
		return v.ctx.Err()
	}
	v.printHeader()
	if v.config.TUN && !isAdmin() {
		return fmt.Errorf("full-device TUN requires Administrator/root privileges")
	}
	ports := []int{v.config.PACPort}
	if v.config.Mode == ModeSSH || v.config.V2Ray.ConfigPath == "" {
		ports = append(ports, v.config.SOCKSPort)
	}
	for _, port := range ports {
		if port > 0 {
			if err := checkLocalPort(port); err != nil {
				return err
			}
		}
	}
	if v.config.TUN {
		var err error
		v.tunExcluded, err = v.prepareTUN()
		if err != nil {
			return err
		}
	}
	if v.config.Mode == ModeV2Ray || v.config.Mode == ModeXray {
		if err := v.v2rayClient.Start(v.config.SOCKSPort); err != nil {
			return fmt.Errorf("start core: %w", err)
		}
		if err := waitForSOCKS(v.ctx, v.config.SOCKSPort); err != nil {
			return err
		}
	} else {
		if err := v.connectSSH(); err != nil {
			return err
		}
	}
	return v.startSOCKSServer()
}

// Stop may be called by the UI or signal handler. Cancellation interrupts
// startup; Start owns teardown after every acquired resource is accounted for.
func (v *VPNClient) Cancel() { v.cancel() }
func (v *VPNClient) Stop() {
	v.cancel()
	v.lifecycle.Lock()
	defer v.lifecycle.Unlock()
	if v.stopped {
		return
	}
	v.stopped = true
	v.running.Store(false)
	if v.listener != nil {
		v.listener.Close()
	}
	if v.tunProcess != nil {
		v.tunProcess.Stop()
	}
	v.reconnectMu.Lock()
	if v.v2rayClient != nil {
		v.v2rayClient.Stop()
	}
	if client := v.connPool.GetClient(); client != nil {
		client.Close()
	}
	v.reconnectMu.Unlock()
	if v.pacServer.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = v.pacServer.server.Shutdown(ctx)
		cancel()
	}
	v.workers.Wait()
}

func (v *VPNClient) printHeader() {
	v.logln("\n============================================================")
	v.logln("Enhanced VPN Client - SSH + V2Ray/Xray Support")
	v.logln("============================================================")

	if v.config.Mode == ModeSSH {
		v.logf("Mode: SSH Tunnel\n")
		v.logf("Server: %s:%d\n", v.config.Host, v.config.Port)
		v.logf("SNI: %s\n", v.config.SNIHostname)
	} else {
		v.logf("Mode: %s\n", v.config.Mode)
		v.logf("Protocol: %s\n", v.config.V2Ray.Protocol)
		v.logf("Server: %s:%d\n", v.config.V2Ray.Address, v.config.V2Ray.Port)
		v.logf("Network: %s\n", v.config.V2Ray.Network)
		v.logf("Security: %s\n", v.config.V2Ray.Security)
		v.logf("SNI: %s\n", v.config.V2Ray.SNI)
	}

	v.logf("Max Connections: %d\n", v.config.MaxConnections)
	v.logln("============================================================")
}

func (v *VPNClient) printBanner() {
	v.logln("\n============================================================")
	v.logln("LOCAL PROXY STARTED — connection check pending")
	v.logln("============================================================")
	v.logf("SOCKS5 Proxy: 127.0.0.1:%d\n", v.config.SOCKSPort)
	v.logf("Mode: %s\n", v.config.Mode)

	if v.config.Mode == ModeV2Ray || v.config.Mode == ModeXray {
		v.logf("Protocol: %s over %s (%s)\n",
			v.config.V2Ray.Protocol,
			v.config.V2Ray.Network,
			v.config.V2Ray.Security)
		v.logf("Server: %s:%d\n", v.config.V2Ray.Address, v.config.V2Ray.Port)
	}

	if v.config.PACPort > 0 {
		v.logf("\n🎉 PAC URL: http://127.0.0.1:%d/proxy.pac\n", v.config.PACPort)
		v.logf("Config Page: http://127.0.0.1:%d/\n", v.config.PACPort)
	}

	v.logln("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	v.logln("✅ TEST YOUR CONNECTION:")
	v.logln("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Test commands
	v.logln("\n1. Check your VPN IP:")
	v.logf("   curl --socks5-hostname 127.0.0.1:%d https://ipinfo.io/ip\n", v.config.SOCKSPort)

	v.logln("\n2. Compare with your real IP:")
	v.logln("   curl https://ipinfo.io/ip")

	v.logln("\n3. Test in browser (after configuring PAC):")
	v.logln("   Visit: https://ipinfo.io")
	v.logln("          https://ipleak.net")

	v.logln("\n4. Speed test:")
	v.logln("   Visit: https://fast.com")

	if v.config.Mode == ModeV2Ray || v.config.Mode == ModeXray {
		v.logln("\n💡 Tip: You're using V2Ray/Xray mode")
		v.logln("   Your traffic is already being proxied through the SOCKS5 port")
		v.logln("   Just configure your browser to use the PAC file or SOCKS5 proxy")
	}

	v.logln("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	v.logln("Press Ctrl+C to disconnect...")
	v.logln("============================================================")

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

// checkLocalPort rejects occupied listeners without changing another process.
func checkLocalPort(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("cannot use local port %d: %w; choose another -socks-port or -pac-port", port, err)
	}
	return listener.Close()
}

func (v *VPNClient) logf(format string, args ...interface{}) {
	out := v.config.Output
	if out == nil {
		out = os.Stdout
	}
	fmt.Fprintf(out, format, args...)
}
func (v *VPNClient) logln(args ...interface{}) {
	out := v.config.Output
	if out == nil {
		out = os.Stdout
	}
	fmt.Fprintln(out, args...)
}
