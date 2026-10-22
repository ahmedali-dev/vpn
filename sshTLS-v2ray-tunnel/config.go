package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Flag parsing
func parseConfig(args []string) (Config, error) {
	fs := flag.NewFlagSet("tunnel", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	// Mode selection
	mode := fs.String("mode", "ssh", "Tunnel mode: ssh, v2ray, xray")

	// Common flags
	socksPort := fs.Int("socks-port", DefaultSOCKSPort, "SOCKS5 port")
	autoRoute := fs.Bool("auto-route", false, "Alias for -tun: full-device routing (requires administrator)")
	pacPort := fs.Int("pac-port", 0, "PAC server port")
	maxConns := fs.Int("max-conns", MaxConnections, "Max concurrent connections")

	ui := fs.Bool("ui", false, "Start desktop control API/interface")
	uiHelperAddress := fs.String("ui-helper-address-file", "", "Private parent-helper rendezvous file")
	uiHelper := fs.Bool("ui-helper", false, "Restricted privileged networking helper with a parent lease")
	uiNoBrowser := fs.Bool("ui-no-browser", false, "Do not open the control interface in a browser")
	uiReadyFile := fs.String("ui-ready-file", "", "Desktop helper readiness file")
	uiPort := fs.Int("ui-port", 0, "Loopback control port (0 chooses a free port)")
	tun := fs.Bool("tun", false, "Full-device TUN routing through sing-box (requires administrator)")
	tunBinary := fs.String("tun-binary", "", "Path to sing-box executable")
	proxyURL := fs.String("proxy", "", "HTTP(S) CONNECT upstream URL for SSH transport")
	payload := fs.String("payload-file", "", "Custom SSH CONNECT payload template file")
	payloadStage := fs.String("payload-stage", "before-tls", "Send CONNECT/payload before-tls or after-tls")
	knownHosts := fs.String("ssh-known-hosts", "", "SSH known_hosts path (default ~/.ssh/known_hosts)")
	sshIPv4Only := fs.Bool("ssh-ipv4-only", false, "SSH IPv4 compatibility: suppress IPv6 DNS answers and reject IPv6 destinations")
	sshTOFU := fs.Bool("ssh-trust-on-first-use", false, "Explicitly accept the first SSH key for this connection session")
	hostKey := fs.String("ssh-host-key", "", "Trusted SSH host-key fingerprint (SHA256:...)")
	sshPin := fs.String("ssh-cert-sha256", "auto", "SSH TLS: auto verified pin, none, insecure compatibility pin, or a trusted 64-hex pin")
	tlsCA := fs.String("tls-ca", "", "PEM CA certificates for SSH TLS validation")
	tlsVersion := fs.String("tls-version", "auto", "TLS version: auto, tls1.2, or tls1.3")
	// SSH flags
	host := fs.String("H", "", "SSH server hostname/IP")
	port := fs.Int("P", 0, "SSH server port")
	username := fs.String("u", "", "SSH username")
	password := fs.String("p", "", "SSH password")
	sni := fs.String("S", "", "SNI hostname")

	// V2Ray/Xray flags
	v2rayProtocol := fs.String("v2ray-protocol", "vmess", "Protocol: vmess, vless, trojan, shadowsocks")
	v2rayUUID := fs.String("v2ray-uuid", "", "V2Ray UUID/password")
	v2rayAddr := fs.String("v2ray-addr", "", "V2Ray server address")
	v2rayPort := fs.Int("v2ray-port", 0, "V2Ray server port")
	v2rayNetwork := fs.String("v2ray-network", "tcp", "Network: tcp, ws, grpc, http")
	v2raySecurity := fs.String("v2ray-security", "none", "Security: none, tls, reality")
	v2raySNI := fs.String("v2ray-sni", "", "TLS SNI override, including imported links (default: link SNI or server address)")
	v2rayPin := fs.String("v2ray-cert-sha256", "auto", "auto: verify real server hostname and pin when SNI differs; none: normal SNI verification; insecure: unverified session pin; or 64 hex digits")
	v2rayPath := fs.String("v2ray-path", "/", "WebSocket path or HTTP path")
	v2rayHost := fs.String("v2ray-host", "", "WebSocket/HTTP host")
	v2rayService := fs.String("v2ray-service", "", "gRPC service name")
	v2rayConfig := fs.String("v2ray-config", "", "V2Ray config file path")
	v2rayBinary := fs.String("v2ray-binary", "", "V2Ray/Xray binary path")

	// V2Ray link import
	v2rayLink := fs.String("v2ray-link", "", "Import from vmess://, vless://, or trojan:// link")

	fs.Usage = func() {
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
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	tunnelMode := TunnelMode(strings.ToLower(*mode))

	config := Config{
		Mode:        tunnelMode,
		SOCKSPort:   *socksPort,
		AutoRoute:   false,
		UIReadyFile: *uiReadyFile, UI: *ui, UINoBrowser: *uiNoBrowser, UIHelper: *uiHelper, UIHelperAddressFile: *uiHelperAddress, UIPort: *uiPort, TUN: *tun || *autoRoute, TUNBinary: *tunBinary, ProxyURL: *proxyURL, PayloadFile: *payload, PayloadStage: *payloadStage, SSHKnownHosts: *knownHosts, SSHHostKey: *hostKey, SSHTrustOnFirstUse: *sshTOFU, SSHIPv4Only: *sshIPv4Only, TLSCA: *tlsCA,
		PACPort:        *pacPort,
		MaxConnections: *maxConns,
	}
	if *tlsVersion != "auto" && *tlsVersion != "tls1.2" && *tlsVersion != "tls1.3" {
		return Config{}, fmt.Errorf("tls-version must be auto, tls1.2, or tls1.3")
	}
	config.TLSVersion = *tlsVersion

	if config.UIPort < 0 || config.UIPort > 65535 {
		return Config{}, fmt.Errorf("invalid UI port")
	}
	if config.UI {
		return config, nil
	}
	if config.TUN && config.AutoRoute {
		return Config{}, fmt.Errorf("use -tun for full-device routing; do not combine with -auto-route")
	}
	if config.PayloadStage != "before-tls" && config.PayloadStage != "after-tls" {
		return Config{}, fmt.Errorf("payload-stage must be before-tls or after-tls")
	}
	if config.ProxyURL != "" {
		if _, err := parseProxyURL(config.ProxyURL); err != nil {
			return Config{}, err
		}
	}
	if config.PayloadFile != "" {
		b, err := os.ReadFile(config.PayloadFile)
		if err != nil {
			return Config{}, fmt.Errorf("payload: %w", err)
		}
		if len(b) > 64*1024 {
			return Config{}, fmt.Errorf("payload exceeds 64 KiB")
		}
		config.Payload = string(b)
	}
	// Parse based on mode
	if tunnelMode == ModeSSH {
		if *host == "" || *port == 0 || *username == "" || *password == "" {
			return Config{}, fmt.Errorf("SSH mode requires: -H, -P, -u, -p")
		}
		config.Host = *host
		config.Port = *port
		config.Username = *username
		config.Password = *password
		config.SSHAutoPin = *sshPin == "auto"
		config.SSHUnverifiedPin = *sshPin == "insecure"
		if *sshPin != "auto" && *sshPin != "none" && *sshPin != "insecure" {
			pin, err := hex.DecodeString(*sshPin)
			if err != nil || len(pin) != 32 {
				return Config{}, fmt.Errorf("ssh-cert-sha256 requires auto, none, insecure, or 64 hex digits")
			}
			config.SSHCertPin = strings.ToLower(*sshPin)
		}
		config.SNIHostname = *sni
		if config.SNIHostname == "" {
			config.SNIHostname = config.Host
		}
		if config.SSHKnownHosts == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return Config{}, err
			}
			config.SSHKnownHosts = filepath.Join(home, ".ssh", "known_hosts")
		}
	} else if tunnelMode == ModeV2Ray || tunnelMode == ModeXray {
		// Parse V2Ray link if provided
		if *v2rayLink != "" {
			v2rayConf, err := parseV2RayLink(*v2rayLink)
			if err != nil {
				return Config{}, fmt.Errorf("failed to parse V2Ray link: %w", err)
			}
			config.V2Ray = v2rayConf
			config.V2Ray.Enabled = true
		} else if *v2rayConfig != "" {
			config.V2Ray.Enabled = true
		} else {
			// Manual configuration
			if *v2rayAddr == "" || *v2rayPort == 0 || *v2rayUUID == "" {
				return Config{}, fmt.Errorf("V2Ray mode requires a share link, config file, or -v2ray-addr, -v2ray-port, -v2ray-uuid")
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

	if tunnelMode != ModeSSH && tunnelMode != ModeV2Ray && tunnelMode != ModeXray {
		return Config{}, fmt.Errorf("unknown mode: %s", tunnelMode)
	}
	if config.SOCKSPort < 1 || config.SOCKSPort > 65535 || config.PACPort < 0 || config.PACPort > 65535 {
		return Config{}, fmt.Errorf("invalid SOCKS or PAC port")
	}
	if config.PACPort == config.SOCKSPort {
		return Config{}, fmt.Errorf("PAC and SOCKS ports must differ")
	}
	if config.MaxConnections < 1 {
		return Config{}, fmt.Errorf("max-conns must be positive")
	}
	if tunnelMode == ModeSSH && (config.Port < 1 || config.Port > 65535) {
		return Config{}, fmt.Errorf("invalid SSH port")
	}
	if config.V2Ray.Enabled {
		if *v2rayPin != "" && *v2rayPin != "auto" && *v2rayPin != "none" && *v2rayPin != "insecure" {
			if *v2rayConfig != "" {
				return Config{}, fmt.Errorf("set the certificate pin inside the custom config")
			}
			pin, err := hex.DecodeString(*v2rayPin)
			if err != nil || len(pin) != 32 {
				return Config{}, fmt.Errorf("v2ray-cert-sha256 must contain 64 hexadecimal digits")
			}
			config.V2Ray.PeerCertSHA256 = strings.ToLower(*v2rayPin)
		}

		if *v2raySNI != "" {
			if *v2rayConfig != "" {
				return Config{}, fmt.Errorf("set SNI inside the custom config; -v2ray-sni applies to generated configs")
			}
			config.V2Ray.SNI = *v2raySNI
		}
		config.V2Ray.UnverifiedPin = *v2rayPin == "insecure"
		config.V2Ray.TLSVersion = *tlsVersion
		if config.V2Ray.UnverifiedPin && *v2rayConfig != "" {
			return Config{}, fmt.Errorf("unverified session pin requires a generated TLS config")
		}
		config.V2Ray.AutoPin = *v2rayPin == "auto" && *v2rayConfig == ""
		config.V2Ray.ConfigPath = *v2rayConfig
		config.V2Ray.BinaryPath = *v2rayBinary
		if *v2rayLink != "" && *v2rayConfig != "" {
			return Config{}, fmt.Errorf("choose either -v2ray-link or -v2ray-config")
		}
		if config.V2Ray.ConfigPath == "" && (config.V2Ray.Port < 1 || config.V2Ray.Port > 65535) {
			return Config{}, fmt.Errorf("invalid V2Ray port")
		}
		if config.V2Ray.ConfigPath == "" {
			switch config.V2Ray.Protocol {
			case "vmess", "vless", "trojan", "shadowsocks":
			default:
				return Config{}, fmt.Errorf("unsupported protocol %q", config.V2Ray.Protocol)
			}
		}
		if config.V2Ray.Network == "" {
			config.V2Ray.Network = "tcp"
		}
		if config.V2Ray.Security == "" {
			config.V2Ray.Security = "none"
		}
		if (config.V2Ray.PeerCertSHA256 != "" || config.V2Ray.UnverifiedPin) && config.V2Ray.Security != "tls" {
			return Config{}, fmt.Errorf("v2ray-cert-sha256 requires TLS security")
		}
		if config.V2Ray.SNI == "" {
			config.V2Ray.SNI = config.V2Ray.Address
		}
		if (config.AutoRoute || config.TUN) && config.V2Ray.ConfigPath != "" {
			return Config{}, fmt.Errorf("auto-route needs a server address; use manual flags or a share link")
		}
	}
	if tunnelMode != ModeSSH && (config.ProxyURL != "" || config.Payload != "") {
		return Config{}, fmt.Errorf("HTTP CONNECT/payload options currently apply to SSH mode")
	}
	return config, nil
}

// Parse V2Ray share links
func decodeShareBase64(data string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(data); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid share-link base64")
}

func parseV2RayLink(link string) (V2RayConfig, error) {
	cfg := V2RayConfig{Enabled: true, Network: "tcp", Security: "none", Path: "/", Cipher: "auto"}
	link = strings.TrimSpace(link)
	if strings.HasPrefix(link, "vmess://") {
		b, err := decodeShareBase64(strings.TrimPrefix(link, "vmess://"))
		if err != nil {
			return cfg, err
		}
		var obj map[string]json.RawMessage
		if err = json.Unmarshal(b, &obj); err != nil {
			return cfg, fmt.Errorf("invalid VMess JSON: %w", err)
		}
		str := func(k string) string {
			var v string
			if json.Unmarshal(obj[k], &v) == nil {
				return v
			}
			var n json.Number
			if json.Unmarshal(obj[k], &n) == nil {
				return n.String()
			}
			return ""
		}
		cfg.Protocol = "vmess"
		cfg.Address = str("add")
		cfg.UUID = str("id")
		cfg.Port, err = strconv.Atoi(str("port"))
		if err != nil {
			return cfg, fmt.Errorf("invalid VMess port")
		}
		if n := str("net"); n != "" {
			cfg.Network = n
		}
		if str("tls") == "tls" {
			cfg.Security = "tls"
		}
		cfg.SNI = str("sni")
		cfg.Host = str("host")
		if p := str("path"); p != "" {
			cfg.Path = p
		}
		if fp := str("fp"); fp != "" {
			cfg.Fingerprint = fp
		}
		if a := str("alpn"); a != "" && a != "none" {
			cfg.ALPN = strings.Split(a, ",")
		}
		if c := str("scy"); c != "" {
			cfg.Cipher = c
		}
		if aid := str("aid"); aid != "" && aid != "0" {
			return cfg, fmt.Errorf("legacy VMess alterId is unsupported; export an AEAD profile with alterId 0")
		}
	} else {
		u, err := url.Parse(link)
		if err != nil {
			return cfg, fmt.Errorf("invalid share URL: %w", err)
		}
		if u.Scheme != "vless" && u.Scheme != "trojan" {
			return cfg, fmt.Errorf("supported share links: vmess, vless, trojan")
		}
		if u.User == nil {
			return cfg, fmt.Errorf("missing UUID/password")
		}
		cfg.Protocol = u.Scheme
		cfg.UUID = u.User.Username()
		cfg.Address = u.Hostname()
		cfg.Port, err = strconv.Atoi(u.Port())
		if err != nil {
			return cfg, fmt.Errorf("invalid share-link port")
		}
		q := u.Query()
		if n := q.Get("type"); n != "" {
			cfg.Network = n
		}
		if sec := q.Get("security"); sec != "" {
			cfg.Security = sec
		}
		if cfg.Protocol == "trojan" && q.Get("security") == "" {
			cfg.Security = "tls"
		}
		cfg.SNI = q.Get("sni")
		cfg.Host = q.Get("host")
		if p := q.Get("path"); p != "" {
			cfg.Path = p
		}
		cfg.ServiceName = q.Get("serviceName")
		if fp := q.Get("fp"); fp != "" {
			cfg.Fingerprint = fp
		}
		if a := q.Get("alpn"); a != "" && a != "none" {
			cfg.ALPN = strings.Split(a, ",")
		}
		cfg.Flow = q.Get("flow")
		cfg.RealityPublicKey = q.Get("pbk")
		cfg.RealityShortID = q.Get("sid")
	}
	if cfg.Address == "" || cfg.UUID == "" || cfg.Port < 1 || cfg.Port > 65535 {
		return cfg, fmt.Errorf("share link needs server, credentials, and valid port")
	}
	if strings.ContainsAny(cfg.Address, "\r\n ") {
		return cfg, fmt.Errorf("invalid server address")
	}
	switch cfg.Network {
	case "tcp", "raw", "ws", "grpc", "http", "h2", "httpupgrade", "xhttp":
	default:
		return cfg, fmt.Errorf("unsupported network %q", cfg.Network)
	}
	if cfg.Security != "none" && cfg.Security != "tls" && cfg.Security != "reality" {
		return cfg, fmt.Errorf("unsupported security %q", cfg.Security)
	}
	if cfg.Security == "reality" && (cfg.RealityPublicKey == "" || cfg.SNI == "") {
		return cfg, fmt.Errorf("REALITY link needs SNI and public key")
	}
	cfg.SNISource = "link"
	if cfg.SNI == "" {
		// NetMod-style VMess WebSocket exports often omit sni and use host
		// for both the HTTP Host header and TLS server name. Explicit sni wins.
		if cfg.Protocol == "vmess" && cfg.Security == "tls" && (cfg.Network == "ws" || cfg.Network == "httpupgrade") && cfg.Host != "" {
			cfg.SNISource = "host"
			cfg.SNI = cfg.Host
			if host, _, err := net.SplitHostPort(cfg.Host); err == nil {
				cfg.SNI = host
			}
		} else {
			cfg.SNISource = "server"
			cfg.SNI = cfg.Address
		}
	}

	return cfg, nil
}
