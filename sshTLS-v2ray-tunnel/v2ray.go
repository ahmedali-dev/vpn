package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// V2Ray/Xray Management

// generateV2RayConfig generates V2Ray/Xray configuration
func (v *V2RayClient) generateV2RayConfig(socksPort int) (string, error) {
	dialAddress := v.config.Address
	if v.config.DialAddress != "" {
		dialAddress = v.config.DialAddress
	}
	cipher := v.config.Cipher
	if cipher == "" {
		cipher = "auto"
	}
	fingerprint := v.config.Fingerprint

	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "info",
		},
		"inbounds": []map[string]interface{}{
			{
				"listen":   "127.0.0.1",
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
					"address": dialAddress,
					"port":    v.config.Port,
					"users": []map[string]interface{}{
						{
							"id":       v.config.UUID,
							"alterId":  0, // Modern VMess uses 0
							"security": cipher,
						},
					},
				},
			},
		}

	case "vless":
		outbound["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": dialAddress,
					"port":    v.config.Port,
					"users": []map[string]interface{}{
						{
							"id":         v.config.UUID,
							"encryption": "none",
							"flow":       v.config.Flow, // Add flow if using XTLS
						},
					},
				},
			},
		}

	case "trojan":
		outbound["settings"] = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  dialAddress,
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
					"address":  dialAddress,
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
			"serviceName":          v.config.ServiceName,
			"multiMode":            false,
			"idle_timeout":         60,
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

	case "httpupgrade":
		streamSettings["httpupgradeSettings"] = map[string]interface{}{"host": v.config.Host, "path": v.config.Path}
	case "xhttp":
		streamSettings["xhttpSettings"] = map[string]interface{}{"host": v.config.Host, "path": v.config.Path}
	case "tcp", "raw":
		// TCP can have header obfuscation
		streamSettings["tcpSettings"] = map[string]interface{}{
			"header": map[string]interface{}{
				"type": "none",
			},
		}
	}

	// Configure TLS/Security
	if v.config.Security == "tls" {
		tlsSettings := map[string]interface{}{}
		if v.config.SNI != "" {
			tlsSettings["serverName"] = v.config.SNI
		}
		if v.config.PeerCertSHA256 != "" {
			tlsSettings["pinnedPeerCertSha256"] = v.config.PeerCertSHA256
		}
		// Add fingerprint if available
		if fingerprint != "" && fingerprint != "none" {
			tlsSettings["fingerprint"] = fingerprint
		}
		if len(v.config.ALPN) > 0 {
			tlsSettings["alpn"] = v.config.ALPN
		}
		streamSettings["tlsSettings"] = tlsSettings

	} else if v.config.Security == "reality" {
		if fingerprint == "" || fingerprint == "none" {
			fingerprint = "chrome"
		}
		realitySettings := map[string]interface{}{
			"fingerprint": fingerprint,
			"serverName":  v.config.SNI,
			"show":        false,
			"password":    v.config.RealityPublicKey,
			"shortId":     v.config.RealityShortID,
		}
		streamSettings["realitySettings"] = realitySettings
	}

	config["outbounds"] = []map[string]interface{}{
		outbound,
		{
			"protocol": "freedom",
			"tag":      "direct",
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
	if v.done != nil {
		<-v.done
	}

	ctx := v.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := v.resolveAutomaticPin(ctx); err != nil {
		return err
	}
	binaryPath, err := findCore(v.config.BinaryPath, "xray", "v2ray")
	if err != nil {
		return err
	}
	v.coreLogf("[*] Using binary: %s\n", binaryPath)

	// Generate or use existing config
	var configPath string
	var generatedPath string
	handedOff := false
	defer func() {
		if !handedOff && generatedPath != "" {
			os.Remove(generatedPath)
		}
	}()
	if v.config.ConfigPath != "" {
		configPath = v.config.ConfigPath
		v.coreLogf("[*] Using config file: %s\n", configPath)
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
		generatedPath = configPath

		if _, err := tmpFile.Write([]byte(configJSON)); err != nil {
			tmpFile.Close()
			return fmt.Errorf("failed to write config: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			return fmt.Errorf("failed to close config: %w", err)
		}

		v.coreLogf("[*] Generated config: %s\n", configPath)

	}
	// Wait exactly once, so an exited process cannot look alive as a zombie.
	cmd := exec.Command(binaryPath, "run", "-c", configPath)
	output := v.output
	if output == nil {
		output = os.Stdout
	}
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start v2ray/xray: %w", err)
	}
	v.cmd = cmd
	v.done = make(chan struct{})
	v.exitErr = nil
	done := v.done
	v.running.Store(true)
	handedOff = true
	go func() {
		err := cmd.Wait()
		if generatedPath != "" {
			os.Remove(generatedPath)
		}
		v.exitErr = err
		v.running.Store(false)
		close(done)
	}()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
		return ctx.Err()
	case <-done:
		return v.startupExitError()
	case <-timer.C:
	}
	select {
	case <-done:
		return v.startupExitError()
	default:
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
		case <-done:
		}
	}()
	v.coreLogf("[+] V2Ray/Xray started (PID: %d)\n", cmd.Process.Pid)
	return nil
}

// startupExitError is called only after done closes, which publishes exitErr.
func (v *V2RayClient) startupExitError() error {
	if v.exitErr != nil {
		return fmt.Errorf("v2ray/xray exited during startup: %w", v.exitErr)
	}
	return fmt.Errorf("v2ray/xray exited during startup")
}

// Stop terminates the core and waits for its sole process waiter to finish.
func (v *V2RayClient) Stop() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.done == nil {
		return nil
	}
	if !v.running.Load() {
		<-v.done
		return nil
	}
	v.coreLogln("[*] Stopping V2Ray/Xray...")
	if err := v.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		_ = v.cmd.Process.Kill()
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-v.done:
	case <-timer.C:
		_ = v.cmd.Process.Kill()
		<-v.done
	}
	v.coreLogln("[+] V2Ray/Xray stopped")
	return nil
}

// IsRunning checks if V2Ray/Xray is running
func (v *V2RayClient) IsRunning() bool {
	return v.running.Load()
}

// testV2RayConnection distinguishes an unavailable IP service from a broken tunnel.
func (v *VPNClient) testV2RayConnection() {
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-v.ctx.Done():
		return
	}
	v.logln("\n[*] Checking HTTPS through the SOCKS proxy...")
	proxyURL := &url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", v.config.SOCKSPort)}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSHandshakeTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	for _, target := range []string{"https://ipinfo.io/ip", "https://example.com"} {
		req, err := http.NewRequestWithContext(v.ctx, http.MethodGet, target, nil)
		if err != nil {
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			if v.ctx.Err() != nil {
				return
			}
			v.logf("[!] Check %s failed: %v\n", target, err)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			v.logf("[!] Check %s returned HTTP %d (read error: %v)\n", target, resp.StatusCode, readErr)
			continue
		}
		if target == "https://ipinfo.io/ip" {
			ip := net.ParseIP(strings.TrimSpace(string(body)))
			if ip == nil {
				v.logln("[!] IP lookup returned an invalid address; checking another HTTPS site")
				continue
			}
			v.logf("[+] HTTPS through proxy verified. Exit IP: %s\n", ip)
		} else {
			v.logln("[+] HTTPS through proxy verified with example.com; the IP lookup check failed")
		}
		return
	}
	v.logln("[!] Neither HTTPS check succeeded. The local proxy is running, but upstream connectivity is unverified.")
}

func (v *V2RayClient) coreLogf(format string, args ...interface{}) {
	out := v.output
	if out == nil {
		out = os.Stdout
	}
	fmt.Fprintf(out, format, args...)
}
func (v *V2RayClient) coreLogln(args ...interface{}) {
	out := v.output
	if out == nil {
		out = os.Stdout
	}
	fmt.Fprintln(out, args...)
}
