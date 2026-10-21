package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func findCore(explicit string, names ...string) (string, error) {
	if explicit != "" {
		return filepath.Abs(explicit)
	}
	exe, _ := os.Executable()
	for _, name := range names {
		filename := name
		if runtime.GOOS == "windows" {
			filename += ".exe"
		}
		for _, dir := range []string{filepath.Join(filepath.Dir(exe), "cores"), filepath.Dir(exe)} {
			path := filepath.Join(dir, filename)
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				return path, nil
			}
		}
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("required core %s was not found; put it in cores/ beside tunnel or specify its binary path", strings.Join(names, "/"))
}

type tunProcess struct {
	mu   sync.Mutex
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func (t *tunProcess) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done == nil {
		return
	}
	select {
	case <-t.done:
		return
	default:
	}
	if err := t.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		_ = t.cmd.Process.Kill()
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-t.done:
	case <-timer.C:
		_ = t.cmd.Process.Kill()
		<-t.done
	}
}

func generateTUNConfig(cfg Config, excluded []string) ([]byte, error) {
	outbound := map[string]interface{}{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": cfg.SOCKSPort, "version": "5"}
	rules := []map[string]interface{}{{"port": 53, "action": "hijack-dns"}}
	if cfg.Mode == ModeSSH {
		outbound["network"] = "tcp"
		rules = append(rules, map[string]interface{}{"network": "udp", "action": "reject"})
	}
	return json.MarshalIndent(map[string]interface{}{
		"log":       map[string]interface{}{"level": "info", "timestamp": true},
		"inbounds":  []map[string]interface{}{{"type": "tun", "tag": "device", "address": []string{"172.30.111.1/30", "fdfe:dcba:9876::1/126"}, "mtu": 1500, "auto_route": true, "strict_route": true, "route_exclude_address": excluded}},
		"outbounds": []map[string]interface{}{outbound},
		"dns":       map[string]interface{}{"servers": []map[string]interface{}{{"type": "tcp", "tag": "tunnel-dns", "server": "1.1.1.1", "detour": "proxy"}}, "final": "tunnel-dns", "strategy": "prefer_ipv4"},
		"route":     map[string]interface{}{"auto_detect_interface": true, "rules": rules, "final": "proxy"},
	}, "", "  ")
}

// Resolve before TUN activation and fix the core's dial address. Otherwise DNS
// resolution during reconnect could recursively depend on the stopped core.
func (v *VPNClient) prepareTUN() (excluded []string, err error) {
	host := v.config.Host
	if v.config.Mode != ModeSSH {
		host = v.config.V2Ray.Address
	}
	ips, err := net.DefaultResolver.LookupIPAddr(v.ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve TUN upstream: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no upstream addresses")
	}
	selected := ips[0].IP.String()
	for _, ip := range ips {
		bits := 128
		if ip.IP.To4() != nil {
			bits = 32
			selected = ip.IP.String()
		}
		excluded = append(excluded, ip.IP.String()+"/"+strconv.Itoa(bits))
	}
	v.config.DialAddress = selected
	if v.v2rayClient != nil {
		v.v2rayClient.config.DialAddress = selected
	}
	if v.config.ProxyURL != "" {
		proxy, _ := parseProxyURL(v.config.ProxyURL)
		ips, err = net.DefaultResolver.LookupIPAddr(v.ctx, proxy.Hostname())
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no proxy addresses")
		}
		v.config.ProxyDialAddress = ips[0].IP.String()
		for _, ip := range ips {
			bits := 128
			if ip.IP.To4() != nil {
				bits = 32
				v.config.ProxyDialAddress = ip.IP.String()
			}
			excluded = append(excluded, ip.IP.String()+"/"+strconv.Itoa(bits))
		}
	}
	return excluded, nil
}

func (v *VPNClient) startTUN(excluded []string) error {
	binary, err := findCore(v.config.TUNBinary, "sing-box")
	if err != nil {
		return err
	}
	v.logf("[*] TUN helper: %s (engine platform: %s/%s)\n", binary, runtime.GOOS, runtime.GOARCH)
	b, err := generateTUNConfig(v.config, excluded)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "tunnel-tun-*.json")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	// The check command validates schema without touching routes or interfaces.
	check := exec.CommandContext(v.ctx, binary, "check", "-c", path)
	if out, err := check.CombinedOutput(); err != nil {
		if strings.Contains(string(out), "qemu-") || strings.Contains(string(out), "ld-linux-") {
			return fmt.Errorf("TUN helper %q could not run on %s/%s: install a native sing-box build for this Linux machine and set -tun-binary to its absolute path; check uname -m and file on the helper. No TUN routes were enabled. Original error: %w: %s", binary, runtime.GOOS, runtime.GOARCH, err, out)
		}
		return fmt.Errorf("TUN config validation failed: %w: %s", err, out)
	}
	cmd := exec.Command(binary, "run", "-c", path)
	output := v.config.Output
	if output == nil {
		output = os.Stdout
	}
	cmd.Stdout = output
	cmd.Stderr = output
	if err = cmd.Start(); err != nil {
		return err
	}
	t := &tunProcess{cmd: cmd, done: make(chan struct{})}
	v.tunProcess = t
	// Keep the generated file until the process has read it and started.
	go func() { t.err = cmd.Wait(); close(t.done) }()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-t.done:
		return fmt.Errorf("TUN exited during startup: %v", t.err)
	case <-v.ctx.Done():
		t.Stop()
		return v.ctx.Err()
	case <-timer.C:
	}
	go func() {
		select {
		case <-v.ctx.Done():
		case <-t.done:
			fmt.Fprintf(output, "[!] TUN stopped: %v; stopping tunnel\n", t.err)
			v.cancel()
		}
	}()
	fmt.Fprintln(output, "[+] Full-device TUN started; DNS is sent through the tunnel")
	return nil
}
