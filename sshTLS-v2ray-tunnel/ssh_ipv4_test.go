package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSSHIPv4CompatibilityIsScopedAndPortable(t *testing.T) {
	cfg, err := parseConfig([]string{"-H", "example.com", "-P", "443", "-u", "user", "-p", "test", "-ssh-ipv4-only"})
	if err != nil || !cfg.SSHIPv4Only {
		t.Fatalf("flag: %v", err)
	}
	for _, mode := range []TunnelMode{ModeSSH, ModeXray} {
		data, err := generateTUNConfig(Config{Mode: mode, SSHIPv4Only: true, SOCKSPort: 1082}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			DNS struct {
				Strategy string `json:"strategy"`
			}
			Inbounds []struct {
				Address []string `json:"address"`
			}
		}
		if err = json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
		expected := "prefer_ipv4"
		if mode == ModeSSH {
			expected = "ipv4_only"
		}
		if result.DNS.Strategy != expected || len(result.Inbounds[0].Address) != 2 {
			t.Fatal("DNS compatibility changed another mode or removed IPv6 capture")
		}
	}
	p := testShareProfile()
	p.Args = append(p.Args, "-ssh-ipv4-only")
	code, err := encodeProfileShare(p, "")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeProfileShare(code, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, arg := range decoded.Args {
		if arg == "-ssh-ipv4-only" {
			found = true
		}
	}
	if !found {
		t.Fatal("sharing lost compatibility flag")
	}
	client := NewVPNClient(cfg)
	defer client.cancel()
	if _, err = client.dialThroughSSH("[2001:db8::1]:443"); err == nil {
		t.Fatal("IPv6 should fail before contacting SSH")
	}
}

// Exercise the production DNS policy without TUN or administrator privileges.
func TestBundledSSHIPv4DNSFiltersAAAA(t *testing.T) {
	if os.Getenv("TUNNEL_VERIFY_BUNDLED_CORES") != "1" {
		t.Skip("requires bundled sing-box")
	}
	arch := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	platform := runtime.GOOS
	if platform == "windows" {
		platform = "win32"
	}
	name := "sing-box"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	core, err := filepath.Abs(filepath.Join("dist/runtime", platform+"-"+arch, "cores", name))
	if err != nil {
		t.Fatal(err)
	}
	// The fake resolver returns an IPv6 answer if queried; IPv4-only mode must filter it.
	resolver, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	go func() {
		for {
			c, e := resolver.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				h := make([]byte, 2)
				if _, e := io.ReadFull(c, h); e != nil {
					return
				}
				q := make([]byte, int(binary.BigEndian.Uint16(h)))
				if _, e := io.ReadFull(c, q); e != nil || len(q) < 16 {
					return
				}
				qt := binary.BigEndian.Uint16(q[len(q)-4:])
				q[2] = 0x81
				q[3] = 0x80
				q[7] = 1
				answer := []byte{198, 51, 100, 10}
				if qt == 28 {
					answer = net.ParseIP("2001:db8::10").To16()
				}
				q = append(q, 0xc0, 0x0c, byte(qt>>8), byte(qt), 0, 1, 0, 0, 0, 60, 0, byte(len(answer)))
				q = append(q, answer...)
				binary.BigEndian.PutUint16(h, uint16(len(q)))
				c.Write(append(h, q...))
			}()
		}
	}()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	udp.Close()
	data, _ := generateTUNConfig(Config{Mode: ModeSSH, SSHIPv4Only: true, SOCKSPort: 1082}, nil)
	var config map[string]interface{}
	json.Unmarshal(data, &config)
	config["inbounds"] = []interface{}{map[string]interface{}{"type": "direct", "listen": "127.0.0.1", "listen_port": port, "network": "udp", "override_address": "1.1.1.1", "override_port": 53}}
	config["route"] = map[string]interface{}{"rules": []interface{}{map[string]interface{}{"action": "hijack-dns"}}}
	config["outbounds"] = []interface{}{map[string]interface{}{"type": "direct", "tag": "direct"}}
	dns := config["dns"].(map[string]interface{})
	dns["servers"] = []interface{}{map[string]interface{}{"type": "tcp", "tag": "tunnel-dns", "server": "127.0.0.1", "server_port": resolver.Addr().(*net.TCPAddr).Port}}
	data, _ = json.Marshal(config)
	file := filepath.Join(t.TempDir(), "dns.json")
	os.WriteFile(file, data, 0600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "run", "-c", file)
	logs := &logBuffer{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	for i := 0; i < 100; i++ {
		if strings.Contains(logs.String(), "sing-box started") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	for _, qtype := range []byte{1, 28} {
		query := []byte{0x12, qtype, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, qtype, 0, 1}
		conn.Write(query)
		answer := make([]byte, 512)
		n, err := conn.Read(answer)
		if err != nil || n < 12 {
			t.Fatalf("DNS query %d failed: %v %s", qtype, err, logs.String())
		}
		if answer[3]&15 != 0 {
			t.Fatalf("DNS response code for type %d: %d", qtype, answer[3]&15)
		}
		count := binary.BigEndian.Uint16(answer[6:8])
		if (qtype == 1 && count != 1) || (qtype == 28 && count != 0) {
			t.Fatalf("unexpected DNS answer count for type %d: %d", qtype, count)
		}
	}
}
