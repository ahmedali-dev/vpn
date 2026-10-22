//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Must be launched by scripts/test-linux-network.sh in a private network/mount namespace.
// The destination cannot be reached directly: only the fake SOCKS upstream can respond.
func TestLinuxFullDeviceCapture(t *testing.T) {
	if os.Getenv("TUNNEL_NAMESPACE_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("namespace test requires root")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observed := make(chan string, 32)
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go serveIntegrationSOCKS(c, observed)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	data, err := generateTUNConfig(Config{Mode: ModeSSH, SOCKSPort: port}, []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "tun.json")
	if err = os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Getenv("TUNNEL_TEST_CORE"), "run", "-c", file)
	logs := &logBuffer{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var processErr error
	go func() { processErr = cmd.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		})
	}
	defer stop()
	for i := 0; i < 100; i++ {
		if strings.Contains(logs.String(), "sing-box started") {
			break
		}
		select {
		case <-done:
			t.Fatalf("TUN startup failed: %v\n%s", processErr, logs.String())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	for _, host := range []string{"198.18.0.10", "2001:db8::10"} {
		target := net.JoinHostPort(host, "18080")
		resp, err := client.Get("http://" + target + "/capture")
		if err != nil {
			t.Fatalf("ordinary TCP did not traverse TUN: %v\n%s", err, logs.String())
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "captured-by-socks" {
			t.Fatal("unexpected direct response")
		}
		select {
		case got := <-observed:
			if got != target {
				t.Fatalf("wrong captured target %s", got)
			}
		case <-time.After(time.Second):
			t.Fatal("SOCKS upstream did not see TCP")
		}
	}
	// A normal UDP DNS request must be hijacked and carried over TCP through SOCKS.
	dns, err := net.DialTimeout("udp", "1.1.1.1:53", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	_ = dns.SetDeadline(time.Now().Add(5 * time.Second))
	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	if _, err = dns.Write(query); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, 512)
	n, err := dns.Read(answer)
	if err != nil || !bytes.Contains(answer[:n], []byte{198, 51, 100, 10}) {
		t.Fatalf("DNS did not traverse SOCKS: %v\n%s", err, logs.String())
	}
	select {
	case got := <-observed:
		if got != "1.1.1.1:53" {
			t.Fatal("DNS used wrong upstream")
		}
	case <-time.After(time.Second):
		t.Fatal("DNS upstream missing")
	}
	// SSH mode must reject general UDP instead of sending it directly.
	udp, err := net.DialTimeout("udp", "198.18.0.10:19090", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = udp.SetDeadline(time.Now().Add(250 * time.Millisecond))
	_, _ = udp.Write([]byte("blocked"))
	_, err = udp.Read(answer)
	udp.Close()
	if err == nil {
		t.Fatal("SSH unexpectedly carried general UDP")
	}
	stop()
	if err = exec.Command("ip", "link", "show", "tun0").Run(); err == nil {
		t.Fatal("TUN interface survived clean shutdown")
	}
}
func serveIntegrationSOCKS(c net.Conn, observed chan<- string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(c)
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}
	_, _ = c.Write([]byte{5, 0})
	req := make([]byte, 4)
	if _, err := io.ReadFull(reader, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(reader, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(reader, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		n, err := reader.ReadByte()
		if err != nil {
			return
		}
		b := make([]byte, int(n))
		if _, err = io.ReadFull(reader, b); err != nil {
			return
		}
		host = string(b)
	default:
		return
	}
	if _, err := io.ReadFull(reader, header); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(header)
	_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	observed <- net.JoinHostPort(host, strconv.Itoa(int(port)))
	if port == 53 {
		if _, err := io.ReadFull(reader, header); err != nil {
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(header)))
		if _, err := io.ReadFull(reader, query); err != nil {
			return
		}
		if len(query) < 12 {
			return
		}
		query[2] = 0x81
		query[3] = 0x80
		query[6] = 0
		query[7] = 1
		query = append(query, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 10)
		binary.BigEndian.PutUint16(header, uint16(len(query)))
		_, _ = c.Write(append(header, query...))
		return
	}
	if _, err := http.ReadRequest(reader); err != nil {
		return
	}
	body := "captured-by-socks"
	_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}
