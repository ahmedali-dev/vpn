package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

//go:embed desktop/ui/*
var uiFiles embed.FS

type logBuffer struct {
	mu   sync.Mutex
	data string
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data += string(p)
	if len(b.data) > 65536 {
		b.data = b.data[len(b.data)-65536:]
	}
	return len(p), nil
}
func (b *logBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.data }

type controlManager struct {
	shutdown  context.CancelFunc
	mu        sync.Mutex
	client    *VPNClient
	done      chan struct{}
	lastError string
	logs      *logBuffer
	profiles  *profileStore
}

func (m *controlManager) start(args []string) error {
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	if cfg.UI {
		return fmt.Errorf("nested control servers are not allowed")
	}
	if cfg.TUN && !isAdmin() {
		return fmt.Errorf("restart the desktop app as Administrator/root to enable full-device TUN")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done != nil {
		select {
		case <-m.done:
		default:
			return fmt.Errorf("a connection is already active; disconnect first")
		}
	}
	m.logs = &logBuffer{}
	cfg.Output = m.logs
	m.client = NewVPNClient(cfg)
	m.done = make(chan struct{})
	m.lastError = ""
	client, done := m.client, m.done
	go func() {
		err := client.Start()
		m.mu.Lock()
		defer m.mu.Unlock()
		if err != nil && err != context.Canceled {
			m.lastError = err.Error()
			fmt.Fprintln(m.logs, "[!]", err)
		}
		close(done)
	}()
	return nil
}
func (m *controlManager) stop() error {
	m.mu.Lock()
	client, done := m.client, m.done
	m.mu.Unlock()
	if client == nil || done == nil {
		return nil
	}
	client.Cancel()
	select {
	case <-done:
		return nil
	case <-time.After(20 * time.Second):
		return fmt.Errorf("connection is still shutting down")
	}
}
func (m *controlManager) status() map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := "disconnected"
	logs := ""
	if m.logs != nil {
		logs = m.logs.String()
	}
	if m.done != nil {
		select {
		case <-m.done:
			if m.lastError != "" {
				state = "error"
			}
		default:
			state = "connecting"
			if m.client.running.Load() {
				state = "connected"
				if m.client.v2rayClient != nil && !m.client.v2rayClient.IsRunning() {
					state = "reconnecting"
				}
			}
			if m.client.ctx.Err() != nil {
				state = "stopping"
			}
		}
	}
	result := map[string]interface{}{"state": state, "error": m.lastError, "logs": logs, "administrator": isAdmin()}
	if m.client != nil {
		server := net.JoinHostPort(m.client.config.Host, strconv.Itoa(m.client.config.Port))
		sni := m.client.config.SNIHostname
		if m.client.config.Mode != ModeSSH {
			server = net.JoinHostPort(m.client.config.V2Ray.Address, strconv.Itoa(m.client.config.V2Ray.Port))
			sni = m.client.config.V2Ray.SNI
		}
		result["connection"] = map[string]string{"server": server, "sni": sni, "mode": string(m.client.config.Mode)}
	}
	return result
}
func readJSON(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		return fmt.Errorf("expected one JSON value")
	}
	return nil
}
func controlHandler(host, token string, manager *controlManager) http.Handler {
	files, _ := fs.Sub(uiFiles, "desktop/ui")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Tunnel-Token")), []byte(token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+host {
			http.Error(w, "invalid origin", 403)
			return
		}
		var result interface{} = map[string]bool{"ok": true}
		var err error
		switch r.URL.Path {
		case "/api/status":
			if r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			result = manager.status()
		case "/api/start":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			var req struct {
				Args []string `json:"args"`
			}
			err = readJSON(w, r, &req)
			if err == nil {
				err = manager.start(req.Args)
			}
		case "/api/stop":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			err = manager.stop()
		case "/api/quit":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			err = manager.stop()
			if err == nil && manager.shutdown != nil {
				defer manager.shutdown()
			}
		case "/api/import":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			var req struct {
				Link string `json:"link"`
			}
			err = readJSON(w, r, &req)
			if err == nil {
				result, err = parseV2RayLink(req.Link)
			}
		case "/api/profiles":
			if r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			result, err = manager.profiles.list()
		case "/api/profiles/save":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			var req savedProfile
			err = readJSON(w, r, &req)
			if err == nil {
				result, err = manager.profiles.save(req)
			}
		case "/api/profiles/delete":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			var req struct {
				ID int64 `json:"id"`
			}
			err = readJSON(w, r, &req)
			if err == nil {
				err = manager.profiles.delete(req.ID)
			}
		default:
			w.WriteHeader(404)
			return
		}
		if err != nil {
			w.WriteHeader(400)
			result = map[string]string{"error": err.Error()}
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	assets := http.FileServer(http.FS(files))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/app.js" && r.URL.Path != "/style.css" {
			http.NotFound(w, r)
			return
		}
		assets.ServeHTTP(w, r)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host {
			http.Error(w, "invalid host", 403)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		mux.ServeHTTP(w, r)
	})
}
func serveControl(ctx context.Context, port int, readyFile string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return err
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		listener.Close()
		return err
	}
	token := hex.EncodeToString(random)
	host := listener.Addr().String()
	manager := &controlManager{shutdown: cancel}
	manager.profiles, err = openProfileStore()
	if err != nil {
		listener.Close()
		return err
	}
	defer manager.profiles.close()
	server := &http.Server{Handler: controlHandler(host, token, manager), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	address := fmt.Sprintf("http://%s/#%s", host, token)
	if readyFile != "" {
		if err := os.WriteFile(readyFile, []byte(address), 0600); err != nil {
			listener.Close()
			return err
		}
		defer os.Remove(readyFile)
	}
	fmt.Printf("CONTROL_URL=%s\n", address)
	go func() {
		<-ctx.Done()
		_ = manager.stop()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
