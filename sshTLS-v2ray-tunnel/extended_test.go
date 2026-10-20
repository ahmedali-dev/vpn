package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLinkImportsIPv6EscapingAndTransport(t *testing.T) {
	c, err := parseV2RayLink("vless://test-id@[2001:db8::1]:443?type=ws&security=tls&sni=front.example.com&path=%2Fapi%3Fv%3D1&host=ws.example.com#remark")
	if err != nil {
		t.Fatal(err)
	}
	if c.Address != "2001:db8::1" || c.Path != "/api?v=1" || c.Host != "ws.example.com" {
		t.Fatalf("escaped/IPv6 import failed: %+v", c)
	}
	c, err = parseV2RayLink("trojan://p%40ss%3Aword@example.com:443")
	if err != nil || c.UUID != "p@ss:word" {
		t.Fatalf("encoded password failed: %v", err)
	}
	for _, link := range []string{"vless://id@example.com:bad", "vless://id@example.com:70000", "vless://id@:443", "vless://id@example.com:443?security=reality", "vmess://bad"} {
		if _, err := parseV2RayLink(link); err == nil {
			t.Errorf("accepted invalid link %s", link)
		}
	}
}
func TestAutomaticPinDefaultsAndTransportFields(t *testing.T) {
	raw := `{"add":"example.com","port":443,"id":"test-id","net":"ws","tls":"tls","sni":"front.example.com","fp":"firefox","alpn":"http/1.1","path":"/socket"}`
	cfg, err := parseConfig([]string{"-mode", "xray", "-v2ray-link", "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(raw))})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.V2Ray.AutoPin || cfg.V2Ray.Fingerprint != "firefox" || len(cfg.V2Ray.ALPN) != 1 {
		t.Fatal("automatic pin or transport fields lost")
	}
	generated, err := (&V2RayClient{config: cfg.V2Ray}).generateV2RayConfig(1082)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(generated, `"firefox"`) || !strings.Contains(generated, `"/socket"`) {
		t.Fatal("generated config lost import settings")
	}
}
func TestTUNConfigRoutesDNSAndExcludesUpstream(t *testing.T) {
	b, err := generateTUNConfig(Config{Mode: ModeXray, SOCKSPort: 1082}, []string{"192.0.2.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err = json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	inbound := cfg["inbounds"].([]interface{})[0].(map[string]interface{})
	if inbound["auto_route"] != true || inbound["strict_route"] != true {
		t.Fatal("TUN does not enable full-device routes")
	}
	if !strings.Contains(string(b), `"192.0.2.1/32"`) || !strings.Contains(string(b), `"hijack-dns"`) || !strings.Contains(string(b), `"detour": "proxy"`) {
		t.Fatal("DNS or upstream exclusions missing")
	}
	b, err = generateTUNConfig(Config{Mode: ModeSSH, SOCKSPort: 1082}, nil)
	if err != nil || !strings.Contains(string(b), `"reject"`) {
		t.Fatal("SSH UDP should be explicitly rejected")
	}
}
func TestControlRequiresTokenAndLocalHost(t *testing.T) {
	handler := controlHandler("127.0.0.1:12345", "secret", &controlManager{})
	for _, tc := range []struct {
		host, token, origin string
		want                int
	}{{"evil.example", "secret", "", 403}, {"127.0.0.1:12345", "wrong", "", 401}, {"127.0.0.1:12345", "secret", "https://evil.example", 403}, {"127.0.0.1:12345", "secret", "", 200}} {
		req := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/api/status", nil)
		req.Header.Set("X-Tunnel-Token", tc.token)
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != tc.want {
			t.Fatalf("got %d, want %d", response.Code, tc.want)
		}
	}
}

func TestBundledSingBoxAcceptsTUNConfig(t *testing.T) {
	path := "dist/runtime/" + runtime.GOOS + "-" + runtime.GOARCH + "/cores/sing-box"
	if runtime.GOOS == "darwin" && runtime.GOARCH == "amd64" {
		path = "dist/runtime/darwin-x64/cores/sing-box"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skip("bundled sing-box unavailable")
	}
	b, err := generateTUNConfig(Config{Mode: ModeXray, SOCKSPort: 1082}, []string{"192.0.2.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "tun.json")
	if err = os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(path, "check", "-c", file).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box schema check: %v\n%s", err, out)
	}
}

func TestNetModWebSocketHostFallsBackToSNI(t *testing.T) {
	obj := map[string]string{"add": "us-23.hihu.net", "aid": "0", "id": "00000000-0000-4000-8000-000000000001", "host": "web.whatsapp.com", "net": "ws", "path": "/wovfpasr", "port": "443", "tls": "tls", "type": "none", "v": "2"}
	for _, tc := range []struct{ explicit, host, network, want string }{
		{"", "web.whatsapp.com", "ws", "web.whatsapp.com"},
		{"explicit.example.com", "web.whatsapp.com", "ws", "explicit.example.com"},
		{"", "", "ws", "us-23.hihu.net"},
		{"", "web.whatsapp.com", "tcp", "us-23.hihu.net"},
		{"", "web.whatsapp.com:443", "ws", "web.whatsapp.com"},
	} {
		obj["sni"] = tc.explicit
		obj["host"] = tc.host
		obj["net"] = tc.network
		raw, _ := json.Marshal(obj)
		link := "vmess://" + base64.StdEncoding.EncodeToString(raw)
		cfg, err := parseConfig([]string{"-mode", "xray", "-v2ray-link", link})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.V2Ray.SNI != tc.want || cfg.V2Ray.Host != tc.host || cfg.V2Ray.Path != "/wovfpasr" || cfg.V2Ray.Address != "us-23.hihu.net" {
			t.Fatalf("wrong imported profile: %+v", cfg.V2Ray)
		}
		generated, err := (&V2RayClient{config: cfg.V2Ray}).generateV2RayConfig(1086)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Outbounds []struct {
				Settings       struct{ VNext []struct{ Address string } }
				StreamSettings struct {
					TLSSettings map[string]interface{}
					WSSettings  struct {
						Path    string
						Headers map[string]string
					}
				}
			}
		}
		if err = json.Unmarshal([]byte(generated), &doc); err != nil {
			t.Fatal(err)
		}
		outbound := doc.Outbounds[0]
		stream := outbound.StreamSettings
		if outbound.Settings.VNext[0].Address != "us-23.hihu.net" || stream.TLSSettings["serverName"] != tc.want {
			t.Fatal("outbound address or SNI changed")
		}
		if tc.network == "ws" && (stream.WSSettings.Path != "/wovfpasr" || stream.WSSettings.Headers["Host"] != tc.host && tc.host != "") {
			t.Fatal("WebSocket Host/path lost")
		}
		if _, ok := stream.TLSSettings["fingerprint"]; ok {
			t.Fatal("fingerprint inserted although link omitted it")
		}
		if _, ok := stream.TLSSettings["alpn"]; ok {
			t.Fatal("ALPN inserted although link omitted it")
		}
	}
}

func TestStatusIdentifiesActiveProfileWithoutCredentials(t *testing.T) {
	client := NewVPNClient(Config{Mode: ModeXray, V2Ray: V2RayConfig{Enabled: true, Address: "active.example.com", Port: 443, SNI: "front.example.com", UUID: "never-export-this-credential"}})
	defer client.cancel()
	client.running.Store(true)
	client.v2rayClient.running.Store(true)
	manager := &controlManager{client: client, done: make(chan struct{})}
	status := manager.status()
	connection := status["connection"].(map[string]string)
	if connection["server"] != "active.example.com:443" || connection["sni"] != "front.example.com" {
		t.Fatal("status lost active profile identity")
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "never-export-this-credential") {
		t.Fatal("status exposed profile credentials")
	}
}

func TestControlServesTunnelNestLogo(t *testing.T) {
	handler := controlHandler("127.0.0.1:12345", "secret", &controlManager{})
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:12345/tunnelnest-mark.png", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("logo status = %d", response.Code)
	}
	if response.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("logo content type = %s", response.Header().Get("Content-Type"))
	}
	if !strings.HasPrefix(response.Body.String(), "\x89PNG\r\n\x1a\n") {
		t.Fatal("logo response is not a PNG")
	}
	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:12345/desktop/assets/tunnelnest.png", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatal("non-public asset path exposed")
	}
}

func TestControlServesLocalQRDependencies(t *testing.T) {
	handler := controlHandler("127.0.0.1:12345", "secret", &controlManager{})
	for _, path := range []string{"/qrcode.js", "/qr-reader.js", "/share-qr.js"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:12345"+path, nil)
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "javascript") {
			t.Fatalf("QR dependency not served: %s", path)
		}
	}
}
