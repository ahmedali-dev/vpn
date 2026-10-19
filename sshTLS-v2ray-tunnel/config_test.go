package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"testing"
)

func TestCombinedModes(t *testing.T) {
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"example.com","port":"443","id":"test-id","net":"ws","tls":"tls","path":"/tunnel"}`))
	cases := []struct {
		name     string
		args     []string
		mode     TunnelMode
		protocol string
	}{
		{"ssh", []string{"-H", "example.com", "-P", "443", "-u", "user", "-p", "test-password", "-S", "example.com"}, ModeSSH, ""},
		{"vmess", []string{"-mode", "v2ray", "-v2ray-link", vmess, "-v2ray-binary", "/custom/xray"}, ModeV2Ray, "vmess"},
		{"vless", []string{"-mode", "xray", "-v2ray-link", "vless://test-id@example.com:443?security=tls"}, ModeXray, "vless"},
		{"trojan", []string{"-mode", "xray", "-v2ray-link", "trojan://test-password@example.com:443"}, ModeXray, "trojan"},
		{"manual", []string{"-mode", "v2ray", "-v2ray-protocol", "shadowsocks", "-v2ray-addr", "example.com", "-v2ray-port", "443", "-v2ray-uuid", "test-password"}, ModeV2Ray, "shadowsocks"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseConfig(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Mode != tc.mode || cfg.V2Ray.Protocol != tc.protocol {
				t.Fatalf("wrong mode or protocol: %s / %s", cfg.Mode, cfg.V2Ray.Protocol)
			}
			client := NewVPNClient(cfg)
			defer client.cancel()
			if cfg.Mode == ModeSSH {
				if client.v2rayClient != nil || cfg.SNIHostname != "example.com" {
					t.Fatal("SSH initialization lost")
				}
				return
			}
			if client.v2rayClient == nil || !cfg.V2Ray.Enabled {
				t.Fatal("missing V2Ray client")
			}
			if tc.name == "vmess" && cfg.V2Ray.BinaryPath != "/custom/xray" {
				t.Fatal("binary override was lost on import")
			}
			generated, err := client.v2rayClient.generateV2RayConfig(cfg.SOCKSPort)
			if err != nil {
				t.Fatal(err)
			}
			var output struct {
				Inbounds []struct {
					Listen string
					Port   int
				}
				Outbounds []struct {
					Protocol       string
					StreamSettings struct {
						Network     string
						Security    string
						TLSSettings struct{ ServerName string }
					}
				}
			}
			if err := json.Unmarshal([]byte(generated), &output); err != nil {
				t.Fatal(err)
			}
			if len(output.Inbounds) != 1 || output.Inbounds[0].Listen != "127.0.0.1" || output.Inbounds[0].Port != 1080 {
				t.Fatal("SOCKS listener changed")
			}
			outbound := output.Outbounds[0]
			if outbound.Protocol != tc.protocol || outbound.StreamSettings.Network == "" {
				t.Fatal("incomplete outbound")
			}
			if cfg.V2Ray.Security == "tls" && outbound.StreamSettings.TLSSettings.ServerName != "example.com" {
				t.Fatal("SNI fallback missing")
			}
		})
	}
}

func TestConfigFileWithoutServerFlags(t *testing.T) {
	cfg, err := parseConfig([]string{"-mode", "xray", "-v2ray-config", "custom.json", "-v2ray-binary", "/custom/xray"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.V2Ray.Enabled || cfg.V2Ray.ConfigPath != "custom.json" || cfg.V2Ray.BinaryPath != "/custom/xray" {
		t.Fatal("config file overrides lost")
	}
}

func TestInvalidConfiguration(t *testing.T) {
	ssh := []string{"-H", "example.com", "-P", "443", "-u", "user", "-p", "test-password"}
	cases := [][]string{
		{"-mode", "unknown"},
		{"-mode", "ssh"},
		{"-mode", "v2ray"},
		{"-mode", "v2ray", "-v2ray-link", "not-a-link"},
		{"-mode", "xray", "-v2ray-config", "custom.json", "-auto-route"},
		{"-mode", "xray", "-v2ray-config", "custom.json", "-v2ray-link", "trojan://password@example.com:443"},
	}
	for _, extra := range [][]string{{"-socks-port", "0"}, {"-P", "65536"}, {"-pac-port", "-1"}, {"-pac-port", "1080"}, {"-max-conns", "0"}, {"unexpected"}} {
		cases = append(cases, append(append([]string{}, ssh...), extra...))
	}
	for _, args := range cases {
		if _, err := parseConfig(args); err == nil {
			t.Errorf("expected rejection for %v", args)
		}
	}
}

func TestHelp(t *testing.T) {
	if _, err := parseConfig([]string{"-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help returned %v", err)
	}
}

func TestImportedSNIOverride(t *testing.T) {
	for _, linkSNI := range []string{"", "original.example.com"} {
		payload, err := json.Marshal(map[string]string{"add": "node-uk.connectsuite.org", "port": "2053", "id": "test-id", "net": "tcp", "tls": "tls", "sni": linkSNI})
		if err != nil {
			t.Fatal(err)
		}
		link := "vmess://" + base64.StdEncoding.EncodeToString(payload)
		cfg, err := parseConfig([]string{"-mode", "v2ray", "-v2ray-link", link, "-v2ray-sni", "web.whatsapp.com"})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.V2Ray.SNI != "web.whatsapp.com" || cfg.V2Ray.Address != "node-uk.connectsuite.org" {
			t.Fatal("override changed address or lost SNI")
		}
		core := &V2RayClient{config: cfg.V2Ray}
		generated, err := core.generateV2RayConfig(cfg.SOCKSPort)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Outbounds []struct {
				StreamSettings struct{ TLSSettings struct{ ServerName string } }
			}
		}
		if err := json.Unmarshal([]byte(generated), &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Outbounds[0].StreamSettings.TLSSettings.ServerName != "web.whatsapp.com" {
			t.Fatal("generated TLS config ignored override")
		}
	}
}

func TestPinnedSNIConfiguration(t *testing.T) {
	const pin = "c4879a97111039561dab0c5333ae603577850934edcbaa785d8d26803c19338a"
	args := []string{"-mode", "xray", "-v2ray-protocol", "vmess", "-v2ray-addr", "node-uk.connectsuite.org", "-v2ray-port", "2053", "-v2ray-uuid", "test-id", "-v2ray-security", "tls", "-v2ray-sni", "web.whatsapp.com", "-v2ray-cert-sha256", pin}
	cfg, err := parseConfig(args)
	if err != nil {
		t.Fatal(err)
	}
	core := &V2RayClient{config: cfg.V2Ray}
	generated, err := core.generateV2RayConfig(cfg.SOCKSPort)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Outbounds []struct {
			StreamSettings struct {
				TLSSettings struct {
					ServerName           string
					PinnedPeerCertSha256 string
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(generated), &doc); err != nil {
		t.Fatal(err)
	}
	tls := doc.Outbounds[0].StreamSettings.TLSSettings
	if tls.ServerName != "web.whatsapp.com" || tls.PinnedPeerCertSha256 != pin {
		t.Fatal("pin or SNI lost")
	}
	for _, bad := range []string{"invalid", "aa", pin + "00"} {
		invalid := append([]string{}, args...)
		invalid[len(invalid)-1] = bad
		if _, err := parseConfig(invalid); err == nil {
			t.Errorf("accepted invalid pin %q", bad)
		}
	}
}

func TestVMessEmptyAndCustomWebSocketHost(t *testing.T) {
	for _, tc := range []struct{ name, raw, address, host, path string }{
		{"empty host", `{"type":"none","path":"/vpnjantit","host":"","net":"ws","port":"8080","add":"fr2.vpnjantit.com","ps":"sda322-vpnjantit.com","tls":"tls","aid":"0","v":"2","id":"a8ca35ba-cbc4-11f1-91a9-73f996bef7a7"}`, "fr2.vpnjantit.com", "", "/vpnjantit"},
		{"custom host", `{"add":"us-23.hihu.net","aid":"0","id":"a656b300-cb28-11f1-b030-205c6d5f5d78","host":"web.whatsapp.com","net":"ws","path":"/wovfpasr","port":"443","tls":"tls","type":"none","v":"2"}`, "us-23.hihu.net", "web.whatsapp.com", "/wovfpasr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseV2RayLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(tc.raw)))
			if err != nil {
				t.Fatal(err)
			}
			wantSNI := tc.host
			if wantSNI == "" {
				wantSNI = tc.address
			}
			if cfg.Address != tc.address || cfg.Host != tc.host || cfg.SNI != wantSNI {
				t.Fatalf("incorrect import: %+v", cfg)
			}
			generated, err := (&V2RayClient{config: cfg}).generateV2RayConfig(10808)
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Outbounds []struct {
					StreamSettings struct {
						TLSSettings struct{ ServerName string }
						WSSettings  map[string]interface{}
					}
				}
			}
			if err := json.Unmarshal([]byte(generated), &doc); err != nil {
				t.Fatal(err)
			}
			stream := doc.Outbounds[0].StreamSettings
			if stream.TLSSettings.ServerName != wantSNI || stream.WSSettings["path"] != tc.path {
				t.Fatal("incorrect TLS name or WS path")
			}
			headers, hasHeaders := stream.WSSettings["headers"].(map[string]interface{})
			if tc.host == "" && hasHeaders {
				t.Fatal("empty Host must not inject WebSocket headers")
			}
			if tc.host != "" && (!hasHeaders || headers["Host"] != tc.host) {
				t.Fatal("WebSocket Host was lost")
			}
		})
	}
}
