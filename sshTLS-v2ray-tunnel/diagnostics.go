package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var diagnosticURL = regexp.MustCompile(`(?i)\b(?:https?|vmess|vless|trojan|socks5h?)://[^\s]+`)
var diagnosticAddress = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[a-fA-F0-9]{1,4}:){2,}[a-fA-F0-9:]*\b|\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b`)

func redactDiagnostics(text string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[redacted]")
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		text = strings.ReplaceAll(text, home, "[home]")
	}
	text = diagnosticURL.ReplaceAllString(text, "[url]")
	return diagnosticAddress.ReplaceAllString(text, "[address]")
}
func (m *controlManager) diagnostics() map[string]interface{} {
	if h := m.getHelper(); h != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		report, err := h.request(ctx, "/api/diagnostics", nil)
		if err == nil {
			return report
		}
		return map[string]interface{}{"error": "Privileged helper diagnostics are unavailable"}
	}
	status := m.status()
	m.mu.Lock()
	var secrets []string
	if m.client != nil {
		cfg := m.client.config
		secrets = []string{cfg.Password, cfg.Username, cfg.V2Ray.UUID, cfg.ProxyURL}
	}
	m.mu.Unlock()
	out := map[string]interface{}{"schemaVersion": 1, "generatedAt": time.Now().UTC(), "platform": runtime.GOOS + "/" + runtime.GOARCH, "goVersion": runtime.Version(), "state": status["state"], "health": sanitizedHealth(status["health"], secrets), "logs": redactDiagnostics(asDiagnosticString(status["logs"]), secrets...), "privacy": "Endpoints, URLs, home paths and known credentials are redacted. Review before sharing."}
	if runtime.GOOS == "linux" {
		routes := map[string]string{}
		for name, args := range map[string][]string{"interfaces": {"-j", "address", "show"}, "rules": {"-j", "rule", "show"}, "routes": {"-j", "route", "show", "table", "2022"}} {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			data, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
			cancel()
			if err != nil {
				routes[name] = "unavailable"
			} else {
				if len(data) > 8192 {
					data = data[:8192]
				}
				routes[name] = redactDiagnostics(string(data), secrets...)
			}
		}
		out["network"] = routes
	}
	return out
}
func asDiagnosticString(v interface{}) string { s, _ := v.(string); return s }

func sanitizedHealth(value interface{}, secrets []string) interface{} {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var data map[string]interface{}
	if json.Unmarshal(raw, &data) != nil {
		return nil
	}
	for k, v := range data {
		if s, ok := v.(string); ok {
			data[k] = redactDiagnostics(s, secrets...)
		}
	}
	return data
}
