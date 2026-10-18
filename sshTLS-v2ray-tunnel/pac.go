package main

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// PAC Server
func (v *VPNClient) startPACServer() error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", v.pacServer.port))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy.pac", v.handlePAC)
	mux.HandleFunc("/", v.handlePACInfo)
	v.pacServer.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = v.pacServer.server.Serve(listener) }()
	return nil
}

func (v *VPNClient) handlePAC(w http.ResponseWriter, r *http.Request) {
	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (isPlainHostName(host) || shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }
    return "SOCKS5 127.0.0.1:%d";
}`, v.pacServer.socksPort)

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Write([]byte(pac))
}

func (v *VPNClient) handlePACInfo(w http.ResponseWriter, r *http.Request) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>VPN Proxy</title><style>
body{font-family:Arial;max-width:800px;margin:50px auto;padding:20px}
.info{background:#e3f2fd;padding:20px;border-radius:5px;margin:20px 0}
h1{color:#1976d2}code{background:#f5f5f5;padding:2px 6px;border-radius:3px}
</style></head><body>
<h1>🚀 VPN Proxy Active</h1>
<div class="info">
<p>Mode: <code>%s</code></p>
<p>SOCKS5: <code>127.0.0.1:%d</code></p>
<p>PAC: <code>http://127.0.0.1:%d/proxy.pac</code></p>
</div></body></html>`, v.config.Mode, v.pacServer.socksPort, v.pacServer.port)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}
