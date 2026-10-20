# TunnelNest

![TunnelNest Safe Flight logo](desktop/assets/tunnelnest.png)

**TunnelNest** uses the selected **Safe Flight** identity: a folded home-shaped ribbon and forward arrow in sage green and charcoal. Branding notes are in [TunnelNest.md](../TunnelNest.md).

A desktop and command-line client for SSH over TLS, VMess, VLESS, Trojan, and manual Shadowsocks configurations. Desktop packages target Windows x64, Linux x64, and macOS Apple Silicon/Intel, with Xray and sing-box included.

## Desktop

Version 1.2.0 uses the Soft Workspace interface: warm white and lavender profile cards, search and protocol filters, a connection summary, and live logs inside the selected profile card. Create, edit, run, or delete profiles from the main screen. The profile editor includes custom keyboard-accessible dropdowns, TLS version selection, editable VMess transport fields, and SSH settings.

An absent SNI and Host leave the SNI input blank; the automatic TLS name is shown separately. Explicit SNI takes priority, followed by a VMess WebSocket Host, then the server address. Saved profiles preserve routing, binary paths, and TLS settings.

Extract a desktop archive and launch **Tunnel Desktop**. Paste a VMess/VLESS/Trojan share link, choose proxy or full-device VPN, then press **Connect**. For VMess TLS over WebSocket, a missing SNI falls back to the WebSocket Host before the provider address, matching NetMod exports. Explicit SNI always takes priority. Host, path, and effective SNI are shown in the interface. Missing fingerprint and ALPN settings are left unset.

Link imports preserve SNI, WebSocket host/path, gRPC service, fingerprint, ALPN, and VLESS REALITY parameters. Desktop profiles are stored locally in a per-user SQLite database with restrictive file permissions; profile arguments, including SSH passwords when saved, never leave the device.

The desktop window is an Electron shell with an embedded local interface. Node integration is disabled, renderer isolation/sandboxing is enabled, external navigation is blocked, and the loopback control API requires a random session token and validates Host/Origin. The connection activity panel includes core errors and verification events.

Full-device VPN requests system administrator authorization for a separate Go networking helper; the desktop renderer stays unprivileged. Windows uses UAC, macOS uses the system authorization dialog, and Linux requires `pkexec` plus a running PolicyKit authentication agent. Denying authorization leaves proxy mode available. Disconnect or quit the app to stop its core and TUN helper.

Builds are unsigned/unnotarized. Windows and Linux packages are cross-built, so platform runtime testing is still required before treating them as production releases.

## Automatic certificate pins

For a link with a different TLS SNI, certificate discovery is automatic:

```sh
./tunnel -mode xray -v2ray-link 'vmess://YOUR_LINK' -socks-port 1082 -pac-port 8080
```

There is no need to copy a certificate hash. With the default `-v2ray-cert-sha256 auto`, the client verifies a TLS connection against the **real server hostname** using the operating system's trusted roots, then pins that certificate for the alternate SNI connection. An observed, unverified certificate is never automatically trusted. If real-hostname verification fails, the connection is refused.

The certificate is checked again when the core restarts. `-v2ray-cert-sha256 none` uses ordinary SNI/hostname verification; a trusted 64-hex SHA-256 value can still be supplied manually. Custom core config files retain their own TLS settings. Xray's certificate pin support is documented at https://xtls.github.io/en/config/transports/tls.html.

## Full-device routing

```sh
# Run as Administrator/root, or use the desktop authorization prompt.
./tunnel -mode xray -v2ray-link 'vmess://YOUR_LINK' -socks-port 1082 -tun
```

`-auto-route` is now an alias for `-tun`. sing-box creates a virtual interface, enables automatic IPv4/IPv6 routes, and sends DNS through the local SOCKS tunnel. Server/upstream-proxy addresses are resolved before activation and excluded to prevent routing loops. Core dial addresses remain fixed during a connection session so reconnect does not require DNS through a stopped tunnel. Reconnect the profile to refresh upstream IP addresses.

TCP and UDP are available when supported by the chosen Xray protocol/server. SSH mode carries TCP and tunneled TCP DNS; other UDP traffic is explicitly rejected. This does not implement UDP-over-SSH. TUN process failure cancels the session. This is not a persistent OS kill switch: when the app/TUN stops, ordinary system routing resumes. Changes from TUN are managed by sing-box; live route installation/cleanup must be verified on each target OS. See https://sing-box.sagernet.org/configuration/inbound/tun/.

## SSH over TLS

SSH TLS certificate validation and SSH host-key verification are enabled. Supply either a trusted known_hosts file or an operator-provided SSH fingerprint:

```sh
./tunnel -mode ssh -H server.example.com -P 443 -u username -p 'password' \
  -S tls.example.com -ssh-host-key 'SHA256:TRUSTED_SSH_FINGERPRINT' \
  -socks-port 1082 -pac-port 8080
```

`-ssh-known-hosts` defaults to `~/.ssh/known_hosts`. Missing/unknown/changed host keys fail rather than being accepted. Use `-tls-ca ca.pem` for a private CA. Alternate TLS SNI uses the same verified automatic pin approach (`-ssh-cert-sha256 auto`); `none` uses ordinary SNI verification, and a trusted 64-hex TLS pin can be set explicitly. SSH fingerprints are not automatically trusted from the network.

### HTTP CONNECT and custom payloads

These transport options currently apply to SSH mode. The remote service must understand the specified HTTP CONNECT/payload protocol.

```sh
./tunnel -mode ssh -H server.example.com -P 443 -u username -p 'password' \
  -S server.example.com -ssh-host-key 'SHA256:TRUSTED_SSH_FINGERPRINT' \
  -proxy 'https://proxy.example.com:443' -payload-file payload.txt
```

HTTP and HTTPS proxy URLs support URL-encoded Basic credentials. HTTPS proxies are certificate-verified. `-payload-stage before-tls` (default) sends the custom CONNECT request before the SSH TLS handshake; `after-tls` sends the custom request inside TLS. When using an upstream proxy, its CONNECT negotiation still occurs before server TLS. CONNECT responses must be successful (2xx).

Example `payload.txt` (literal placeholders):

```text
CONNECT [host_port] [protocol][crlf]Host: [host][crlf][proxy_auth]Proxy-Connection: Keep-Alive[crlf][crlf]
```

Placeholders: `[host]`, `[port]`, `[host_port]`, `[protocol]`, `[crlf]`, `[cr]`, `[lf]`, `[ua]`, `[proxy_auth]`. `[split]` divides writes. The generated `[proxy_auth]` contains the complete Basic authorization header, or is empty. Header responses are bounded and buffered tunnel bytes are preserved. Payload files are limited to 64 KiB. Payloads are transport templates, not a general scripting engine.

## Proxy mode

Configure apps for SOCKS5 `127.0.0.1:1082` with remote DNS, or use `http://127.0.0.1:8080/proxy.pac` when PAC is enabled. PAC no longer falls back to a direct public connection when the proxy fails; local/private hosts retain their direct rule. No ad-blocking rules are injected. A second HTTPS check is used when IP lookup fails; a started process alone does not prove connectivity.

```sh
curl --socks5-hostname 127.0.0.1:1082 --max-time 20 https://ipinfo.io/ip
```

Use `curl.exe` in Windows PowerShell. Press Ctrl+C to stop command-line sessions. Occupied listener ports are rejected before launching a core. Both CLI and desktop stop/reconnect use cancellation, one process waiter, cleanup of temporary configs, and bounded restart backoff.

## Cores and builds

Go 1.25.3+ is required to build the engine. Desktop packaging uses Node 22.12+ and pinned npm dependencies. A package looks for cores in `cores/` beside the engine, then on PATH; explicit `-v2ray-binary` and `-tun-binary` paths are supported. Custom core files use `-v2ray-config` and must provide the expected local SOCKS listener.

```sh
go build -o tunnel .
go test -race ./...
go vet ./...
python3 scripts/fetch-cores.py
python3 scripts/build.py
npm ci --prefix desktop
npm --prefix desktop run package
python3 scripts/archive.py
```

The core-fetch script pins Xray v26.3.27 and sing-box v1.14.3 and verifies each archive against the SHA-256 digest in the official GitHub release metadata. A core manifest and original core licenses are included. Cores are unmodified; their source releases are https://github.com/XTLS/Xray-core/tree/v26.3.27 and https://github.com/SagerNet/sing-box/tree/v1.14.3.

For local development, build the engine into `dist/runtime/<platform>-<arch>/`, fetch cores, then run `npm start --prefix desktop`. `./tunnel -ui` also runs the same interface without the desktop shell and prints a local URL with a session token; keep that URL private.

Remaining validation limits: real Windows/Linux TUN behavior and native administrator prompts require testing on those operating systems. A local test cannot establish reliability of a third-party VMess account/server. No signing certificates, installers with auto-update, persistent kill switch, or UDP-over-SSH relay are included.

### Expired-certificate compatibility mode

For a server that works only with certificate verification disabled, select **Certificate verification → Compatibility · accept unverified server certificate**, then reconnect. This is opt-in; Automatic verification remains the default. The CLI equivalent is `-v2ray-cert-sha256 insecure`.

Compatibility mode fetches the certificate using your configured SNI without checking expiry, hostname, or CA trust, then passes its SHA-256 leaf pin to Xray. It keeps that pin in memory across core restarts until you disconnect; a new connection fetches a new pin. The initial certificate is unauthenticated and can be supplied by an impersonator. This does not establish the provider's identity or repair its expired certificate. Prefer a renewed certificate or a provider-verified manual pin. SSH verification is unchanged.

SSH profiles also support the explicit `-ssh-cert-sha256 insecure` compatibility setting for servers that expose an expired, self-signed, or mismatched TLS certificate. The secure default remains automatic verification; use compatibility mode only when you accept that the initial TLS certificate is unauthenticated.

## GitHub Actions releases

The repository-root `Tunnel Desktop Release` workflow builds each desktop package on its matching Windows, Linux, or macOS runner. Push a `v*` tag that matches `desktop/package.json` (for example, `v1.2.0`) to run tests, fetch checksum-verified cores, package desktop and CLI archives, and publish the release with a combined `SHA256SUMS.txt`. All four platform jobs must succeed before publication. A manual workflow run builds downloadable workflow artifacts without publishing a release.

Release notes live in `release-notes/<tag>.md`. Each platform archive includes its engine and networking cores. Interactive GUI startup and administrator-approved full-device routing still require platform testing.

## Profile sharing

Choose **Share** on a saved profile, then select **QR code**, **File**, or **Compact code**. A password is optional. Leaving it blank produces the shortest code; anyone holding that code, QR image, or file can import its credentials. When a password is provided, the profile is encrypted with AES-256-GCM using a scrypt-derived key and fresh salt/nonce. Send that password separately.

The version 2 format uses binary option IDs, removes nested VMess base64 before compression, and chooses raw or DEFLATE data according to which is smaller. An example SSH test profile uses 128 characters without a password, versus 183 with a password and 232 in the previous format. Real sizes vary with the settings. Fully offline codes carry the configuration itself; a six-character lookup code would require a separate hosting service.

- `TN2.` is compressed, **not encrypted**, and has a CRC32 checksum for accidental corruption. It does not authenticate the sender.
- `TN2P.` is password-protected and authenticated with AES-GCM.
- Existing password-protected `TN1.` codes still import.

QR codes can be scanned or saved as PNG images. Large profiles that exceed QR capacity must use File or Code. Profile files use the `.tnprofile` extension and contain the same compact code. Exports stay on the device; there are no third-party QR services.

To import, open **Import a shared profile**, paste the code or choose **Open file / QR**, enter a password only if protected, then select **Validate & save profile**. Imports validate settings, create a new SQLite profile, add a suffix for duplicate names, and never connect automatically. Invalid, oversized, damaged, unsupported, and unsafe settings are rejected before saving. Passwords used to protect exports are never stored with profiles or included in the code.

Device-specific executable paths are omitted. Profiles referencing local payload, CA, known_hosts, or custom core-config files must have those references removed before sharing because the files are not transferred.
