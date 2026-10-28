# Connection recovery and stability

SSH+TLS and Xray/V2Ray share the same recovery controller in proxy and full-device modes.

- Each attempt refreshes upstream/proxy DNS, discovers the TLS certificate when required, then starts and verifies the transport. Discovery has a 45-second overall deadline. The session certificate pin and SSH first-use key remain fixed across retries.
- Transient failures retry with exponential delays of approximately 2, 4, 8, 16 and 30 seconds (20% jitter, capped at 30 seconds). Six consecutive failures stop the session. At least 60 seconds of connected service restores the failure budget; time spent connecting or cleaning up does not count.
- Rejected SSH/proxy credentials, changed or untrusted certificates/SSH keys, missing cores, invalid TUN configuration and permanent local I/O errors stop retries. Transport timeouts and connection loss remain retryable. External cores do not expose typed remote authentication failures; their generic startup exits remain bounded by the retry budget.
- Startup still requires a successful HTTPS check. Running sessions probe every 30 seconds, marking health degraded on a failed cycle and restarting after three consecutive failed cycles. A successful cycle clears the failure count. In TUN mode both proxy and system routes are checked.
- Only one probe cycle runs at a time. Core/SSH liveness checks continue every second during slow probes. Cancellation aborts and joins probe tasks before networking cleanup.

Saved session logs contain stage durations, attempt durations, connected time, retry delays and recovery timing. Authenticated status and diagnostics exports include bounded recovery metadata and the last failure, with credentials redacted. Existing logging file rotation and retention apply.

## Steps 4–7

- Physical network observations run every five seconds. Linux observes main-table gateways and addresses on their interfaces; Windows observes active gateway adapters; macOS observes the default gateway/interface. Two consecutive changed observations trigger recovery, avoiding a restart for a single inconsistent snapshot. Changing TUN addresses and expiring address lifetimes do not count as physical network changes.
- A wall-clock gap longer than twenty seconds triggers wake recovery. Upstream/proxy DNS address sets are checked every minute. A complete address-set replacement triggers recovery; overlapping round-robin pools do not repeatedly restart a healthy transport. These are read-only observations: no direct Internet bypass probes are sent, and routes are never modified by the watcher.
- Network changes cancel the active attempt through its normal cleanup path. Recovery waits while no physical gateway is available, refreshes DNS/exclusions after cleanup, and preserves TLS pins and session-trusted SSH identity. A permanent trust/authentication error takes precedence over a simultaneous network event. Linux requires `ip` (iproute2/iproute), included in native package dependencies. Inspection failures log a warning and retain the existing transport/health recovery policy.
- SSH timing is configurable without changing existing defaults. TCP sockets use TCP_NODELAY. Overloaded SOCKS connections are refused with an explicit log rather than silently disappearing; a rejected or timed-out forwarding channel affects that client connection rather than restarting the shared SSH transport.
- Core configurations are preflighted with `run -test -config` (Xray), `test -c` (V2Ray 5), legacy `-test -config` (V2Ray 4) or `check -c` (sing-box). Rejected configurations stop retries. Runtime core exits remain retryable and record PID, exit status and uptime; stdout/stderr continue into the saved redacted session log.
- Core and TUN readiness are bounded by a configurable deadline. Readiness work does not block child-exit checks or cancellation. TUN readiness requires its configured IPv4 address to appear and a system IPv4 exit matching the SOCKS exit. TUN health checks compare fresh proxy/system exits each cycle. This comparison uses api4.ipify.org with a Cloudflare IPv4 trace fallback and must succeed before reporting verified full-device routing; if both services are unavailable, routing remains unverified. IPv6 and DNS leak checks remain separate platform tests.
- TUN cleanup waits briefly for its address to disappear and exports `recovery.tunCleanupVerified`. Failed cleanup verification stops automatic route reinstallation. A preexisting TUN address is rejected. This does not prove every OS firewall/policy rule was removed; compare before/after snapshots on each target OS. The app does not delete arbitrary system routes.

### Advanced CLI/profile options

These value options are accepted in CLI arguments and shared profiles, and preserved by the profile editor:

- `-ssh-connect-timeout 45`: transport setup seconds, range 5–300.
- `-ssh-handshake-timeout 30`: SSH key exchange and authentication seconds, range 5–300 per exchange.
- `-ssh-channel-timeout 30`: forwarding-channel open seconds, range 1–300.
- `-ssh-keepalive-interval 15`: seconds, range 0–300; zero disables keepalives.
- `-ssh-keepalive-max 3`: missed keepalive limit, range 1–10.
- `-ssh-inactivity-timeout 90`: seconds, range 0–3600; zero disables it. Nonzero values must exceed the configured keepalive window.
- `-tun-mtu 1500`: range 1280–9000. Try 1400 or 1280 only when testing demonstrates a path-MTU problem.
- `-startup-timeout 30`: core/TUN readiness seconds, range 5–180. This is separate from the transport and core schema-validation deadlines.

The TLS handshake retains its existing thirty-second deadline; TLS discovery retains its forty-five-second overall deadline. SSH remains TCP-only, with unsupported general UDP explicitly rejected by TUN/SOCKS policy.

## Step 8: validation

Automated tests cover network change debouncing, DNS rotation, preservation of identity checks, readiness delays/timeouts/cancellation, child crashes during pending probes, rejected core configurations, MTU/routing policy generation, profile option validation, and soak report calculations. Core schema/DNS tests use bundled binaries when available.

Live acceptance tests must run on Windows x64, Ubuntu 24.04 x64, Fedora 44 x64, and Arch x64. Test each of SSH proxy, SSH full-device, Xray proxy and Xray full-device. Live Windows/Linux routing and eight-hour runs have not been performed by adding the harness. Use [vpn-stability-testing.md](vpn-stability-testing.md) for the exact procedure. Endpoint failover is outside this change.

## WebSocket/UDP stream diagnostics and rolling helper logs

Helper snapshots now include a session identifier and absolute log byte cursors. Polling appends only unseen bytes, ignores stale responses from retired sessions, and reports gaps when the helper produces more data than its live buffer can retain. Older helpers use exact suffix/prefix overlap detection, including Unicode and rolling buffers. Saved session files retain the existing rotation and redaction rules.

Core WebSocket abnormal closures, connection resets, timeouts, UDP closed pipes and local client broken pipes have separate bounded counters in authenticated status/diagnostics (`transportErrors`). Three upstream stream errors within fifteen seconds request an early connectivity check, at most once every thirty seconds. Secondary local/UDP pipe errors do not independently trigger checks. A healthy check keeps the current transport alive; the dashboard still shows recent stream failures rather than hiding them behind a successful general health check. Established application streams cannot be replayed safely after a remote reset.

The profile editor's **Prefer TCP for web traffic** option (`-block-quic`) blocks only UDP destination port 443 in generated Xray and TUN policies. It is off by default. This can encourage browsers to fall back to TCP when QUIC is unreliable; it does not repair a server or reverse proxy that resets WebSocket connections, and QUIC-only applications may fail with the option enabled. General UDP in Xray remains available. DNS interception and SSH's existing TCP-only policy stay in place. Custom core configurations keep their own policy and reject this generated-config-only option.

Rebuild the app to use these changes. For the supplied VMess/WebSocket session, compare a new log with the option off and on while repeating the same activity. If resets/abnormal closures persist, correlate the original event timestamps with server/reverse-proxy logs. No server configuration or live VPN routes are changed by these client fixes or their local tests.

## Slow proxy verification

HTTPS reachability probes run concurrently, succeed as soon as either endpoint returns a successful status, and abort the remaining probe. Each endpoint has a configurable `-health-timeout` (20 seconds by default, range 5–120). The editor exposes this as **Connection check timeout (seconds)**. IPv4 exit checks use the same selected per-request timeout. Successful reachability or matching exits are still required; these changes do not bypass certificate checks or declare a failed proxy connected.

Failure messages include the endpoint, HTTP status or timeout classification, and the underlying request/SOCKS/TLS error chain. Core `[Warning]` messages remain warnings even when their package path contains `common/errors`. A timeout after successful DNS and local SOCKS startup can still require investigation of the upstream TLS/WebSocket path or server; increasing the deadline cannot repair a persistently unavailable server.
