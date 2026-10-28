# Windows/Linux VPN stability acceptance tests

Run these tests on the actual OS or a disposable VM. Tests create local reports, including public IPs, adapter names and routes. Do not commit or publicly upload the reports without reviewing them. Python 3 and curl are required; Linux also needs iproute2/iproute. On Windows use `py -3` in place of `python3`.

The read-only `scripts/vpn_stability.py` harness never connects/disconnects TunnelNest, kills a core, changes a route, or disables an adapter. Start TunnelNest separately and approve its normal full-device administrator request. Disable browser manual proxies when testing TUN. Do not use ping or generic UDP to judge SSH TCP-only forwarding.

## Run each scenario

Repeat on Windows, Ubuntu, Fedora and Arch for SSH proxy, SSH TUN, Xray proxy and Xray TUN. For V2Ray mode use `--mode v2ray`; cores named `v2ray` use the detected legacy V4 or modern V5 CLI. Xray remains the bundled default. Replace all example IPs and paths. Use the SOCKS port shown in the app, which may differ from 1080.

1. Before connecting, determine the normal public IPv4 using `curl --noproxy '*' -4 https://api.ipify.org` (PowerShell: `curl.exe --noproxy "*" -4 /Users/khald/Library/Application Support/TunnelNestRust/logshttps://api.ipify.org`).
2. Capture baseline routes and DNS:

```sh
python3 scripts/vpn_stability.py snapshot --label before --mode ssh --routing tun --expected-ip YOUR_NORMAL_IPV4 --output /tmp/tunnelnest-ssh-tun
```

3. Connect the profile with full-device VPN enabled. Determine the exit IPv4 through SOCKS: `curl --proxy socks5h://127.0.0.1:1080 --noproxy "" https://api.ipify.org`. Capture the connected snapshot using that exit IPv4:

```sh
python3 scripts/vpn_stability.py snapshot --label connected --mode ssh --routing tun --socks-port 1080 --expected-ip VPN_EXIT_IPV4 --output /tmp/tunnelnest-ssh-tun
```

For proxy-only scenarios use `--routing proxy` and verify that system traffic retains its ordinary exit while SOCKS uses the VPN exit. For Xray use `--mode xray`. On Windows, an output directory such as `.\vpn-test-results\ssh-tun` works in place of `/tmp/...`.

4. If IPv6 is supported, pass `--expected-ipv6 VPN_EXIT_IPV6` to connected snapshots. If IPv6 is unavailable or intentionally blocked, the report records that. A successful IPv6 request without an expected exit is marked unverified, not leak-free. A DNS lookup confirms functionality, not absence of DNS leaks; inspect traffic on the physical adapter separately for that acceptance check.
5. Run an eight-hour observation while the app remains connected:

```sh
python3 scripts/vpn_stability.py soak --mode ssh --routing tun --socks-port 1080 --expected-ip VPN_EXIT_IPV4 --duration 28800 --interval 30 --output /tmp/tunnelnest-ssh-tun
```

Samples go to `soak.jsonl`; `summary.json` records failures, longest failure streak and observed recovery times. A run with any failed samples exits nonzero, including deliberate outage tests. Explain intentional failures in the test record rather than treating them as an uninterrupted successful soak. A clean eight-hour soak should have no failed samples or unexpected restarts. IPv6 is captured in the initial route snapshot; the soak focuses on IPv4 egress and system DNS availability.
6. Disconnect and capture `--label after` with `--expected-ip YOUR_NORMAL_IPV4`. Confirm normal Internet/DNS return. Compare `before.json` and `after.json`: the TunnelNest address `172.30.111.1`, its `172.30.111.0/30` and `fdfe:dcba:9876::/126` routes, and newly added sing-box policy rules should be gone. Windows: inspect Task Manager; Linux: `pgrep -a -f 'xray|v2ray|sing-box'`. Only processes started by this session should stop. Do not kill other VPN sessions.

## Fault and recovery runs

Record the event time, expected outcome, recovery time and saved TunnelNest log for each case. Run these separately from the clean soak:

- Disable/re-enable the VM network for ten seconds, then for three minutes. Expect offline waiting and recovery when a gateway returns, without spending the retry budget while known offline.
- Switch Wi-Fi/Ethernet or switch between two VM networks. Expect a single debounced restart, refreshed DNS and upstream exclusions, and retained server identity.
- Suspend/resume the test machine. Expect recovery after the scheduling gap. Existing application TCP streams may need reconnection.
- Rotate a controlled test server's DNS A/AAAA records while keeping its certificate and SSH host key fixed. Expect new exclusions after teardown, without routing the upstream through itself. Deliberately change a pin/key in a separate test; reconnect must stop.
- In an isolated VM network, inject packet loss/latency using the hypervisor or an owned test gateway. Record the tool and loss rate. Short probe failures should degrade health; repeated failures should restart. No packet-loss configuration is applied by the harness.
- Temporarily make DNS unavailable on the test network, then restore it. Check stage logs, recovery and DNS usability.
- Terminate only this session's Xray or sing-box PID from the log. Expect prompt detection with PID/status/uptime, clean teardown, and a retry. Invalid configuration should fail preflight without repeated launches.
- Try incorrect SSH credentials and exhausted forwarding capacity. Credentials should stop retries; a rejected channel/overload should not kill an otherwise healthy shared SSH session.
- Repeat connect/disconnect at least twenty times, including cancellation during startup, DNS lookup and backoff. No session processes, temporary generated configs, TUN adapter or new route/policy rules should remain.
- Test MTU 1500, then 1400/1280 only if needed, including a large download/upload and normal HTTPS browsing. Keep the measured working value; do not infer improvement from ping in SSH mode.

## Current evidence

Local automated tests and core schema/DNS checks are distinct from live platform acceptance. Record OS/version, app commit, mode, routing, MTU/timing flags, start/end timestamps and each report directory. Windows/Linux live fault tests and the eight-hour matrix are pending until someone runs them on those systems.
