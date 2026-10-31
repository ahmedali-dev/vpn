# Native VPN acceptance

The GitHub workflow tests and builds Windows x64, macOS ARM64/Intel, Linux x64, and Ubuntu 24.04 ARM64 on matching runners. It validates the bundled cores and exercises local routing without changing the runner's system routes. A successful workflow does **not** certify desktop authorization prompts or live full-device VPN behavior.

Before a release, test Windows 11, both supported Mac architectures when available, and Linux x64/ARM64 with a working test account. Never upload real credentials to CI. The commands below inspect connectivity and write local reports; they do not start/stop a VPN, change network settings, kill a process, or put the device to sleep.

## For each SSH and Xray profile

1. Fetch/build the package for the host architecture. Confirm the included engine, Xray, and sing-box run natively; keep the matching cores together. Open the desktop app, unlock the vault, and check saved profiles and their rules survive reopening.
2. With the VPN disconnected, record `before` using your normal public IPv4.
3. Connect in Proxy mode. Record `connected` using the expected VPN IPv4 and the profile's SOCKS port. Test a browser configured to use that proxy.
4. Disconnect, switch to Full-device VPN, authorize through the OS prompt, and record `connected` with `--routing tun`. System and proxy IPv4 must match the VPN exit; DNS must resolve. Record the VPN IPv6 with `--expected-ipv6` if available. A blocked/unavailable IPv6 result does not prove IPv6 connectivity or leak protection.
5. Test a direct domain, a direct IP range, an explicit tunnel rule, and a blocked destination. Test a process rule using its actual executable name. Confirm a specific rule precedes LAN bypass and unmatched traffic still tunnels. Test LAN bypass against a device you own. Domain matching may be unavailable for encrypted names, cached DNS, or shared IPs; it is not a security boundary.
6. While the read-only soak observer is running, manually sleep/wake the machine, switch Wi-Fi/Ethernet, or stop the networking core you launched for this test. Use a separate output directory per scenario. The app must recover or show a clear error, retain identity checks, and avoid duplicate routes. Inspect the recorded failure intervals and recovery times; soak returns a failing result if any sample fails, even after recovery.
7. Disconnect. Record `after` using your normal IPv4. Confirm normal DNS, no owned TUN address, and no leftover routes/rules referencing the observed tunnel interface. Compare `before.json` and `after.json`; network changes can legitimately change physical routes. On Linux also inspect firewall redirection and policy rules. The observer's address check alone does not prove all route/firewall cleanup.

Example commands (replace the sample IPs and port; Windows can use `py -3`):

```sh
python3 scripts/vpn_stability.py snapshot --label before --mode ssh --routing tun --expected-ip 192.0.2.10 --socks-port 1082 --output vpn-test-results/ssh-normal
python3 scripts/vpn_stability.py snapshot --label connected --mode ssh --routing tun --expected-ip 198.51.100.20 --socks-port 1082 --output vpn-test-results/ssh-normal
python3 scripts/vpn_stability.py soak --scenario network-change --mode ssh --routing tun --expected-ip 198.51.100.20 --socks-port 1082 --duration 600 --interval 10 --output vpn-test-results/ssh-network-change
python3 scripts/vpn_stability.py snapshot --label after --mode ssh --routing tun --expected-ip 192.0.2.10 --socks-port 1082 --output vpn-test-results/ssh-normal
```

Keep reports local: they contain public IPs, process/platform details, and route information. Record OS version, architecture, package checksum, mode, scenario, result, and any untested cases in the release QA notes. CI artifacts are candidate builds, not a completed physical-device test report.

## Record evidence without claiming unrun tests

Use one evidence directory per device, account, and mode (SSH/Xray, Proxy/TUN). Keep normal snapshots in `normal/`, and soak reports under `sleep-wake/`, `network-change/`, and `core-crash/`. The observer labels tests but never performs sleep, switches a network, or kills a core. If interruptions produce failed samples, the soak remains failed even if it recovers; investigate the failures and retain the recovery measurements.

After physically checking the window, OS elevation prompt, route rules, and cleanup, write an `operator.json` with `osVersion`, `architecture`, `appVersion`, `mode`, `routing`, and the Boolean fields `windowOpened`, `elevationPrompt`, `routingRulesChecked`, and `cleanupInspected`. Mark a field true only after checking it on that device. Then run:

```sh
python3 scripts/acceptance_status.py vpn-test-results/windows11-ssh-tun
```

Missing reports and unchecked items fail this check. Operator observations are labelled **reported**, not independently verified. This checker never connects a VPN or sends reports anywhere. Mac CI validates native Intel/ARM builds and local fixtures; it does not certify physical-device routing. Use the new `--tun-address4` and `--tun-address6` observer options when testing non-default virtual addresses.

For deliberate split routing, `--expected-ip` must remain the verified proxy exit. If the system IP probe is intentionally direct, also set `--expected-system-ip` to that expected direct exit. This checks both paths against explicit expectations; it does not independently validate every routing rule. An unsuccessful address inspection now fails the after-disconnect snapshot rather than assuming cleanup succeeded.
