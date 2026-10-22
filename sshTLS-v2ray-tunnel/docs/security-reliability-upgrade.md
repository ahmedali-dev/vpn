# Security and reliability upgrade

Implementation work following the 21 October application review. This is development work, not an announcement of a published or signed release.

## Behavior changes

- The editor normalizes `-auto-route` to `-tun` and preserves options it cannot display, including connection limits and manual protocol fields.
- Profiles and the UI remain under the normal user. Elevation starts a loopback authenticated networking helper with no profile or vault endpoints. Its lease expires after 35 seconds without the owning application.
- Running `sudo tunnel -ui` delegates the UI and profile database back to the sudo user. The root process retains only networking operations.
- Profile arguments use authenticated AES-GCM encryption. A random key is stored in macOS Keychain, Windows Credential Manager, or Linux Secret Service. If unavailable, the UI requires a master password (at least 12 bytes), derived with scrypt. There is no silent plaintext fallback. An existing missing key is never replaced.
- Legacy plaintext records migrate only after the vault can unlock. Older application versions cannot read the encrypted argument format; keep a protected backup before upgrading if downgrade support is needed. SQLite secure deletion and vacuum reduce old copies in the live database; backups and filesystem snapshots are outside this migration.
- Unchecking Remember credentials stores connection settings without SSH credentials, protocol links/UUIDs, or upstream proxy authentication. The complete arguments remain in application memory until exit. After restart, re-enter SSH credentials or paste the protocol link again. Imported profiles save credentials in the encrypted vault by default.
- TLS compatibility does not implicitly trust SSH host keys. Use a known-hosts file or verified SHA256 host-key fingerprint. The separate first-use checkbox explicitly trusts the first observed key for this client session and rejects changes across reconnects. It does not establish persistent operator-verified trust.
- Bounded SSH keepalive and destination dial calls, periodic proxy/TUN HTTPS checks, degraded status, and recovery replace process-only health reporting. Three consecutive failed probes trigger recovery; external probe outages can still affect status.
- Diagnostic export includes redacted logs and selected Linux rules/routes. Review the export before sharing.
- Go and SSH dependencies and Electron packaging dependencies are upgraded. CI scans both dependency sets and runs native builds for five platform/architecture combinations.

## Network validation

`scripts/test-linux-network.sh` starts disposable Linux network/mount namespaces. A fake SOCKS upstream is the only destination capable of returning the expected response. The test exercises ordinary IPv4/IPv6 TCP capture, UDP DNS carried over SOCKS TCP, SSH general-UDP rejection, and interface removal after shutdown. It requires root, TUN, nftables and nfnetlink_queue support. It does not alter the host namespace's routes or DNS.

The test is wired into Linux x64 and ARM64 Actions jobs. Native Windows/macOS administrator prompts, routing, DNS and crash behavior still require acceptance testing on those operating systems. A successful public HTTPS probe alone is not proof that all traffic traverses the VPN.

## Release signing setup

Tagged release jobs require signing. Configure repository Actions secrets through GitHub Settings; never paste private signing keys into issues or chat:

- macOS: `MAC_CERT_P12_B64`, `MAC_CERT_PASSWORD`, `MAC_SIGN_IDENTITY` (Developer ID Application identity), `APPLE_API_KEY_B64` (p8), `APPLE_API_KEY_ID`, `APPLE_API_ISSUER`.
- Windows: `WIN_CERT_PFX_B64`, `WIN_CERT_PASSWORD`. The PFX must be a signing credential supported by the chosen provider; hardware-backed/cloud signing requires a corresponding integration.

The workflow imports credentials into temporary runner storage, signs runtime executables and the desktop app, notarizes the macOS app and separate CLI archive, and deletes temporary credentials even on failure. Signing and notarization errors fail the build. CLI executables cannot carry a stapled app ticket; Gatekeeper checks their notarization online. Manual development builds can remain unsigned when no credentials are configured.

Signing integration is implemented; actual signed/notarized artifacts cannot be produced until valid repository secrets are provided. Signing alone does not guarantee SmartScreen reputation or a tested installation/update experience.

## Remaining acceptance work

- Verify live routing and DNS on the user's Linux ARM64 environment, then native macOS and Windows.
- Verify keychain permission prompts, desktop elevation, forced termination cleanup and installation on clean machines.
- Supply real signing credentials and verify downloaded signed artifacts on clean machines.
- A persistent kill switch is a separate opt-in feature and is not implemented. Failure cleanup restores ordinary networking, which can permit direct traffic. The helper lease cleans up an orphan session; it is not a kill switch.

## Local verification

Go race tests, vet and desktop tests passed during implementation. The vulnerability scanner found no affected code paths; it also reported one advisory in a required module whose affected code is not called. The five-platform Actions build at commit `5aa8388` passed, including Linux x64 and ARM64 namespace traffic and policy cleanup tests. These checks cannot establish native desktop prompts or live operation on the user’s machine.
