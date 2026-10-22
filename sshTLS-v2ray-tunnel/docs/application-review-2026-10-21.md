# TunnelNest application review

Reviewed 21 October 2026. Baseline: source corresponding to v1.2.7, commit `149b0d1`, and the current working files. This review did not modify application code or publish a release. Existing working changes were preserved.

## Assessment

Prioritize security updates, profile correctness, and verifiable full-device routing before more design changes or features. Successful builds and configuration validation have not established reliable full-device operation on the user's Linux ARM64 machine.

## 1. P1 — Update SSH dependencies and the build toolchain

`go.mod:13` pins `golang.org/x/crypto v0.45.0`. The official `govulncheck` scanner reports nine symbol-level findings in that module and one in the local Go standard library. These are scanner reports requiring per-advisory applicability checks, not ten demonstrated exploits.

Two relevant examples:

- An established SSH connection can be deadlocked by a malicious peer before x/crypto v0.56.0. The application calls the affected `ssh.NewClientConn`. [GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355).
- Revocation of a host certificate's signing CA is not correctly enforced by affected `knownhosts` versions before v0.52.0. This matters when certificate-authority entries and revocations are used. [GO-2026-5021](https://pkg.go.dev/vuln/GO-2026-5021).

The local scanner used Go 1.27.2 and reported GO-2026-6809 in `crypto/x509`, with a fix in Go 1.27.3. This local result must not be treated as proof of the same standard-library exposure in every downloadable package: CI currently requests Go 1.25.x in `.github/workflows/tunnel-سسا ؤؤrelease.yml:53`. Inspect release binary build information separately.

Recommended change: select a supported, patched Go toolchain; update x/crypto to at least v0.56.0 or a newer reviewed version; update related modules as needed; add a pinned vulnerability scanner to CI. Test SSH interoperability after upgrading.

## 2. P1 — Preserve all profile settings during editing

Evidence: `desktop/ui/app.js:17` reads only selected arguments; `desktop/ui/app.js:30` reconstructs the saved arguments from the editor controls. This is a lossy conversion.

Reproduction used the actual editor functions with a mock DOM and dummy credentials. Input contained `-auto-route` and `-max-conns 5`. After opening and serializing it:

```json
{"editorTunEnabled":false,"savedHasAutoRoute":false,"savedHasTun":false,"savedHasMaxConns":false}
```

This is especially important because the shared-profile importer accepts those options. A valid imported profile can change behavior merely by being edited and saved. The elevation decision also checks only for literal `-tun` in `desktop/ui/app.js:32`.

Recommended change: use a versioned typed profile schema, normalize routing aliases, and preserve settings that the editor cannot currently represent. Add round-trip tests for SSH, VMess, VLESS, manual configurations, imported shares, explicit core paths, and routing aliases. Reject unsupported edits visibly rather than silently discarding options.

## 3. P1 — Keep profiles and the interface outside the privileged backend

Evidence: `desktop/main.cjs:84` starts an elevated backend, then lines 88–90 switch the whole interface to it. Every backend independently calls `openProfileStore()` at `control.go:335`; the database location comes from the current process's `os.UserConfigDir()` at `profiles.go:26`.

On Linux, `pkexec` normally runs with root's user environment. The elevated backend can therefore open a different profile database. After a full-device connection, profiles may appear missing or saves may go to a privileged user's store. This is a source-level finding; it was not reproduced through an actual authentication prompt during this review.

Recommended change: retain profile CRUD, secret storage, and the renderer under the normal user. Give a small privileged helper only the networking operations it needs. Do not solve this by making root routinely open user-writable profile databases.

## 4. P1 — Prove full-device routing, rather than just HTTPS availability

Evidence: `v2ray.go:404` checks ordinary HTTPS with environment proxies disabled after TUN starts. This is useful for detecting an outage, but it also succeeds if traffic bypasses TUN and reaches the internet directly. It does not establish correct route capture, egress identity, IPv6 handling, or DNS isolation.

The user's earlier Linux log showed successful SOCKS HTTPS, a running TUN interface, and DNS exchanges without ordinary TUN connection entries. v1.2.7 added Linux redirection, but its effect on the user's machine remains unconfirmed.

CI currently checks configuration parsing and executable startup (`.github/workflows/tunnel-release.yml:85`); it does not exercise privileged route installation or data transfer through TUN.

Recommended change: add Linux x64/ARM64 integration tests in disposable VMs or network namespaces. Verify actual TCP capture and proxy egress, DNS behavior, IPv4/IPv6, upstream exclusions, connect/disconnect cleanup, and restoration after failure. Add native macOS/Windows acceptance tests. Include a diagnostic export with selected helper, interface, relevant routes/rules, and redacted logs.

## 5. P1 — Make connection health continuous and bounded

Evidence: `control.go:119` bases the connected state on a running flag; `client.go:371` checks whether the Xray process is alive. HTTPS verification runs at startup, not continuously. A live core with a broken upstream can still appear connected.

SSH keepalive calls `SendRequest` without a request deadline (`client.go:438`). Forwarded destination connections use `client.Dial` without a context/deadline (`socks.go:179`). A peer that stops responding can delay recovery or leave requests waiting.

Recommended change: distinguish process running, proxy reachable, upstream healthy, and TUN connectivity. Add bounded keepalive/dial operations and periodic end-to-end probes with backoff and cancellation. Recheck connectivity after reconnecting, not just after the first start. Do not restart on one failed public probe alone.

## 6. P2 — Improve secret storage and compatibility trust

`profiles.go:93` serializes all profile arguments, including SSH passwords and protocol credentials, as readable JSON in SQLite. Unix permissions help, but this is not encryption at rest. Windows-specific access control is not established here. Password-protected sharing does not protect the profile database.

Recommended change: store secrets in macOS Keychain, Windows credential protection, or Linux Secret Service, with a documented fallback and an option not to save passwords.

Compatibility mode also couples unverified TLS to accepting an unknown SSH host key. Its observed host key is stored in a new callback-local variable (`transport.go:109`) each time a connection is attempted (`ssh.go:45`), so it does not retain host-key trust across reconnections. Separate TLS compatibility from SSH host-key policy; support explicit, persistent, user-approved trust and reject changed identities.

## 7. P2 — Patch or replace vulnerable desktop build dependencies

`npm audit` reported six affected dependency entries: two high and four moderate. These counts include transitive propagation, not six distinct vulnerabilities. Findings include `extract-zip` path traversal through the packager dependency tree and a formatting-library denial of service.

The audited entries are development/build dependencies; this is not proof of a remotely exploitable shipped renderer. The archive extraction issue is a build-pipeline concern when processing malicious archives. The reviewed [extract-zip advisory](https://github.com/advisories/GHSA-jmr9-qjv8-65gv) lists no patched release, so blindly running `npm audit fix --force` is not an adequate plan.

Recommended change: update supported build tools, remove unnecessary transitive dependencies, and patch or replace unsafe extraction where necessary. Use isolated runners and trusted, verified downloads. Add audit reporting and triage to CI without claiming that all devDependency findings affect end users.

## 8. P2 — Define crash cleanup and optional leak protection

Elevated helpers can outlive the normal application (`desktop/main.cjs:48`, `:51`, `:54`). Normal quit sends an API request, but a crashed desktop does not execute that handler. There is no helper lease or parent-health protocol visible in the source.

Recommended change: add an authenticated helper lease, explicit ownership, and recovery for stale sessions. Test forced termination and failed elevation cleanup. Treat a persistent kill switch as a separate, opt-in feature: current failure handling intentionally restores normal networking and can allow direct traffic afterward. Explain that behavior in the UI.

## 9. P2 — Sign releases and make installation predictable

`desktop/package.cjs` does not configure platform signing or notarization. The macOS Gatekeeper block previously reported by the user is consistent with this release process.

Recommended change: add Developer ID signing and notarization for the macOS app and nested executables, Windows signing, and tested installation/update workflows. Check helper architecture/version before connecting and show which package matches the detected platform. Keep Linux ARM64 native smoke tests.

## Suggested implementation order

1. Security/toolchain patch release and vulnerability gates.
2. Lossless profile editing and unprivileged profile ownership.
3. Full-device integration tests and continuous connection health.
4. Secret storage, helper lifecycle, and explicit trust decisions.
5. Signed installation and update packages.

Avoid adding more cosmetic features until the first three items are addressed.

## Verification performed

- `go test -race ./...`: passed for the existing suite on the local macOS ARM64 host.
- `go vet ./...`: passed.
- `node --test desktop/*.test.cjs`: 14 tests passed.
- Additional temporary editor reproduction demonstrated routing/max-connection option loss; no real profile database was changed.
- `govulncheck`: reported ten symbol-level findings in the current build, with applicability caveats above.
- `npm audit`: six affected dependency entries, including build-time advisories.

Passing tests do not negate the uncovered profile bug or prove privileged networking behavior. No live Linux TUN session, native administrator dialog, malicious-peer exploit, or crash-recovery scenario was executed in this review. No application code was changed or released.
