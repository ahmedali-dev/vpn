# TunnelNest — Rust port

A separate Rust implementation of the tunnel engine, local control service, and native desktop window. The existing HTML/CSS/JavaScript interface is embedded into the Rust binary. The native window uses Wry/Tao and the operating system webview; Electron is optional. No Go executable or Go toolchain is needed to run or build this port.

## Build and run

Install stable Rust and OpenSSL development libraries, including static archives. On macOS, `brew install openssl@3 pkg-config` supplies these. Linux additionally needs a C compiler, pkg-config, and OpenSSL headers. The native desktop feature also needs GTK 3 and WebKitGTK 4.1 development packages on Linux, or the WebView2 runtime on Windows. Node is only needed for the optional Electron shell and existing JavaScript tests.

```sh
cd rust
cargo build --release --features desktop --locked
./target/release/tunnel --desktop
```

With the desktop feature enabled, launching without arguments also opens the native window. For a smaller CLI/browser-only build:

```sh
cargo build --release --locked
./target/release/tunnel -ui
# Headless control API:
./target/release/tunnel -ui -ui-no-browser
```

The CLI accepts the original single-dash flags and double-dash equivalents. `--help` lists options.

```sh
./target/release/tunnel -mode xray -v2ray-link 'vless://YOUR_LINK' -socks-port 1082
./target/release/tunnel -mode ssh -H server.example -P 443 -u username -p password \
  -S tls.example -ssh-host-key 'SHA256:TRUSTED_FINGERPRINT'
```

Xray and sing-box remain external networking cores, as in the Go app. Place them in `cores/` beside the binary or on PATH, or use `-v2ray-binary` and `-tun-binary`. Keep Xray's `geoip.dat` and `geosite.dat` alongside it.

Build the native engine into the expected desktop runtime layout:

```sh
TUNNEL_PACKAGE_TARGET=darwin-arm64 python3 scripts/fetch-cores.py
python3 scripts/build.py
./dist/runtime/darwin-arm64/tunnel --desktop
```

Use the matching platform key: `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`, or `win32-x64`. On macOS the script also creates `dist/TunnelNest Rust.app`, including any fetched cores. The build script builds for its host platform; run it on each matching release runner. Set `TUNNELNEST_CLI_ONLY=1` to omit the native window. The fetch script retains the original pinned versions and verifies the official release SHA-256 metadata.

## Behavior

- SSH over TLS with password authentication, known_hosts or SHA-256 SSH fingerprints, explicit session first-use trust, HTTP/HTTPS CONNECT proxies, and bounded custom payload templates.
- VMess, VLESS, Trojan, manual Shadowsocks, TLS/REALITY, WebSocket, gRPC, HTTP, HTTPUpgrade, and XHTTP configurations through Xray/V2Ray.
- Certificate validation by default. Alternate SNI can use an automatically discovered certificate pin only after verification against the real hostname. Explicit `insecure` compatibility pins are kept only for the current connection session. SSH key trust remains independent.
- Loopback SOCKS5 and PAC, capped SSH connections, HTTPS startup checks, health monitoring, bounded reconnect backoff, child-process cleanup, and private temporary configs.
- Full-device sing-box routing with upstream exclusions, tunneled DNS, Linux auto_redirect, and a second check through system routing. SSH carries TCP; general UDP is rejected. IPv4 compatibility filters AAAA and HTTPS/SVCB DNS hints. For cached IPv6 TLS/HTTP destinations it recovers the visible server hostname and forwards the original request unchanged through SSH with remote DNS. Other literal IPv6 destinations remain blocked. If an application retains encrypted or non-HTTP IPv6 requests from before VPN activation, restart that application to clear its cache; disable IPv4 compatibility only when the SSH server supports IPv6.
- The native window supports administrator authorization and saving profile/QR files. The elevated helper exposes only networking endpoints and stops when its parent lease expires. Profiles and the window remain under the normal user.
- AES-256-GCM encrypted SQLite profiles, OS credential storage with a master-password fallback, and session-only credentials. Password keys use scrypt. The Rust profile store and keychain namespace are separate (`TunnelNestRust`), preserving the Go application's data.
- Compatible `TN2.`, `TN2P.`, and legacy `TN1.` imports. New exports use TN2/TN2P. Transfer existing profiles with shared profile files/codes; the Go SQLite database is not opened or migrated automatically.
- Random session-token authentication, loopback Host/Origin checks, restricted helper routes, request-size limits, and a fixed allowlist of embedded UI assets. Diagnostics omit endpoints, credentials, and raw core logs.

The optional Electron shell is kept in `desktop/` for compatibility. It runs the Rust binary from this folder's `dist/runtime/`. Use Node 22.12+ and `npm ci --prefix desktop`, then `npm start --prefix desktop`. The native Rust window needs neither npm nor Electron.

## Verification

```sh
cargo test --features desktop --locked
cargo clippy --all-targets --features desktop --locked -- -D warnings
cargo fmt --all --check
npm ci --prefix desktop
node --test desktop/*.test.cjs
```

Tests cover imports, TLS and SSH identity rejection, local TLS/SSH forwarding, CONNECT buffering, profile encryption and restart, session credential removal, sharing tampering, Go-generated TN1/TN2/TN2P fixtures, API authentication, core shutdown, and occupied ports. Networking tests bind only local test listeners. Core schema tests run when the platform's `dist/runtime/<platform>/cores` exists; set `TUNNELNEST_CORE_DIR` to another core directory.

Live third-party VPN connections, native authorization prompts, and actual route installation/cleanup still need platform acceptance testing on Windows, Linux, and macOS. A connectivity check is not a leak test or a persistent kill switch. Builds are unsigned; the copied Electron signing configuration is not a native Rust packaging/signing pipeline.

## Push code and publish a GitHub release

### Build Windows, DEB, RPM, and Arch packages without publishing

GitHub Actions builds Windows x64 (`.zip` containing `tunnel.exe`), Ubuntu 24.04 x64/ARM64 (`.deb`), Fedora 44 x64 (`.rpm`), and Arch Linux x64 (`.pkg.tar.zst`). Portable Linux `.tar.gz` files are retained. The package installs a `tunnelnest` launcher, application-menu entry, icon, and networking cores. macOS is excluded from CI builds.

You can trigger all platforms from a Mac. Install GitHub CLI and authenticate, then install the workflow at the actual repository root:

```sh
brew install gh
gh auth login
python3 rust/scripts/install-workflow.py
```

The helper supports this project being a subfolder of a larger Git repository: it adjusts workflow paths and installs `.github/workflows/rust-release.yml` at the Git root. It refuses to overwrite a different existing workflow; `--output FILE` writes a preview instead. Commit the application changes and workflow, and push them to your default branch. The workflow must be on that branch for GitHub's manual Run workflow button.

Then open **GitHub → Actions → TunnelNest Rust Release → Run workflow**. Alternatively, from your repository:

```sh
gh workflow run rust-release.yml
gh run list --workflow rust-release.yml
# Replace RUN_ID with the completed run's ID:
gh run download RUN_ID --dir rust/dist/downloads
```

Manual runs use the version already selected in Cargo.toml and build downloadable Actions artifacts without publishing a GitHub release. To change the version before committing/building, run `python3 rust/scripts/version.py 1.3.1`. Downloads include SHA-256 sidecars. Tag pushes still create a release through the separate publish job.

To build a Linux package locally, use the matching Linux distro and architecture with Rust, Python 3, GTK 3/WebKitGTK 4.1/OpenSSL development libraries, and its native package tools installed. From `rust/`:

```sh
# Ubuntu 24.04 x64; use linux-arm64 on ARM64 Ubuntu.
export OPENSSL_STATIC=0 TUNNEL_PACKAGE_TARGET=linux-x64
python3 scripts/fetch-cores.py
python3 scripts/build.py
python3 scripts/archive.py --target linux-x64 --distro ubuntu-24.04 --version 1.3.0 --native-package
# Fedora: replace --distro with fedora-44 (requires rpm-build).
# Arch: replace --distro with arch (requires base-devel and zstd).
```

Use the version in Cargo.toml for `--version`. On Windows, build from a Visual Studio/MSVC developer environment with Python 3, stable Rust, and OpenSSL configured as in the workflow; fetch cores with `TUNNEL_PACKAGE_TARGET=win32-x64`, run `scripts/build.py`, and package with `scripts/archive.py --target win32-x64 --version VERSION`. Install Microsoft WebView2 Runtime on the destination machine.

Install the resulting Linux packages with `sudo apt install ./FILE.deb`, `sudo dnf install ./FILE.rpm`, or `sudo pacman -U ./FILE.pkg.tar.zst`. Launch with `tunnelnest` or the application menu. Native package installation and launcher/core startup are checked inside the respective CI containers; live GUI, administrator authorization, and VPN routing still require target-OS testing.

### Publish a versioned GitHub release

The Bash entry point is `scripts/release.sh`. It is prepared for later use; creating the script does not push code, build an app, or publish a release.

From the full project root, when you are ready:

```sh
bash rust/scripts/release.sh --version 1.3.1 --repo YOUR_NAME/YOUR_REPO
```

Omit `--version` to enter it interactively before any build. You can also set `RELEASE_VERSION` in the script or environment. Versions use `X.Y.Z`; the script updates `rust/Cargo.toml`, the package entry in `rust/Cargo.lock`, and the copied Electron package metadata. Application builds read the selected version from Cargo.toml.

Install Git, Python 3, and the GitHub CLI first. Run `gh auth login` yourself and ensure your account/token can push code and workflow files. A local Rust toolchain is not required for this release script.

If this project has no Git repository, the script initializes one. If there is no origin, it asks for `OWNER/REPO` or uses `--repo`, connects to that repository if it exists, or creates it private by default. Use `--visibility public` only when you want a new public repository. Existing origins are preserved. The repository contains the full project, including the `rust/` port and the workflow at the repository root.

The script stages the project, shows the actual changes, and asks before committing and pushing. Cancellation leaves the local version changes staged. After confirmation, it commits, creates a `rust-vX.Y.Z` tag, and atomically pushes the branch and tag. Existing local/remote tags are refused; pushes are never forced. Build outputs and dependencies remain excluded by the existing `.gitignore` files.

The root `.github/workflows/rust-release.yml` reacts to `rust-v*` tags. It checks the version, installs dependencies, downloads verified cores, runs the Rust and interface tests, and builds Ubuntu 24.04 x64/ARM64, Fedora 44 x64, Arch Linux x64, and Windows x64. The four Linux jobs compile inside Ubuntu, Fedora, or Arch containers with their own native development libraries. macOS is excluded from the release workflow. Runner labels follow [GitHub's hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). Private repositories use your account's Actions minutes.

Only after all five builds succeed for a tag push does the publish job create a draft release, upload the four native Linux packages, five portable archives and `SHA256SUMS.txt`, and publish it. Manual runs skip publication. Failed uploads leave a draft that a workflow rerun can resume; already published releases are never overwritten. Optional release notes belong in `release-notes/rust-vX.Y.Z.md`. Otherwise the workflow generates brief runtime instructions. Linux packages use their distribution's OpenSSL, GTK 3, WebKitGTK 4.1, and D-Bus libraries. Arch targets the rolling release at build time. All packages and archives include the required networking cores and their license files.

The versioning, build, packaging, push, and release steps run only when you explicitly execute the script and approve its prompt. Remote Actions execution and all platform builds must still be verified on your GitHub repository.


Linux release builds use Ubuntu 24.04 (x64 and ARM64), Fedora 44 (x64), and official Arch Linux (x64). The Ubuntu ARM64 build is retained; Fedora and Arch release artifacts are x64. The workflow uses Fedora's `webkit2gtk4.1-devel` and Arch's `webkit2gtk-4.1` packages; see the [Fedora package](https://packages.fedoraproject.org/pkgs/webkitgtk/webkit2gtk4.1-devel/) and [Arch package](https://archlinux.org/packages/extra/x86_64/webkit2gtk-4.1/) for native dependency details. The existing macOS source/local build support remains available, but produces no macOS release assets in GitHub Actions.

## Saved connection logs

The **Logs** button sits between **All profiles** and **V2Ray** in the profile navigation. It opens the saved log viewer with file selection, message search, severity filters, live following, full-file download, and a copyable folder path. Clearing the activity panel clears only its display; saved files remain available after disconnecting or restarting the app.

Every connection writes UTC timestamps, severity, and component names to a log file. SSH events include DNS resolution, socket and proxy setup, TLS version/cipher and certificate checks, SSH host-key verification, authentication stages and timeouts, TCP forwarding destinations, transferred byte counts, reconnect attempts/backoff, and cleanup. Xray/V2Ray and sing-box output is labelled by core and stdout/stderr, and HTTPS checks report HTTP status or failure details. Oversized core output lines are omitted to keep memory bounded.

Files live under the normal user's configuration directory at `TunnelNestRust/logs` (normally `~/.config/TunnelNestRust/logs` on Linux). The viewer shows the exact directory. Log rotation caps files at 2 MiB and retains the 20 newest files. On Unix, the log directory uses mode 0700 and files use 0600. Failure to create/write logs is shown in the interface while in-memory activity continues. Helper output is also mirrored into the normal user's files while the helper is attached, with a final capture when it stops.

Known connection passwords, protocol credentials/share links, proxy credentials, authorization headers, and control tokens are redacted before reaching the activity panel or disk. Logs retain server and forwarding destination addresses for troubleshooting. The authenticated log API only lists/reads bounded log files from this directory; arbitrary paths and symlinks are rejected.
