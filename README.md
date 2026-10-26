# TunnelNest — Rust desktop

A Rust implementation of the tunnel engine, local control service, and native desktop window. The existing HTML/CSS/JavaScript interface is embedded into the Rust binary. The native desktop shell uses Tauri 2 and the operating system webview; the previous direct Wry/Tao shell has been replaced. Electron remains optional. No Go executable or Go toolchain is needed to run or build this port.

The application source, Cargo manifest, desktop UI, and scripts live directly in the Git repository root. Run all commands below from that root. Older source is preserved in local archives (see below).

## Build and run

Install stable Rust and OpenSSL development libraries, including static archives. On macOS, `brew install openssl@3 pkg-config` supplies these. Linux additionally needs a C compiler, pkg-config, and OpenSSL headers. The Tauri desktop feature also needs GTK 3 and WebKitGTK 4.1 development packages on Linux, or the WebView2 runtime on Windows. The frontend is plain HTML/CSS/JavaScript bundled by Tauri; no frontend build server is required. Node is only needed for the optional Electron shell and existing JavaScript tests.

```sh
# From the repository root
cargo build --release --features desktop --locked
./target/release/tunnel --desktop
```

With the desktop feature enabled, launching without arguments also opens the Tauri window. For a smaller CLI/browser-only build:

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
TUNNEL_PACKAGE_TARGET=linux-x64 python3 scripts/fetch-cores.py
python3 scripts/build.py
./dist/runtime/linux-x64/tunnel --desktop
```

Release scripts support only `linux-x64` (Ubuntu, Fedora, Arch) and `win32-x64` (Windows), on matching x86_64/AMD64 hosts. macOS, ARM64, and 32-bit builds are excluded. Source development on other platforms remains available through Cargo directly. Set `TUNNELNEST_CLI_ONLY=1` to omit the native window. The fetch script retains the original pinned versions and verifies the official release SHA-256 metadata.

## Behavior

- SSH over TLS with password authentication, known_hosts or SHA-256 SSH fingerprints, explicit session first-use trust, HTTP/HTTPS CONNECT proxies, and bounded custom payload templates.
- VMess, VLESS, Trojan, manual Shadowsocks, TLS/REALITY, WebSocket, gRPC, HTTP, HTTPUpgrade, and XHTTP configurations through Xray/V2Ray.
- Certificate validation by default. Alternate SNI can use an automatically discovered certificate pin only after verification against the real hostname. Explicit `insecure` compatibility pins are kept only for the current connection session. SSH key trust remains independent.
- Loopback SOCKS5 and PAC, capped SSH connections, HTTPS startup checks, health monitoring, bounded reconnect backoff, child-process cleanup, and private temporary configs.
- Full-device sing-box routing with upstream exclusions, tunneled DNS, Linux auto_redirect, and a second check through system routing. SSH carries TCP; general UDP is rejected. IPv4 compatibility filters AAAA and HTTPS/SVCB DNS hints. For cached IPv6 TLS/HTTP destinations it recovers the visible server hostname and forwards the original request unchanged through SSH with remote DNS. Other literal IPv6 destinations remain blocked. If an application retains encrypted or non-HTTP IPv6 requests from before VPN activation, restart that application to clear its cache; disable IPv4 compatibility only when the SSH server supports IPv6.
- The Tauri window supports administrator authorization and saving profile/QR files. The elevated helper exposes only networking endpoints and stops when its parent lease expires. Profiles and the window remain under the normal user.
- AES-256-GCM encrypted SQLite profiles, OS credential storage with a master-password fallback, and session-only credentials. Password keys use scrypt. The Rust profile store and keychain namespace are separate (`TunnelNestRust`), preserving the Go application's data.
- Compatible `TN2.`, `TN2P.`, and legacy `TN1.` imports. New exports use TN2/TN2P. Transfer existing profiles with shared profile files/codes; the Go SQLite database is not opened or migrated automatically.
- Random session-token authentication, loopback Host/Origin checks, restricted helper routes, request-size limits, and a fixed allowlist of embedded UI assets. Diagnostics omit endpoints, credentials, and raw core logs.

The Tauri configuration lives in `tauri.conf.json`; `build.rs` generates permissions for exactly three application commands. The bundled `main` window can request allowlisted control operations, start the existing administrator helper, and save validated profile/QR exports. Remote web pages receive no capabilities, external navigation and popups are blocked, and a content security policy limits resources to bundled assets and Tauri IPC. The control token remains in Rust and is never placed in the desktop URL or frontend storage. CLI/browser mode retains its authenticated loopback API. Window close and application quit wait for the control service to stop its tunnel/helper before exiting.

`python3 scripts/build.py` continues to use Cargo directly with the Tauri desktop feature; DEB, RPM, Arch x86_64, and Windows portable packaging continue to include cores beside the executable. There is no Tauri JavaScript CLI dependency. `cargo build --release --locked` without `--features desktop` remains the CLI-only build.

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

### One-command local builds

Run the matching script from the application checkout. All scripts use the version already set in `Cargo.toml`, fetch checksum-verified networking cores, build the Tauri desktop app, and write packages/checksums to `dist/release/`.

```sh
# Linux: automatically choose Ubuntu 24.04, Fedora 44, or Arch.
bash scripts/build_for_all.sh
# Or choose a single distribution explicitly:
bash scripts/build_for_ubuntu.sh
bash scripts/build_for_fedora.sh
bash scripts/build_for_arch.sh
# Check dependencies without installing or building (exit 1 when missing):
bash scripts/build_for_all.sh --check
```

On Windows, open **64-bit PowerShell**:

```powershell
.\scripts\build_for_all.ps1
# Or the Windows-only entry point:
.\scripts\build_for_windows.ps1
# Check only:
.\scripts\build_for_windows.ps1 -Check
```

`build_for_all` detects the current OS and runs its native build; it does not cross-compile four operating systems on one machine. Use GitHub Actions below to build all four together. Windows Git Bash can also run `build_for_all.sh`.

Missing Linux dependencies are installed with apt, dnf, or pacman, using sudo only for system package operations. Arch installs missing packages with `pacman -Syu`, which also upgrades the system to avoid partial upgrades. Missing Rust stable is installed through rustup under the invoking user. Windows checks Python, Git, C++ Build Tools/Windows SDK, Rust stable MSVC, WebView2, and vcpkg OpenSSL; missing tools are installed with winget, the signed Microsoft Build Tools installer, and vcpkg. Windows needs Microsoft's App Installer (`winget`) for automatic package installation and may show administrator prompts or request a restart. OpenSSL is built using the same static MSVC triplet as CI. Node/Electron is not needed for these native builds.

These scripts require x86_64/AMD64 hosts. Ubuntu/Fedora versions are checked so package labels match the build distribution. To set the version first, run `python3 scripts/version.py X.Y.Z` (Windows: `py -3 scripts/version.py X.Y.Z`). The local build scripts do not commit, push, or publish releases.

### Build Windows, DEB, RPM, and Arch packages without publishing

GitHub Actions builds Windows x64 (`.zip` containing `tunnel.exe`), Ubuntu 24.04 x64 (`.deb`), Fedora 44 x64 (`.rpm`), and Arch Linux x64 (`.pkg.tar.zst`). Portable Linux `.tar.gz` files are retained. The package installs a `tunnelnest` launcher, application-menu entry, icon, and networking cores. macOS is excluded from CI builds.

You can trigger all platforms from a Mac. Install GitHub CLI and authenticate, then install the workflow at the actual repository root:

```sh
brew install gh
gh auth login
python3 scripts/install-workflow.py
```

The helper supports this project being a subfolder of a larger Git repository: it adjusts workflow paths and installs `.github/workflows/rust-release.yml` at the Git root. It refuses to overwrite a different existing workflow; `--output FILE` writes a preview instead. Commit the application changes and workflow, and push them to your default branch. The workflow must be on that branch for GitHub's manual Run workflow button.

Then open **GitHub → Actions → TunnelNest Rust Release → Run workflow**. Alternatively, from your repository:

```sh
gh workflow run rust-release.yml
gh run list --workflow rust-release.yml
# Replace RUN_ID with the completed run's ID:
gh run download RUN_ID --dir dist/downloads
```

Manual runs use the version already selected in Cargo.toml and build downloadable Actions artifacts without publishing a GitHub release. To change the version before committing/building, run `python3 scripts/version.py 1.3.1`. Downloads include SHA-256 sidecars. Tag pushes still create a release through the separate publish job.

To build a Linux package locally, use the matching Linux distro and architecture with Rust, Python 3, GTK 3/WebKitGTK 4.1/OpenSSL development libraries, and its native package tools installed. From the repository root:

```sh
# Ubuntu 24.04 x64 (x86_64/AMD64 only).
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
bash scripts/release.sh --version 1.3.1 --repo YOUR_NAME/YOUR_REPO
```

Omit `--version` to enter it interactively before any build. You can also set `RELEASE_VERSION` in the script or environment. Versions use `X.Y.Z`; the script updates `Cargo.toml`, the package entry in `Cargo.lock`, and the copied Electron package metadata. Application builds read the selected version from Cargo.toml.

Install Git, Python 3, and the GitHub CLI first. Run `gh auth login` yourself and ensure your account/token can push code and workflow files. A local Rust toolchain is not required for this release script.

If this project has no Git repository, the script initializes one. If there is no origin, it asks for `OWNER/REPO` or uses `--repo`, connects to that repository if it exists, or creates it private by default. Use `--visibility public` only when you want a new public repository. Existing origins are preserved. The repository contains the full project, including the Rust app and its workflow at the repository root.

The script stages the project, shows the actual changes, and asks before committing and pushing. Cancellation leaves the local version changes staged. After confirmation, it commits, creates a `rust-vX.Y.Z` tag, and atomically pushes the branch and tag. Existing local/remote tags are refused; pushes are never forced. Build outputs and dependencies remain excluded by the existing `.gitignore` files.

The root `.github/workflows/rust-release.yml` reacts to `rust-v*` tags. It checks the version, installs dependencies, downloads verified cores, runs the Rust and interface tests, and builds Ubuntu 24.04 x64, Fedora 44 x64, Arch Linux x64, and Windows x64. The three Linux jobs compile inside Ubuntu, Fedora, or Arch containers with their own native development libraries. macOS is excluded from the release workflow. Runner labels follow [GitHub's hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). Private repositories use your account's Actions minutes.

Only after all four builds succeed for a tag push does the publish job create a draft release, upload the three native Linux packages, four portable archives and `SHA256SUMS.txt`, and publish it. Manual runs skip publication. Failed uploads leave a draft that a workflow rerun can resume; already published releases are never overwritten. Optional release notes belong in `release-notes/rust-vX.Y.Z.md`. Otherwise the workflow generates brief runtime instructions. Linux packages use their distribution's OpenSSL, GTK 3, WebKitGTK 4.1, and D-Bus libraries. Arch targets the rolling release at build time. All packages and archives include the required networking cores and their license files.

The versioning, build, packaging, push, and release steps run only when you explicitly execute the script and approve its prompt. Remote Actions execution and all platform builds must still be verified on your GitHub repository.


Linux release builds use Ubuntu 24.04, Fedora 44, and official Arch Linux containers, all on x86_64 runners. Windows uses an x64 runner. No ARM64, 32-bit, or macOS release assets are built. The workflow uses Fedora's `webkit2gtk4.1-devel` and Arch's `webkit2gtk-4.1` development packages. Packaging verifies that the app, Xray, and sing-box match the selected architecture.

## Desktop appearance and dropdowns

The desktop uses the Nocturne interface: a white control room with soft green accents, quick connection controls, real session details, live activity, and the saved profile library. Selecting a profile updates the quick connection panel. Its full-device toggle overrides routing for the next connection without rewriting the saved profile; changing profiles restores that profile's saved routing setting. Routing controls lock while a connection is active.

All select controls use styled dropdown menus, including connection mode, TLS and certificate settings, transports, saved log files, and severity. The hidden native selects remain form models so existing imports, resets, and option values are preserved. Dropdowns support mouse selection, arrow keys, Home/End, Enter/Space, typing to find an option, Tab, and Escape. Dynamic log options refresh without replacing an unchanged menu.

The top **Add / import** menu combines manual setup, pasted share codes, profile files, and QR images. Drop a single file, share code, or supported protocol link on the button/menu, or use the import dialog. Dropped files and codes are staged for review; protected shares still require their password and explicit validation before saving. Dropped protocol links open the editor. None of these actions starts a connection. File and QR size limits apply equally to browsing and dropping files.

The sidebar arrow pins it open or collapses it. When collapsed, hovering reveals labels temporarily and leaving closes it again; keyboard focus also reveals navigation labels. The pinned preference is stored locally. SSH fingerprint, known_hosts, and session-only first-use trust settings are grouped under **Trusted SSH fingerprint**, alongside the existing HTTP CONNECT section. Saved trust settings expand the section when editing.

New desktop profiles default to **Compatibility** for TLS certificate verification in both SSH and V2Ray modes. This accepts unverified TLS certificates and retains a temporary certificate pin until disconnect; SSH host-key verification is independent. Existing saved profiles retain their explicit verification choices, and profiles without a saved certificate option continue to use Automatic.

## Saved connection logs

The **Logs** button sits between **All profiles** and **V2Ray** in the profile navigation. It opens the saved log viewer with file selection, message search, severity filters, live following, full-file download, and a copyable folder path. Clearing the activity panel clears only its display; saved files remain available after disconnecting or restarting the app.

Every connection writes UTC timestamps, severity, and component names to a log file. SSH events include DNS resolution, socket and proxy setup, TLS version/cipher and certificate checks, SSH host-key verification, authentication stages and timeouts, TCP forwarding destinations, transferred byte counts, reconnect attempts/backoff, and cleanup. Xray/V2Ray and sing-box output is labelled by core and stdout/stderr, and HTTPS checks report HTTP status or failure details. Oversized core output lines are omitted to keep memory bounded.

Files live under the normal user's configuration directory at `TunnelNestRust/logs` (normally `~/.config/TunnelNestRust/logs` on Linux). The viewer shows the exact directory. Log rotation caps files at 2 MiB and retains the 20 newest files. On Unix, the log directory uses mode 0700 and files use 0600. Failure to create/write logs is shown in the interface while in-memory activity continues. Helper output is also mirrored into the normal user's files while the helper is attached, with a final capture when it stops.

Known connection passwords, protocol credentials/share links, proxy credentials, authorization headers, and control tokens are redacted before reaching the activity panel or disk. Logs retain server and forwarding destination addresses for troubleshooting. The authenticated log API only lists/reads bounded log files from this directory; arbitrary paths and symlinks are rejected.


Arch release packages use `x86_64`. ARM64 (`aarch64`) machines cannot install these packages; use a compatible ARM64 build from an earlier release/run or build from source with Cargo and matching networking cores.

## Local legacy archives

The older main-folder files and SSH/Go application are preserved locally in `archives/main-legacy-20261026.tar.gz` and `archives/sshTLS-legacy-20261026.tar.gz`. Each includes a verified SHA-256 manifest and has a checksum sidecar. Archives are excluded from Git because they may contain local settings or logs. The original sources also remain in Git history.

The repository root now contains `Cargo.toml`, `Cargo.lock`, `build.rs`, `tauri.conf.json`, `src/`, `desktop/`, `scripts/`, and `tests/`. Generated `target/`, `dist/`, installed dependencies, and caches remain excluded and have been removed.
