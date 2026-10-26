# TunnelNest — Tauri + Rust

The active app is in **rust/**. Windows x64, Ubuntu 24.04 DEB, Fedora 44 RPM, and Arch x86_64 builds are supported.

From this repository root:

```bash
bash rust/scripts/build_for_all.sh
# Or check dependencies without installing/building:
bash rust/scripts/build_for_all.sh --check
```

Windows PowerShell:

```powershell
.\rust\scripts\build_for_all.ps1
```

For development, build and run from `rust/`:

```bash
cd rust
cargo build --release --locked --features desktop
./target/release/tunnel --desktop
```

[Application and release instructions](rust/README.md)

## Repository layout

- `rust/`: active application, UI, assets, tests, and build/release scripts.
- `.github/workflows/rust-release.yml`: builds the four supported x64 platforms; tag pushes publish releases.
- `archives/`: local, verified compressed backups of the previous root files and Go app. This directory is excluded from Git because the backups can contain local settings or logs.
- `sshTLS-v2ray-tunnel/README.md`: relocation notice for the former project location.

## Local legacy backups

`archives/main-legacy-20261026.tar.gz` and `archives/sshTLS-legacy-20261026.tar.gz` preserve the older source and local files. Each archive includes a SHA-256 file manifest and has a separate `.sha256` checksum. Verify checksums before extracting into a separate folder. Compiled binaries, build outputs, installed dependencies, and caches are excluded.

Build outputs and downloaded networking cores are generated under `rust/target/` and `rust/dist/`. Build scripts remain in source control. Git history is preserved.
