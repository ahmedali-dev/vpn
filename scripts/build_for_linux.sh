#!/usr/bin/env bash
# Shared implementation; use build_for_ubuntu.sh, build_for_fedora.sh, or build_for_arch.sh.
set -euo pipefail
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
expected="${1:-}"
shift || true
check_only=false
case "${1:-}" in
  --check) check_only=true; shift ;;
  -h|--help)
    printf 'Usage: build_for_%s.sh [--check]\nChecks/installs dependencies, fetches verified cores, builds Tauri, and creates native and portable packages.\n--check reports dependencies without installing or building.\n' "$expected"
    exit 0 ;;
esac
(($# == 0)) || fail 'Unknown arguments; use --help.'
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail 'Requires native x86_64 Linux.'
[[ -r /etc/os-release ]] || fail 'Cannot detect Linux distribution.'
. /etc/os-release
[[ "${ID:-}" == "$expected" ]] || fail "This script requires $expected; detected ${ID:-unknown}."
case "$expected" in
  ubuntu)
    [[ "${VERSION_ID:-}" == 24.04 ]] || fail 'Ubuntu packaging requires Ubuntu 24.04.'
    distro=ubuntu-24.04
    packages=(git curl ca-certificates python3 build-essential pkg-config libssl-dev libdbus-1-dev libgtk-3-dev libwebkit2gtk-4.1-dev tar gzip unzip zstd dpkg-dev desktop-file-utils pkexec iproute2)
    ;;
  fedora)
    [[ "${VERSION_ID:-}" == 44 ]] || fail 'Fedora packaging requires Fedora 44.'
    distro=fedora-44
    packages=(git curl-minimal ca-certificates python3 gcc gcc-c++ make perl pkgconf-pkg-config openssl-devel dbus-devel gtk3-devel webkit2gtk4.1-devel tar gzip unzip zstd which rpm-build desktop-file-utils polkit iproute)
    ;;
  arch)
    distro=arch
    packages=(git curl ca-certificates python base-devel pkgconf openssl dbus gtk3 webkit2gtk-4.1 tar gzip unzip zstd which desktop-file-utils polkit iproute2)
    ;;
  *) fail 'Supported distributions: ubuntu, fedora, arch.' ;;
esac
missing=()
for package in "${packages[@]}"; do
  case "$expected" in
    ubuntu) [[ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)" == 'install ok installed' ]] || missing+=("$package") ;;
    fedora)
      # Full curl also satisfies this dependency; avoid conflicting packages.
      if [[ "$package" == curl-minimal ]] && rpm -q curl >/dev/null 2>&1; then continue; fi
      rpm -q "$package" >/dev/null 2>&1 || missing+=("$package") ;;
    arch) pacman -Q "$package" >/dev/null 2>&1 || missing+=("$package") ;;
  esac
done
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
export PATH="$cargo_home/bin:$PATH"
rust_missing=false
if ! command -v rustup >/dev/null 2>&1 || ! rustup run stable cargo --version >/dev/null 2>&1; then
  rust_missing=true
fi
if ((${#missing[@]})); then printf 'Missing system packages: %s\n' "${missing[*]}"; else printf 'System dependencies: ready.\n'; fi
if "$rust_missing"; then printf 'Missing toolchain: Rust stable (rustup).\n'; else printf 'Rust stable: ready.\n'; fi
if "$check_only"; then
  ((${#missing[@]} == 0)) && ! "$rust_missing"
  exit $?
fi
if ((${#missing[@]})); then
  elevate=()
  if ((EUID != 0)); then
    command -v sudo >/dev/null 2>&1 || fail 'Install sudo or have an administrator install the listed packages.'
    elevate=(sudo)
  fi
  case "$expected" in
    ubuntu)
      "${elevate[@]}" apt-get update
      "${elevate[@]}" apt-get install -y --no-install-recommends "${missing[@]}" ;;
    fedora) "${elevate[@]}" dnf install -y "${missing[@]}" ;;
    arch)
      # Arch requires a full upgrade when refreshing repositories; never do a partial upgrade.
      printf 'Installing missing dependencies with a full Arch system upgrade (pacman -Syu).\n'
      "${elevate[@]}" pacman -Syu --noconfirm --needed "${missing[@]}" ;;
  esac
fi
if ! command -v rustup >/dev/null 2>&1; then
  (
    installer="$(mktemp)"
    trap 'rm -f -- "$installer"' EXIT
    curl --proto '=https' --tlsv1.2 --fail --show-error --silent https://sh.rustup.rs -o "$installer"
    sh "$installer" -y --profile minimal --default-toolchain stable --no-modify-path
  )
fi
if ! rustup run stable cargo --version >/dev/null 2>&1; then
  rustup toolchain install stable --profile minimal
fi
# Pin this process to stable even if the user's global default is different.
export RUSTUP_TOOLCHAIN=stable OPENSSL_STATIC=0 TUNNEL_PACKAGE_TARGET=linux-x64
export TUNNELNEST_CLI_ONLY=0
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$root"
version="$(python3 -c 'from scripts.version import package_version; from pathlib import Path; print(package_version(Path("Cargo.toml").read_text()))')"
python3 scripts/version.py "$version" --check
python3 scripts/fetch-cores.py
python3 scripts/build.py
python3 scripts/archive.py --target linux-x64 --distro "$distro" --version "$version" --native-package
printf '\nBuild complete. Packages and checksums: %s/dist/release/\n' "$root"
