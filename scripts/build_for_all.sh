#!/usr/bin/env bash
# Dispatch to the native host build; this does not cross-compile.
set -euo pipefail
scripts="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
case "${1:-}" in
  -h|--help)
    printf 'Usage: bash build_for_all.sh [--check]\nBuilds for the current host: macOS ARM64/Intel, or x86_64 Windows, Ubuntu 24.04, Fedora 44, or Arch.\nBuilds and packages with networking cores. Linux/Windows install missing dependencies; macOS reports prerequisites.\n--check reports missing dependencies without installing or building.\n'
    exit 0 ;;
esac
case "$(uname -s)" in
  Darwin) exec bash "$scripts/build_for_macos.sh" "$@" ;;
  Linux)
    [[ -r /etc/os-release ]] || { echo 'Cannot detect Linux distribution.' >&2; exit 1; }
    . /etc/os-release
    case "${ID:-}" in
      ubuntu|fedora|arch) exec bash "$scripts/build_for_${ID}.sh" "$@" ;;
      *) echo 'Supported Linux distributions: Ubuntu 24.04, Fedora 44, Arch.' >&2; exit 1 ;;
    esac ;;
  MINGW*|MSYS*|CYGWIN*)
    powershell=()
    if command -v pwsh >/dev/null 2>&1; then powershell=(pwsh)
    elif command -v powershell.exe >/dev/null 2>&1; then powershell=(powershell.exe)
    else echo 'PowerShell is required for Windows builds.' >&2; exit 1
    fi
    arguments=()
    if [[ "${1:-}" == --check ]]; then arguments=(-Check); shift; fi
    (($# == 0)) || { echo 'Unknown arguments; use --help.' >&2; exit 1; }
    script="$scripts/build_for_windows.ps1"
    if command -v cygpath >/dev/null 2>&1; then script="$(cygpath -w "$script")"; fi
    exec "${powershell[@]}" -NoProfile -File "$script" "${arguments[@]}" ;;
  *) echo 'Builds support macOS ARM64/Intel and x86_64 Windows, Ubuntu, Fedora, and Arch. Use matching hosts or GitHub Actions.' >&2; exit 1 ;;
esac
