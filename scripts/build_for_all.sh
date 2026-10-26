#!/usr/bin/env bash
# Dispatch to the native host build; this does not cross-compile.
set -euo pipefail
scripts="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
case "${1:-}" in
  -h|--help)
    printf 'Usage: bash build_for_all.sh [--check]\nBuilds for the current x86_64 host: Windows, Ubuntu 24.04, Fedora 44, or Arch.\nInstalls missing dependencies, then builds and packages the app with networking cores.\n--check reports missing dependencies without installing or building.\n'
    exit 0 ;;
esac
case "$(uname -s)" in
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
  *) echo 'Builds support x86_64 Windows, Ubuntu, Fedora, and Arch only. Use matching hosts or GitHub Actions.' >&2; exit 1 ;;
esac
