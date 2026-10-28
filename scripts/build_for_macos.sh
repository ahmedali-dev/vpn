#!/usr/bin/env bash
# Build a native macOS app bundle with its verified networking cores.
set -euo pipefail
scripts="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec python3 "$scripts/package_macos.py" "$@"
