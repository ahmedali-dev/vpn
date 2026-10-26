#!/usr/bin/env bash
# Push a versioned release and trigger GitHub Actions when run by the user.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

usage() {
  cat <<'HELP'
Usage: bash push_and_release.sh [X.Y.Z] [release options]
       bash push_and_release.sh --version X.Y.Z [release options]

Without a version argument, prompts for the release version.
Requires git, Python 3, GitHub CLI (gh), and an existing gh auth login.

When you run this script:
  1. Validate the version, GitHub login, repository and release tag.
  2. Update application version metadata and stage the code changes.
  3. Show the staged changes and ask for confirmation.
  4. Commit and atomically push the current branch and rust-vX.Y.Z tag.
  5. The tag starts rust-release.yml, which builds Windows x64, Ubuntu DEB,
     Fedora RPM and Arch packages, then publishes the GitHub release.

Examples:
  bash push_and_release.sh
  bash push_and_release.sh 1.3.3
  bash push_and_release.sh --version 1.3.3 --repo OWNER/REPO

Uses scripts/release.sh; accepts its --repo and --visibility options.
No local build is performed. Existing release tags cannot be reused.
HELP
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  '') ;;
  -*) ;; # Named options are validated by the release script.
  *)
    version="$1"
    shift
    set -- --version "$version" "$@"
    ;;
esac

[[ -f "$ROOT/scripts/release.sh" ]] || {
  printf 'Error: scripts/release.sh is missing; use the full source checkout.\n' >&2
  exit 1
}
exec bash "$ROOT/scripts/release.sh" "$@"
