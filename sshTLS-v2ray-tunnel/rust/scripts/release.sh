#!/usr/bin/env bash
# Prepare and push a versioned Rust release. GitHub Actions builds the app.
# Set RELEASE_VERSION here, pass --version, or enter it when prompted.
set -euo pipefail
RELEASE_VERSION="${RELEASE_VERSION:-}"
REPOSITORY=""
VISIBILITY="private"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"

usage() {
  cat <<'HELP'
Usage: bash rust/scripts/release.sh [--version X.Y.Z] [--repo OWNER/REPO]
                                    [--visibility private|public]

Prompts for the version before changing files or starting any build.
Updates Rust/Electron version metadata, commits the repository's changes,
then pushes the branch and rust-vX.Y.Z tag. GitHub Actions tests and builds
Ubuntu 24.04 x64/ARM64 DEB, Fedora 44 x64 RPM, Arch Linux x64/ARM64 pkg.tar.zst,
and Windows x64 ZIP (plus portable Linux tarballs),
then publishes a release. macOS is excluded from release builds.

First use without a Git repository or origin:
  bash rust/scripts/release.sh --version 1.3.1 --repo YOUR_NAME/YOUR_REPO

An absent repository is created private unless --visibility public is supplied.
Existing origins are preserved. Requires git, gh, Python 3, Git identity,
and a prior 'gh auth login' with permission to push GitHub Actions workflows.
No local Rust toolchain is needed. Review and confirm the staged files before push.
HELP
}
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
# Use the existing gh login for HTTPS Git operations without changing global Git settings.
git_auth() { git -c credential.helper= -c 'credential.helper=!gh auth git-credential' "$@"; }
while (($#)); do
  case "$1" in
    --version|--repo|--visibility)
      (($# >= 2)) || fail "Missing value for $1"
      case "$1" in
        --version) RELEASE_VERSION="$2" ;;
        --repo) REPOSITORY="$2" ;;
        --visibility) VISIBILITY="$2" ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown argument: $1" ;;
  esac
done
for tool in git gh python3; do command -v "$tool" >/dev/null 2>&1 || fail "Install $tool first."; done
[[ "$VISIBILITY" == private || "$VISIBILITY" == public ]] || fail 'Visibility must be private or public.'
if [[ -z "$RELEASE_VERSION" ]]; then
  read -r -p 'Release version (X.Y.Z, for example 1.3.1): ' RELEASE_VERSION
fi
RELEASE_VERSION="${RELEASE_VERSION#v}"
[[ "$RELEASE_VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || fail 'Use a version such as 1.3.1 (no prerelease suffix).'
TAG="rust-v$RELEASE_VERSION"
cd -- "$ROOT"
[[ -f .github/workflows/rust-release.yml && -f rust/Cargo.toml ]] || fail 'Run this script from the full TunnelNest source checkout.'
gh auth status >/dev/null 2>&1 || fail 'Run gh auth login first (include workflow permissions).'

if git rev-parse --show-toplevel >/dev/null 2>&1; then
  GIT_ROOT="$(git rev-parse --show-toplevel)"
  [[ "$(cd -- "$GIT_ROOT" && pwd -P)" == "$ROOT" ]] || fail 'This folder is inside another Git repository; initialize a separate checkout first.'
else
  git init --initial-branch=main
fi
BRANCH="$(git symbolic-ref --quiet --short HEAD)" || fail 'Check out a branch first; detached HEAD is unsupported.'
git var GIT_AUTHOR_IDENT >/dev/null 2>&1 || fail 'Configure git user.name and user.email first.'
if git show-ref --verify --quiet "refs/tags/$TAG"; then fail "Local tag $TAG already exists. Choose a new version."; fi

if git remote get-url origin >/dev/null 2>&1; then
  CURRENT_REPO="$(env -u GH_REPO gh repo view --json nameWithOwner --jq .nameWithOwner)" || fail 'Cannot identify the origin GitHub repository.'
  if [[ -n "$REPOSITORY" && "$REPOSITORY" != "$CURRENT_REPO" ]]; then fail "Origin belongs to $CURRENT_REPO, not $REPOSITORY. Origin was not changed."; fi
  REPOSITORY="$CURRENT_REPO"
else
  if [[ -z "$REPOSITORY" ]]; then read -r -p 'GitHub repository (OWNER/REPO): ' REPOSITORY; fi
  [[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail 'Repository must be OWNER/REPO.'
  if gh repo view "$REPOSITORY" >/dev/null 2>&1; then
    HOST="${GH_HOST:-github.com}"
    git remote add origin "https://$HOST/$REPOSITORY.git"
  else
    gh repo create "$REPOSITORY" "--$VISIBILITY" --source "$ROOT" --remote origin
  fi
fi
REMOTE_TAG="$(git_auth ls-remote --tags origin "refs/tags/$TAG")" || fail 'Cannot read remote tags.'
[[ -z "$REMOTE_TAG" ]] || fail "Remote tag $TAG already exists. Choose a new version."
# Preflight visibility/version mismatches before changing the checked-out version.
python3 rust/scripts/version.py "$RELEASE_VERSION"

# The preview includes the actual version updates. Nothing is committed or pushed
# until the person running this script approves the staged file list.
git add -- .
printf '\nRepository: %s\nBranch: %s\nVersion: %s\nTag: %s\n\n' "$REPOSITORY" "$BRANCH" "$RELEASE_VERSION" "$TAG"
git diff --cached --stat
printf '\nThis commits ALL staged changes and pushes the branch plus release tag.\n'
read -r -p 'Continue and start GitHub release builds? [y/N] ' answer
[[ "$answer" == y || "$answer" == Y ]] || fail 'Cancelled. Version edits remain staged locally; nothing was committed or pushed.'
if ! git diff --cached --quiet; then git commit -m "Release TunnelNest Rust $RELEASE_VERSION"; fi
git rev-parse --verify HEAD >/dev/null || fail 'There is no commit to release.'
git tag -a "$TAG" -m "TunnelNest Rust $RELEASE_VERSION"
# Atomic push prevents publishing a tag if updating the branch is rejected.
if ! git_auth push --atomic --set-upstream origin "HEAD:refs/heads/$BRANCH" "refs/tags/$TAG"; then
  fail "Push failed. No remote refs were updated by the atomic push. The local commit and $TAG remain for inspection/retry."
fi
printf '\nPushed %s. GitHub Actions will publish the release after every build succeeds.\n' "$TAG"
printf 'View builds: gh run list --repo %q --workflow rust-release.yml\n' "$REPOSITORY"
printf 'View release: gh release view %q --repo %q\n' "$TAG" "$REPOSITORY"
