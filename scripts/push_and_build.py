#!/usr/bin/env python3
"""Prompt for branch/version, commit all project changes, push and start GitHub Actions.

Requires Git and an authenticated GitHub CLI (gh auth login). No force pushes.
Normal runs build downloadable Actions artifacts. --release publishes via rust-vX.Y.Z.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import version as versions

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = 'rust-release.yml'


class CommandError(RuntimeError):
    pass


def run(*args, capture=False, allowed=(0,)):
    # Argument arrays only: branch names and versions are never executed as shell code.
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=capture,
                            env={k: v for k, v in os.environ.items() if k != 'GH_REPO'})
    if result.returncode not in allowed:
        detail = (result.stderr or result.stdout or '').strip() if capture else ''
        raise CommandError(f'{args[0]} {args[1]} failed (exit {result.returncode}).'
                           + ('\n' + detail if detail else ''))
    return result


def git(*args, **kwargs):
    # Use the existing gh login without rewriting global Git credentials.
    return run('git', '-c', 'credential.helper=',
               '-c', 'credential.helper=!gh auth git-credential', *args, **kwargs)


def read_inputs(branch=None, version=None):
    branch = (input('Branch name [main]: ') if branch is None else branch).strip() or 'main'
    version = (input('Version (X.Y.Z): ') if version is None else version).strip().removeprefix('v')
    if not versions.VERSION.fullmatch(version):
        raise ValueError('Version must be X.Y.Z, for example 1.3.6.')
    return branch, version


def remote_ref(ref):
    result = git('ls-remote', '--exit-code', 'origin', ref, capture=True, allowed=(0, 2))
    return result.stdout.split()[0] if result.returncode == 0 else None


def select_branch(branch, remote_sha):
    exists = git('show-ref', '--verify', '--quiet', 'refs/heads/' + branch,
                 capture=True, allowed=(0, 1)).returncode == 0
    if exists:
        git('switch', branch)
    elif remote_sha:
        git('fetch', '--no-tags', 'origin', 'refs/heads/' + branch)
        git('switch', '-c', branch, 'FETCH_HEAD')
    else:
        print('Creating branch from the current HEAD: ' + branch, flush=True)
        git('switch', '-c', branch)


def execute(branch, version, release=False, dry_run=False):
    if not shutil.which('git'):
        raise ValueError('Install Git first.')
    top = Path(run('git', 'rev-parse', '--show-toplevel', capture=True).stdout.strip()).resolve()
    if top != ROOT.resolve():
        raise ValueError('Use this script from the complete TunnelNest Git checkout.')
    run('git', 'check-ref-format', '--branch', branch, capture=True)
    if not (ROOT / '.github/workflows' / WORKFLOW).is_file():
        raise ValueError('The TunnelNest release workflow is missing.')
    # Validate all metadata before any writes. Prepare it again after branch selection.
    versions.metadata(version)
    tag = 'rust-v' + version
    print(f'Branch: {branch}\nVersion: {version}\nAction: '
          + ('publish ' + tag if release else 'build Actions artifacts'), flush=True)
    print('Includes ALL staged, unstaged and untracked files not excluded by Git ignore rules.', flush=True)
    if dry_run:
        print('Dry run: no files, branches, commits, tags, remote refs or workflows changed.')
        return
    if not shutil.which('gh'):
        raise ValueError('Install GitHub CLI and run gh auth login first.')
    run('gh', 'auth', 'status', capture=True)
    origin = git('remote', 'get-url', 'origin', capture=True).stdout.strip()
    repo = json.loads(run('gh', 'repo', 'view', origin, '--json', 'nameWithOwner,url', capture=True).stdout)
    repo_url = repo['url']
    git('var', 'GIT_AUTHOR_IDENT', capture=True)
    if git('diff', '--name-only', '--diff-filter=U', capture=True).stdout.strip():
        raise ValueError('Resolve existing merge conflicts first.')
    branch_ref = 'refs/heads/' + branch
    remote_sha = remote_ref(branch_ref)
    if release:
        local_tag = git('show-ref', '--verify', '--quiet', 'refs/tags/' + tag,
                        capture=True, allowed=(0, 1)).returncode == 0
        if local_tag or remote_ref('refs/tags/' + tag):
            raise ValueError(tag + ' already exists. Choose a new version; existing tags are never moved.')
    else:
        # Manual dispatch requires the workflow to be registered on the default branch.
        run('gh', 'workflow', 'view', WORKFLOW, '--repo', repo_url, capture=True)
    select_branch(branch, remote_sha)
    for path, content in versions.metadata(version).items():
        path.write_text(content)
    git('add', '-A', '--', '.')
    git('diff', '--cached', '--stat')
    changed = git('diff', '--cached', '--quiet', capture=True, allowed=(0, 1)).returncode == 1
    if changed:
        git('commit', '-m', 'Update TunnelNest to ' + version)
    else:
        print('No new changes to commit; using the current commit.', flush=True)
    if release:
        git('tag', '-a', tag, '-m', 'TunnelNest ' + version)
        # Atomic, normal pushes: rejected branch updates cannot leave a remote release tag.
        git('push', '--atomic', '--set-upstream', 'origin', 'HEAD:' + branch_ref, 'refs/tags/' + tag)
        print('Pushed ' + tag + '; its push triggers the build and release workflow.', flush=True)
    else:
        git('push', '--set-upstream', 'origin', 'HEAD:' + branch_ref)
        try:
            run('gh', 'workflow', 'run', WORKFLOW, '--repo', repo_url, '--ref', branch)
        except CommandError as error:
            raise CommandError(str(error) + '\nThe push succeeded. Retry the workflow without another commit:\n'
                               + f'gh workflow run {WORKFLOW} --repo {repo_url} --ref {json.dumps(branch)}') from error
    print('Actions: ' + repo_url.rstrip('/') + '/actions', flush=True)
    if not release and branch == 'main':
        print('The existing main push trigger may also queue its automatic validation build.')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--branch', help='Skip branch prompt; an empty value means main')
    parser.add_argument('--version', help='Skip version prompt (X.Y.Z)')
    parser.add_argument('--release', action='store_true', help='Push a new release tag; Actions publishes the release')
    parser.add_argument('--dry-run', action='store_true', help='Validate local inputs and show intent without changing anything')
    args = parser.parse_args()
    try:
        branch, version = read_inputs(args.branch, args.version)
        execute(branch, version, args.release, args.dry_run)
        return 0
    except (ValueError, CommandError, OSError) as error:
        print('Error: ' + str(error), file=sys.stderr)
        print('Existing commits and local changes are kept. No reset or force push was performed.', file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print('\nCancelled. Existing work was kept.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
