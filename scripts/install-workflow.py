#!/usr/bin/env python3
"""Install the build workflow at the Git root, including for nested checkouts."""
import argparse
import json
import pathlib
import subprocess

PROJECT = pathlib.Path(__file__).resolve().parents[1]


def render(source, prefix):
    if prefix:
        source = source.replace('working-directory: .',
                                'working-directory: ' + json.dumps(prefix))
        source = source.replace('path: dist/release/*',
                                'path: ' + json.dumps(prefix + '/dist/release/*'))
        source = source.replace('notes="release-notes/', 'notes="' + prefix + '/release-notes/')
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, help='Write a preview to this file instead')
    args = parser.parse_args()
    repo = pathlib.Path(subprocess.check_output(
        ['git', '-C', str(PROJECT), 'rev-parse', '--show-toplevel'], text=True).strip()).resolve()
    relative = PROJECT.relative_to(repo).as_posix()
    prefix = '' if relative == '.' else relative
    if any(c in prefix for c in '\n\r"$`\\'):
        parser.error('Repository subdirectory contains unsupported shell characters')
    template = PROJECT / '.github/workflows/rust-release.yml'
    destination = args.output or repo / '.github/workflows/rust-release.yml'
    content = render(template.read_text(), prefix)
    if destination.exists() and destination.read_text() == content:
        print('Workflow already current: ' + str(destination))
        return
    if destination.exists() and destination.resolve() != template.resolve():
        parser.error('Destination already exists with different content; review it before replacing: ' + str(destination))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content)
    print('Saved ' + str(destination))
    print('Commit the workflow and application changes, then push to the default branch.')
    print('Build without publishing: gh workflow run rust-release.yml')


if __name__ == '__main__':
    main()
