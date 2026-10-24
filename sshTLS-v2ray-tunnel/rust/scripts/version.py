#!/usr/bin/env python3
"""Set/check release metadata without building, resolving dependencies, or pushing."""
import argparse
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z')


def package_version(text):
    block = re.search(r'(?ms)^\[package\]\s*\n(.*?)(?=^\[|\Z)', text)
    if not block:
        raise ValueError('Cargo.toml has no [package] section')
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', block.group(1))
    if not match:
        raise ValueError('Cargo.toml has no package version')
    return match.group(1)


def metadata(version):
    manifest = ROOT / 'Cargo.toml'
    source = manifest.read_text()
    current = package_version(source)
    updated, count = re.subn(
        r'(?m)^(version\s*=\s*)"' + re.escape(current) + r'"',
        lambda m: m.group(1) + json.dumps(version), source, count=1)
    if count != 1:
        raise ValueError('Cannot update Cargo.toml version')
    result = {manifest: updated}
    lock = ROOT / 'Cargo.lock'
    source = lock.read_text()
    pattern = r'(?m)(^name = "tunnelnest"\nversion = ")[^"]+("$)'
    updated, count = re.subn(pattern, lambda m: m.group(1) + version + m.group(2), source)
    if count != 1:
        raise ValueError('Cargo.lock must contain exactly one tunnelnest package')
    result[lock] = updated
    for filename in ('package.json', 'package-lock.json'):
        path = ROOT / 'desktop' / filename
        data = json.loads(path.read_text())
        data['version'] = version
        if filename == 'package-lock.json':
            data['packages']['']['version'] = version
        result[path] = json.dumps(data, indent=2) + '\n'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version', help='X.Y.Z release version')
    parser.add_argument('--check', action='store_true', help='Check only; never modify files')
    args = parser.parse_args()
    if not VERSION.fullmatch(args.version):
        parser.error('Version must be X.Y.Z without leading zeroes or prerelease suffixes')
    # Prepare and validate every change before writing any version metadata.
    updates = metadata(args.version)
    if args.check:
        changed = [str(p.relative_to(ROOT)) for p, value in updates.items() if p.read_text() != value]
        if changed:
            parser.exit(1, 'Version metadata does not match the tag: ' + ', '.join(changed) + '\n')
        print('Version metadata matches ' + args.version)
        return
    for path, content in updates.items():
        path.write_text(content)
    print('Set application version to ' + args.version)


if __name__ == '__main__':
    main()
