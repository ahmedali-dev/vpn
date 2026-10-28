#!/usr/bin/env python3
"""Build TunnelNest.app natively on macOS (Apple Silicon or Intel)."""
import argparse
import hashlib
import os
import pathlib
import platform
import plistlib
import shutil
import subprocess
import sys

from version import package_version

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(command, **kwargs):
    subprocess.run([str(part) for part in command], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Check prerequisites without building or installing')
    parser.add_argument('--debug', action='store_true', help='Use a faster development build instead of an optimized release build')
    parser.add_argument('--no-cores', action='store_true', help='Build a UI-only bundle; connections require separately installed networking cores')
    parser.add_argument('--open', action='store_true', help='Open the completed app bundle')
    args = parser.parse_args()
    if platform.system() != 'Darwin':
        parser.error('Run this script on macOS; it builds for the current Mac, without cross-compiling.')
    arch = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'x64'}.get(platform.machine().lower())
    if not arch:
        parser.error('Only macOS ARM64 and Intel x64 are supported.')
    env = os.environ.copy()
    cargo = env.get('CARGO') or shutil.which('cargo')
    missing = []
    if not cargo:
        missing.append('Rust/Cargo: install from https://rustup.rs and restart your terminal')
    if not shutil.which('xcrun') or subprocess.run(['xcrun', '--find', 'clang'], capture_output=True).returncode:
        missing.append('Xcode Command Line Tools: run xcode-select --install')
    openssl = env.get('OPENSSL_DIR')
    if not openssl:
        brew = shutil.which('brew')
        if brew:
            found = subprocess.run([brew, '--prefix', 'openssl@3'], capture_output=True, text=True)
            if found.returncode == 0:
                openssl = found.stdout.strip()
    if not openssl or not (pathlib.Path(openssl) / 'lib/libssl.a').is_file():
        missing.append('Static OpenSSL: brew install openssl@3 pkg-config (or set OPENSSL_DIR)')
    if missing:
        parser.exit(1, 'Missing prerequisites:\n- ' + '\n- '.join(missing) + '\n')
    print('macOS prerequisites ready for ' + arch, flush=True)
    if args.check:
        return
    env['OPENSSL_DIR'] = openssl
    env['OPENSSL_STATIC'] = '1'
    env['TUNNEL_PACKAGE_TARGET'] = 'darwin-' + arch
    build = [cargo, 'build', '--locked', '--features', 'desktop']
    if not args.debug:
        build.append('--release')
    run(build, cwd=ROOT, env=env)
    target = pathlib.Path(env.get('CARGO_TARGET_DIR', ROOT / 'target'))
    if not target.is_absolute():
        target = ROOT / target
    executable = target / ('debug' if args.debug else 'release') / 'tunnel'
    # Reject accidental Homebrew dynamic OpenSSL dependencies in a portable app.
    linked = subprocess.check_output(['otool', '-L', str(executable)], text=True)
    if any(prefix in line for line in linked.splitlines()[1:] for prefix in ('/opt/homebrew/', '/usr/local/opt/')):
        parser.exit(1, 'App depends on Homebrew dynamic libraries; rebuild with static OpenSSL.\n')
    runtime = ROOT / 'dist/runtime' / env['TUNNEL_PACKAGE_TARGET']
    runtime.mkdir(parents=True, exist_ok=True)
    shutil.copy2(executable, runtime / 'tunnel')
    if not args.no_cores:
        run([sys.executable, ROOT / 'scripts/fetch-cores.py'], cwd=ROOT, env=env)
        for name in ('xray', 'sing-box'):
            run([runtime / 'cores' / name, 'version'], stdout=subprocess.DEVNULL)
    version = package_version((ROOT / 'Cargo.toml').read_text())
    output = ROOT / 'dist/macos'
    output.mkdir(parents=True, exist_ok=True)
    staging = output / 'TunnelNest-build.app'
    if staging.exists():
        shutil.rmtree(staging)
    contents = staging / 'Contents'
    (contents / 'MacOS').mkdir(parents=True)
    (contents / 'Resources').mkdir()
    shutil.copy2(executable, contents / 'MacOS/tunnel')
    if not args.no_cores:
        shutil.copytree(runtime / 'cores', contents / 'Resources/cores')
    licenses = contents / 'Resources/licenses'
    licenses.mkdir()
    for notice in (ROOT / 'desktop/assets').glob('LICENSE-*.txt'):
        shutil.copy2(notice, licenses / notice.name)
    shutil.copy2(ROOT / 'desktop/assets/tunnelnest.icns', contents / 'Resources/tunnelnest.icns')
    info = {
        'CFBundleDevelopmentRegion': 'en', 'CFBundleExecutable': 'tunnel',
        'CFBundleIdentifier': 'org.tunnelnest.rust', 'CFBundleInfoDictionaryVersion': '6.0',
        'CFBundleName': 'TunnelNest', 'CFBundleDisplayName': 'TunnelNest',
        'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': version,
        'CFBundleVersion': version, 'CFBundleIconFile': 'tunnelnest.icns',
        'NSHighResolutionCapable': True, 'NSPrincipalClass': 'NSApplication',
        'LSMinimumSystemVersion': '11.0', 'LSUIElement': False,
    }
    (contents / 'Info.plist').write_bytes(plistlib.dumps(info))
    # Ad-hoc signing is for local builds; it is not Developer ID notarization.
    identity = env.get('MAC_SIGN_IDENTITY', '-')
    for binary in ([] if args.no_cores else [contents / 'Resources/cores/xray', contents / 'Resources/cores/sing-box']):
        command = ['codesign', '--force', '--sign', identity]
        if identity != '-':
            command += ['--timestamp', '--options', 'runtime']
        run(command + [binary])
    bundle_sign = ['codesign', '--force', '--sign', identity]
    if identity != '-':
        bundle_sign += ['--timestamp', '--options', 'runtime']
    run(bundle_sign + [staging])
    run(['codesign', '--verify', '--deep', '--strict', staging])
    app = output / 'TunnelNest.app'
    if app.exists():
        shutil.rmtree(app)
    staging.rename(app)
    archive = output / ('TunnelNest-macos-' + arch + '-' + version + ('-debug' if args.debug else '') + '.zip')
    if archive.exists():
        archive.unlink()
    run(['ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', app, archive])
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    archive.with_suffix(archive.suffix + '.sha256').write_text(digest.hexdigest() + '  ' + archive.name + '\n')
    print('Built app: ' + str(app))
    print('Archive: ' + str(archive))
    print('Signing: ' + ('ad-hoc local development; distribution still requires signing/notarization' if identity == '-' else 'Developer ID; notarization is a separate distribution step'))
    if args.no_cores:
        print('UI-only build: networking cores were explicitly omitted.')
    if args.open:
        run(['open', app])


if __name__ == '__main__':
    main()
