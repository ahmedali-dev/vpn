#!/usr/bin/env python3
"""Build the Rust application and its native desktop runtime."""
import os
import pathlib
import platform
import shutil
import subprocess
from version import package_version

ROOT = pathlib.Path(__file__).resolve().parents[1]
version = package_version((ROOT / 'Cargo.toml').read_text())
system = {'Darwin': 'darwin', 'Linux': 'linux', 'Windows': 'win32'}[platform.system()]
arch = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'x64', 'AMD64': 'x64'}[platform.machine()]
key = f'{system}-{arch}'
requested = os.environ.get('TUNNEL_PACKAGE_TARGET', key)
if requested != key:
    raise SystemExit(f'This script builds natively ({key}). Build {requested} on its matching runner.')
build = ['cargo', 'build', '--release', '--locked']
if os.environ.get('TUNNELNEST_CLI_ONLY') != '1':
    build += ['--features', 'desktop']
subprocess.run(build, cwd=ROOT, check=True)
name = 'tunnel.exe' if system == 'win32' else 'tunnel'
target_dir = pathlib.Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target'))
if not target_dir.is_absolute():
    target_dir = ROOT / target_dir
runtime = ROOT / 'dist' / 'runtime' / key
runtime.mkdir(parents=True, exist_ok=True)
shutil.copy2(target_dir / 'release' / name, runtime / name)
print(f'Built {runtime / name}')

# A native macOS app bundle can be launched directly from Finder.
if system == 'darwin' and os.environ.get('TUNNELNEST_CLI_ONLY') != '1':
    import plistlib
    bundle = ROOT / 'dist' / 'TunnelNest Rust.app'
    contents = bundle / 'Contents'
    macos = contents / 'MacOS'
    resources = contents / 'Resources'
    macos.mkdir(parents=True, exist_ok=True)
    resources.mkdir(parents=True, exist_ok=True)
    shutil.copy2(runtime / name, macos / name)
    if (runtime / 'cores').exists():
        shutil.copytree(runtime / 'cores', macos / 'cores', dirs_exist_ok=True)
    shutil.copy2(ROOT / 'desktop/assets/tunnelnest.icns', resources / 'tunnelnest.icns')
    (contents / 'Info.plist').write_bytes(plistlib.dumps({
        'CFBundleName': 'TunnelNest Rust',
        'CFBundleDisplayName': 'TunnelNest Rust',
        'CFBundleIdentifier': 'org.tunnelnest.rust',
        'CFBundleExecutable': name,
        'CFBundleIconFile': 'tunnelnest.icns',
        'CFBundlePackageType': 'APPL',
        'CFBundleShortVersionString': version,
        'CFBundleVersion': version,
        'NSHighResolutionCapable': True,
        'LSMinimumSystemVersion': '11.0',
    }))
    print(f'Built {bundle}')
