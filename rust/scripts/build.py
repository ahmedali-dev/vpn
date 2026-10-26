#!/usr/bin/env python3
"""Build the Rust application and its native desktop runtime."""
import os
import pathlib
import platform
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
system = {'Linux': 'linux', 'Windows': 'win32'}.get(platform.system())
if system is None or platform.machine().lower() not in ('x86_64', 'amd64'):
    raise SystemExit('Release builds require x86_64 Windows or Linux (Ubuntu, Fedora, or Arch). '
                     'Run this script on the matching native runner; macOS, ARM64, and 32-bit hosts are unsupported.')
arch = 'x64'
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
