#!/usr/bin/env python3
"""Package the native Rust app and networking cores for a GitHub release."""
import argparse
import hashlib
import pathlib
import shutil
import tarfile
import tempfile
from version import VERSION, package_version

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = ('linux-x64', 'linux-arm64', 'win32-x64')
DISTROS = ('ubuntu-24.04', 'fedora-44', 'arch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, choices=TARGETS)
    parser.add_argument('--version', required=True)
    parser.add_argument('--distro', choices=DISTROS, help='Linux distribution used for this build')
    parser.add_argument('--native-package', action='store_true', help='Also build a DEB, RPM, or Arch package using this Linux host\'s package tools')
    args = parser.parse_args()
    if args.distro and not args.target.startswith('linux-'):
        parser.error('--distro applies only to Linux builds')
    if args.native_package and (not args.distro or not args.target.startswith('linux-')):
        parser.error('--native-package requires a Linux --target and --distro')
    if not VERSION.fullmatch(args.version):
        parser.error('Version must be X.Y.Z')
    if package_version((ROOT / 'Cargo.toml').read_text()) != args.version:
        parser.error('Requested version differs from Cargo.toml')
    runtime = ROOT / 'dist/runtime' / args.target
    suffix = '.exe' if args.target.startswith('win32-') else ''
    for path in (runtime / ('tunnel' + suffix), runtime / 'cores' / ('xray' + suffix),
                 runtime / 'cores' / ('sing-box' + suffix), runtime / 'core-manifest.json'):
        if not path.is_file():
            parser.error('Missing build/core artifact: ' + str(path))
    output = ROOT / 'dist/release'
    output.mkdir(parents=True, exist_ok=True)
    label = args.distro + '-' + args.target.removeprefix('linux-') if args.distro else args.target
    name = 'TunnelNestRust-' + args.version + '-' + label
    with tempfile.TemporaryDirectory(prefix='release-', dir=ROOT / 'dist') as temporary:
        stage = pathlib.Path(temporary) / name
        stage.mkdir()
        shutil.copytree(runtime, stage, dirs_exist_ok=True, symlinks=True)
        shutil.copy2(ROOT / 'README.md', stage / 'README.md')
        if args.target.startswith('linux-'):
            commands = {
                'ubuntu-24.04': 'sudo apt install libgtk-3-0t64 libwebkit2gtk-4.1-0 libssl3t64 libdbus-1-3 pkexec',
                'fedora-44': 'sudo dnf install gtk3 webkit2gtk4.1 openssl-libs dbus-libs polkit',
                'arch': 'sudo pacman -S gtk3 webkit2gtk-4.1 openssl dbus polkit',
            }
            launch = ('Linux: run ./tunnel --desktop. Built for ' + (args.distro or 'the build host')
                      + '; requires GTK 3, WebKitGTK 4.1, OpenSSL, and D-Bus.\n')
            if args.distro:
                launch += 'Install runtime dependencies: ' + commands[args.distro] + '\n'
            if args.distro == 'arch':
                launch += 'Arch is rolling; update the system before running this build.\n'
        else:
            launch = 'Windows: open tunnel.exe (requires Microsoft WebView2 Runtime).\n'
        (stage / 'RUN.txt').write_text(
            'TunnelNest Rust ' + args.version + ' — ' + label + '\n\n' + launch +
            'CLI: tunnel -ui or tunnel --help. Keep the cores folder beside tunnel.\n'
            'Profiles are separate from the Go app; transfer them with share codes/files.\n'
            'These builds are unsigned. Native authorization and actual TUN routing '
            'still require testing on the target OS.\n', encoding='utf-8')
        if args.target.startswith('linux-'):
            archive = output / (name + '.tar.gz')
            with tarfile.open(archive, 'w:gz') as tar:
                tar.add(stage, arcname=name)
        else:
            archive = pathlib.Path(shutil.make_archive(str(output / name), 'zip',
                                                      temporary, name))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    pathlib.Path(str(archive) + '.sha256').write_text(digest + '  ' + archive.name + '\n')
    print('Packaged ' + str(archive))
    if args.native_package:
        from package_linux import build_package
        build_package(ROOT, runtime, args.target, args.distro, args.version, output)


if __name__ == '__main__':
    main()
