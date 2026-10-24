"""Create native distro packages from a previously built Linux runtime."""
import hashlib
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile

NAME = 'tunnelnest-rust'
DEPS = {
    'ubuntu-24.04': ['libc6', 'libgcc-s1', 'libstdc++6', 'libgtk-3-0t64', 'libwebkit2gtk-4.1-0', 'libssl3t64', 'libdbus-1-3', 'pkexec'],
    'fedora-44': ['gtk3', 'webkit2gtk4.1', 'openssl-libs', 'dbus-libs', 'polkit'],
    'arch': ['gtk3', 'webkit2gtk-4.1', 'openssl', 'dbus', 'polkit'],
}


def validate_runtime_arch(runtime, target):
    expected = {'linux-x64': 62, 'linux-arm64': 183}[target]
    for name in ('tunnel', 'cores/xray', 'cores/sing-box'):
        path = runtime / name
        with path.open('rb') as stream:
            header = stream.read(20)
        if (len(header) < 20 or header[:5] != b'\x7fELF\x02'
                or header[5] not in (1, 2)):
            raise ValueError(f'{path} is not a valid 64-bit Linux ELF executable')
        machine = int.from_bytes(header[18:20], 'little' if header[5] == 1 else 'big')
        if machine != expected:
            raise ValueError(f'{path} has ELF machine {machine}, but {target} requires {expected}; rebuild for the requested architecture')


def stage_payload(root, runtime, destination):
    """Keep cores beside the executable so discovery works after installation."""
    app = destination / 'usr/lib/tunnelnest'
    shutil.copytree(runtime, app, symlinks=True)
    for name in ('tunnel', 'cores/xray', 'cores/sing-box'):
        (app / name).chmod(0o755)
    launcher = destination / 'usr/bin/tunnelnest'
    launcher.parent.mkdir(parents=True)
    launcher.write_text('#!/bin/sh\nexec /usr/lib/tunnelnest/tunnel "$@"\n')
    launcher.chmod(0o755)
    desktop = destination / 'usr/share/applications/org.tunnelnest.rust.desktop'
    desktop.parent.mkdir(parents=True)
    desktop.write_text('[Desktop Entry]\nType=Application\nName=TunnelNest\n'
                       'Comment=SSH over TLS and V2Ray tunnel\nExec=tunnelnest --desktop\n'
                       'Icon=tunnelnest\nTerminal=false\nCategories=Network;\n')
    icon = destination / 'usr/share/pixmaps/tunnelnest.png'
    icon.parent.mkdir(parents=True)
    shutil.copy2(root / 'desktop/assets/tunnelnest.png', icon)
    docs = destination / ('usr/share/doc/' + NAME)
    docs.mkdir(parents=True)
    shutil.copy2(root / 'README.md', docs / 'README.md')
    # Static assets also contain third-party notices used by the embedded UI.
    for notice in (root / 'desktop/assets').glob('LICENSE*.txt'):
        shutil.copy2(notice, docs / notice.name)
    # Normalize modes; checkout/copy permissions must not make installed files
    # writable by ordinary users or make documentation executable.
    for path in destination.rglob('*'):
        if path.is_symlink():
            continue
        path.chmod(0o755 if path.is_dir() or path in (launcher, app / 'tunnel', app / 'cores/xray', app / 'cores/sing-box') else 0o644)


def checksum(path):
    with path.open('rb') as stream:
        hasher = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            hasher.update(chunk)
        digest = hasher.hexdigest()
    pathlib.Path(str(path) + '.sha256').write_text(digest + '  ' + path.name + '\n')


def build_package(root, runtime, target, distro, version, output):
    if not target.startswith('linux-') or distro not in DEPS:
        raise ValueError('Native packages require a Linux target and distribution')
    validate_runtime_arch(runtime, target)
    arch = {'linux-x64': 'x86_64', 'linux-arm64': 'aarch64'}[target]
    output = output.resolve()
    with tempfile.TemporaryDirectory(prefix='tunnelnest-package-') as temporary:
        work = pathlib.Path(temporary)
        payload = work / 'payload'
        stage_payload(root, runtime, payload)
        if distro == 'ubuntu-24.04':
            deb_arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[arch]
            control = payload / 'DEBIAN/control'
            control.parent.mkdir()
            size = sum(p.stat().st_size for p in payload.rglob('*') if p.is_file())
            control.write_text(f'Package: {NAME}\nVersion: {version}-1\nArchitecture: {deb_arch}\n'
                               'Maintainer: TunnelNest maintainers\nSection: net\nPriority: optional\n'
                               f'Installed-Size: {(size + 1023) // 1024}\nDepends: {", ".join(DEPS[distro])}\n'
                               'Description: TunnelNest native Rust desktop and tunnel engine\n'
                               ' Includes the Xray and sing-box networking cores.\n')
            control.chmod(0o644)
            package = output / f'{NAME}_{version}-1_ubuntu24.04_{deb_arch}.deb'
            subprocess.run(['dpkg-deb', '--build', '--root-owner-group', str(payload), str(package)], check=True)
        elif distro == 'fedora-44':
            top = work / 'rpm'
            for directory in ('BUILD', 'BUILDROOT', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS'):
                (top / directory).mkdir(parents=True)
            with tarfile.open(top / 'SOURCES/payload.tar.gz', 'w:gz') as archive:
                archive.add(payload / 'usr', arcname='usr')
            spec = top / 'SPECS/tunnelnest.spec'
            spec.write_text(f'''Name: {NAME}
Version: {version}
Release: 1.fc44
Summary: TunnelNest native Rust desktop and tunnel engine
License: LicenseRef-TunnelNest AND MPL-2.0 AND GPL-3.0-or-later
BuildArch: {arch}
Source0: payload.tar.gz
Requires: {', '.join(DEPS[distro])}
%global debug_package %{{nil}}
# Prebuilt, already stripped Rust/Go executables: do not rewrite bundled cores.
%global __os_install_post %{{nil}}

%description
TunnelNest desktop with the Xray and sing-box networking cores.

%prep

%build

%install
mkdir -p "%{{buildroot}}"
tar -xzf "%{{SOURCE0}}" -C "%{{buildroot}}"

%files
%defattr(-,root,root,-)
/usr/bin/tunnelnest
/usr/lib/tunnelnest
/usr/share/applications/org.tunnelnest.rust.desktop
/usr/share/pixmaps/tunnelnest.png
%doc /usr/share/doc/{NAME}
''')
            subprocess.run(['rpmbuild', '-bb', '--define', '_topdir ' + str(top), str(spec)], check=True)
            built, = (top / 'RPMS').rglob('*.rpm')
            package = output / built.name
            shutil.copy2(built, package)
        else:
            # makepkg supplies .PKGINFO/.BUILDINFO/.MTREE and root ownership.
            # It refuses root, including inside CI's root-owned containers.
            (work / 'PKGBUILD').write_text(f'''pkgname={NAME}
pkgver={version}
pkgrel=1
pkgdesc='TunnelNest native Rust desktop with Xray and sing-box'
arch=('{arch}')
license=('LicenseRef-TunnelNest' 'MPL-2.0' 'GPL-3.0-or-later')
depends=({' '.join(repr(d) for d in DEPS[distro])})
options=('!strip' '!debug')
source=()
sha256sums=()
package() {{
    cp -a --no-preserve=ownership "$startdir/payload/." "$pkgdir/"
}}
''')
            command = ['makepkg', '--force', '--noconfirm', '--nodeps', 'PKGEXT=.pkg.tar.zst']
            if os.geteuid() == 0:
                import pwd
                account = pwd.getpwnam('nobody')
                work.chmod(0o755)
                for path in (work, *work.rglob('*')):
                    os.chown(path, account.pw_uid, account.pw_gid, follow_symlinks=False)
                command = ['runuser', '-u', 'nobody', '--', *command]
            subprocess.run(command, cwd=work, check=True)
            built, = work.glob('*.pkg.tar.zst')
            package = output / built.name
            shutil.copy2(built, package)
    checksum(package)
    print('Packaged ' + str(package))
    return package
