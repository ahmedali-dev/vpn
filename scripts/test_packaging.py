import hashlib
import importlib.util
import os
import pathlib
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import archive
from package_linux import build_package, stage_payload, validate_runtime_arch


class PackagingTests(unittest.TestCase):
    def test_release_build_rejects_unsupported_hosts_before_starting_cargo(self):
        script = pathlib.Path(__file__).with_name('build.py')
        for system, machine in [('Darwin', 'x86_64'), ('Darwin', 'arm64'),
                                ('Linux', 'aarch64'), ('Linux', 'i686'),
                                ('Windows', 'ARM64'), ('Windows', 'x86')]:
            with self.subTest(system=system, machine=machine), \
                    patch('platform.system', return_value=system), \
                    patch('platform.machine', return_value=machine), \
                    patch('subprocess.run') as cargo:
                with self.assertRaisesRegex(SystemExit, 'Release builds require x86_64'):
                    runpy.run_path(str(script), run_name='__main__')
                cargo.assert_not_called()

    def test_native_release_packaging_rejects_arm64(self):
        with self.assertRaisesRegex(ValueError, 'require linux-x64'):
            build_package(self.root, self.root / 'missing-runtime', 'linux-arm64',
                          'arch', '1.2.3', self.root / 'output')

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        (self.root / 'Cargo.toml').write_text('[package]\nname = "tunnelnest"\nversion = "1.2.3"\n')
        (self.root / 'README.md').write_text('Application instructions\n')
        assets = self.root / 'desktop/assets'
        assets.mkdir(parents=True)
        (assets / 'tunnelnest.png').write_bytes(b'icon')
        (assets / 'LICENSE-ui.txt').write_text('UI license notice')

    def runtime(self, target):
        runtime = self.root / 'dist/runtime' / target
        (runtime / 'cores').mkdir(parents=True)
        suffix = '.exe' if target.startswith('win32-') else ''
        for name in ('tunnel', 'cores/xray', 'cores/sing-box'):
            path = runtime / (name + suffix)
            if target.startswith('linux-') and sys.platform == 'linux':
                shutil.copyfile('/bin/true', path)
            else:
                path.write_bytes(b'#!/bin/sh\nexit 0\n')
        (runtime / 'cores/LICENSE-sing-box.txt').write_text('Core license notice')
        (runtime / 'core-manifest.json').write_text('{}')
        return runtime

    def test_linux_architecture_checks_all_three_executables(self):
        for target, machine in [('linux-x64', 62), ('linux-arm64', 183)]:
            runtime = self.runtime(target)
            header = bytearray(64)
            header[:6] = b'\x7fELF\x02\x01'
            header[18:20] = machine.to_bytes(2, 'little')
            for name in ('tunnel', 'cores/xray', 'cores/sing-box'):
                (runtime / name).write_bytes(header)
            validate_runtime_arch(runtime, target)
            for name in ('tunnel', 'cores/xray', 'cores/sing-box'):
                mismatch = header.copy()
                mismatch[18:20] = (183 if machine == 62 else 62).to_bytes(2, 'little')
                (runtime / name).write_bytes(mismatch)
                with self.assertRaisesRegex(ValueError, 'rebuild for the requested architecture'):
                    validate_runtime_arch(runtime, target)
                (runtime / name).write_bytes(header)
            (runtime / 'tunnel').write_bytes(b'not an ELF executable')
            with self.assertRaisesRegex(ValueError, 'not a valid 64-bit Linux ELF'):
                validate_runtime_arch(runtime, target)

    def test_installed_payload_preserves_core_discovery_and_private_program_files(self):
        stage = self.root / 'staged'
        stage_payload(self.root, self.runtime('linux-x64'), stage)
        for name in ('tunnel', 'cores/xray', 'cores/sing-box'):
            path = stage / 'usr/lib/tunnelnest' / name
            self.assertTrue(path.is_file())
            if os.name != 'nt':
                self.assertEqual(path.stat().st_mode & 0o777, 0o755)
        if os.name != 'nt':
            self.assertEqual((stage / 'usr/bin/tunnelnest').stat().st_mode & 0o777, 0o755)
        self.assertTrue((stage / 'usr/lib/tunnelnest/cores/LICENSE-sing-box.txt').is_file())
        self.assertTrue((stage / 'usr/share/doc/tunnelnest-rust/LICENSE-ui.txt').is_file())
        for path in stage.rglob('*'):
            if os.name != 'nt' and not path.is_symlink():
                self.assertEqual(path.stat().st_mode & 0o022, 0, str(path))

    def test_windows_zip_contains_executable_cores_and_valid_checksum(self):
        self.runtime('win32-x64')
        with patch.object(archive, 'ROOT', self.root), patch.object(sys, 'argv', [
            'archive.py', '--target', 'win32-x64', '--version', '1.2.3'
        ]):
            archive.main()
        package, = (self.root / 'dist/release').glob('*.zip')
        with zipfile.ZipFile(package) as zipped:
            names = set(zipped.namelist())
            prefix = 'TunnelNestRust-1.2.3-win32-x64/'
            for name in ('tunnel.exe', 'cores/xray.exe', 'cores/sing-box.exe',
                         'cores/LICENSE-sing-box.txt', 'core-manifest.json', 'RUN.txt'):
                self.assertIn(prefix + name, names)
        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        self.assertEqual(pathlib.Path(str(package) + '.sha256').read_text(),
                         digest + '  ' + package.name + '\n')

    def test_workflow_installer_supports_nested_repository(self):
        spec = importlib.util.spec_from_file_location('installer', pathlib.Path(__file__).with_name('install-workflow.py'))
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        source = (pathlib.Path(__file__).resolve().parents[1] / '.github/workflows/rust-release.yml').read_text()
        nested = installer.render(source, 'apps/Tunnel Nest')
        self.assertNotIn('working-directory: .', nested)
        self.assertNotIn('path: dist/release/*', nested)
        self.assertIn('working-directory: "apps/Tunnel Nest"', nested)
        self.assertEqual(installer.render(source, ''), source)

    @unittest.skipUnless(sys.platform == 'linux' and os.environ.get('TUNNELNEST_TEST_DISTRO'),
                         'Native package inspection runs in the matching Linux CI container')
    def test_native_package_can_be_read_by_distribution_package_manager(self):
        distro = os.environ['TUNNELNEST_TEST_DISTRO']
        target = os.environ.get('TUNNEL_PACKAGE_TARGET', 'linux-x64')
        output = self.root / 'output'
        output.mkdir()
        package = build_package(self.root, self.runtime(target), target, distro, '1.2.3', output)
        if distro == 'ubuntu-24.04':
            metadata = subprocess.check_output(['dpkg-deb', '--field', str(package)], text=True)
            data = subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(package)])
            import io
            with tarfile.open(fileobj=io.BytesIO(data)) as contents:
                names = contents.getnames()
                for member in contents:
                    self.assertEqual((member.uid, member.gid), (0, 0))
        elif distro == 'fedora-44':
            metadata = subprocess.check_output(['rpm', '-qpi', str(package)], text=True)
            names = subprocess.check_output(['rpm', '-qpl', str(package)], text=True)
            owners = subprocess.check_output(['rpm', '-qp', '--queryformat', '[%{FILEUSERNAME}:%{FILEGROUPNAME}\n]', str(package)], text=True)
            self.assertTrue(all(owner == 'root:root' for owner in owners.splitlines()))
        else:
            metadata = subprocess.check_output(['bsdtar', '-xOf', str(package), '.PKGINFO'], text=True)
            names = subprocess.check_output(['bsdtar', '-tf', str(package)], text=True)
        self.assertIn('1.2.3', metadata)
        self.assertIn('usr/bin/tunnelnest', '\n'.join(names) if isinstance(names, list) else names)
        self.assertIn('usr/lib/tunnelnest/cores/sing-box', '\n'.join(names) if isinstance(names, list) else names)
        self.assertTrue(pathlib.Path(str(package) + '.sha256').is_file())


if __name__ == '__main__':
    unittest.main()
