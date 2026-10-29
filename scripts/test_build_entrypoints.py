"""Exercise dependency/build orchestration with fake package managers; never install anything."""
import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent


@unittest.skipIf(os.name == 'nt', 'Bash dependency orchestration tests run on Unix')
class BuildEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.scripts = self.root / 'scripts'
        self.scripts.mkdir()
        self.release = self.root / 'os-release'
        for script in SCRIPTS.glob('build_for_*.sh'):
            text = script.read_text().replace('/etc/os-release', str(self.release))
            (self.scripts / script.name).write_text(text)
        self.log = self.root / 'commands'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        MOCK_LOG=str(self.log), MOCK_STATE=str(self.root / 'installed'),
                        MOCK_MACHINE='x86_64', MOCK_MISSING='', MOCK_RUST='ready',
                        CARGO_HOME=str(self.root / 'cargo'))
        self.stub('uname', 'case "$1" in -s) echo Linux;; -m) echo "$MOCK_MACHINE";; esac')
        self.stub('sudo', 'exec "$@"')
        self.stub('rustup', '''
if [[ "$1" == run ]]; then
  [[ "$MOCK_RUST" == ready || -f "$MOCK_STATE.rust" ]]
else
  echo "rustup $*" >> "$MOCK_LOG"
  touch "$MOCK_STATE.rust"
fi''')
        self.stub('dpkg-query', '''
if [[ "${@: -1}" != "$MOCK_MISSING" || -f "$MOCK_STATE" ]]; then echo 'install ok installed'; else exit 1; fi''')
        self.stub('rpm', '[[ "${@: -1}" != "$MOCK_MISSING" || -f "$MOCK_STATE" ]]')
        self.stub('pacman', '''
if [[ "$1" == -Q ]]; then
  [[ "$2" != "$MOCK_MISSING" || -f "$MOCK_STATE" ]]
else
  echo "pacman $*" >> "$MOCK_LOG"
  touch "$MOCK_STATE"
fi''')
        for manager in ('apt-get', 'dnf'):
            self.stub(manager, 'echo "' + manager + ' $*" >> "$MOCK_LOG"\ntouch "$MOCK_STATE"')
        self.stub('python3', '''
echo "python3 $*" >> "$MOCK_LOG"
if [[ "$1" == -c ]]; then echo 1.3.0; fi''')

    def stub(self, name, body):
        path = self.bin / name
        path.write_text('#!/usr/bin/env bash\nset -euo pipefail\n' + body + '\n')
        path.chmod(0o755)

    def run_script(self, distro='ubuntu', args=(), script='build_for_all.sh'):
        version = {'ubuntu': '24.04', 'fedora': '44', 'arch': ''}[distro]
        self.release.write_text(f'ID={distro}\nVERSION_ID={version}\n')
        return subprocess.run(['bash', str(self.scripts / script), *args], env=self.env,
                              capture_output=True, text=True)

    def test_check_only_reports_missing_dependencies_without_installing_or_building(self):
        for distro in ('ubuntu', 'fedora', 'arch'):
            with self.subTest(distro=distro):
                self.env.update(MOCK_MISSING='git', MOCK_RUST='missing')
                result = self.run_script(distro, ['--check'])
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('git', result.stdout)
                self.assertIn('Rust stable', result.stdout)
                self.assertFalse(self.log.exists())

    def test_ready_check_is_successful_without_building(self):
        result = self.run_script(args=['--check'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.log.exists())

    def test_missing_dependencies_are_installed_before_fetch_build_and_package(self):
        for distro, manager, package_format in [('ubuntu', 'apt-get', 'ubuntu-24.04'),
                                               ('fedora', 'dnf', 'fedora-44'),
                                               ('arch', 'pacman', 'arch')]:
            with self.subTest(distro=distro):
                self.env.update(MOCK_MISSING='git', MOCK_RUST='missing')
                result = self.run_script(distro)
                self.assertEqual(result.returncode, 0, result.stderr)
                commands = self.log.read_text()
                self.assertLess(commands.index(manager), commands.index('scripts/fetch-cores.py'))
                self.assertLess(commands.index('rustup toolchain install stable'), commands.index('scripts/build.py'))
                self.assertLess(commands.index('scripts/build.py'), commands.index('scripts/archive.py'))
                self.assertIn('--distro ' + package_format, commands)
                self.assertIn('--native-package', commands)
                self.log.unlink()
                pathlib.Path(self.env['MOCK_STATE']).unlink()
                pathlib.Path(self.env['MOCK_STATE'] + '.rust').unlink()

    def test_arm64_ubuntu_uses_matching_core_and_package_target(self):
        self.env['MOCK_MACHINE']='aarch64'
        result=self.run_script()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('--target linux-arm64',self.log.read_text())

    def test_unsupported_architecture_and_wrong_distro_stop_before_installation(self):
        self.env['MOCK_MACHINE'] = 'i686'
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('x86_64', result.stderr)
        self.env['MOCK_MACHINE'] = 'x86_64'
        result = self.run_script('fedora', script='build_for_ubuntu.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('requires ubuntu', result.stderr)
        self.assertFalse(self.log.exists())


if __name__ == '__main__':
    unittest.main()
