"""Exercise publishing against disposable local Git remotes; never contact GitHub."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import push_and_build as publish
import version as versions


@unittest.skipUnless(shutil.which('git'), 'Git required for local repository fixtures')
class PublishTests(unittest.TestCase):
    def git(self, *args, root=None):
        return subprocess.check_output(['git', '-C', str(root or self.root), *args], text=True,
                                       stderr=subprocess.DEVNULL).strip()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'project'
        self.root.mkdir()
        self.remote = Path(self.temp.name) / 'remote.git'
        subprocess.run(['git','init','--bare',str(self.remote)], check=True, capture_output=True)
        self.git('init', '--initial-branch=main')
        self.git('config','user.name','Fixture')
        self.git('config','user.email','fixture@example.invalid')
        self.git('config','commit.gpgsign','false')
        self.git('config','tag.gpgsign','false')
        (self.root/'Cargo.toml').write_text('[package]\nname = "tunnelnest"\nversion = "1.0.0"\n')
        (self.root/'Cargo.lock').write_text('[[package]]\nname = "tunnelnest"\nversion = "1.0.0"\n')
        (self.root/'desktop').mkdir()
        (self.root/'desktop/package.json').write_text('{"version":"1.0.0"}')
        (self.root/'desktop/package-lock.json').write_text('{"version":"1.0.0","packages":{"":{"version":"1.0.0"}}}')
        workflow=self.root/'.github/workflows/rust-release.yml'
        workflow.parent.mkdir(parents=True)
        workflow.write_text('name: fixture\non: workflow_dispatch\n')
        self.git('add','.')
        self.git('commit','-m','initial fixture')
        self.git('remote','add','origin',str(self.remote))
        self.git('push','origin','main')
        for target, name in [(publish,'ROOT'),(versions,'ROOT')]:
            patch=mock.patch.object(target,name,self.root);patch.start();self.addCleanup(patch.stop)
        self.commands=[]
        real_run=publish.run
        def fake_run(*args, **kwargs):
            self.commands.append(args)
            if args[0]=='gh':
                if args[1:3]==('repo','view'):
                    value=json.dumps({'nameWithOwner':'fixture/repo','url':'https://github.com/fixture/repo'})
                else:
                    value=''
                return subprocess.CompletedProcess(args,0,value,'')
            return real_run(*args,**kwargs)
        patch=mock.patch.object(publish,'run',side_effect=fake_run);patch.start();self.addCleanup(patch.stop)
        real_which=shutil.which
        patch=mock.patch.object(publish.shutil,'which',side_effect=lambda name: 'fake-gh' if name=='gh' else real_which(name))
        patch.start();self.addCleanup(patch.stop)
        output=contextlib.redirect_stdout(io.StringIO());output.__enter__();self.addCleanup(output.__exit__,None,None,None)

    def test_empty_branch_defaults_to_main_and_version_is_checked(self):
        with mock.patch('builtins.input',side_effect=['','v1.2.3']):
            self.assertEqual(publish.read_inputs(),('main','1.2.3'))
        for invalid in ['','1.2','1.02.3','1.2.3;echo unsafe']:
            with self.assertRaises(ValueError):publish.read_inputs('main',invalid)

    def test_dry_run_does_not_write_commit_push_or_dispatch(self):
        before=self.git('rev-parse','HEAD')
        publish.execute('new-branch','1.2.3',dry_run=True)
        self.assertEqual(self.git('rev-parse','HEAD'),before)
        self.assertIn('1.0.0',(self.root/'Cargo.toml').read_text())
        self.assertFalse(any(c[0]=='gh' or 'push' in c or 'switch' in c for c in self.commands))

    def test_new_branch_commits_changes_updates_all_versions_pushes_then_dispatches(self):
        (self.root/'new-feature.txt').write_text('fixture update')
        publish.execute('feature/fixture','1.2.3')
        self.assertEqual(self.git('branch','--show-current'),'feature/fixture')
        self.assertEqual(self.git('show','feature/fixture:new-feature.txt',root=self.remote),'fixture update')
        self.assertIn('version = "1.2.3"',self.git('show','feature/fixture:Cargo.toml',root=self.remote))
        self.assertIn('version = "1.2.3"',self.git('show','feature/fixture:Cargo.lock',root=self.remote))
        lock=json.loads(self.git('show','feature/fixture:desktop/package-lock.json',root=self.remote))
        self.assertEqual(lock['packages']['']['version'],'1.2.3')
        dispatch=[i for i,c in enumerate(self.commands) if c[:3]==('gh','workflow','run')]
        push=[i for i,c in enumerate(self.commands) if 'push' in c]
        self.assertLess(push[0],dispatch[0])
        self.assertEqual(self.commands[dispatch[0]][-2:],('--ref','feature/fixture'))
        self.assertFalse(any('--force' in c for c in self.commands))

    def test_remote_only_branch_is_used_instead_of_created_from_wrong_head(self):
        self.git('switch','-c','existing')
        (self.root/'remote-only.txt').write_text('keep branch history')
        self.git('add','.')
        self.git('commit','-m','remote branch fixture')
        self.git('push','origin','existing')
        self.git('switch','main')
        self.git('branch','-D','existing')
        publish.execute('existing','1.2.3')
        self.assertEqual((self.root/'remote-only.txt').read_text(),'keep branch history')

    def test_release_pushes_tag_atomically_and_refuses_reusing_it(self):
        publish.execute('main','1.2.3',release=True)
        self.assertEqual(self.git('rev-parse','main',root=self.remote),self.git('rev-parse','rust-v1.2.3^{}',root=self.remote))
        self.assertTrue(any('push' in c and '--atomic' in c for c in self.commands))
        self.assertFalse(any(c[:3]==('gh','workflow','run') for c in self.commands))
        head=self.git('rev-parse','HEAD')
        with self.assertRaisesRegex(ValueError,'already exists'):
            publish.execute('main','1.2.3',release=True)
        self.assertEqual(self.git('rev-parse','HEAD'),head)

    def test_invalid_branch_is_rejected_before_metadata_changes(self):
        with self.assertRaises(publish.CommandError):publish.execute('--unsafe','1.2.3')
        self.assertIn('1.0.0',(self.root/'Cargo.toml').read_text())

    def test_dispatch_failure_keeps_successful_push_and_reports_retry(self):
        base_run=publish.run
        def fail_dispatch(*args,**kwargs):
            if args[:3]==('gh','workflow','run'):raise publish.CommandError('fixture dispatch failed')
            return base_run(*args,**kwargs)
        with mock.patch.object(publish,'run',side_effect=fail_dispatch):
            with self.assertRaisesRegex(publish.CommandError,'The push succeeded.*'):
                publish.execute('main','1.2.3')
        self.assertEqual(self.git('rev-parse','main',root=self.remote),self.git('rev-parse','HEAD'))

    def test_remote_changes_are_not_overwritten_and_dispatch_is_not_started_after_rejection(self):
        other=self.root.parent/'other'
        subprocess.run(['git','clone','--branch','main',str(self.remote),str(other)],check=True,capture_output=True)
        self.git('config','user.name','Fixture',root=other)
        self.git('config','user.email','fixture@example.invalid',root=other)
        self.git('config','commit.gpgsign','false',root=other)
        (other/'remote-change.txt').write_text('must survive')
        self.git('add','.',root=other)
        self.git('commit','-m','parallel update',root=other)
        self.git('push','origin','main',root=other)
        remote_head=self.git('rev-parse','main',root=self.remote)
        with self.assertRaises(publish.CommandError):publish.execute('main','1.2.3')
        self.assertEqual(self.git('rev-parse','main',root=self.remote),remote_head)
        self.assertFalse(any(c[:3]==('gh','workflow','run') for c in self.commands))

    def test_rerunning_same_version_dispatches_without_an_empty_commit(self):
        publish.execute('main','1.2.3')
        head=self.git('rev-parse','HEAD')
        self.commands.clear()
        publish.execute('main','1.2.3')
        self.assertEqual(self.git('rev-parse','HEAD'),head)
        self.assertFalse(any('commit' in c for c in self.commands))
        self.assertTrue(any(c[:3]==('gh','workflow','run') for c in self.commands))
