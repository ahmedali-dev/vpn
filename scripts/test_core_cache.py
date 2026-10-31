"""A restored core cache must still match trusted release metadata; no network."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile


class CoreCacheTests(unittest.TestCase):
    def test_valid_restored_archive_is_reverified_and_corruption_is_rejected(self):
        path=Path(__file__).with_name('fetch-cores.py')
        spec=importlib.util.spec_from_file_location('core_cache_fixture',path)
        fetcher=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fetcher)
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as file:
            file.writestr('xray','fixture binary')
        data=archive.getvalue()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            cache=root/'cache'
            cache.mkdir()
            file=cache/'fixture.zip'
            file.write_bytes(data)
            asset={'digest':'sha256:'+hashlib.sha256(data).hexdigest(),'browser_download_url':'https://example.invalid/never-requested'}
            task=('linux-x64','XTLS/Xray-core','fixture.zip',asset)
            with mock.patch.dict(os.environ,{'TUNNEL_CORE_CACHE_DIR':str(cache)}), mock.patch.object(fetcher,'ROOT',root), mock.patch.object(fetcher,'get',side_effect=AssertionError('unexpected network access')):
                manifest=fetcher.fetch(task)
                self.assertEqual(manifest['sha256'],hashlib.sha256(data).hexdigest())
                self.assertEqual((root/'dist/runtime/linux-x64/cores/xray').read_text(),'fixture binary')
                file.write_bytes(b'corrupted cached data')
                with self.assertRaisesRegex(RuntimeError,'Checksum mismatch'):
                    fetcher.fetch(task)
