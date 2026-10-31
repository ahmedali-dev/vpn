import json
from pathlib import Path
import tempfile
import unittest
import acceptance_status as acceptance

class EvidenceTests(unittest.TestCase):
    def test_no_reports_never_count_as_complete(self):
        with tempfile.TemporaryDirectory() as d:
            result=acceptance.assess(Path(d))
            self.assertFalse(result['complete'])
            self.assertTrue(any(c['status']=='missing' for c in result['checks']))
    def test_complete_fixture_retains_operator_scope_and_rejects_failed_soak(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            def write(path,value):
                file=root/path;file.parent.mkdir(parents=True,exist_ok=True);file.write_text(json.dumps(value))
            for label in ('before','connected','after'):
                write('normal/'+label+'.json',{'pass':True,'tunAddressRemains':False,'cleanupInspectionSucceeded':True})
            for scenario in acceptance.SCENARIOS:
                write(scenario+'/summary.json',dict(samples=5,failedSamples=0,unrecoveredFailure=False,interrupted=False))
            write('operator.json',dict(osVersion='Windows 11 fixture',architecture='x64',appVersion='test',mode='ssh',routing='tun',**{k:True for k in acceptance.MANUAL}))
            self.assertTrue(acceptance.assess(root)['complete'])
            write('core-crash/summary.json',dict(samples=5,failedSamples=1,unrecoveredFailure=False,interrupted=False))
            self.assertFalse(acceptance.assess(root)['complete'])
            write('normal/after.json',{'pass':True})
            self.assertTrue(any(v['check']=='after' and v['status']=='failed' for v in acceptance.assess(root)['checks']))
