import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('survey',ROOT/'tools/permission_survey/survey.py')
survey=importlib.util.module_from_spec(spec);spec.loader.exec_module(survey)

class SurveyTests(unittest.TestCase):
    def test_placeholders(self):
        for value in ('', '00000000-0000-0000-0000-000000000000', 'To Be Filled By O.E.M.', 'none'):
            self.assertEqual(survey.value_status(value),'empty_or_placeholder')
    def test_lsblk_never_returns_value(self):
        class Done:
            stdout=json.dumps({'blockdevices':[{'type':'disk','serial':'PRIVATE_SERIAL','wwn':None,'children':[{'type':'part','uuid':'PRIVATE_UUID'}]}]})
        with patch.object(survey.subprocess,'run',return_value=Done()): result=survey.lsblk()
        self.assertEqual(result['disk_serial'],'available');self.assertEqual(result['filesystem_uuid'],'available')
        self.assertEqual(result['disk_wwn'],'unavailable_or_unsupported')
        self.assertNotIn('PRIVATE_',json.dumps(result))
    def test_combined_classification(self):
        rows=[{'access_level':'runner-user','signals':{'x':'available','y':'permission_denied','z':'absent'}},
              {'access_level':'isolated-user','signals':{'x':'available','y':'permission_denied','z':'absent'}},
              {'access_level':'root','signals':{'x':'available','y':'available','z':'absent'}}]
        with tempfile.TemporaryDirectory() as d:
            names=[]
            for i,row in enumerate(rows):
                path=Path(d)/f'{i}.json';path.write_text(json.dumps(row));names.append(str(path))
            out=subprocess.run([sys.executable,str(ROOT/'tools/permission_survey/combine.py'),*names],capture_output=True,text=True,check=True)
        result=json.loads(out.stdout)
        self.assertEqual(result['classification']['x'],'readable_by_both_unprivileged_users')
        self.assertEqual(result['classification']['y'],'root_only_on_this_runner')
        self.assertEqual(result['classification']['z'],'unavailable_or_unverified_on_this_runner')
        self.assertEqual(result['schema_version'],2)

class NativeSurveyTests(unittest.TestCase):
    def invoke(self, expected, data):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input.json'
            path.write_text(data, encoding='utf-8')
            return subprocess.run([sys.executable,str(ROOT/'tools/permission_survey/validate_native.py'),expected,str(path)], capture_output=True,text=True)

    def test_fixed_native_schema_and_privacy(self):
        samples=[('windows',{'schema_version':1,'platform':'windows','architecture':'x86_64','privilege':'not_elevated',
                 'firmware':'ok','signals':{'product_uuid':'present','system_serial':'placeholder','board_serial':'ambiguous','machine_guid_metadata':'string_type_only'}}),
                 ('macos',{'schema_version':1,'platform':'macos','architecture':'arm64','privilege':'nonroot',
                 'platform_service':'found','signals':{'platform_uuid_property':'string_type_only','platform_serial_property':'unavailable_or_denied'}})]
        for system, sample in samples:
            with self.subTest(system=system):
                result=self.invoke(system,json.dumps(sample));self.assertEqual(result.returncode,0,result.stderr)
                parsed=json.loads(result.stdout);self.assertEqual(parsed['signals'],sample['signals'])
                self.assertIn('os_version',parsed)
                sample['raw_identifier']='PRIVATE_MARKER_MUST_NOT_LEAK'
                result=self.invoke(system,json.dumps(sample));self.assertNotEqual(result.returncode,0)
                self.assertNotIn('PRIVATE_MARKER',result.stdout+result.stderr)
                del sample['raw_identifier']
                field=next(iter(sample['signals']))
                sample['signals'][field]='PRIVATE_MARKER_MUST_NOT_LEAK'
                result=self.invoke(system,json.dumps(sample));self.assertNotEqual(result.returncode,0)
                self.assertNotIn('PRIVATE_MARKER',result.stdout+result.stderr)

    def test_duplicate_fields_and_inconsistent_status_rejected(self):
        result=self.invoke('macos','{"platform":"macos","platform":"PRIVATE_MARKER"}')
        self.assertNotEqual(result.returncode,0);self.assertNotIn('PRIVATE_MARKER',result.stdout+result.stderr)
        sample={'schema_version':1,'platform':'windows','architecture':'x86_64','privilege':'unknown','firmware':'read_error',
                'signals':{'product_uuid':'present','system_serial':'not_checked','board_serial':'not_checked','machine_guid_metadata':'absent'}}
        self.assertNotEqual(self.invoke('windows',json.dumps(sample)).returncode,0)
        result=self.invoke('macos','x'*5000+'PRIVATE_MARKER')
        self.assertNotEqual(result.returncode,0);self.assertNotIn('PRIVATE_MARKER',result.stdout+result.stderr)

if __name__=='__main__': unittest.main(verbosity=2)
