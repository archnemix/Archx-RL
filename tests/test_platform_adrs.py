"""Maintain the boundaries and evidence links in the platform ADR dossier."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / 'Docs/Research/Platform-ADRs.md'


class PlatformAdrTests(unittest.TestCase):
    def test_all_decisions_have_explicit_evidence_and_failure_boundaries(self):
        text = DOC.read_text(encoding='utf-8')
        sections = re.split(r'(?m)^## ', text)
        for label in ('W1', 'W2', 'W3', 'M1', 'M2'):
            with self.subTest(decision=label):
                matching = [section for section in sections if section.startswith(label + ' ')]
                self.assertEqual(len(matching), 1)
                section = matching[0].lower()
                for requirement in ('api', 'privacy', 'fail', 'evidence', 'tests', 'user'):
                    self.assertIn(requirement, section)
                self.assertIn('https://', section)
        self.assertIn('do **not** approve Windows or macOS releases', text)
        self.assertIn('No Windows fallback exists', text)
        self.assertIn('No physical hardware or signed sandbox was tested', text)
        self.assertIn('#4/#6/#30', text)
        self.assertIn('not device or person authentication', text)

    def test_recorded_fixture_and_survey_paths_exist(self):
        text = DOC.read_text(encoding='utf-8')
        required = ('src/signals_windows.c', 'src/smbios.c', 'src/fallback_posix.c',
                    'src/macos_cf_uuid.c', 'tests/test_smbios.c', 'tests/test_windows_firmware.c',
                    'tests/fuzz_smbios.c', 'tests/test_macos_cf_uuid.c', 'tests/test_uuid_value.c',
                    'tests/test_platform.c', 'tests/test_fallback_faults.c', 'tests/test_survey.py',
                    'tests/platform/test_posix_fallback.c', 'tools/permission_survey/native_macos.c',
                    'tools/permission_survey/native_windows.c', 'tools/permission_survey/validate_native.py')
        for relative in required:
            with self.subTest(path=relative):
                self.assertIn(relative, text)
                self.assertTrue((ROOT / relative).is_file())
        self.assertTrue((ROOT / 'Docs/Test-Results/unreleased/native-permission-survey.md').is_file())
        for run in ('45816632804', '46144559246'):
            self.assertIn('https://github.com/archnemix/Archx-RL/actions/runs/' + run, text)


if __name__ == '__main__': unittest.main(verbosity=2)
