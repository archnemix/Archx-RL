"""Keep project-license copies and declared package metadata consistent."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LicenseTests(unittest.TestCase):
    def test_copies_match_owner_selected_license(self):
        license_text = (ROOT / 'LICENSE').read_bytes()
        self.assertIn(b'BSD Zero Clause License', license_text)
        self.assertIn(b'Permission to use, copy, modify', license_text)
        self.assertIn(b'THE SOFTWARE IS PROVIDED "AS IS"', license_text)
        for name in ('bindings/node/LICENSE', 'bindings/python/LICENSE',
                     'integrations/wsgi/LICENSE', 'demo/browser/LICENSE'):
            with self.subTest(name=name):
                self.assertEqual((ROOT / name).read_bytes(), license_text)

    def test_package_license_metadata(self):
        for name in ('bindings/node', 'demo/browser'):
            with self.subTest(name=name):
                package = json.loads((ROOT / name / 'package.json').read_text())
                lock = json.loads((ROOT / name / 'package-lock.json').read_text())
                self.assertEqual(package['license'], '0BSD')
                self.assertEqual(lock['packages']['']['license'], '0BSD')
        for name in ('bindings/python', 'integrations/wsgi'):
            with self.subTest(name=name):
                self.assertIn('license = {file = "LICENSE"}', (ROOT / name / 'pyproject.toml').read_text())


if __name__ == '__main__':
    unittest.main()
