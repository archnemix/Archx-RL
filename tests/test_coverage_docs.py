"""Guard ABI-v1 heuristic documentation and the current score-free demo UI.

This is a targeted regression, not a semantic proof about future documentation
or other clients. A future UI displaying the field needs an explicit review.
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CoverageDocumentationTests(unittest.TestCase):
    def test_abi_and_readme_explain_the_legacy_marker(self):
        header = (ROOT / 'include/archx.h').read_text(encoding='utf-8').lower()
        readme = (ROOT / 'README.md').read_text(encoding='utf-8').lower()
        self.assertIn('availability heuristic', header)
        self.assertIn('not a probability', header)
        self.assertIn('not 10 percent coverage', header)
        self.assertIn('availability-weight sum', readme)
        self.assertIn('not probabilities', readme)
        self.assertIn('legacy marker', readme)

    def test_current_demo_ui_does_not_present_the_abi_heuristic(self):
        for path in sorted((ROOT / 'demo/site').iterdir()):
            if path.suffix in {'.js', '.html'}:
                with self.subTest(path=path.name):
                    self.assertNotIn('confidence', path.read_text(encoding='utf-8').lower())


if __name__ == '__main__':
    unittest.main(verbosity=2)
