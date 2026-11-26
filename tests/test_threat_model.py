"""Check the threat inventory has traceable, present synthetic evidence references.

This is a documentation integrity check, not proof of mitigation or coverage.
"""
import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / 'Docs' / 'Threat-Model.md'
REFERENCE = re.compile(r'\[`([^`]+)`\]\(\.\./((?:tests|tools)/[^)]+)\)')


class ThreatModelTests(unittest.TestCase):
    def test_security_policy_discloses_unverified_private_reporting(self):
        text=(ROOT/'SECURITY.md').read_text(encoding='utf-8')
        self.assertIn('private vulnerability reporting was **disabled when last checked**',text)
        self.assertIn('no working private reporting channel',text)
        self.assertIn('do not disclose',text.lower())

    def test_threats_have_traceable_evidence_or_known_limitation(self):
        text = MODEL.read_text(encoding='utf-8')
        rows = [line for line in text.splitlines() if re.match(r'^\| T\d{2} \|', line)]
        ids = [line.split('|')[1].strip() for line in rows]
        self.assertEqual(ids, [f'T{i:02d}' for i in range(1, 14)])
        for row in rows:
            cells = [part.strip() for part in row.split('|')[1:-1]]
            self.assertEqual(len(cells), 4)
            threat, evidence, response = cells[1:]
            self.assertTrue(threat and response)
            refs = REFERENCE.findall(evidence)
            self.assertTrue(refs or '**Known limitation:**' in evidence, cells[0])
            for label, relative in refs:
                path = ROOT / relative
                self.assertTrue(path.is_file(), relative)
                if label.startswith('test_'):
                    self.assertEqual(path.suffix, '.py')
                    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
                    functions = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
                    self.assertIn(label, functions, f'{relative}::{label}')
                elif label == 'main':
                    self.assertEqual(path.suffix, '.c')
                    self.assertRegex(path.read_text(encoding='utf-8'), r'\bmain\s*\(')
                else:
                    self.assertEqual(label, path.name)
        self.assertIn('neither authentication nor proof of a unique person or device', text)
        self.assertIn('does **not** imply maintainer or operator acceptance', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
