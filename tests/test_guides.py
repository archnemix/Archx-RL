"""Check the component guide map and local Markdown references.

These checks detect broken references and key boundary disclaimers; they do
not establish that all documentation is complete or a deployment is safe.
"""
import re
import unittest
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
GUIDES = ('Native-Core.md', 'Policy-Service.md', 'Browser-Protocol.md',
          'Privacy-Security.md', 'Deployment.md')


def anchors(text):
    found = set()
    for heading in re.findall(r'^#{1,6}\s+(.+?)\s*$', text, flags=re.MULTILINE):
        heading = re.sub(r'[^\w\- ]', '', heading.lower()).replace(' ', '-')
        found.add(heading)
    return found


class GuideTests(unittest.TestCase):
    def test_guide_map_and_local_references(self):
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        for name in GUIDES:
            path = ROOT / 'Docs' / 'Guides' / name
            with self.subTest(guide=name):
                self.assertIn('Docs/Guides/' + name, readme)
                content = path.read_text(encoding='utf-8')
                for target in re.findall(r'\]\(([^)]+)\)', content):
                    if '://' in target or target.startswith('mailto:'):
                        continue
                    filename, _, fragment = target.partition('#')
                    destination = (path.parent / unquote(filename)).resolve() if filename else path
                    self.assertTrue(destination.is_file(), target)
                    if fragment:
                        self.assertIn(fragment, anchors(destination.read_text(encoding='utf-8')), target)

    def test_key_component_boundaries_are_explicit(self):
        def content(name):
            return (ROOT / 'Docs' / 'Guides' / name).read_text(encoding='utf-8').lower()
        self.assertIn('separate from the python request-policy engine', content('Native-Core.md'))
        self.assertIn('not** the c token-bucket api', content('Policy-Service.md'))
        self.assertIn('cannot read linux machine ids', content('Browser-Protocol.md'))
        self.assertIn('not authentication', content('Privacy-Security.md'))
        self.assertIn('no supported production deployment profile', content('Deployment.md'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
