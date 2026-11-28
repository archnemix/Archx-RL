"""Summarize selected synthetic V8 coverage files without archiving raw dumps."""
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
targets = {
    (root / 'bindings/node/index.js').as_uri(): 'bindings/node/index.js',
    (root / 'build/browser/archx-client.mjs').as_uri(): 'build/browser/archx-client.mjs (bundled dependencies)',
}
summary = {name: {'process_scripts': 0, 'function_records': 0, 'executed_function_records': 0,
                  'range_records': 0, 'executed_range_records': 0} for name in targets.values()}
for path in Path(sys.argv[1]).glob('*.json'):
    data = json.loads(path.read_text())
    for script in data.get('result', []):
        name = targets.get(script.get('url'))
        if name is None: continue
        counts = summary[name]
        counts['process_scripts'] += 1
        for function in script['functions']:
            ranges = function['ranges']
            counts['function_records'] += 1
            counts['executed_function_records'] += bool(ranges and ranges[0]['count'])
            counts['range_records'] += len(ranges)
            counts['executed_range_records'] += sum(r['count'] > 0 for r in ranges)
if any(item['process_scripts'] == 0 for item in summary.values()):
    raise SystemExit('Expected synthetic Node coverage target was not observed')
report = {'description': 'V8 function/range records across synthetic Node test processes; not line/branch coverage or Chromium coverage.',
          'targets': summary}
Path(sys.argv[2]).write_text(json.dumps(report, indent=2) + '\n')
