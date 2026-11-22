import json, os, platform, sys
from datetime import datetime, timezone
records = []
for file in sys.argv[1:]:
    with open(file) as f: records.append(json.load(f))
print(json.dumps({'schema_version': 1, 'tested_at_utc': datetime.now(timezone.utc).isoformat(),
                  'environment': {'platform':'linux', 'kernel':platform.release(),
                                  'arch':platform.machine(), 'runner':'GitHub-hosted ubuntu-latest',
                                  'run_id':os.getenv('GITHUB_RUN_ID','unknown'), 'commit':os.getenv('GITHUB_SHA','unknown')},
                  'disclaimer':'Availability only; no identifier values are included. One virtual runner is not representative of physical desktops.',
                  'access_levels':records}, indent=2))
