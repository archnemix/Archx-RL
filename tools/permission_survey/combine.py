import json, os, platform, sys
from datetime import datetime, timezone
records = []
for file in sys.argv[1:]:
    with open(file) as f: records.append(json.load(f))
by_role = {x['access_level']: x for x in records}
runner, isolated, root = (by_role[x]['signals'] for x in ('runner-user','isolated-user','root'))
catalog = {}
for signal in sorted(set(runner) | set(isolated) | set(root)):
    a, b, c = runner.get(signal), isolated.get(signal), root.get(signal)
    usable = {'available', 'accessible'}
    if a in usable and b in usable: classification = 'readable_by_both_unprivileged_users'
    elif a in usable: classification = 'runner_user_only'
    elif b in usable: classification = 'isolated_user_only'
    elif c in usable and ('permission_denied' in (a,b)): classification = 'root_only_on_this_runner'
    else: classification = 'unavailable_or_unverified_on_this_runner'
    catalog[signal] = classification
print(json.dumps({'schema_version': 2, 'tested_at_utc': datetime.now(timezone.utc).isoformat(),
                  'environment': {'platform':'linux', 'kernel':platform.release(),
                                  'arch':platform.machine(), 'runner':'GitHub-hosted ubuntu-latest',
                                  'run_id':os.getenv('GITHUB_RUN_ID','unknown'), 'commit':os.getenv('GITHUB_SHA','unknown')},
                  'disclaimer':'Availability only; no identifier values are included. One virtual runner is not representative of physical desktops.',
                  'classification': catalog, 'access_levels':records}, indent=2))
