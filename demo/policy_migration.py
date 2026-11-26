"""Offline, explicitly invoked tightening of schema-3 prototype quotas.

Not a general schema migration, backup/restore facility or deployment tool.
The operator must stop ALL old clients (including older code that does not
recheck metadata). Database and directory are trusted and privately owned.
"""
import copy

from engine import policy
from sqlite_engine import SQLiteEngine, persistent_checks

_MUTABLE = frozenset(('max_requests', 'ip_max_requests', 'device_max_requests',
                      'ip_challenge_after', 'messages'))


def _validated(value):
    if not isinstance(value, dict) or not isinstance(value.get('name'), str):
        raise ValueError('A complete policy is required')
    value = copy.deepcopy(value)
    try:
        normalized = policy(value['name'], {k: v for k, v in value.items() if k != 'name'})
    except (ValueError, TypeError, KeyError) as exc:
        raise ValueError('Invalid policy') from exc
    if normalized != value:
        raise ValueError('Policy must be complete and canonical')
    return value


def tighten_policy(engine, target):
    """Atomically replace the stored policy check without deleting any state.

    Only explicit decreases in IP/device limits and addition/tightening of an
    IP soft challenge are permitted. Duration, matching and all other semantic
    settings must remain exactly the same. Returns no new running engine; start
    a new one with the target policy after the maintenance transaction.
    """
    if not isinstance(engine, SQLiteEngine):
        raise ValueError('SQLiteEngine required')
    old, new = _validated(engine.settings), _validated(target)
    if any(old.get(k) != new.get(k) for k in (set(old) | set(new)) - _MUTABLE):
        raise ValueError('Only quota tightening is supported')
    if new['max_requests'] > old['max_requests']:
        raise ValueError('Default quota cannot increase')
    for name in ('ip_max_requests', 'device_max_requests'):
        if new.get(name, new['max_requests']) > old.get(name, old['max_requests']):
            raise ValueError('Effective quota cannot increase')
    if 'ip_challenge_after' in old and ('ip_challenge_after' not in new or
                                       new['ip_challenge_after'] > old['ip_challenge_after']):
        raise ValueError('Existing IP challenge cannot be removed or weakened')
    expected = persistent_checks(engine.secret, new)
    con = engine.connect()
    try:
        engine._begin_writer(con)
        changed = con.execute("UPDATE meta SET value=? WHERE name='policy_check'",
                              (expected['policy_check'],)).rowcount
        if changed != 1:
            raise ValueError('Policy metadata missing')
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()
