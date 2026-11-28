"""Offline schema-2/3 migration for an entirely empty prototype store.

This is not a general migration or a safe backup/restore protocol. Stop and
drain every old and new writer; the directory and all ancestors must be
trusted. Active or expired quota/history records cannot be re-keyed here.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat

from engine import policy
from sqlite_engine import EXPECTED_SCHEMA, persistent_checks

_HISTORICAL_FIELDS = frozenset(('name', 'required', 'conditional', 'min_matches',
    'window_seconds', 'max_requests', 'max_clock_skew_seconds',
    'timezone_tolerance_minutes', 'timezone_enforce', 'history_seconds'))


def migrate_empty_schema(path, secret, settings, *, source, target):
    """Atomically transition 2 <-> 3 only with exactly known empty state.

    The policy must be identical and representable in both versions. This does
    not transform HMAC keys, delete records, or initialize replay. File and
    directory ancestry, SQLite durability, operator coordination, old clients,
    backups and crash recovery remain operator responsibilities. An error on
    commit may have an ambiguous outcome; inspect before any subsequent action.
    """
    if type(source) is not int or type(target) is not int or (source, target) not in ((2, 3), (3, 2)):
        raise ValueError('Only schema 2/3 transitions are supported')
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError('Persistent secret must be at least 32 bytes')
    if not isinstance(settings, dict) or set(settings) != _HISTORICAL_FIELDS:
        raise ValueError('Policy must use only historical schema-2 fields')
    try:
        normalized = policy(settings['name'], {k: v for k, v in settings.items() if k != 'name'})
    except (TypeError, ValueError, KeyError):
        raise ValueError('Invalid policy') from None
    if normalized != settings:
        raise ValueError('Canonical unchanged policy required')
    target_path = Path(path).absolute()
    parent = target_path.parent
    if parent.resolve(strict=True) != parent:
        raise ValueError('Database directory path must not traverse symlinks')
    st = parent.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ValueError('Database directory must be private and owned by the service user')
    fd = os.open(target_path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise ValueError('Database must be a private regular file owned by the service user')
    finally:
        os.close(fd)
    current = persistent_checks(secret, settings)
    historical = dict(current)
    historical['schema'] = '2'
    historical['policy_check'] = hashlib.sha256(json.dumps(
        settings, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    before = historical if source == 2 else current
    after = historical if target == 2 else current
    con = sqlite3.connect(target_path.as_uri() + '?mode=rw', uri=True, timeout=5, isolation_level=None)
    try:
        con.execute('PRAGMA foreign_keys=ON')
        con.execute('BEGIN IMMEDIATE')
        objects = {name: (kind, sql) for kind, name, sql in con.execute(
            'SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL')}
        expected = {name: ('table' if sql.startswith('CREATE TABLE ') else 'index', sql)
                    for name, sql in EXPECTED_SCHEMA.items()}
        if objects != expected:
            raise ValueError('Unknown or incomplete schema')
        metadata = dict(con.execute('SELECT name,value FROM meta'))
        if (set(metadata) != set(before) or any(
                not isinstance(metadata[k], str) or not hmac.compare_digest(
                    metadata[k].encode('utf-8'), v.encode('ascii')) for k, v in before.items())):
            raise ValueError('Schema, secret or policy metadata mismatch')
        if con.execute('PRAGMA integrity_check').fetchall() != [('ok',)] or con.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('Database integrity check failed')
        if any(con.execute(f'SELECT 1 FROM {table} LIMIT 1').fetchone() is not None
               for table in ('windows', 'observations', 'signals')):
            raise ValueError('Migration requires an entirely empty store')
        for name in ('schema', 'policy_check'):
            if con.execute('UPDATE meta SET value=? WHERE name=?', (after[name], name)).rowcount != 1:
                raise ValueError('Required metadata missing')
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()
