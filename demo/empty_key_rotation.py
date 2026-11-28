"""Offline rotation of an entirely empty schema-3 prototype store.

Not an online migration, a way to re-key HMACs, or a production key manager.
The operator must stop and drain all writers, including older binaries, before
calling this API. Never restore a stale database or reuse a compromised key.
"""
import hmac

from replay import REPLAY_MARKER, REPLAY_SCHEMA
from sqlite_engine import EXPECTED_SCHEMA, SQLiteEngine, persistent_checks


def rotate_empty_key(engine, new_secret):
    """Change the key check atomically only if all recognized state is empty.

    Refuse unknown schema objects/metadata, partial replay schema, corruption,
    orphan signals, active or expired rows. Expiration must be performed by the
    normal engine/replay cleanup APIs before entering this offline operation.
    No data is transformed or deleted. A return value means the DB transaction
    committed, not that filesystem, backup, secret-distribution or crash safety
    has been established. On ambiguous commit failure inspect the actual store.
    """
    if not isinstance(engine, SQLiteEngine):
        raise ValueError('SQLiteEngine required')
    if not isinstance(new_secret, bytes) or len(new_secret) < 32:
        raise ValueError('New secret must contain at least 32 bytes')
    if hmac.compare_digest(engine.secret, new_secret):
        raise ValueError('New secret must differ')
    new_checks = persistent_checks(new_secret, engine.settings)
    con = engine.connect()
    try:
        engine._begin_writer(con)
        objects = {name: (kind, sql) for kind, name, sql in con.execute(
            "SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL")}
        expected = {name: ('table' if sql.startswith('CREATE TABLE ') else 'index', sql)
                    for name, sql in EXPECTED_SCHEMA.items()}
        replay_objects = {name: ('table' if sql.startswith('CREATE TABLE ') else 'index',
                                  sql.replace(' IF NOT EXISTS', ''))
                          for name, sql in REPLAY_SCHEMA.items()}
        metadata = dict(con.execute('SELECT name,value FROM meta'))
        marker = metadata.pop(REPLAY_MARKER, None)
        if marker is not None:
            if marker != '1': raise ValueError('Unrecognized replay metadata')
            expected.update(replay_objects)
        if objects != expected or metadata != engine._persistent_checks:
            raise ValueError('Unknown or incomplete schema or metadata')
        if con.execute('PRAGMA integrity_check').fetchall() != [('ok',)] or con.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('Database integrity check failed')
        tables = ['windows', 'observations', 'signals']
        if marker is not None: tables.append('replay_challenges_v1')
        if any(con.execute(f'SELECT 1 FROM {table} LIMIT 1').fetchone() is not None for table in tables):
            raise ValueError('Rotation requires an empty store')
        changed = con.execute("UPDATE meta SET value=? WHERE name='key_check'",
                              (new_checks['key_check'],)).rowcount
        if changed != 1: raise ValueError('Key metadata missing')
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()
