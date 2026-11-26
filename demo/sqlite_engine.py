"""SQLite persistence for the request-policy prototype.

SQLite provides transaction serialization on one host, not a multi-host store.
The database and its parent directory must be private to the service operator.
"""
import hashlib
import hmac
import ipaddress
import json
import math
import os
import sqlite3
import stat
from contextlib import suppress
from pathlib import Path

from engine import Engine, CLEANUP_BUDGET

SCHEMA = {
    'meta': 'CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT NOT NULL)',
    'windows': 'CREATE TABLE IF NOT EXISTS windows (key TEXT PRIMARY KEY, start REAL NOT NULL, count INTEGER NOT NULL)',
    'windows_start': 'CREATE INDEX IF NOT EXISTS windows_start ON windows(start)',
    'observations': 'CREATE TABLE IF NOT EXISTS observations (id INTEGER PRIMARY KEY, expires REAL NOT NULL, fingerprint TEXT NOT NULL UNIQUE)',
    'observations_expires': 'CREATE INDEX IF NOT EXISTS observations_expires ON observations(expires)',
    'signals': 'CREATE TABLE IF NOT EXISTS signals (observation_id INTEGER NOT NULL REFERENCES observations(id) ON DELETE CASCADE, name TEXT NOT NULL, token TEXT NOT NULL, PRIMARY KEY (observation_id, name))',
    'signals_lookup': 'CREATE INDEX IF NOT EXISTS signals_lookup ON signals(name, token, observation_id)',
    'signals_by_name': 'CREATE INDEX IF NOT EXISTS signals_by_name ON signals(name, observation_id)',
}
# SQLite records CREATE statements without IF NOT EXISTS. Checking the exact
# known definitions at startup avoids silently recreating lost state tables.
EXPECTED_SCHEMA = {name: sql.replace(' IF NOT EXISTS', '') for name, sql in SCHEMA.items()}

class SQLiteEngine(Engine):
    def __init__(self, db_path, settings, secret, **kwargs):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError('Persistent mode requires an explicit secret of at least 32 bytes')
        if not db_path or str(db_path) == ':memory:':
            raise ValueError('Persistent mode requires a file path')
        super().__init__(settings=settings, secret=secret, **kwargs)
        self.db_path = str(Path(db_path).absolute())
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            fd = os.open(self.db_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
        except FileExistsError:
            fd = os.open(self.db_path, flags)
            created = False
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
                raise ValueError('Database must be a private regular file owned by the service user')
        finally:
            os.close(fd)
        self._initialize(created)

    def connect(self):
        con = sqlite3.connect(Path(self.db_path).as_uri() + '?mode=rw', uri=True, timeout=5, isolation_level=None)
        try:
            con.execute('PRAGMA foreign_keys=ON')
            con.execute('PRAGMA secure_delete=ON')
            con.execute('PRAGMA busy_timeout=5000')
            return con
        except BaseException:
            # Even initialization errors must not leak a live connection.
            with suppress(Exception):
                con.close()
            raise

    def _initialize(self, created):
        con = self.connect()
        try:
            con.execute('PRAGMA journal_mode=WAL')
            con.execute('BEGIN IMMEDIATE')
            objects = {name: (kind, sql) for kind, name, sql in con.execute(
                'SELECT type, name, sql FROM sqlite_master')}
            if created and not objects:
                for sql in SCHEMA.values():
                    con.execute(sql)
                fresh = True
            else:
                fresh = False
                for name, sql in EXPECTED_SCHEMA.items():
                    kind = 'table' if sql.startswith('CREATE TABLE ') else 'index'
                    if objects.get(name) != (kind, sql):
                        raise ValueError('Database schema is incomplete or changed; restore or migrate explicitly')
            key_check = hmac.new(self.secret, b'archx-persistent-key-check-v1', hashlib.sha256).hexdigest()
            policy_check = hashlib.sha256(json.dumps({k:v for k,v in self.settings.items() if k != 'messages' and not (k == 'ip_storage' and v == 'hash')}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            for key, expected in [('schema','3'), ('key_check',key_check), ('policy_check',policy_check)]:
                if fresh:
                    con.execute('INSERT INTO meta(name,value) VALUES(?,?)',(key,expected))
                else:
                    row = con.execute('SELECT value FROM meta WHERE name=?',(key,)).fetchone()
                    if (row is None or not isinstance(row[0], str) or
                        not hmac.compare_digest(row[0].encode('utf-8'), expected.encode('ascii'))):
                        raise ValueError('Database secret, policy, or schema does not match; restore or migrate explicitly')
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def _prune_windows(self, con, now):
        cutoff = now - self.settings['window_seconds']
        con.execute('DELETE FROM windows WHERE key IN (SELECT key FROM windows WHERE start <= ? ORDER BY start LIMIT ?)',
                    (cutoff, CLEANUP_BUDGET))
        return con.execute('SELECT 1 FROM windows WHERE start <= ? LIMIT 1', (cutoff,)).fetchone() is not None

    def _prune_observations(self, con, now):
        con.execute('DELETE FROM observations WHERE id IN (SELECT id FROM observations WHERE expires <= ? ORDER BY expires LIMIT ?)',
                    (now, CLEANUP_BUDGET))
        return con.execute('SELECT 1 FROM observations WHERE expires <= ? LIMIT 1', (now,)).fetchone() is not None

    def _charge(self, con, key_limits, now):
        keys = list(key_limits)
        if not keys: return None
        marks = ','.join('?' for _ in keys)
        rows = {key:(start,count) for key,start,count in con.execute(f'SELECT key,start,count FROM windows WHERE key IN ({marks})', keys)}
        count = con.execute('SELECT count(*) FROM windows').fetchone()[0]
        if count + sum(k not in rows for k in keys) > self.max_entries:
            return {'decision':'capacity_exceeded','message':self.message('capacity_exceeded'),'retry_after_seconds':self.settings['window_seconds'],'relation':'inconclusive'}
        retry = 0
        for key in keys:
            start, old = rows.get(key, (now, 0))
            con.execute('INSERT INTO windows(key,start,count) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET count=excluded.count', (key, start, old+1))
            if old+1 > key_limits[key]:
                retry = max(retry, math.ceil(self.settings['window_seconds'] - (now - start)))
        return {'decision':'rate_limited','message':self.message('rate_limited'),'retry_after_seconds':retry,'relation':'inconclusive'} if retry else None

    def _storage_error(self):
        return {'decision':'storage_error','message':self.message('storage_error'),'retry_after_seconds':1,'relation':'inconclusive'}

    def reject_malformed(self, peer):
        ip = ipaddress.ip_address(peer)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped: ip = ip.ipv4_mapped
        try:
            con = self.connect()
            try:
                con.execute('BEGIN IMMEDIATE')
                now = self.clock()
                result = self._cleanup_busy() if self._prune_windows(con, now) else self._charge(con, {self.ip_key(ip):self._quota('ip')}, now)
                con.commit()
                return result
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()
        except sqlite3.Error:
            return self._storage_error()

    def check(self, raw, peer, *, _ip_precharged=False):
        _, tokens, missing, zone, clock_status = self.prepare(raw, peer)
        try:
            con = self.connect()
            try:
                con.execute('BEGIN IMMEDIATE')
                # A waiting writer must not use a stale pre-transaction time.
                now = self.clock()
                if self._prune_windows(con, now):
                    con.commit()
                    return self._cleanup_busy()
                cleanup_pending = self._prune_observations(con, now)
                key_limits = {}
                for name, value in tokens.items():
                    if _ip_precharged and name == 'ip': continue
                    key_limits[value] = min(key_limits.get(value, self._quota(name)), self._quota(name))
                failure = self._charge(con, key_limits, now)
                if failure is None: failure = self.decision_before_matching(missing, zone, clock_status)
                if failure is None and cleanup_pending: failure = self._cleanup_busy()
                if failure:
                    con.commit()
                    return failure
                # All matching fields must refer to the same prior observation.
                predicates = ' OR '.join('(name=? AND token=?)' for _ in tokens)
                params = [x for pair in tokens.items() for x in pair]
                rows = con.execute(f'SELECT observation_id, name FROM signals WHERE {predicates} ORDER BY observation_id', params).fetchall()
                matches = {}
                for obs_id, name in rows: matches.setdefault(obs_id, set()).add(name)
                best_set = max(matches.values(), key=len) if matches else set()
                best = [name for name in tokens if name in best_set]
                threshold = self.settings['min_matches']
                if len(best) >= threshold:
                    relation = 'related'
                elif con.execute('SELECT 1 FROM observations LIMIT 1').fetchone() is None:
                    relation = 'new'
                else:
                    marks = ','.join('?' for _ in tokens)
                    comparable = con.execute(f'SELECT 1 FROM signals WHERE name IN ({marks}) GROUP BY observation_id HAVING count(*) >= ? LIMIT 1', [*tokens,threshold]).fetchone()
                    relation = 'below_threshold' if comparable else 'inconclusive'
                # Keep one record for an identical signal snapshot, rather than
                # consuming one history slot per repeated request.
                fingerprint = hashlib.sha256(json.dumps(sorted(tokens.items()), separators=(',', ':')).encode()).hexdigest()
                existing = con.execute('SELECT id FROM observations WHERE fingerprint=?', (fingerprint,)).fetchone()
                expires = now + self.settings['history_seconds']
                if existing:
                    con.execute('UPDATE observations SET expires=? WHERE id=?', (expires, existing[0]))
                else:
                    if con.execute('SELECT count(*) FROM observations').fetchone()[0] >= self.max_entries:
                        earliest = con.execute('SELECT min(expires) FROM observations').fetchone()[0]
                        con.commit()
                        return {'decision':'capacity_exceeded','message':self.message('capacity_exceeded'),'retry_after_seconds':max(1, math.ceil(earliest-now)), 'relation':'inconclusive'}
                    cur = con.execute('INSERT INTO observations(expires, fingerprint) VALUES(?,?)', (expires, fingerprint))
                    con.executemany('INSERT INTO signals(observation_id,name,token) VALUES(?,?,?)', [(cur.lastrowid, name, token) for name,token in tokens.items()])
                con.commit()
                return {'decision':'allow','relation':relation,'matched_signals':best, 'timezone':zone, 'clock':clock_status,
                        'retry_after_seconds':0, 'warning':'A relation is not proof of the same person; shared IPs can link unrelated users.'}
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()
        except sqlite3.Error:
            return self._storage_error()
