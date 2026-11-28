"""Bounded, single-use challenges for sealed requests on one process or host.

Challenges are not client authentication. First arrival wins; an interceptor
may race the original request. SQLite coordinates only processes using one DB.
"""
import hashlib
import hmac
import ipaddress
import math
import re
import secrets
import sqlite3
import threading


REPLAY_SCHEMA = {
    'replay_challenges_v1': 'CREATE TABLE IF NOT EXISTS replay_challenges_v1 (token TEXT PRIMARY KEY, peer TEXT NOT NULL, expires REAL NOT NULL)',
    'replay_challenges_expiry': 'CREATE INDEX IF NOT EXISTS replay_challenges_expiry ON replay_challenges_v1(expires)',
    'replay_challenges_peer': 'CREATE INDEX IF NOT EXISTS replay_challenges_peer ON replay_challenges_v1(peer)',
}
REPLAY_MARKER = 'replay_schema_v1'


class ReplayUnavailable(Exception):
    """Challenge capacity or storage is unavailable."""


def canonical_ip(peer):
    address = ipaddress.ip_address(peer)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


class MemoryReplay:
    def __init__(self, secret, clock, ttl=120, capacity=10000, per_peer=5):
        if (not isinstance(secret, bytes) or not secret or not callable(clock) or
                type(ttl) not in (int, float) or not 1 <= ttl <= 300 or
                type(capacity) is not int or type(per_peer) is not int or
                not 1 <= per_peer <= capacity):
            raise ValueError('Invalid replay-store configuration')
        self.secret, self.clock, self.ttl = secret, clock, ttl
        self.capacity, self.per_peer = capacity, per_peer
        self.lock = threading.Lock()
        self.pending = {}

    def _digest(self, purpose, value):
        return hmac.new(self.secret, ('archx-replay-v1\0' + purpose + '\0' + value).encode(), hashlib.sha256).hexdigest()

    def _peer(self, peer):
        return self._digest('peer', canonical_ip(peer))

    def _token(self, token):
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            return None
        return self._digest('nonce', token)

    def _new_token(self):
        # Treat entropy-provider errors and malformed outputs as unavailability;
        # never persist an unusable token or include provider details in errors.
        try:
            token = secrets.token_urlsafe(32)
            digest = self._token(token)
            if digest is None:
                raise ValueError('Invalid generated token')
            return token, digest
        except Exception:
            raise ReplayUnavailable('Challenge generation unavailable') from None

    def _validated_time(self):
        # SQLite stores REAL timestamps; use the same representation in memory.
        # Validate before *any* prune/consume so a bad sample cannot erase live
        # challenges. This does not detect a plausible but incorrect wall clock.
        try:
            raw = self.clock()
            if type(raw) not in (int, float):
                raise ValueError('Invalid clock type')
            now = float(raw)
            if (type(self.ttl) not in (int, float) or not 1 <= self.ttl <= 300 or
                    not math.isfinite(now)):
                raise ValueError('Invalid clock or TTL')
            expiry = now + self.ttl
            if not math.isfinite(expiry) or expiry <= now:
                raise ValueError('Unrepresentable challenge expiry')
            return now, expiry
        except Exception:
            raise ValueError('Invalid replay clock or expiry') from None

    def _operation_time(self):
        try:
            return self._validated_time()
        except ValueError:
            raise ReplayUnavailable('Challenge clock unavailable') from None

    def _prune(self, now):
        self.pending = {key:value for key,value in self.pending.items() if value[1] > now}

    def cleanup_expired(self):
        """Delete at most 64 expired challenges; scan is bounded by capacity."""
        with self.lock:
            now, _ = self._validated_time()
            expired = []
            pending = False
            for key, (_, expires) in self.pending.items():
                if expires <= now:
                    if len(expired) == 64:
                        pending = True
                        break
                    expired.append(key)
            for key in expired: del self.pending[key]
            return {'challenges_pending':pending}

    def issue(self, peer):
        peer_key = self._peer(peer)
        with self.lock:
            # Expiry must be checked after waiting for the lock.
            now, expiry = self._operation_time()
            self._prune(now)
            if len(self.pending) >= self.capacity or sum(value[0] == peer_key for value in self.pending.values()) >= self.per_peer:
                raise ReplayUnavailable('Challenge capacity exceeded')
            token, digest = self._new_token()
            if digest in self.pending:
                raise ReplayUnavailable('Challenge generation unavailable')
            self.pending[digest] = (peer_key, expiry)
            return token

    def consume(self, token, peer):
        key = self._token(token)
        if key is None:
            return False
        peer_key = self._peer(peer)
        with self.lock:
            # Expiry must be checked after waiting for the lock.
            now, _ = self._operation_time()
            self._prune(now)
            if key not in self.pending or self.pending[key][0] != peer_key:
                return False
            del self.pending[key]
            return True


class SQLiteReplay(MemoryReplay):
    def __init__(self, engine, ttl=120, capacity=10000, per_peer=5):
        super().__init__(engine.secret, engine.clock, ttl, capacity, per_peer)
        self.engine = engine
        try:
            con = self.engine.connect()
            try:
                self._begin_writer(con)
                marker = con.execute('SELECT value FROM meta WHERE name=?', (REPLAY_MARKER,)).fetchone()
                objects = {name:(kind, sql) for kind, name, sql in con.execute(
                    'SELECT type, name, sql FROM sqlite_master WHERE name IN (?,?,?)', tuple(REPLAY_SCHEMA))}
                if marker is not None and marker != ('1',):
                    raise ReplayUnavailable('Challenge schema mismatch')
                if marker is None and not objects:
                    # First use of replay protection on an existing core store.
                    for sql in REPLAY_SCHEMA.values():
                        con.execute(sql)
                else:
                    # Also permit validated pre-marker stores, without dropping
                    # their outstanding challenges, then record the marker.
                    for name, sql in REPLAY_SCHEMA.items():
                        expected = sql.replace(' IF NOT EXISTS', '')
                        kind = 'table' if expected.startswith('CREATE TABLE ') else 'index'
                        if objects.get(name) != (kind, expected):
                            raise ReplayUnavailable('Challenge schema is incomplete or changed')
                if marker is None:
                    con.execute('INSERT INTO meta(name, value) VALUES(?,?)', (REPLAY_MARKER, '1'))
                con.commit()
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()
        except sqlite3.Error as exc:
            raise ReplayUnavailable('Challenge storage unavailable') from exc

    def _begin_writer(self, con):
        # Share the engine's transaction-time metadata check. Otherwise a replay
        # store created before a policy/key change can mutate persistent state
        # even though the corresponding engine has been invalidated.
        self.engine._begin_writer(con)
        if (not isinstance(self.secret, bytes) or
                not isinstance(self.engine.secret, bytes) or
                not hmac.compare_digest(self.secret, self.engine.secret)):
            raise sqlite3.DatabaseError('Persistent replay secret changed')

    def cleanup_expired(self):
        """Delete one indexed, bounded batch, propagating storage failure."""
        try:
            con = self.engine.connect()
            try:
                self._begin_writer(con)
                now, _ = self._validated_time()
                con.execute('DELETE FROM replay_challenges_v1 WHERE token IN (SELECT token FROM replay_challenges_v1 WHERE expires <= ? ORDER BY expires LIMIT 64)', (now,))
                pending=con.execute('SELECT 1 FROM replay_challenges_v1 WHERE expires <= ? LIMIT 1',(now,)).fetchone() is not None
                con.commit()
                return {'challenges_pending':pending}
            except BaseException:
                con.rollback()
                raise
            finally:
                con.close()
        except sqlite3.Error as exc:
            raise ReplayUnavailable('Challenge storage unavailable') from exc

    def issue(self, peer):
        peer_key = self._peer(peer)
        try:
            con = self.engine.connect()
            try:
                self._begin_writer(con)
                now, expiry = self._operation_time()
                con.execute('DELETE FROM replay_challenges_v1 WHERE expires <= ?', (now,))
                total = con.execute('SELECT count(*) FROM replay_challenges_v1').fetchone()[0]
                count = con.execute('SELECT count(*) FROM replay_challenges_v1 WHERE peer = ?', (peer_key,)).fetchone()[0]
                if total >= self.capacity or count >= self.per_peer:
                    raise ReplayUnavailable('Challenge capacity exceeded')
                token, digest = self._new_token()
                con.execute('INSERT INTO replay_challenges_v1(token,peer,expires) VALUES(?,?,?)', (digest, peer_key, expiry))
                con.commit()
                return token
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()
        except sqlite3.Error as exc:
            raise ReplayUnavailable('Challenge storage unavailable') from exc

    def consume(self, token, peer):
        key = self._token(token)
        if key is None:
            return False
        peer_key = self._peer(peer)
        try:
            con = self.engine.connect()
            try:
                self._begin_writer(con)
                now, _ = self._operation_time()
                count = con.execute('DELETE FROM replay_challenges_v1 WHERE token=? AND peer=? AND expires>?', (key, peer_key, now)).rowcount
                con.execute('DELETE FROM replay_challenges_v1 WHERE expires <= ?', (now,))
                con.commit()
                return count == 1
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()
        except sqlite3.Error as exc:
            raise ReplayUnavailable('Challenge storage unavailable') from exc
