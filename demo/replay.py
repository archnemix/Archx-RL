"""Bounded, single-use challenges for sealed requests on one process or host.

Challenges are not client authentication. First arrival wins; an interceptor
may race the original request. SQLite coordinates only processes using one DB.
"""
import hashlib
import hmac
import ipaddress
import re
import secrets
import sqlite3
import threading


class ReplayUnavailable(Exception):
    """Challenge capacity or storage is unavailable."""


def canonical_ip(peer):
    address = ipaddress.ip_address(peer)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


class MemoryReplay:
    def __init__(self, secret, clock, ttl=120, capacity=10000, per_peer=5):
        if not isinstance(secret, bytes) or not secret or not 1 <= ttl <= 300 or not 1 <= per_peer <= capacity:
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

    def _prune(self, now):
        self.pending = {key:value for key,value in self.pending.items() if value[1] > now}

    def issue(self, peer):
        peer_key = self._peer(peer)
        with self.lock:
            # Expiry must be checked after waiting for the lock.
            now = self.clock()
            self._prune(now)
            if len(self.pending) >= self.capacity or sum(value[0] == peer_key for value in self.pending.values()) >= self.per_peer:
                raise ReplayUnavailable('Challenge capacity exceeded')
            token = secrets.token_urlsafe(32)
            self.pending[self._token(token)] = (peer_key, now + self.ttl)
            return token

    def consume(self, token, peer):
        key = self._token(token)
        if key is None:
            return False
        peer_key = self._peer(peer)
        with self.lock:
            # Expiry must be checked after waiting for the lock.
            now = self.clock()
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
            with self.engine.connect() as con:
                con.execute('CREATE TABLE IF NOT EXISTS replay_challenges_v1 (token TEXT PRIMARY KEY, peer TEXT NOT NULL, expires REAL NOT NULL)')
                con.execute('CREATE INDEX IF NOT EXISTS replay_challenges_expiry ON replay_challenges_v1(expires)')
                con.execute('CREATE INDEX IF NOT EXISTS replay_challenges_peer ON replay_challenges_v1(peer)')
        except sqlite3.Error as exc:
            raise ReplayUnavailable('Challenge storage unavailable') from exc

    def issue(self, peer):
        peer_key = self._peer(peer)
        try:
            con = self.engine.connect()
            try:
                con.execute('BEGIN IMMEDIATE')
                now = self.clock()
                con.execute('DELETE FROM replay_challenges_v1 WHERE expires <= ?', (now,))
                total = con.execute('SELECT count(*) FROM replay_challenges_v1').fetchone()[0]
                count = con.execute('SELECT count(*) FROM replay_challenges_v1 WHERE peer = ?', (peer_key,)).fetchone()[0]
                if total >= self.capacity or count >= self.per_peer:
                    raise ReplayUnavailable('Challenge capacity exceeded')
                token = secrets.token_urlsafe(32)
                con.execute('INSERT INTO replay_challenges_v1(token,peer,expires) VALUES(?,?,?)', (self._token(token), peer_key, now + self.ttl))
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
                con.execute('BEGIN IMMEDIATE')
                now = self.clock()
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
