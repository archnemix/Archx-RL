"""Single-host example of coupling a trial entitlement to policy in one SQLite transaction.

This is an internal integration API, NOT an HTTP endpoint or an authentication
system. The host must authenticate the principal and protect every access route.
The local entitlement table is the example's source of truth; an external
entitlement service would need its own transactional/idempotent integration.
"""
import hashlib
import hmac
import json
import sqlite3

from sqlite_engine import SQLiteEngine


class TrialService:
    def __init__(self, engine, *, related_action='review', min_signal_matches=1,
                 signal_retention_seconds=86400, max_entitlements=10000):
        if not isinstance(engine, SQLiteEngine):
            raise ValueError('Trial example requires a SQLiteEngine')
        if related_action not in ('review', 'observe'):
            raise ValueError('Invalid related action')
        if type(min_signal_matches) is not int or not 1 <= min_signal_matches <= len(engine.settings['required'] + engine.settings['conditional']):
            raise ValueError('Invalid signal threshold')
        if type(signal_retention_seconds) is not int or not 60 <= signal_retention_seconds <= 31536000:
            raise ValueError('Invalid trial signal retention')
        if type(max_entitlements) is not int or not 1 <= max_entitlements <= 1000000:
            raise ValueError('Invalid entitlement capacity')
        self.engine = engine
        self.related_action = related_action
        self.min_signal_matches = min_signal_matches
        self.signal_retention_seconds = signal_retention_seconds
        self.max_entitlements = max_entitlements
        settings = json.dumps([1,related_action,min_signal_matches,signal_retention_seconds,max_entitlements], separators=(',',':'))
        config_hash = hashlib.sha256(settings.encode()).hexdigest()
        con = engine.connect()
        try:
            con.execute('BEGIN IMMEDIATE')
            row = con.execute("SELECT value FROM meta WHERE name='trial_policy_v1'").fetchone()
            existing = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('trial_entitlements','trial_signals')")}
            if (row is not None and existing != {'trial_entitlements','trial_signals'}) or (row is None and existing):
                raise ValueError('Trial tables and metadata are inconsistent; restore or migrate explicitly')
            con.execute('CREATE TABLE IF NOT EXISTS trial_entitlements (id INTEGER PRIMARY KEY, account_token TEXT NOT NULL, offer_token TEXT NOT NULL, idem_token TEXT NOT NULL, request_token TEXT NOT NULL, created REAL NOT NULL, UNIQUE(account_token,offer_token), UNIQUE(account_token,idem_token))')
            con.execute('CREATE TABLE IF NOT EXISTS trial_signals (trial_id INTEGER NOT NULL REFERENCES trial_entitlements(id) ON DELETE CASCADE, name TEXT NOT NULL, token TEXT NOT NULL, expires REAL NOT NULL, PRIMARY KEY(trial_id,name))')
            con.execute('CREATE INDEX IF NOT EXISTS trial_signal_lookup ON trial_signals(name,token,expires,trial_id)')
            con.execute('CREATE INDEX IF NOT EXISTS trial_signal_expiry ON trial_signals(expires)')
            if row is None:
                con.execute("INSERT INTO meta(name,value) VALUES('trial_policy_v1',?)", (config_hash,))
            elif not hmac.compare_digest(row[0], config_hash):
                raise ValueError('Trial policy does not match; use a new database or migrate explicitly')
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    @staticmethod
    def _validate(value, label):
        if not isinstance(value,str) or not 1 <= len(value) <= 128 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('Invalid ' + label)

    def status(self, *, authenticated_account, offer):
        """Read the local entitlement for a host-authenticated account.

        A storage error is distinct from an inactive entitlement; the host must
        decide its failure policy and cannot treat an error as authorization.
        """
        self._validate(authenticated_account,'account')
        self._validate(offer,'offer')
        try:
            con = self.engine.connect()
            try:
                row = con.execute('SELECT 1 FROM trial_entitlements WHERE account_token=? AND offer_token=?',
                                  (self.engine.token('trial-account',authenticated_account), self.engine.token('trial-offer',offer))).fetchone()
                return {'decision':'active' if row else 'not_active'}
            finally:
                con.close()
        except sqlite3.Error:
            return self.engine._storage_error()

    def activate(self, *, authenticated_account, offer, idempotency_key, signals, peer,
                 timezone=None, timestamp=None):
        """Atomically check and create the local entitlement for a trusted principal.

        `authenticated_account` and `peer` must be derived by the host, never
        trusted from a request body. The caller must apply HTTP authentication,
        input limits and malformed-request charging before invoking this API.
        Only successful activations are idempotently replayed; denied/reviewed
        attempts are charged again. Do not grant an external trial separately.
        """
        for value, label in ((authenticated_account,'account'), (offer,'offer'), (idempotency_key,'idempotency key')):
            self._validate(value, label)
        request = {'account':authenticated_account, 'signals':signals}
        if timezone is not None: request['timezone'] = timezone
        if timestamp is not None: request['timestamp'] = timestamp
        prepared = self.engine.prepare(request, peer)
        now, tokens, missing, zone, clock_status = prepared
        device_tokens = {name:value for name,value in tokens.items() if name != 'ip'}
        token = self.engine.token
        account_key = token('trial-account',authenticated_account)
        offer_key = token('trial-offer',offer)
        idem_key = token('trial-idempotency',idempotency_key)
        # Bind an idempotency key to the offer and normalized device data. Exclude
        # IP and time so legitimate retries can move networks or refresh clocks.
        bound = json.dumps([offer_key, sorted(device_tokens.items())], separators=(',',':'))
        request_key = token('trial-request',bound)
        attempt_key = token('trial-attempt',json.dumps([account_key,offer_key], separators=(',',':')))
        try:
            con = self.engine.connect()
            try:
                con.execute('BEGIN IMMEDIATE')
                previous = con.execute('SELECT offer_token,request_token FROM trial_entitlements WHERE account_token=? AND idem_token=?',(account_key,idem_key)).fetchone()
                if previous:
                    if not hmac.compare_digest(previous[0],offer_key) or not hmac.compare_digest(previous[1],request_key):
                        result = {'decision':'conflict','reason':'idempotency_key_reused'}
                    else:
                        result = {'decision':'activated','reason':'idempotent_replay'}
                else:
                    already = con.execute('SELECT 1 FROM trial_entitlements WHERE account_token=? AND offer_token=?',(account_key,offer_key)).fetchone()
                    if already:
                        failure = self.engine._charge(con, [*tokens.values(),attempt_key], now)
                        result = failure or {'decision':'already_used','reason':'account_offer_used'}
                    else:
                        result = self.engine._check_in_transaction(con, prepared, [attempt_key])
                        if result['decision'] == 'allow':
                            # Compare only against successful activations, not all
                            # observed attempts; IP alone never triggers review.
                            con.execute('DELETE FROM trial_signals WHERE expires <= ?', (now,))
                            matched = set()
                            if device_tokens:
                                conditions = ' OR '.join('(s.name=? AND s.token=?)' for _ in device_tokens)
                                params = [offer_key, *[x for pair in device_tokens.items() for x in pair], self.min_signal_matches]
                                rows = con.execute('SELECT s.trial_id, count(*) FROM trial_signals s JOIN trial_entitlements e ON e.id=s.trial_id WHERE e.offer_token=? AND ('+conditions+') GROUP BY s.trial_id HAVING count(*) >= ?',params).fetchall()
                                matched = {row[0] for row in rows}
                            if matched and self.related_action == 'review':
                                result = {'decision':'review','reason':'related_prior_activation','message':'Additional review is required; a matching signal is not proof of misuse.'}
                            elif con.execute('SELECT count(*) FROM trial_entitlements').fetchone()[0] >= self.max_entitlements:
                                result = {'decision':'capacity_exceeded','retry_after_seconds':1}
                            else:
                                cur = con.execute('INSERT INTO trial_entitlements(account_token,offer_token,idem_token,request_token,created) VALUES(?,?,?,?,?)',(account_key,offer_key,idem_key,request_key,now))
                                con.executemany('INSERT INTO trial_signals(trial_id,name,token,expires) VALUES(?,?,?,?)',[(cur.lastrowid,n,v,now+self.signal_retention_seconds) for n,v in device_tokens.items()])
                                result = {'decision':'activated','reason':'created','prior_signal_match':bool(matched)}
                con.commit()
                return result
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()
        except sqlite3.Error:
            return self.engine._storage_error()
