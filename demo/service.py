"""Framework-independent request gate for the Python prototype.

The host supplies an IP obtained from its own trusted transport boundary and
must enforce every returned decision. This is not authentication or middleware.
"""
import json
import time

from metrics import ServiceMetrics
from engine import StateClockUnavailable

from replay import ReplayUnavailable
from sealed_payload import TransportKeyRing, unseal, unseal_v3


def parse_json(data):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate key')
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError('Invalid JSON constant')

    try:
        return json.loads(data, object_pairs_hook=unique_pairs, parse_constant=invalid_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError('Invalid JSON') from None


def status_for(result):
    return {'allow':200, 'invalid':400, 'challenge':403, 'rate_limited':429,
            'capacity_exceeded':503, 'storage_error':503}.get(result['decision'], 500)


class RequestService:
    def __init__(self, engine, *, sealed_key=None, replay=None, reputation=None,
                 reputation_mode='observe', reputation_stale='open', turnstile=None, metrics=None):
        if reputation_mode not in ('observe', 'block') or reputation_stale not in ('open', 'closed'):
            raise ValueError('Invalid reputation policy')
        if sealed_key is not None and replay is None:
            raise ValueError('Encrypted mode requires a replay store')
        if metrics is not None and not isinstance(metrics, ServiceMetrics):
            raise ValueError('Invalid metrics collector')
        self.metrics = metrics
        self.engine, self.sealed_key, self.replay = engine, sealed_key, replay
        self.reputation, self.reputation_mode, self.reputation_stale = reputation, reputation_mode, reputation_stale
        self.turnstile = turnstile

    def failure(self, decision, reason):
        return {'decision':decision, 'reason':reason, 'message':self.engine.message(reason), 'relation':'inconclusive'}

    def config(self):
        protocol = ('sealed-v3' if type(self.sealed_key) is TransportKeyRing else
                    'sealed-v2' if self.sealed_key is not None else 'raw-v2')
        return {'protocol':protocol,
                'required':self.engine.settings['required'], 'conditional':self.engine.settings['conditional'],
                'missing_required_message':self.engine.message('missing_required'),
                'turnstile':{'sitekey':self.turnstile.sitekey, 'action':self.turnstile.action} if self.turnstile else None}

    def challenge(self, peer):
        if self.sealed_key is None:
            return None
        try:
            return {'nonce':self.replay.issue(peer), 'expires_in':self.replay.ttl}
        except ReplayUnavailable:
            if self.metrics is not None:
                try: self.metrics.observe_event('replay_unavailable')
                except Exception: pass
            return self.failure('storage_error', 'replay_unavailable')

    def check(self, envelope, peer):
        if self.metrics is None:
            return self._check(envelope, peer)
        # Instrumentation is best-effort and must not change or hide a gate
        # decision or exception. Only a fixed decision category is retained.
        try:
            started = time.perf_counter()
        except Exception:
            started = None
        decision, reason = 'unexpected', None
        try:
            result = self._check(envelope, peer)
            try:
                if isinstance(result, dict):
                    decision = result.get('decision')
                    reason = result.get('reason')
            except Exception:
                decision = 'unexpected'
            return result
        finally:
            try:
                seconds = time.perf_counter() - started if started is not None else None
                self.metrics.observe(decision, seconds, reason)
            except Exception:
                pass

    def _check(self, envelope, peer):
        # Precharge once before expensive decryption or Siteverify. Device buckets
        # are charged only after reputation and Turnstile verification succeed.
        limited = self.engine.reject_malformed(peer)
        if limited:
            return limited
        try:
            if self.sealed_key is not None:
                plaintext = (unseal_v3(envelope, self.sealed_key)
                             if type(self.sealed_key) is TransportKeyRing
                             else unseal(envelope, self.sealed_key))
                body = parse_json(plaintext)
                if not isinstance(body, dict):
                    raise ValueError('Invalid request')
                body = dict(body)
                nonce = body.pop('nonce', None)
                try:
                    if not self.replay.consume(nonce, peer):
                        return self.failure('invalid', 'replay_rejected')
                except ReplayUnavailable:
                    return self.failure('storage_error', 'replay_unavailable')
            else:
                if not isinstance(envelope, dict):
                    raise ValueError('Invalid request')
                body = dict(envelope)
            token = body.pop('turnstile_token', None) if self.turnstile else None
            _, _, missing, zone, clock_status = self.engine.prepare(body, peer)
            failure = self.engine.decision_before_matching(missing, zone, clock_status)
            if failure:
                return failure
            info = None
            if self.reputation:
                info = self.reputation.lookup(peer)
                if info['status'] == 'listed' and self.reputation_mode == 'block':
                    result = self.failure('challenge', 'reputation_blocked'); result['reputation'] = info
                    return result
                if info['status'] in ('stale', 'unavailable') and self.reputation_stale == 'closed':
                    result = self.failure('storage_error', 'reputation_unavailable'); result['reputation'] = info
                    return result
            if self.turnstile:
                verified = self.turnstile.verify(token)
                if verified != 'valid':
                    reason = 'turnstile_invalid' if verified == 'invalid' else 'turnstile_unavailable'
                    return self.failure('challenge' if verified == 'invalid' else 'storage_error', reason)
            result = self.engine.check(body, peer, _ip_precharged=True)
            if info is not None:
                result['reputation'] = info
            return result
        except StateClockUnavailable:
            return self.failure('storage_error', 'storage_error')
        except (ValueError, TypeError, KeyError):
            return self.failure('invalid', 'invalid_request')
