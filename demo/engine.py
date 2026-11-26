"""Archx request-policy demonstration. Not an authentication/security boundary."""
import hashlib
import hmac
import ipaddress
import math
import secrets
import threading
import time
from datetime import datetime, timezone
from contextlib import contextmanager
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from signal_validation import SIGNALS, normalize_signal
from observation_index import ObservationIndex
from expiry_heap import ExpiryHeap
from metrics import ServiceMetrics

CLEANUP_BUDGET = 64

DEFAULT_MESSAGES = {
    'rate_limited': 'Too many requests. Please wait and try again.',
    'missing_required': 'This service requires device information that your device did not provide. Contact the service provider for help.',
    'invalid_request': 'We could not process this request. Please check your information and try again.',
    'timezone_mismatch': 'Check your timezone or network location, then retry.',
    'clock_out_of_range': 'Check your device clock, then retry.',
    'capacity_exceeded': 'The service is busy. Please try again later.',
    'storage_error': 'The service is temporarily unavailable. Please try again later.',
    'reputation_blocked': 'This network cannot be accepted right now. Please contact support.',
    'reputation_unavailable': 'Network checks are temporarily unavailable. Please try again later.',
    'turnstile_invalid': 'Please complete the security check and try again.',
    'turnstile_unavailable': 'The security check is temporarily unavailable. Please try again later.',
    'replay_rejected': 'This security check has expired or was already used. Please try again.',
    'replay_unavailable': 'The security check is temporarily unavailable. Please try again later.',
}

PRESETS = {
    'basic': {'required':['machine_id'], 'conditional':['product_uuid', 'board_serial'], 'min_matches':1},
    'standard': {'required':['machine_id'], 'conditional':['product_uuid','board_serial','disk_serial','disk_wwn','filesystem_uuid','partition_uuid','installation_id'], 'min_matches':2},
    'hard': {'required':['machine_id'], 'conditional':[s for s in SIGNALS if s != 'machine_id'], 'min_matches':3},
}


def policy(preset='basic', override=None):
    if preset not in PRESETS: raise ValueError('Unknown preset')
    p = {'name':preset, **PRESETS[preset], 'window_seconds':60, 'max_requests':5,
         'max_clock_skew_seconds':300, 'timezone_tolerance_minutes':30, 'timezone_enforce':False, 'history_seconds':86400}
    if override is not None:
        if not isinstance(override, dict): raise ValueError('Policy must be an object')
        allowed = {'required','conditional','min_matches','window_seconds','max_requests','max_clock_skew_seconds','timezone_tolerance_minutes','timezone_enforce','history_seconds','messages','ip_storage','ip_max_requests','device_max_requests'}
        if set(override) - allowed: raise ValueError('Unknown policy setting')
        p.update(override)
    for key in ('required','conditional'):
        if not isinstance(p[key], list) or any(not isinstance(x, str) or x not in SIGNALS for x in p[key]) or len(p[key]) != len(set(p[key])):
            raise ValueError('Invalid signal list')
    if set(p['required']) & set(p['conditional']): raise ValueError('Signal roles overlap')
    for key, low, high in [('min_matches',1,1+len(p['required'])+len(p['conditional'])),('window_seconds',1,86400),('history_seconds',60,31536000),('max_requests',1,10000),('max_clock_skew_seconds',0,86400),('timezone_tolerance_minutes',0,180)]:
        if type(p[key]) is not int or not low <= p[key] <= high: raise ValueError('Invalid '+key)
    for key in ('ip_max_requests','device_max_requests'):
        if key in p and (type(p[key]) is not int or not 1 <= p[key] <= 10000):
            raise ValueError('Invalid ' + key)
    if not isinstance(p['timezone_enforce'], bool): raise ValueError('Invalid timezone enforcement')
    if p.get('ip_storage','hash') not in ('hash','raw'): raise ValueError('IP storage must be hash or raw; device signals are always hashed')
    if 'messages' in p:
        messages=p['messages']
        if not isinstance(messages,dict) or set(messages)-set(DEFAULT_MESSAGES): raise ValueError('Invalid messages')
        if any(not isinstance(v,str) or not 1 <= len(v) <= 500 or any(ord(c) < 32 or ord(c) == 127 for c in v) for v in messages.values()): raise ValueError('Invalid messages')
        p['messages']=dict(messages)
    return p

class Engine:
    def __init__(self, settings=None, secret=None, geo=None, clock=None, max_entries=10000, metrics=None):
        if metrics is not None and not isinstance(metrics, ServiceMetrics): raise ValueError('Invalid metrics collector')
        self.metrics = metrics
        self.settings = settings or policy()
        self.secret = secret or secrets.token_bytes(32)
        self.geo = geo or [] # [(ip_network, [IANA zones])], configured by operator; no auto lookup
        self.clock = clock or time.time
        self.max_entries = max_entries
        self.lock = threading.Lock()
        self.windows = {} # HMAC key -> [window_start, count]
        self.window_expiries = ExpiryHeap() # one entry per window, no tombstones
        self.observations = ObservationIndex(max_entries) # bounded token snapshots

    def _record_wait(self, started):
        if self.metrics is not None:
            try:
                elapsed = time.perf_counter() - started if started is not None else None
                self.metrics.observe_wait(elapsed)
            except Exception:
                pass

    @contextmanager
    def _serialized(self):
        started = None
        if self.metrics is not None:
            try: started = time.perf_counter()
            except Exception: pass
        waited = None
        try:
            with self.lock:
                if started is not None:
                    try: waited = time.perf_counter() - started
                    except Exception: pass
                yield
        finally:
            if self.metrics is not None:
                try: self.metrics.observe_wait(waited)
                except Exception: pass

    def message(self, name):
        return self.settings.get('messages', {}).get(name, DEFAULT_MESSAGES[name])

    def _cleanup_busy(self):
        return {'decision':'capacity_exceeded','message':self.message('capacity_exceeded'),
                'retry_after_seconds':1, 'relation':'inconclusive'}

    def _prune_windows(self, now):
        """Drain at most CLEANUP_BUDGET; callers deny if stale entries remain."""
        cutoff = now - self.settings['window_seconds']
        removed = 0
        while removed < CLEANUP_BUDGET:
            top = self.window_expiries.peek()
            if top is None or top[0] > cutoff:
                return False
            _, key = self.window_expiries.pop()
            del self.windows[key]
            removed += 1
        top = self.window_expiries.peek()
        return top is not None and top[0] <= cutoff

    def _new_window(self, key, now):
        row = [now, 0]
        self.windows[key] = row
        self.window_expiries.set(key, now)
        return row

    def _window(self, key, now):
        row = self.windows.get(key)
        return row if row is not None else self._new_window(key, now)

    def token(self, name, value):
        return hmac.new(self.secret, ('archx-raw-v2\0'+name+'\0'+value).encode(), hashlib.sha256).hexdigest()

    def _quota(self, name):
        setting = 'ip_max_requests' if name == 'ip' else 'device_max_requests'
        return self.settings.get(setting, self.settings['max_requests'])

    def ip_key(self, ip):
        return 'raw-ip:' + str(ip) if self.settings.get('ip_storage','hash') == 'raw' else self.token('ip',str(ip))

    def timezone_status(self, ip, zone, stamp, now):
        if stamp is not None:
            if type(stamp) not in (int,float) or not math.isfinite(stamp): raise ValueError('Invalid timestamp')
            clock_status = 'ok' if abs(now - stamp) <= self.settings['max_clock_skew_seconds'] else 'clock_out_of_range'
        else: clock_status = 'unknown'
        if zone is None: return 'unknown', clock_status
        if not isinstance(zone, str) or len(zone) > 128: raise ValueError('Invalid timezone')
        try: client = ZoneInfo(zone)
        except (ZoneInfoNotFoundError, ValueError): raise ValueError('Invalid timezone') from None
        candidates = next((zones for network, zones in self.geo if ip in network), None)
        if not candidates: return 'unknown', clock_status
        when = datetime.fromtimestamp(now, timezone.utc)
        client_offset = when.astimezone(client).utcoffset().total_seconds()
        offsets = [when.astimezone(ZoneInfo(z)).utcoffset().total_seconds() for z in candidates]
        match = any(abs(client_offset - offset) <= self.settings['timezone_tolerance_minutes'] * 60 for offset in offsets)
        return ('consistent' if match else 'mismatch'), clock_status

    def reject_malformed(self, peer):
        """Charge malformed requests to the peer bucket too; never trust forwarded IP."""
        ip = ipaddress.ip_address(peer)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped: ip = ip.ipv4_mapped
        key = self.ip_key(ip); window = self.settings['window_seconds']
        with self._serialized():
            now = self.clock()
            if self._prune_windows(now): return self._cleanup_busy()
            if key not in self.windows and len(self.windows) >= self.max_entries:
                return {'decision':'capacity_exceeded','message':self.message('capacity_exceeded'),'retry_after_seconds':window,'relation':'inconclusive'}
            row = self._window(key,now); row[1] += 1
            if row[1] > self._quota('ip'):
                return {'decision':'rate_limited','message':self.message('rate_limited'),'retry_after_seconds':math.ceil(window-(now-row[0])), 'relation':'inconclusive'}
        return None

    def prepare(self, raw, peer):
        now = self.clock()
        ip = ipaddress.ip_address(peer)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped: ip = ip.ipv4_mapped
        # Validate shape; IP always comes from server connection, never client input.
        if not isinstance(raw, dict) or set(raw) - {'account','signals','timezone','timestamp'}:
            raise ValueError('Invalid request fields')
        # Legacy clients may send account; it is ignored and never identifies a user.
        if 'account' in raw and (not isinstance(raw['account'],str) or not 1 <= len(raw['account']) <= 128 or any(ord(c)<32 for c in raw['account'])): raise ValueError('Invalid legacy field')
        signals = raw.get('signals')
        if not isinstance(signals,dict) or len(signals)>len(SIGNALS): raise ValueError('Invalid signals')
        selected = set(self.settings['required'] + self.settings['conditional'])
        if set(signals) - selected: raise ValueError('Unknown or disabled signal')
        signals = {name: normalize_signal(name, value) for name,value in signals.items()}
        missing = [s for s in self.settings['required'] if s not in signals]
        zone, clock_status = self.timezone_status(ip, raw.get('timezone'), raw.get('timestamp'), now)
        tokens = {s:self.token(s,v) for s,v in signals.items()}
        tokens['ip'] = self.ip_key(ip)
        return now, tokens, missing, zone, clock_status

    def decision_before_matching(self, missing, zone, clock_status):
        if missing:
            return {'decision':'invalid','reason':'missing_required','missing':missing, 'message':self.message('missing_required'), 'relation':'inconclusive'}
        if self.settings['timezone_enforce'] and zone == 'mismatch':
            return {'decision':'challenge','reason':'timezone_mismatch','message':self.message('timezone_mismatch'), 'timezone':zone, 'clock':clock_status, 'relation':'inconclusive'}
        if self.settings['timezone_enforce'] and clock_status == 'clock_out_of_range':
            return {'decision':'challenge','reason':'clock_out_of_range','message':self.message('clock_out_of_range'), 'timezone':zone, 'clock':clock_status, 'relation':'inconclusive'}
        return None

    def check(self, raw, peer, *, _ip_precharged=False):
        _, tokens, missing, zone, clock_status = self.prepare(raw, peer)
        # The service precharges the IP before expensive verification. Direct callers
        # use the default and charge all buckets together under one lock.
        # A digest collision, however unlikely, charges once at the stricter limit.
        key_limits = {}
        for name, value in tokens.items():
            if _ip_precharged and name == 'ip': continue
            key_limits[value] = min(key_limits.get(value, self._quota(name)), self._quota(name))
        window = self.settings['window_seconds']
        with self._serialized():
            # State time must be sampled after waiting for the lock: an earlier
            # timestamp can expire a newly charged window or history too soon.
            now = self.clock()
            if self._prune_windows(now): return self._cleanup_busy()
            cleanup_pending = self.observations.prune(now, CLEANUP_BUDGET)
            missing_keys = sum(1 for key in key_limits if key not in self.windows)
            if len(self.windows) + missing_keys > self.max_entries:
                return {'decision':'capacity_exceeded','message':self.message('capacity_exceeded'),'retry_after_seconds':window, 'relation':'inconclusive'}
            retry = 0
            for key, limit in key_limits.items():
                row = self._window(key, now)
                row[1] += 1
                if row[1] > limit:
                    retry = max(retry, math.ceil(window - (now-row[0])))
            if retry:
                return {'decision':'rate_limited','message':self.message('rate_limited'),'retry_after_seconds':retry, 'relation':'inconclusive'}
            failure = self.decision_before_matching(missing, zone, clock_status)
            if failure:
                return failure
            if cleanup_pending:
                return self._cleanup_busy()
            relation, best = self.observations.match(tokens, self.settings['min_matches'])
            earliest = self.observations.enroll(tokens, now + self.settings['history_seconds'])
            if earliest is not None:
                return {'decision':'capacity_exceeded','message':self.message('capacity_exceeded'),
                        'retry_after_seconds':max(1, math.ceil(earliest-now)), 'relation':'inconclusive'}
            return {'decision':'allow','relation':relation,'matched_signals':best,
                    'timezone':zone, 'clock':clock_status, 'retry_after_seconds':0,
                    'warning':'A relation is not proof of the same person; shared IPs can link unrelated users.'}


def load_geo(raw):
    if not isinstance(raw, list) or len(raw)>10000: raise ValueError('Invalid geo mapping')
    result=[]
    for entry in raw:
        if not isinstance(entry,dict) or set(entry)!={'network','timezones'} or not isinstance(entry['timezones'],list) or not entry['timezones'] or len(entry['timezones'])>24: raise ValueError('Invalid geo mapping')
        net=ipaddress.ip_network(entry['network'], strict=False)
        for zone in entry['timezones']: ZoneInfo(zone)
        result.append((net,entry['timezones']))
    return sorted(result, key=lambda v: v[0].prefixlen, reverse=True)
