"""Archx request-policy demonstration. Not an authentication/security boundary."""
import hashlib
import hmac
import ipaddress
import math
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

SIGNALS = ('machine_id', 'product_uuid', 'board_serial', 'product_serial', 'chassis_serial',
           'disk_serial', 'disk_wwn', 'filesystem_uuid', 'partition_uuid', 'gpu_uuid',
           'mac_address', 'installation_id')
TOKEN_RE = re.compile(r'^[0-9a-f]{64}$')
PRESETS = {
    'basic': {'required':['machine_id'], 'conditional':['product_uuid', 'board_serial'], 'min_matches':1},
    'standard': {'required':['machine_id'], 'conditional':['product_uuid','board_serial','disk_serial','disk_wwn','filesystem_uuid','partition_uuid','installation_id'], 'min_matches':2},
    'hard': {'required':['machine_id'], 'conditional':[s for s in SIGNALS if s != 'machine_id'], 'min_matches':3},
}


def policy(preset='basic', override=None):
    if preset not in PRESETS: raise ValueError('Unknown preset')
    p = {'name':preset, **PRESETS[preset], 'window_seconds':60, 'max_requests':5,
         'max_clock_skew_seconds':300, 'timezone_tolerance_minutes':30, 'timezone_enforce':False}
    if override is not None:
        if not isinstance(override, dict): raise ValueError('Policy must be an object')
        allowed = {'required','conditional','min_matches','window_seconds','max_requests','max_clock_skew_seconds','timezone_tolerance_minutes','timezone_enforce'}
        if set(override) - allowed: raise ValueError('Unknown policy setting')
        p.update(override)
    for key in ('required','conditional'):
        if not isinstance(p[key], list) or any(not isinstance(x, str) or x not in SIGNALS for x in p[key]) or len(p[key]) != len(set(p[key])):
            raise ValueError('Invalid signal list')
    if set(p['required']) & set(p['conditional']): raise ValueError('Signal roles overlap')
    for key, low, high in [('min_matches',1,1+len(p['required'])+len(p['conditional'])),('window_seconds',1,86400),('max_requests',1,10000),('max_clock_skew_seconds',0,86400),('timezone_tolerance_minutes',0,180)]:
        if type(p[key]) is not int or not low <= p[key] <= high: raise ValueError('Invalid '+key)
    if not isinstance(p['timezone_enforce'], bool): raise ValueError('Invalid timezone enforcement')
    return p

class Engine:
    def __init__(self, settings=None, secret=None, geo=None, clock=None, max_entries=10000):
        self.settings = settings or policy()
        self.secret = secret or secrets.token_bytes(32)
        self.geo = geo or [] # [(ip_network, [IANA zones])], configured by operator; no auto lookup
        self.clock = clock or time.time
        self.max_entries = max_entries
        self.lock = threading.Lock()
        self.windows = {} # HMAC key -> [window_start, count]
        self.observations = [] # (expires, {signal name: HMAC})

    def token(self, name, value):
        return hmac.new(self.secret, (name+'\0'+value).encode(), hashlib.sha256).hexdigest()

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
        now = self.clock()
        ip = ipaddress.ip_address(peer)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped: ip = ip.ipv4_mapped
        key = self.token('ip', str(ip)); window = self.settings['window_seconds']
        with self.lock:
            self.windows = {k:v for k,v in self.windows.items() if now-v[0] < window}
            if key not in self.windows and len(self.windows) >= self.max_entries:
                return {'decision':'capacity_exceeded','retry_after_seconds':window,'relation':'inconclusive'}
            row = self.windows.setdefault(key,[now,0]); row[1] += 1
            if row[1] > self.settings['max_requests']:
                return {'decision':'rate_limited','retry_after_seconds':math.ceil(window-(now-row[0])), 'relation':'inconclusive'}
        return None

    def check(self, raw, peer):
        now = self.clock()
        ip = ipaddress.ip_address(peer)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped: ip = ip.ipv4_mapped
        # Validate shape; IP always comes from server connection, never client input.
        if not isinstance(raw, dict) or set(raw) - {'account','signals','timezone','timestamp'}:
            raise ValueError('Invalid request fields')
        account = raw.get('account')
        if not isinstance(account,str) or not 1 <= len(account) <= 128 or any(ord(c)<32 for c in account): raise ValueError('Invalid account')
        signals = raw.get('signals')
        if not isinstance(signals,dict) or len(signals)>len(SIGNALS): raise ValueError('Invalid signals')
        selected = set(self.settings['required'] + self.settings['conditional'])
        if set(signals) - selected: raise ValueError('Unknown or disabled signal')
        if any(not isinstance(v,str) or not TOKEN_RE.fullmatch(v) for v in signals.values()): raise ValueError('Signals must be lowercase 64-character tokens')
        missing = [s for s in self.settings['required'] if s not in signals]
        zone, clock_status = self.timezone_status(ip, raw.get('timezone'), raw.get('timestamp'), now)
        tokens = {s:self.token(s,v) for s,v in signals.items()}
        tokens['ip'] = self.token('ip', str(ip))
        # Limit independently by IP and each selected observation. A shared IP is a shared bucket.
        keys = list(tokens.values())
        window = self.settings['window_seconds']
        with self.lock:
            self.windows = {k:v for k,v in self.windows.items() if now-v[0] < window}
            self.observations = [(expiry,v) for expiry,v in self.observations if expiry > now]
            missing_keys = sum(1 for key in keys if key not in self.windows)
            if len(self.windows) + missing_keys > self.max_entries:
                return {'decision':'capacity_exceeded','retry_after_seconds':window, 'relation':'inconclusive'}
            retry = 0
            for key in keys:
                row = self.windows.setdefault(key, [now,0])
                row[1] += 1
                if row[1] > self.settings['max_requests']:
                    retry = max(retry, math.ceil(window - (now-row[0])))
            if retry:
                return {'decision':'rate_limited','retry_after_seconds':retry, 'relation':'inconclusive'}
            if missing:
                return {'decision':'invalid','reason':'missing_required','missing':missing, 'relation':'inconclusive'}
            if self.settings['timezone_enforce'] and zone == 'mismatch':
                return {'decision':'challenge','reason':'timezone_mismatch','message':'Check your timezone or network location, then retry.', 'timezone':zone, 'clock':clock_status, 'relation':'inconclusive'}
            if self.settings['timezone_enforce'] and clock_status == 'clock_out_of_range':
                return {'decision':'challenge','reason':'clock_out_of_range','message':'Check your device clock, then retry.', 'timezone':zone, 'clock':clock_status, 'relation':'inconclusive'}
            best = []
            possible = False
            for _, prior in self.observations:
                matching = [s for s, v in tokens.items() if prior.get(s) == v]
                if len(matching) > len(best): best = matching
                possible |= len(set(tokens) & set(prior)) >= self.settings['min_matches']
            relation = 'related' if len(best) >= self.settings['min_matches'] else ('below_threshold' if self.observations and possible else 'inconclusive' if self.observations else 'new')
            if len(self.observations) >= self.max_entries: self.observations.pop(0)
            self.observations.append((now + window, tokens))
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
