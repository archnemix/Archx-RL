"""Deterministic policy tests; synthetic tokens deliberately contain no hardware data."""
import ctypes as C
import json
from pathlib import Path

lib = C.CDLL(str(Path(__file__).resolve().parents[1] / 'build/libarchx.so'))
lib.ax_core_new.argtypes = (C.c_char_p, C.c_size_t)
lib.ax_core_new.restype = C.c_void_p
lib.ax_core_free.argtypes = (C.c_void_p,)
lib.ax_buffer_free.argtypes = (C.c_void_p,)
lib.ax_last_error.restype = C.c_char_p
lib.ax_profile.argtypes = (C.c_void_p, C.POINTER(C.c_void_p), C.POINTER(C.c_size_t))
lib.ax_profile.restype = C.c_int
lib.ax_profile_with_ip.argtypes = (C.c_void_p, C.c_char_p, C.POINTER(C.c_void_p), C.POINTER(C.c_size_t))
lib.ax_profile_with_ip.restype = C.c_int
lib.ax_compare.argtypes = (C.c_void_p, C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t, C.POINTER(C.c_void_p), C.POINTER(C.c_size_t))
lib.ax_compare.restype = C.c_int

def core(policy=None, pepper='test-secret'):
    cfg = {'app_id':'test', 'pepper':pepper}
    if policy is not None: cfg['match'] = policy
    data = json.dumps(cfg).encode()
    return lib.ax_core_new(data, len(data))

def output(fn, *args):
    ptr, length = C.c_void_p(), C.c_size_t()
    rc = fn(*args, C.byref(ptr), C.byref(length))
    if rc != 0: raise ValueError(lib.ax_last_error().decode())
    try: return json.loads(C.string_at(ptr, length.value))
    finally: lib.ax_buffer_free(ptr)

def profile(c): return output(lib.ax_profile, c)
def compare(c, a, b):
    x, y = json.dumps(a).encode(), json.dumps(b).encode()
    return output(lib.ax_compare, c, x, len(x), y, len(y))
def expect(c, a, b, result, states):
    r = compare(c, a, b)
    assert r['result'] == result and r['signals'] == states, r

strict = core(); assert strict
base = profile(strict)
assert set(base['signals']) == {'machine_id','product_uuid','board_serial'}
# Test decision logic independently of permissions and actual OS values.
base['signals'] = {'machine_id':'a'*64, 'product_uuid':'b'*64, 'board_serial':'c'*64}
all_match = dict(base, signals=dict(base['signals']))
changed = dict(base, signals=dict(base['signals'], board_serial='d'*64))
missing = dict(base, signals=dict(base['signals'], board_serial=None))
expect(strict, base, all_match, 'match', dict.fromkeys(base['signals'], 'match'))
expect(strict, base, changed, 'no_match', {'machine_id':'match','product_uuid':'match','board_serial':'changed'})
expect(strict, base, missing, 'inconclusive', {'machine_id':'match','product_uuid':'match','board_serial':'unavailable'})
other = core(pepper='different-secret'); assert other
try:
    try: compare(other, base, base)
    except ValueError: pass
    else: raise AssertionError('wrong pepper should fail')
finally: lib.ax_core_free(other)
lib.ax_core_free(strict)

policy = {'mode':'threshold', 'min_matches':2, 'signals':{'machine_id':'required','product_uuid':'optional','board_serial':'optional'}}
c = core(policy); assert c
expect(c, base, changed, 'match', {'machine_id':'match','product_uuid':'match','board_serial':'changed'})
expect(c, base, missing, 'match', {'machine_id':'match','product_uuid':'match','board_serial':'unavailable'})
required_changed = dict(base, signals=dict(base['signals'], machine_id='d'*64))
expect(c, base, required_changed, 'no_match', {'machine_id':'changed','product_uuid':'match','board_serial':'match'})
required_missing = dict(base, signals=dict(base['signals'], machine_id=None))
expect(c, base, required_missing, 'inconclusive', {'machine_id':'unavailable','product_uuid':'match','board_serial':'match'})
two_changed = dict(base, signals=dict(base['signals'], product_uuid='d'*64, board_serial='e'*64))
expect(c, base, two_changed, 'no_match', {'machine_id':'match','product_uuid':'changed','board_serial':'changed'})
unknown = dict(base, signals=dict(base['signals'], product_uuid='d'*64, board_serial=None))
expect(c, base, unknown, 'inconclusive', {'machine_id':'match','product_uuid':'changed','board_serial':'unavailable'})
malformed = dict(base, signals=dict(base['signals'], machine_id='not-a-token'))
try: compare(c, base, malformed)
except ValueError: pass
else: raise AssertionError('invalid token accepted')
lib.ax_core_free(c)

c = core({'mode':'strict', 'signals':{'machine_id':'optional'}}); assert c
assert set(profile(c)['signals']) == {'machine_id'}
lib.ax_core_free(c)
for invalid in ({'mode':'threshold'}, {'mode':'threshold','min_matches':4}, {'signals':{}},
                {'signals':{'made_up':'required'}}, {'signals':{'machine_id':'sometimes'}},
                {'mode':'strict','min_matches':1}, {'mode':'typo'}, {'unexpected':True}):
    assert not core(invalid), invalid
c = core({'mode':'threshold', 'min_matches':2, 'signals':{'machine_id':'optional','product_uuid':'optional','ip':'optional'}}); assert c
p = output(lib.ax_profile_with_ip, c, b'2001:0db8:0:0:0:0:0:1')
q = output(lib.ax_profile_with_ip, c, b'2001:db8::1')
assert p['signals']['ip'] == q['signals']['ip'] and p['signals']['ip'] is not None
assert profile(c)['signals']['ip'] is None
try: output(lib.ax_profile_with_ip, c, b'not-an-ip')
except ValueError: pass
else: raise AssertionError('invalid IP accepted')
a = dict(p, signals={'machine_id':'a'*64,'product_uuid':'b'*64,'ip':'c'*64})
b = dict(a, signals=dict(a['signals'], ip='d'*64))
expect(c, a, b, 'match', {'machine_id':'match','product_uuid':'match','ip':'changed'})
lib.ax_core_free(c)
print('matching policy tests passed')
