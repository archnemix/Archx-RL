"""Compare two captures; caller owns secure profile storage and request IP trust.

Run: python3 examples/python/match.py
"""
import ctypes as C
import json
import os
from pathlib import Path

lib = C.CDLL(str(Path(__file__).resolve().parents[2] / 'build/libarchx.so'))
lib.ax_core_new.argtypes = (C.c_char_p, C.c_size_t)
lib.ax_core_new.restype = C.c_void_p
lib.ax_core_free.argtypes = (C.c_void_p,)
lib.ax_buffer_free.argtypes = (C.c_void_p,)
lib.ax_last_error.restype = C.c_char_p
lib.ax_profile_with_ip.argtypes = (C.c_void_p, C.c_char_p, C.POINTER(C.c_void_p), C.POINTER(C.c_size_t))
lib.ax_profile_with_ip.restype = C.c_int
lib.ax_compare.argtypes = (C.c_void_p, C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t, C.POINTER(C.c_void_p), C.POINTER(C.c_size_t))
lib.ax_compare.restype = C.c_int

def invoke(fn, *args):
    ptr, length = C.c_void_p(), C.c_size_t()
    if fn(*args, C.byref(ptr), C.byref(length)) != 0:
        raise RuntimeError(lib.ax_last_error().decode())
    try: return C.string_at(ptr, length.value)
    finally: lib.ax_buffer_free(ptr)

config = json.dumps({
    'app_id': 'matching-demo', 'pepper': os.getenv('ARCHX_PEPPER', 'demo-only-change-me'),
    'match': {'mode':'threshold', 'min_matches':2,
              'signals': {'machine_id':'required', 'product_uuid':'optional', 'ip':'optional'}},
}).encode()
core = lib.ax_core_new(config, len(config))
if not core: raise RuntimeError(lib.ax_last_error().decode())
try:
    # Documentation addresses for illustration, not actual client IPs.
    baseline = invoke(lib.ax_profile_with_ip, core, b'192.0.2.1')
    current = invoke(lib.ax_profile_with_ip, core, b'192.0.2.2')
    result = invoke(lib.ax_compare, core, baseline, len(baseline), current, len(current))
    print(json.dumps(json.loads(result), indent=2))
finally:
    lib.ax_core_free(core)
