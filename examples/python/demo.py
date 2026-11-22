"""Minimal Linux ctypes example. Run after ./build.sh: python3 examples/python/demo.py"""
import ctypes as C
import json
import os
from pathlib import Path

lib = C.CDLL(str(Path(__file__).resolve().parents[2] / "build/libarchx.so"))
lib.ax_core_new.argtypes = (C.c_char_p, C.c_size_t)
lib.ax_core_new.restype = C.c_void_p
lib.ax_core_free.argtypes = (C.c_void_p,)
lib.ax_last_error.restype = C.c_char_p
lib.ax_buffer_free.argtypes = (C.c_void_p,)
for name in ("ax_collect", "ax_identify"):
    fn = getattr(lib, name)
    fn.argtypes = (C.c_void_p, C.POINTER(C.c_void_p), C.POINTER(C.c_size_t))
    fn.restype = C.c_int
lib.ax_check.argtypes = (C.c_void_p, C.c_char_p, C.c_int64,
                         C.POINTER(C.c_int64), C.POINTER(C.c_int64))
lib.ax_check.restype = C.c_int

config = json.dumps({"app_id": "python-demo", "pepper": os.getenv("ARCHX_PEPPER", "demo-only-change-me"),
                     "rate_limit": {"capacity": 2, "refill_per_sec": 0}}).encode()
core = lib.ax_core_new(config, len(config))
if not core:
    raise RuntimeError(lib.ax_last_error().decode())
try:
    for name in ("ax_collect", "ax_identify"):
        ptr, length = C.c_void_p(), C.c_size_t()
        if getattr(lib, name)(core, C.byref(ptr), C.byref(length)) != 0:
            raise RuntimeError(lib.ax_last_error().decode())
        try:
            print(name, json.loads(C.string_at(ptr, length.value)))
        finally:
            lib.ax_buffer_free(ptr)
    for _ in range(3):
        remaining, retry = C.c_int64(), C.c_int64()
        decision = lib.ax_check(core, b"example-user", 1, C.byref(remaining), C.byref(retry))
        if lib.ax_last_error():
            raise RuntimeError(lib.ax_last_error().decode())
        print("check", {"decision": "allow" if decision == 0 else "deny", "remaining": remaining.value, "retry_after_ms": retry.value})
finally:
    lib.ax_core_free(core)
