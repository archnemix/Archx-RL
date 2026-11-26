"""Experimental binding to a caller-selected Archx C ABI-v1 shared library.

Only Linux is currently supported by the full core. A loaded native library
runs with the host process's privileges; never load a library from an untrusted
path. Explicitly close each Core (or use a context manager).
"""
import ctypes as C
import json
import os
import threading


class ArchxError(RuntimeError):
    """Native operation failed; a denial without error is returned separately."""


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')


def _cstring(value, name):
    if not isinstance(value, str) or '\0' in value:
        raise ValueError(f'{name} must be a NUL-free string')
    return value.encode('utf-8')


def _load(path):
    path = os.fspath(path)
    if not os.path.isabs(path):
        raise ValueError('An absolute trusted library path is required')
    lib = C.CDLL(path)
    lib.ax_abi_version.argtypes = ()
    lib.ax_abi_version.restype = C.c_uint32
    if lib.ax_abi_version() != 1:
        raise ArchxError('Unsupported Archx ABI version')
    lib.ax_last_error.argtypes = ()
    lib.ax_last_error.restype = C.c_char_p
    lib.ax_core_new.argtypes = (C.c_char_p, C.c_size_t)
    lib.ax_core_new.restype = C.c_void_p
    lib.ax_core_free.argtypes = (C.c_void_p,)
    lib.ax_core_free.restype = None
    lib.ax_buffer_free.argtypes = (C.c_void_p,)
    lib.ax_buffer_free.restype = None
    for name in ('ax_collect', 'ax_identify', 'ax_profile'):
        fn = getattr(lib, name)
        fn.argtypes = (C.c_void_p, C.POINTER(C.c_void_p), C.POINTER(C.c_size_t))
        fn.restype = C.c_int
    # Optional addition within ABI v1; older ABI-v1 libraries remain usable.
    try:
        capability_fn = lib.ax_collect_capabilities
    except AttributeError:
        capability_fn = None
    if capability_fn is not None:
        capability_fn.argtypes = (C.c_void_p, C.POINTER(C.c_void_p), C.POINTER(C.c_size_t))
        capability_fn.restype = C.c_int
    lib.ax_profile_with_ip.argtypes = (C.c_void_p, C.c_char_p, C.POINTER(C.c_void_p), C.POINTER(C.c_size_t))
    lib.ax_profile_with_ip.restype = C.c_int
    lib.ax_compare.argtypes = (C.c_void_p, C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t,
                               C.POINTER(C.c_void_p), C.POINTER(C.c_size_t))
    lib.ax_compare.restype = C.c_int
    lib.ax_check.argtypes = (C.c_void_p, C.c_char_p, C.c_int64, C.POINTER(C.c_int64), C.POINTER(C.c_int64))
    lib.ax_check.restype = C.c_int
    lib.ax_reset.argtypes = (C.c_void_p, C.c_char_p)
    lib.ax_reset.restype = C.c_int
    return lib


class Core:
    def __init__(self, library_path, config):
        self._lock = threading.RLock()
        self._lib = _load(library_path)
        self._handle = None
        data = _json_bytes(config)
        self._handle = self._lib.ax_core_new(data, len(data))
        if not self._handle:
            raise ArchxError(self._error())

    def _error(self):
        raw = self._lib.ax_last_error()
        return raw.decode('utf-8', 'replace') if raw else 'Native operation failed'

    def _require_open(self):
        if self._handle is None:
            raise ArchxError('Core is closed')
        return self._handle

    def close(self):
        with self._lock:
            if self._handle is not None:
                self._lib.ax_core_free(self._handle)
                self._handle = None

    def __enter__(self):
        self._require_open()
        return self

    def __exit__(self, *args):
        self.close()

    def _result(self, name, *args):
        with self._lock:
            handle = self._require_open()
            ptr, length = C.c_void_p(), C.c_size_t()
            try:
                status = getattr(self._lib, name)(handle, *args, C.byref(ptr), C.byref(length))
                if status != 0:
                    raise ArchxError(self._error())
                if not ptr:
                    raise ArchxError('Native operation returned no buffer')
                if length.value > 1048576:
                    raise ArchxError('Invalid native buffer length')
                return json.loads(C.string_at(ptr, length.value))
            finally:
                if ptr:
                    self._lib.ax_buffer_free(ptr)

    def collect(self):
        return self._result('ax_collect')

    def capabilities(self):
        with self._lock:
            self._require_open()
            if not hasattr(self._lib, 'ax_collect_capabilities'):
                raise ArchxError('Capability extension unavailable in this library')
            return self._result('ax_collect_capabilities')

    def identify(self):
        return self._result('ax_identify')

    def profile(self, ip=None):
        return self._result('ax_profile_with_ip', None if ip is None else _cstring(ip, 'ip'))

    def compare(self, baseline, current):
        a, b = _json_bytes(baseline), _json_bytes(current)
        return self._result('ax_compare', a, len(a), b, len(b))

    def check(self, key, cost=1):
        key = _cstring(key, 'key')
        if type(cost) is not int or not 1 <= cost <= (1 << 63) - 1:
            raise ValueError('cost must be a positive signed 64-bit integer')
        with self._lock:
            handle = self._require_open()
            remaining, retry = C.c_int64(), C.c_int64()
            decision = self._lib.ax_check(handle, key, cost, C.byref(remaining), C.byref(retry))
            error = self._lib.ax_last_error()
            if error:
                raise ArchxError(error.decode('utf-8', 'replace'))
            if decision not in (0, 1):
                raise ArchxError('Unexpected native decision')
            return {'decision': 'allow' if decision == 0 else 'rate_limited',
                    'remaining': remaining.value, 'retry_after_ms': retry.value}

    def reset(self, key):
        key = _cstring(key, 'key')
        with self._lock:
            if self._lib.ax_reset(self._require_open(), key) != 0:
                raise ArchxError(self._error())
