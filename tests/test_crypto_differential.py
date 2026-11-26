"""Synthetic SHA-256 and HMAC differential cases against Python hashlib/hmac."""
import ctypes
import hashlib
import hmac
import os
import random
import unittest
from pathlib import Path

# Native CI loads a standalone synthetic crypto fixture, never a full core.
default_lib = Path(__file__).resolve().parents[1] / 'build/libarchx.so'
lib = ctypes.CDLL(os.environ.get('ARCHX_CRYPTO_TEST_LIB', str(default_lib)))

class Context(ctypes.Structure):
    _fields_ = [('h', ctypes.c_uint32 * 8), ('len_bytes', ctypes.c_uint64),
                ('block', ctypes.c_uint8 * 64), ('block_len', ctypes.c_size_t)]

lib.ax_sha256.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)
lib.ax_sha256_init.argtypes = (ctypes.POINTER(Context),)
lib.ax_sha256_update.argtypes = (ctypes.POINTER(Context), ctypes.c_void_p, ctypes.c_size_t)
lib.ax_sha256_final.argtypes = (ctypes.POINTER(Context), ctypes.c_void_p)
lib.ax_hmac_sha256.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)
for function in (lib.ax_sha256, lib.ax_sha256_init, lib.ax_sha256_update, lib.ax_sha256_final, lib.ax_hmac_sha256):
    function.restype = None


def buffer(value):
    # Non-null pointer even for a zero-length synthetic input.
    return ctypes.create_string_buffer(value, max(1, len(value)))


class DifferentialTests(unittest.TestCase):
    def test_sha256_chunking_and_hmac(self):
        rng = random.Random(562341)
        lengths = [0, 1, 2, 31, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 1024, 8192]
        lengths += [rng.randrange(0, 5000) for _ in range(450)]
        for number, length in enumerate(lengths):
            msg = bytes(rng.getrandbits(8) for _ in range(length))
            key_length = rng.choice([0, 1, 32, 63, 64, 65, 131, 256])
            key = bytes(rng.getrandbits(8) for _ in range(key_length))
            out = (ctypes.c_uint8 * 32)()
            src, k = buffer(msg), buffer(key)
            lib.ax_sha256(src, len(msg), out)
            self.assertEqual(bytes(out), hashlib.sha256(msg).digest(), 'one-shot case ' + str(number))
            ctx = Context(); lib.ax_sha256_init(ctypes.byref(ctx))
            offset = 0
            while offset < length:
                size = min(length-offset, rng.randrange(1, 140))
                lib.ax_sha256_update(ctypes.byref(ctx), ctypes.byref(src, offset), size)
                offset += size
            # Exercise a zero-length update with a valid pointer.
            lib.ax_sha256_update(ctypes.byref(ctx), src, 0)
            lib.ax_sha256_final(ctypes.byref(ctx), out)
            self.assertEqual(bytes(out), hashlib.sha256(msg).digest(), 'stream case ' + str(number))
            lib.ax_hmac_sha256(k, len(key), src, len(msg), out)
            self.assertEqual(bytes(out), hmac.digest(key, msg, 'sha256'), 'HMAC case ' + str(number))

if __name__ == '__main__': unittest.main(verbosity=2)
