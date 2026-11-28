"""Atheris fuzz target: synthetic normalization, JSON and sealed envelopes.

Runs only with the optional test-only Atheris dependency. Never uses real keys,
host signals, external services or user-controlled production data.
"""
import base64
import math
import sys
from pathlib import Path

import atheris
from nacl.public import PrivateKey, SealedBox  # preload external native code

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
with atheris.instrument_imports():
    from sealed_payload import PREFIX, PREFIX_V3, TransportKeyRing, unseal, unseal_v3
    from signal_validation import SIGNALS, normalize_signal
    from service import parse_json

KEY = PrivateKey(bytes(range(32)))  # explicitly public synthetic fixture
RING = TransportKeyRing({'test': bytes(KEY)})
BOX = SealedBox(KEY.public_key)


def rejected_or_value(fn):
    try:
        return fn()
    except ValueError as exc:
        # Deliberately require a generic error and no leaked key or payload.
        assert str(exc) == 'Invalid encrypted request'
        return None


def TestOneInput(data):
    if not data or len(data) > 9000:
        return
    mode, body = data[0] % 6, data[1:]
    if mode == 0:
        name = SIGNALS[(body[0] if body else 0) % len(SIGNALS)]
        value = body[1:].decode('utf-8', 'replace')
        try:
            result = normalize_signal(name, value)
        except ValueError:
            return
        assert isinstance(result, str) and result.isascii()
        assert normalize_signal(name, result) == result
    elif mode in (1, 2):
        # Encrypt fuzzed inner plaintext so the prefix and length validation
        # receive coverage; random ciphertext would mostly fail decryption.
        sealed = base64.b64encode(BOX.encrypt(body)).decode('ascii')
        if mode == 1:
            actual = rejected_or_value(lambda: unseal({'version': 'sealed-v2', 'ciphertext': sealed}, bytes(KEY)))
            expected = body[len(PREFIX):] if body.startswith(PREFIX) and len(body) <= 6144 and len(sealed) <= 8192 else None
        else:
            inner = PREFIX_V3 + b'\x04test'
            actual = rejected_or_value(lambda: unseal_v3({'version': 'sealed-v3', 'key_id': 'test', 'ciphertext': sealed}, RING))
            expected = body[len(inner):] if body.startswith(inner) and len(body) <= 6144 and len(sealed) <= 8192 else None
        assert actual == expected
    elif mode == 5:
        try:
            result = parse_json(body)
        except ValueError as exc:
            assert str(exc) == 'Invalid JSON'
            return
        # Walk iteratively, avoiding a second recursion limit near deeply
        # nested but valid JSON. Parsing must never create NaN or infinities.
        pending = [result]
        while pending:
            value = pending.pop()
            if isinstance(value, float):
                assert math.isfinite(value)
            elif isinstance(value, dict):
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
    else:
        # Vary ciphertext and outer shape, including malformed base64. Crypto
        # failures must remain generic and never return attacker data.
        cipher = body.decode('utf-8', 'replace')
        if mode == 3:
            envelope = {'version': 'sealed-v2', 'ciphertext': cipher}
            actual = rejected_or_value(lambda: unseal(envelope, bytes(KEY)))
        else:
            envelope = {'version': 'sealed-v3', 'key_id': 'test', 'ciphertext': cipher}
            actual = rejected_or_value(lambda: unseal_v3(envelope, RING))
        assert actual is None or isinstance(actual, bytes)


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
