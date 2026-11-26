"""Optional libsodium sealed-box request bodies; not a replacement for TLS.

The sender must receive the recipient public key through a trusted channel.
Sealed boxes provide confidentiality and integrity but not sender authentication
or replay protection. Only request bodies, not HTTP metadata or responses, are
sealed. Install PyNaCl to enable this optional prototype feature.
"""
import base64
import binascii
import json
import os
import re
import stat
from pathlib import Path
from types import MappingProxyType

PREFIX = b'archx-sealed-check-v2\x00'
PREFIX_V3 = b'archx-sealed-check-v3\x00'
_KEY_ID = re.compile(r'[A-Za-z0-9_-]{1,32}\Z', re.ASCII)


def _key_id(value):
    if type(value) is not str or not _KEY_ID.fullmatch(value):
        raise ValueError('Invalid transport key ID')
    return value


class TransportKeyRing:
    """Experimental static, bounded set of v3 decryption keys.

    Construct a new ring for every transition; this is not a key manager and
    does not persist keys, select active public keys or rotate pseudonym keys.
    """
    __slots__ = ('_keys',)

    def __init__(self, keys):
        if type(keys) is not dict or not 1 <= len(keys) <= 8:
            raise ValueError('Invalid transport key ring')
        copy = {}
        for name, value in keys.items():
            _key_id(name)
            if type(value) is not bytes or len(value) != 32:
                raise ValueError('Invalid transport key ring')
            copy[name] = value
        self._keys = MappingProxyType(copy)

    def _get(self, name):
        return self._keys.get(name)


def seal_v3(payload, key_id, public_key):
    """Seal a v3 request for an independently authenticated key ID and key."""
    from nacl.public import PublicKey, SealedBox
    name = _key_id(key_id).encode('ascii')
    if type(public_key) is not bytes or len(public_key) != 32:
        raise ValueError('Invalid public key')
    data = json.dumps(payload, separators=(',', ':'), ensure_ascii=True).encode()
    plain = PREFIX_V3 + bytes((len(name),)) + name + data
    if len(plain) > 6144:
        raise ValueError('Encrypted request too large')
    ciphertext = base64.b64encode(SealedBox(PublicKey(public_key)).encrypt(plain)).decode('ascii')
    if len(ciphertext) > 8192:
        raise ValueError('Encrypted request too large')
    return {'version': 'sealed-v3', 'key_id': key_id, 'ciphertext': ciphertext}


def unseal_v3(envelope, ring):
    """Reject unknown IDs, tampering and v2 without fallback to another key."""
    from nacl.public import PrivateKey, SealedBox
    from nacl.exceptions import CryptoError
    try:
        if type(ring) is not TransportKeyRing or type(envelope) is not dict or set(envelope) != {'version', 'key_id', 'ciphertext'} or envelope['version'] != 'sealed-v3':
            raise ValueError()
        name = _key_id(envelope['key_id']).encode('ascii')
        key = ring._get(envelope['key_id'])
        data = envelope['ciphertext']
        if key is None or type(data) is not str or len(data) > 8192:
            raise ValueError()
        ciphertext = base64.b64decode(data, validate=True)
        plain = SealedBox(PrivateKey(key)).decrypt(ciphertext)
        prefix = PREFIX_V3 + bytes((len(name),)) + name
        if len(plain) > 6144 or not plain.startswith(prefix):
            raise ValueError()
        return plain[len(prefix):]
    except (KeyError, ValueError, TypeError, binascii.Error, CryptoError):
        raise ValueError('Invalid encrypted request') from None


def read_key(path, private=False):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (private and (st.st_uid != os.geteuid() or st.st_mode & 0o077)):
            raise ValueError('Invalid key file permissions or type')
        raw=os.read(fd,129)
    finally: os.close(fd)
    try:
        text=raw.decode('ascii').strip()
        if len(text) != 64: raise ValueError()
        key=bytes.fromhex(text)
        if len(key) != 32: raise ValueError()
        return key
    except (UnicodeError,ValueError): raise ValueError('Invalid key file') from None


def seal(payload, public_key):
    from nacl.public import PublicKey, SealedBox
    data=json.dumps(payload,separators=(',',':'),ensure_ascii=True).encode()
    ciphertext=SealedBox(PublicKey(public_key)).encrypt(PREFIX+data)
    return {'version':'sealed-v2','ciphertext':base64.b64encode(ciphertext).decode('ascii')}


def unseal(envelope, private_key):
    from nacl.public import PrivateKey, SealedBox
    from nacl.exceptions import CryptoError
    try:
        if not isinstance(envelope,dict) or set(envelope) != {'version','ciphertext'} or envelope['version'] != 'sealed-v2': raise ValueError()
        data=envelope['ciphertext']
        if not isinstance(data,str) or len(data) > 8192: raise ValueError()
        ciphertext=base64.b64decode(data,validate=True)
        plain=SealedBox(PrivateKey(private_key)).decrypt(ciphertext)
        if not plain.startswith(PREFIX) or len(plain) > 6144: raise ValueError()
        return plain[len(PREFIX):]
    except (KeyError,ValueError,TypeError,binascii.Error,CryptoError):
        raise ValueError('Invalid encrypted request') from None


def create_keys(private_path, public_path):
    from nacl.public import PrivateKey
    if Path(private_path).absolute() == Path(public_path).absolute(): raise ValueError('Key paths must be different')
    key=PrivateKey.generate()
    # Explicit O_EXCL prevents overwriting existing key material.
    fd=os.open(private_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w',encoding='ascii') as out: out.write(bytes(key).hex()+'\n')
        pubfd=os.open(public_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        with os.fdopen(pubfd,'w',encoding='ascii') as out: out.write(bytes(key.public_key).hex()+'\n')
    except Exception:
        os.unlink(private_path)
        raise
