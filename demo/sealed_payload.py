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
import stat
from pathlib import Path

PREFIX = b'archx-sealed-check-v2\x00'


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
