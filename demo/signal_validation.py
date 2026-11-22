"""Conservative syntactic validation for raw Linux signals.

These checks reject malformed or placeholder data; they cannot prove that a
client actually obtained the value from a real device. Formats are a documented
subset, not a universal specification of all manufacturers/filesystems.
"""
import re
import uuid

SERIALS = {'board_serial', 'product_serial', 'chassis_serial', 'disk_serial'}
UUIDS = {'product_uuid', 'filesystem_uuid', 'partition_uuid'}
SIGNALS = ('machine_id', 'product_uuid', 'board_serial', 'product_serial', 'chassis_serial',
           'disk_serial', 'disk_wwn', 'filesystem_uuid', 'partition_uuid', 'gpu_uuid',
           'mac_address', 'installation_id')
PLACEHOLDERS = {
    '0', 'none', 'unknown', 'n/a', 'not applicable', 'not specified',
    'to be filled by o.e.m.', 'to be filled by oem', 'default string',
    'system serial number', 'uninitialized', 'oem',
}
UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
SERIAL_RE = re.compile(r'^[a-z0-9][a-z0-9 ._:/-]{3,127}$')


def normalize_signal(name, value):
    """Return a normalized value or raise a generic, non-sensitive error."""
    def invalid():
        raise ValueError('Invalid or unsupported format for signal: ' + name)

    if name not in SIGNALS or not isinstance(value, str) or len(value) > 128:
        invalid()
    value = value.strip().lower()
    if not value or value in PLACEHOLDERS or not value.isascii():
        invalid()
    if name == 'machine_id':
        if not re.fullmatch(r'[0-9a-f]{32}', value) or value in ('0'*32, 'f'*32): invalid()
    elif name == 'installation_id':
        if not re.fullmatch(r'[0-9a-f]{64}', value) or value in ('0'*64, 'f'*64): invalid()
    elif name in SERIALS:
        if not SERIAL_RE.fullmatch(value) or set(value) <= {'0'}: invalid()
    elif name in UUIDS:
        if UUID_RE.fullmatch(value):
            parsed = uuid.UUID(value)
            if parsed.int in (0, (1 << 128)-1): invalid()
            value = str(parsed)
        elif name == 'filesystem_uuid' and (re.fullmatch(r'[0-9a-f]{4}-[0-9a-f]{4}', value) or re.fullmatch(r'[0-9a-f]{16}', value)):
            if set(value.replace('-', '')) <= {'0'}: invalid()
        elif name == 'partition_uuid' and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{2}', value):
            if set(value.replace('-', '')) <= {'0'}: invalid()
        else: invalid()
    elif name == 'disk_wwn':
        # Common 64- and 128-bit WWNs; optional 0x/eui. transport prefix.
        value = value.removeprefix('0x').removeprefix('eui.')
        if not re.fullmatch(r'(?:[0-9a-f]{16}|[0-9a-f]{32})', value) or set(value) <= {'0'} or set(value) <= {'f'}: invalid()
    elif name == 'gpu_uuid':
        if not value.startswith('gpu-') or not UUID_RE.fullmatch(value[4:]): invalid()
        parsed = uuid.UUID(value[4:])
        if parsed.int in (0, (1 << 128)-1): invalid()
        value = 'gpu-' + str(parsed)
    elif name == 'mac_address':
        if not re.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}', value): invalid()
        if value in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff') or int(value[:2], 16) & 1: invalid()
    return value


def synthetic_signal(name, seed):
    """Create deterministic non-real samples for tests and the simulation."""
    import hashlib
    hexval = hashlib.sha256((name + ':' + seed).encode()).hexdigest()
    if name == 'machine_id': return hexval[:32]
    if name == 'installation_id': return hexval
    if name in SERIALS: return 'demo-' + hexval[:16]
    if name in UUIDS: return str(uuid.UUID(hex=hexval[:32]))
    if name == 'disk_wwn': return '0x' + hexval[:16]
    if name == 'gpu_uuid': return 'GPU-' + str(uuid.UUID(hex=hexval[:32]))
    if name == 'mac_address': return '02:' + ':'.join(hexval[i:i+2] for i in range(0, 10, 2))
    raise ValueError('Unknown signal')
