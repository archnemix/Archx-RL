#!/usr/bin/env python3
"""Report only identifier availability, never identifier values or paths to devices."""
import glob
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone


def value_status(value):
    value = value.strip().lower()
    if not value or value in {'0', 'none', 'unknown', 'not specified', 'to be filled by o.e.m.', 'uninitialized', 'n/a', '-'}:
        return 'empty_or_placeholder'
    if value.replace('-', '') in {'0' * 32, 'f' * 32}:
        return 'empty_or_placeholder'
    return 'available'

def paths_status(pattern):
    paths = glob.glob(pattern)
    if not paths:
        return 'absent'
    statuses = []
    for path in paths:
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                statuses.append(value_status(f.read(1024)))
        except PermissionError:
            statuses.append('permission_denied')
        except OSError:
            statuses.append('unreadable')
    for status in ('available', 'permission_denied', 'unreadable', 'empty_or_placeholder'):
        if status in statuses:
            return status
    return 'absent'

def lsblk():
    try:
        p = subprocess.run(['lsblk', '-J', '-o', 'TYPE,SERIAL,WWN,UUID,PARTUUID'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, check=True)
        data = json.loads(p.stdout)
        out = {x: 'absent' for x in ('disk_serial', 'disk_wwn', 'filesystem_uuid', 'partition_uuid')}
        def walk(items):
            for item in items:
                for key, field in [('disk_serial','serial'), ('disk_wwn','wwn'), ('filesystem_uuid','uuid'), ('partition_uuid','partuuid')]:
                    if key in ('disk_serial','disk_wwn') and item.get('type') != 'disk':
                        continue
                    value = item.get(field)
                    if value and value_status(value) == 'available': out[key] = 'available'
                walk(item.get('children') or [])
        walk(data.get('blockdevices') or [])
        return out
    except (OSError, subprocess.SubprocessError, ValueError):
        return {x: 'unavailable_or_unsupported' for x in ('disk_serial','disk_wwn','filesystem_uuid','partition_uuid')}

def gpu():
    try:
        p = subprocess.run(['nvidia-smi', '--query-gpu=uuid', '--format=csv,noheader'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5)
        return 'available' if p.returncode == 0 and any(value_status(x) == 'available' for x in p.stdout.splitlines()) else 'unavailable_or_unsupported'
    except (OSError, subprocess.SubprocessError):
        return 'unavailable_or_unsupported'

def main():
    roles = {
        'machine_id': paths_status('/etc/machine-id'),
        'product_uuid': paths_status('/sys/class/dmi/id/product_uuid'),
        'board_serial': paths_status('/sys/class/dmi/id/board_serial'),
        'product_serial': paths_status('/sys/class/dmi/id/product_serial'),
        'chassis_serial': paths_status('/sys/class/dmi/id/chassis_serial'),
        'mac_address': paths_status('/sys/class/net/[!l]*/address'),
        'gpu_uuid_nvidia': gpu(),
        'timezone': 'available' if os.path.exists('/etc/localtime') and os.access('/etc/localtime', os.R_OK) else 'unavailable_or_unsupported',
    }
    roles.update(lsblk())
    # Test open permissions only; never send TPM commands or access any keys.
    try:
        fd = os.open('/dev/tpmrm0', os.O_RDWR | os.O_CLOEXEC)
        os.close(fd)
        roles['tpm_device'] = 'accessible'
    except FileNotFoundError: roles['tpm_device'] = 'absent'
    except PermissionError: roles['tpm_device'] = 'permission_denied'
    except OSError: roles['tpm_device'] = 'unreadable'
    print(json.dumps({'access_level': sys.argv[1], 'uid_is_root': os.geteuid() == 0, 'signals': roles}, sort_keys=True))

if __name__ == '__main__': main()
