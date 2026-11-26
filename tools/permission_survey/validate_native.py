#!/usr/bin/env python3
"""Allowlist native survey output before it is logged or uploaded.

Never echo rejected input or exception text. This verifies the output schema,
not that the survey binary or host is trustworthy.
"""
import json
import platform
import re
import sys
from pathlib import Path

ARCHES = {'x86_64', 'arm64', 'x86', 'unknown'}
SIGNAL = {'absent', 'present', 'unsupported', 'placeholder', 'invalid', 'unknown'}
MAC_PROPERTY = {'string_type_only', 'unavailable_or_denied', 'unexpected_type'}


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result


def validate(raw, expected, version='unknown'):
    if len(raw) > 4096:
        raise ValueError('oversize')
    data = json.loads(raw, object_pairs_hook=unique_pairs)
    if type(data) is not dict or type(data.get('schema_version')) is not int or data['schema_version'] != 1:
        raise ValueError('schema')
    if data.get('platform') != expected or data.get('architecture') not in ARCHES:
        raise ValueError('platform')
    if type(data.get('signals')) is not dict:
        raise ValueError('signals')
    signals = data['signals']
    if expected == 'windows':
        if set(data) != {'schema_version','platform','architecture','privilege','firmware','signals'}:
            raise ValueError('fields')
        if data['privilege'] not in {'elevated','not_elevated','unknown'} or data['firmware'] not in {'ok','permission_denied','unsupported','read_error'}:
            raise ValueError('state')
        if set(signals) != {'product_uuid','system_serial','board_serial','machine_guid_metadata'}:
            raise ValueError('fields')
        if signals['machine_guid_metadata'] not in {'string_type_only','absent','permission_denied','unexpected_type','read_error'}:
            raise ValueError('metadata')
        if data['firmware'] == 'ok':
            if signals['product_uuid'] not in SIGNAL or signals['system_serial'] not in SIGNAL or signals['board_serial'] not in SIGNAL | {'ambiguous'}:
                raise ValueError('signal')
        elif any(signals[name] != 'not_checked' for name in ('product_uuid','system_serial','board_serial')):
            raise ValueError('signal')
    elif expected == 'macos':
        if set(data) != {'schema_version','platform','architecture','privilege','platform_service','signals'}:
            raise ValueError('fields')
        if data['privilege'] not in {'root','nonroot'} or data['platform_service'] not in {'found','unavailable','read_error'}:
            raise ValueError('state')
        if set(signals) != {'platform_uuid_property','platform_serial_property'}:
            raise ValueError('fields')
        allowed = MAC_PROPERTY if data['platform_service'] == 'found' else {'not_checked'}
        if any(value not in allowed for value in signals.values()):
            raise ValueError('signal')
    else:
        raise ValueError('platform')
    data['os_version'] = version if isinstance(version, str) and re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,3}', version) and len(version) <= 32 else 'unknown'
    return data


def main():
    try:
        if len(sys.argv) != 3 or sys.argv[1] not in {'windows','macos'}:
            raise ValueError('arguments')
        with Path(sys.argv[2]).open('rb') as f:
            raw = f.read(4097)
        version = platform.mac_ver()[0] if sys.argv[1] == 'macos' else platform.version()
        result = validate(raw, sys.argv[1], version)
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    except Exception:
        print('Native survey validation failed; input was not logged.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
