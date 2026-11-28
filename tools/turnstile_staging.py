"""Opt-in staging probe. Use fresh, independently issued staging tokens only.

No credentials or tokens are accepted as command-line arguments. This probe
prints only fixed scenario names/statuses; it never logs provider responses,
exception text, hostname, tokens, or secrets. Staging infrastructure remains
operator-owned; deterministic transport failures are explicitly labeled.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from security import Turnstile

NAMES = ('SITEKEY', 'SECRET', 'HOSTNAME', 'ACTION', 'TOKEN_SUCCESS',
         'TOKEN_HOSTNAME', 'TOKEN_ACTION', 'TOKEN_SECRET')


class FailureOpener:
    def __init__(self, error): self.error = error
    def open(self, _request, timeout):
        if timeout != 5: raise AssertionError('Unexpected adapter timeout')
        raise self.error


def run_scenarios(values, factory=Turnstile):
    """Return fixed-name statuses. `factory` is injection for synthetic tests."""
    if set(values) != set(NAMES): raise ValueError('Staging configuration incomplete')
    tokens = [values[name] for name in ('TOKEN_SUCCESS', 'TOKEN_HOSTNAME', 'TOKEN_ACTION', 'TOKEN_SECRET')]
    if (any(not isinstance(token, str) or not 1 <= len(token) <= 2048 for token in tokens) or
            len(set(tokens)) != len(tokens) or 'archx-synthetic-invalid-token' in tokens):
        raise ValueError('Four distinct fresh tokens are required')
    site, secret, host, action = (values[name] for name in ('SITEKEY', 'SECRET', 'HOSTNAME', 'ACTION'))
    wrong_host = 'archx-staging-mismatch.invalid'
    if isinstance(host, str) and host.lower() == wrong_host: wrong_host = 'archx-staging-other.invalid'
    wrong_action = 'archx_mismatch' if action != 'archx_mismatch' else 'archx_other'
    invalid_secret = 'archx_synthetic_invalid_secret'
    if secret == invalid_secret: invalid_secret = 'archx_synthetic_invalid_secret_other'
    expected = (
        ('provider_success', 'valid', factory(site, secret, host, action), tokens[0]),
        ('provider_invalid_token', 'invalid', factory(site, secret, host, action), 'archx-synthetic-invalid-token'),
        ('provider_hostname_mismatch', 'invalid', factory(site, secret, wrong_host, action), tokens[1]),
        ('provider_action_mismatch', 'invalid', factory(site, secret, host, wrong_action), tokens[2]),
        ('provider_invalid_secret', 'unavailable', factory(site, invalid_secret, host, action), tokens[3]),
        ('simulated_timeout', 'unavailable', factory(site, secret, host, action, opener=FailureOpener(TimeoutError())), 'synthetic-token'),
        ('simulated_upstream_failure', 'unavailable', factory(site, secret, host, action, opener=FailureOpener(OSError())), 'synthetic-token'),
    )
    results = []
    for label, wanted, verifier, token in expected:
        try:
            result = verifier.verify(token)
            ok = result == wanted
        except Exception:
            # Do not print provider/transport exceptions; they can contain
            # private request data. An exception is never counted as a pass.
            ok = False
        results.append((label, ok))
    return results


def main():
    if os.environ.get('ARCHX_STAGING_ENABLE') != '1':
        print('Staging probe is disabled; explicit opt-in is required.', file=sys.stderr)
        return 2
    values = {name: os.environ.get('ARCHX_STAGING_' + name) for name in NAMES}
    if any(value is None for value in values.values()):
        print('Staging configuration incomplete.', file=sys.stderr)
        return 2
    try:
        results = run_scenarios(values)
    except Exception:
        print('Staging configuration or probe failed; details withheld.', file=sys.stderr)
        return 2
    for label, ok in results:
        print(label + ': ' + ('pass' if ok else 'fail'))
    return 0 if all(ok for _, ok in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
