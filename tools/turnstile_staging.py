"""Opt-in staging probe. Use fresh, independently issued staging tokens only.

No credentials or tokens are accepted as command-line arguments. This probe
prints only fixed scenario names/statuses; it never logs provider responses,
exception text, hostname, tokens, or secrets. Staging infrastructure remains
operator-owned; deterministic transport failures are explicitly labeled.
"""
import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from security import NoRedirect, Turnstile

NAMES = ('SITEKEY', 'SECRET', 'HOSTNAME', 'ACTION', 'TOKEN_SUCCESS',
         'TOKEN_HOSTNAME', 'TOKEN_ACTION', 'TOKEN_SECRET')


class FailureOpener:
    def __init__(self, error): self.error = error
    def open(self, _request, timeout):
        if timeout != 5: raise AssertionError('Unexpected adapter timeout')
        raise self.error


class ObservedOpener:
    """Inspect only bounded provider evidence; never log the response body."""
    def __init__(self, opener, host, action):
        self.opener, self.host, self.action = opener, host, action
        self.provider_valid = self.invalid_token = self.invalid_secret = False

    def open(self, request, timeout):
        context = self.opener.open(request, timeout=timeout)
        owner = self
        class Response:
            def __enter__(self):
                self.response = context.__enter__()
                return self
            def __exit__(self, *args): return context.__exit__(*args)
            def read(self, size):
                raw = self.response.read(size)
                if len(raw) <= 16384:
                    try:
                        doc = json.loads(raw)
                        if not isinstance(doc, dict): return raw
                        host = doc.get('hostname')
                        owner.provider_valid = (doc.get('success') is True and
                            isinstance(host, str) and host.lower() == owner.host.lower() and
                            doc.get('action') == owner.action)
                        codes = doc.get('error-codes')
                        if doc.get('success') is False and isinstance(codes, list):
                            owner.invalid_token = codes == ['invalid-input-response']
                            owner.invalid_secret = codes == ['invalid-input-secret']
                    except (ValueError, TypeError, UnicodeError):
                        pass
                return raw
        return Response()


def run_scenarios(values, opener_factory=None):
    """Return fixed-name statuses; opener_factory injects synthetic tests."""
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
    cases = (
        ('provider_success', 'valid', secret, host, action, tokens[0], 'provider_valid'),
        ('provider_invalid_token', 'invalid', secret, host, action, 'archx-synthetic-invalid-token', 'invalid_token'),
        ('provider_hostname_mismatch', 'invalid', secret, wrong_host, action, tokens[1], 'provider_valid'),
        ('provider_action_mismatch', 'invalid', secret, host, wrong_action, tokens[2], 'provider_valid'),
        ('provider_invalid_secret', 'unavailable', invalid_secret, host, action, tokens[3], 'invalid_secret'),
        ('simulated_timeout', 'unavailable', secret, host, action, 'synthetic-token', None),
        ('simulated_upstream_failure', 'unavailable', secret, host, action, 'synthetic-token', None),
    )
    results = []
    for label, wanted, selected_secret, expected_host, expected_action, token, evidence in cases:
        if label == 'simulated_timeout': opener = FailureOpener(TimeoutError())
        elif label == 'simulated_upstream_failure': opener = FailureOpener(OSError())
        else: opener = opener_factory(label) if opener_factory else urllib.request.build_opener(NoRedirect())
        observed = ObservedOpener(opener, host, action)
        verifier = Turnstile(site, selected_secret, expected_host, expected_action, opener=observed)
        try:
            result = verifier.verify(token)
            ok = result == wanted and (evidence is None or getattr(observed, evidence))
        except Exception:
            # Never print provider/transport exceptions; they can contain data.
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
