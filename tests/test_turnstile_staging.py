"""Fake-only staging-probe tests: never contacts a real provider."""
import contextlib
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from turnstile_staging import NAMES, main, run_scenarios

VALUES = {'SITEKEY': 'synthetic-sitekey', 'SECRET': 'private-secret-marker',
          'HOSTNAME': 'staging.example.invalid', 'ACTION': 'staging_action',
          'TOKEN_SUCCESS': 'fresh-one', 'TOKEN_HOSTNAME': 'fresh-two',
          'TOKEN_ACTION': 'fresh-three', 'TOKEN_SECRET': 'fresh-four'}


class Response:
    def __init__(self, doc): self.doc = doc
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, _limit): return json.dumps(self.doc).encode()


class FakeProvider:
    def __init__(self): self.tokens = []
    def open(self, request, timeout):
        assert timeout == 5
        body = parse_qs(request.data.decode())
        token, secret = body['response'][0], body['secret'][0]
        self.tokens.append(token)
        if secret != VALUES['SECRET']: return Response({'success': False, 'error-codes': ['invalid-input-secret']})
        if token == 'archx-synthetic-invalid-token': return Response({'success': False, 'error-codes': ['invalid-input-response']})
        return Response({'success': True, 'hostname': VALUES['HOSTNAME'], 'action': VALUES['ACTION']})


class StagingTests(unittest.TestCase):
    def test_all_scenarios_against_fake_provider(self):
        fake = FakeProvider()
        results = run_scenarios(VALUES, opener_factory=lambda _label: fake)
        self.assertEqual([label for label, _ in results], [
            'provider_success', 'provider_invalid_token', 'provider_hostname_mismatch',
            'provider_action_mismatch', 'provider_invalid_secret', 'simulated_timeout', 'simulated_upstream_failure'])
        self.assertTrue(all(ok for _, ok in results))
        self.assertEqual(fake.tokens, ['fresh-one', 'archx-synthetic-invalid-token', 'fresh-two', 'fresh-three', 'fresh-four'])

    def test_mismatch_cases_require_provider_accepted_tokens(self):
        class ExpiredProvider(FakeProvider):
            def open(self, request, timeout):
                token = parse_qs(request.data.decode())['response'][0]
                if token in ('fresh-two', 'fresh-three'):
                    return Response({'success': False, 'error-codes': ['timeout-or-duplicate']})
                return super().open(request, timeout)
        fake = ExpiredProvider()
        result = dict(run_scenarios(VALUES, opener_factory=lambda _label: fake))
        self.assertFalse(result['provider_hostname_mismatch'])
        self.assertFalse(result['provider_action_mismatch'])
        self.assertTrue(result['provider_success'])

    def test_invalid_secret_requires_specific_provider_error(self):
        class OutageProvider(FakeProvider):
            def open(self, request, timeout):
                if parse_qs(request.data.decode())['response'][0] == 'fresh-four':
                    return Response({'success': False, 'error-codes': ['internal-error']})
                return super().open(request, timeout)
        fake = OutageProvider()
        result = dict(run_scenarios(VALUES, opener_factory=lambda _label: fake))
        self.assertFalse(result['provider_invalid_secret'])

    def test_distinct_tokens_required_before_any_verification(self):
        duplicate = {**VALUES, 'TOKEN_SECRET': VALUES['TOKEN_SUCCESS']}
        with self.assertRaises(ValueError): run_scenarios(duplicate)
        with self.assertRaises(ValueError): run_scenarios({k: v for k, v in VALUES.items() if k != 'SECRET'})

    def test_cli_opt_in_and_sanitized_output(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(main(), 2)
        env = {'ARCHX_STAGING_ENABLE': '1', **{'ARCHX_STAGING_' + k: v for k, v in VALUES.items()}}
        for scenario in ('success', 'exception'):
            out, err = io.StringIO(), io.StringIO()
            fake = ([('provider_success', True), ('simulated_timeout', False)] if scenario == 'success'
                    else RuntimeError('private-secret-marker fresh-one staging.example.invalid'))
            with patch.dict(os.environ, env, clear=True), patch('turnstile_staging.run_scenarios', side_effect=fake if scenario == 'exception' else None,
                                                               return_value=fake if scenario == 'success' else None), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(main(), 1 if scenario == 'success' else 2)
            text = out.getvalue() + err.getvalue()
            for value in VALUES.values(): self.assertNotIn(value, text)


if __name__ == '__main__': unittest.main(verbosity=2)
