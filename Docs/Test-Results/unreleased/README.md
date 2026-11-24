# Unreleased local tests

Purpose: identify the inputs and environment for the associated sanitized logs.

- Linux sandbox; `./test.sh` invoked the C vector/core/sanitizer tests, Python tests, synthetic abuse lab and benchmark. `full-test.log` contains stdout/stderr; the system Python did not have optional PyNaCl, so two encryption-specific tests were skipped. Tests use fixtures, synthetic signals and loopback; the probe only checks that JSON parses and does not print identifiers. The local collector test also checks format/stability of available local signals without printing values. This is not a production test.
- `build/secure-venv/bin/python tests/test_security.py` ran the security tests with PyNaCl 1.6.2, including sealed request round trip, tampering and downgrade checks. `secure-test.log` captures its output. Turnstile uses mocked Siteverify responses; no real credentials or tokens were used.
- `PATH="$PWD/build/secure-venv/bin:$PATH" ./test.sh` subsequently ran the full hardening suite with PyNaCl enabled; `hardening-full-test.log` includes the C/sanitizer tests, encrypted replay, trusted proxy, host integration, concurrency and synthetic lab output. No encryption tests were skipped in this run.
- IPsum level 3 and level 1 refreshes were separately exercised against GitHub; only entry counts were reported. This confirms retrieval at that moment, not feed correctness or provider availability.

No Windows/macOS or live Cloudflare test was run for these changes. These are local sandbox results, not a released version or a GitHub CI run; see `.github/archx-runner/runs/` for recorded CI results.
