# Unreleased local tests

Purpose: identify the inputs and environment for the associated sanitized logs.

- Linux sandbox; `./test.sh` invoked the C vector/core/sanitizer tests, Python tests, synthetic abuse lab and benchmark. `full-test.log` contains stdout/stderr; the system Python did not have optional PyNaCl, so two encryption-specific tests were skipped. Tests use fixtures, synthetic signals and loopback; the probe only checks that JSON parses and does not print identifiers. The local collector test also checks format/stability of available local signals without printing values. This is not a production test.
- `build/secure-venv/bin/python tests/test_security.py` ran the security tests with PyNaCl 1.6.2, including sealed request round trip, tampering and downgrade checks. `secure-test.log` captures its output. Turnstile uses mocked Siteverify responses; no real credentials or tokens were used.
- `PATH="$PWD/build/secure-venv/bin:$PATH" ./test.sh` subsequently ran the full hardening suite with PyNaCl enabled; `hardening-full-test.log` includes the C/sanitizer tests, encrypted replay, trusted proxy, host integration, concurrency and synthetic lab output. No encryption tests were skipped in this run.
- `PATH="$PWD/build/secure-venv/bin:$PATH" LD_LIBRARY_PATH="$PWD/build/local-browser/lib" ARCHX_REQUIRE_BROWSER=1 ARCHX_TEST_CHROME=/tmp/chromium ./test.sh` ran the full suite with Node, PyNaCl and headless Chromium; `browser-full-test.log` contains the sanitized output. The browser UI test covers synthetic sealed requests with and without a mocked Turnstile widget, plus replay rejection; it does not contact Cloudflare. See `Docs/Workaround.md` for the temporary local browser setup.
- IPsum level 3 and level 1 refreshes were separately exercised against GitHub; only entry counts were reported. This confirms retrieval at that moment, not feed correctness or provider availability.

No Windows/macOS or live Cloudflare test was run for these changes. These are local sandbox results, not a released version or a GitHub CI run; see `.github/archx-runner/runs/` for recorded CI results.
