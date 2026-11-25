# Next-version release backlog

This tracks the requested next version; issues contain the implementation and acceptance requirements. Each issue names @archnemix as a proposed initial owner, subject to confirmation or delegation; GitHub did not set the assignee field, so assignment is not verified. No unperformed work is implied. All remain open pending evidence.

## Release gate

- Native Linux, Windows and macOS builds, collectors, private fallback, bindings and tests. Windows 11 x64 is a proposed starting point, and macOS arm64/x86_64 each require native execution evidence. No other native support is claimed.
- Deliver one bounded single-host service profile; distributed enforcement is a later, separately specified milestone. Self-reported signals are not authentication or attestation.
- Complete privacy and distribution review, platform ADRs, installation artifacts, no silent quota reset, operational recovery, and test evidence. No mandatory elevation, kernel drivers, stealth collection or private-API scraping.
- Required release testing includes fuzzing, model/property, fault injection, privacy, end-to-end TLS/proxy, credentialed provider staging, separate language coverage, advertised browser tests, and agreed soak/load tests.

## Tracked work

| ID | Priority | Item | Issue |
| --- | --- | --- | --- |
| A01 | P0 | Security policy and threat model | [#2](https://github.com/archnemix/Archx-RL/issues/2) |
| A02 | P0 | Read-only PR and push CI | [#3](https://github.com/archnemix/Archx-RL/issues/3) |
| A03 | P1 | Windows native implementation and artifacts | [#4](https://github.com/archnemix/Archx-RL/issues/4) |
| A04 | P1 | macOS native implementation and artifacts | [#5](https://github.com/archnemix/Archx-RL/issues/5) |
| A05 | P1 | Portable platform abstraction | [#6](https://github.com/archnemix/Archx-RL/issues/6) |
| A06 | P1 | Cross-platform build and install | [#7](https://github.com/archnemix/Archx-RL/issues/7) |
| A07 | P1 | Versioned signal and capability schema | [#8](https://github.com/archnemix/Archx-RL/issues/8) |
| A08 | P1 | Native operating-system CI matrix | [#9](https://github.com/archnemix/Archx-RL/issues/9) |
| A09 | P1 | Single-host integration package | [#10](https://github.com/archnemix/Archx-RL/issues/10) |
| A10 | P1 | Low-cardinality operational metrics | [#11](https://github.com/archnemix/Archx-RL/issues/11) |
| A11 | P1 | Secret and transport key versioning | [#12](https://github.com/archnemix/Archx-RL/issues/12) |
| A12 | P1 | Schema migrations and backup restore | [#13](https://github.com/archnemix/Archx-RL/issues/13) |
| A13 | P1 | Retention and deletion operations | [#14](https://github.com/archnemix/Archx-RL/issues/14) |
| A14 | P1 | False-positive and stability evaluation | [#15](https://github.com/archnemix/Archx-RL/issues/15) |
| A15 | P1 | License and release governance | [#16](https://github.com/archnemix/Archx-RL/issues/16) |
| A16 | P2 | Distributed quota and replay backend | [#17](https://github.com/archnemix/Archx-RL/issues/17) |
| B01 | P0 | Prevent active C quota eviction on saturation | [#1](https://github.com/archnemix/Archx-RL/issues/1) |
| B02 | P0 | Separate abuse evidence from authenticated enforcement | [#18](https://github.com/archnemix/Archx-RL/issues/18) |
| B03 | P0 | Bound deployment boundary overload | [#19](https://github.com/archnemix/Archx-RL/issues/19) |
| B04 | P1 | Memory and SQLite behavioral contracts | [#20](https://github.com/archnemix/Archx-RL/issues/20) |
| B05 | P1 | C error propagation and fault injection | [#21](https://github.com/archnemix/Archx-RL/issues/21) |
| B06 | P1 | Triage GCC analyzer warnings | [#22](https://github.com/archnemix/Archx-RL/issues/22) |
| B07 | P1 | Platform signal validation | [#23](https://github.com/archnemix/Archx-RL/issues/23) |
| B08 | P1 | Shared-IP recovery and separate quotas | [#24](https://github.com/archnemix/Archx-RL/issues/24) |
| B09 | P1 | Real TLS reverse proxy topology | [#25](https://github.com/archnemix/Archx-RL/issues/25) |
| B10 | P1 | Credentialed Turnstile staging | [#26](https://github.com/archnemix/Archx-RL/issues/26) |
| B11 | P1 | Shutdown health and readiness | [#27](https://github.com/archnemix/Archx-RL/issues/27) |
| B12 | P1 | Coverage terminology compatibility | [#28](https://github.com/archnemix/Archx-RL/issues/28) |
| C01 | P0 | Private demo and bounded supported entrypoint | [#29](https://github.com/archnemix/Archx-RL/issues/29) |
| C02 | P1 | Remove Linux dependencies from common C | [#30](https://github.com/archnemix/Archx-RL/issues/30) |
| C03 | P1 | Maintained bindings and shared fixtures | [#31](https://github.com/archnemix/Archx-RL/issues/31) |
| C04 | P1 | Crypto and parser provider ADR | [#32](https://github.com/archnemix/Archx-RL/issues/32) |
| C05 | P1 | Architecture and deployment documentation split | [#33](https://github.com/archnemix/Archx-RL/issues/33) |
| D01 | P1 | Bounded inverted observation index | [#34](https://github.com/archnemix/Archx-RL/issues/34) |
| D02 | P1 | Deduplicate memory observations | [#35](https://github.com/archnemix/Archx-RL/issues/35) |
| D03 | P1 | Amortized bounded expiry cleanup | [#36](https://github.com/archnemix/Archx-RL/issues/36) |
| D04 | P1 | Measure and reduce contention | [#37](https://github.com/archnemix/Archx-RL/issues/37) |
| D05 | P1 | Representative state and traffic benchmark | [#38](https://github.com/archnemix/Archx-RL/issues/38) |
| D06 | P1 | Profile SQLite performance and faults | [#39](https://github.com/archnemix/Archx-RL/issues/39) |
| D07 | P2 | Optimize near-full C store | [#40](https://github.com/archnemix/Archx-RL/issues/40) |

Additional release-wide tracks: [test matrix #41](https://github.com/archnemix/Archx-RL/issues/41) and [platform research/ADRs #42](https://github.com/archnemix/Archx-RL/issues/42).

Implementation order: foundation A01–A02, B01–B03, C01; portability A05–A08/C02 and native A03/A04; performance/parity D01–D06/B04–B07; operational release A09–A15/B08–B12/C03–C05 and release tests. A16/D07 are later. Completion requires linked evidence, not just a closed issue.

## Foundation evidence and outstanding verification

- **A01:** commit `a38e410` adds `SECURITY.md` and `Docs/Threat-Model.md`. A private reporting channel and maintainer review are not yet verified.
- **B01:** `tests/test_core.c` exercises exhaustion, 200 new-key churn attempts, targeted reset and 32 concurrent new keys. Full sanitized local output is in [foundation-full-test.log](../Test-Results/unreleased/foundation-full-test.log); the [Linux regression run](https://github.com/archnemix/Archx-RL/actions/runs/45659543851) passed for `a38e410`. Existing entries are not automatically reclaimed; restart resets all C quotas.
- **A02, partial:** that run verified an ordinary push. Source-only PR and fork behavior, a deliberately failing PR, and required branch protection remain unverified. The integration received HTTP 403 when reading branch protection; a repository administrator must configure/verify required checks.
- **A05/C02/B05, partial:** `src/platform.h` now isolates store mutex/clock and OS entropy; Linux uses them, and experimental Windows/macOS primitive adapters have native conformance CI. Fault injection covers init, lock, clock, unlock and entropy failures. Prior clock/mutex/store-only tests passed on Windows Server x64 and macOS Intel; the macOS ARM job was queued. Entropy adapters require their own native run. This does not port the full core, collectors, persistence or bindings. See [platform decision](Platform-Primitives.md); native CI results and sleep/resume evidence must be checked.
- **B02, partial:** the synthetic WSGI host has optional host-owned principal and operation-authorization callbacks with denial/error fail-closed tests, including a spoofed HTTP header over loopback. The [local full test record](../Test-Results/unreleased/host-hooks-full-test.log) includes these cases. The default example is unauthenticated, the host must establish its own trusted context, and forged signals can still poison buckets after authorization. A reviewed supported integration is outstanding.
- **B03, partial:** the private demo applies process-local global connection rate, concurrency and socket-deadline controls before any route, with one request per connection. Seven loopback tests cover mixed routes, pipelining, slow clients, saturation, recovery, thread-start failure and stalled application behavior; the [local full test record](../Test-Results/unreleased/bounded-full-test.log) includes real headless Chromium. The [Linux CI run](https://github.com/archnemix/Archx-RL/actions/runs/45662241847) passed. This does not bound stalled application code, multiple processes or the supported production boundary; B03 remains open.
- **C01, partial:** the demo now defaults to loopback, with explicit host override tested. A supported bounded entrypoint and TLS/proxy/load evidence remain outstanding.
- These links are recorded here because the GitHub integration returned HTTP 403 when attempting to update or comment on the issues. The issues link back to this tracker; they should be updated and formally assigned when permissions permit.
