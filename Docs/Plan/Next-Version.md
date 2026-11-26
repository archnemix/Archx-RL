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

- **A01:** `SECURITY.md` and `Docs/Threat-Model.md` document trust boundaries and map each listed threat to a named synthetic test or a known limitation; the traceability check and full suite are in [local evidence](../Test-Results/unreleased/threat-model-full-test.log). A documented limitation is not formal risk acceptance. A private reporting channel and maintainer review are not yet verified; the GitHub issue remains open.
- **B01:** `tests/test_core.c` exercises exhaustion, 200 new-key churn attempts, existing-key checks, targeted reset and 32 concurrent new keys. Full sanitized local output is in [foundation-full-test.log](../Test-Results/unreleased/foundation-full-test.log), with a later [Linux regression](https://github.com/archnemix/Archx-RL/actions/runs/45678625353). The stated issue-level change and tests are implemented; a 2026-11-22 GitHub issue comment and close attempt both failed with “Resource not accessible by integration”, so [#1](https://github.com/archnemix/Archx-RL/issues/1) remains open. Existing entries are not automatically reclaimed; restart resets all C quotas, so release-wide state durability is still unmet.
- **A02, partial:** that run verified an ordinary push. Source-only PR and fork behavior, a deliberately failing PR, and required branch protection remain unverified. The integration received HTTP 403 when reading branch protection; a repository administrator must configure/verify required checks.
- **A03, partial:** an experimental Windows RSMB collector and bounded, synthetic-fixture-tested SMBIOS parser exist separately from the public core. The parser now handles a single Type 2 baseboard-or-module serial and marks multiple Type 2 records ambiguous without picking one; [local Linux evidence](../Test-Results/unreleased/windows-board-full-test.log) is synthetic; [native CI](https://github.com/archnemix/Archx-RL/actions/runs/45809618141) passed the Windows Server x64 provider and macOS parser fixtures, and [Linux CI](https://github.com/archnemix/Archx-RL/actions/runs/45809618083) passed fuzz smoke. [Windows research and limitations](../Research/Windows.md) record the API boundary. [Primitive and synthetic native CI](https://github.com/archnemix/Archx-RL/actions/runs/45667025930) passed on Windows Server 2022 x64 and macOS 15 Intel/ARM, not full builds. A non-elevated local-user survey has since passed on one hosted Windows Server runner; Windows 11/physical-device permissions, fallback, full builds and bindings remain required.
- **A04/B07, partial:** an internal synthetic CoreFoundation type/UUID validation boundary passed [native macOS Intel/ARM CI](https://github.com/archnemix/Archx-RL/actions/runs/45668492708), with no hardware or registry collection. [macOS policy and API decision](../Research/MacOS.md) records Apple fingerprinting restrictions as a distribution blocker; actual collector selection, policy review, native fallback, builds and bindings remain open.
- **D01/D02/B04, partial:** process-local observations now use bounded name/token postings and deduplicated snapshots; new history is rejected instead of silently evicting active entries. A seeded linear oracle, saturation, concurrency and memory/SQLite model tests are in [local regression evidence](../Test-Results/unreleased/index-full-test.log). The follow-up bounded expiry queue removes at most 64 histories per check and fails closed while expired backlog remains; SQLite does not have this behavior. A popular token and window cleanup can still touch the full bounded store. Representative load, budgets, full parity and production review remain open.
- **B06, partial:** [GCC warning triage](../Research/Analyzer-Triage.md) reproduces seven likely schedule-analysis false positives and records analyzer complexity cutoffs; the original `archx.c` warning is not reproduced and remains unresolved. Deterministic SHA/HMAC differential tests supplement existing known-answer vectors.
- **B12, partial:** ABI-v1 retains the historical `confidence` JSON name but public headers and README define it as an availability heuristic, not an identity probability; fallback's fixed 10 is not a coverage percentage. Synthetic fixtures cover every availability combination and fallback. Any future versioned rename or multi-platform semantics require compatibility review.
- **A12/D06, partial:** SQLite quota/history startup now initializes only a newly created file and rejects missing/changed core schema or missing metadata instead of repairing it. [Local regression](../Test-Results/unreleased/sqlite-startup-full-test.log) covers an empty file, missing objects/metadata, altered schema, failed initial creation and concurrent first startup. Exact SQL definitions are required; startup may change WAL mode before rejection. Deletion, data loss, replacement, old restore and runtime changes remain undetected; migrations and recovery tooling remain open.
- **Replay startup, partial:** replay creates a marker and table transactionally, validates existing exact schema and preserves legacy challenges while adopting a pre-marker table. Missing objects with a present marker fail startup; simultaneous loss of marker and table, pre-marker data loss, downgrade, rollback and runtime schema changes remain undetected. [Regression evidence](../Test-Results/unreleased/replay-startup-full-test.log).
- **Replay expiry, partial:** memory and SQLite challenge issuance and consumption now check time after acquiring their serialization boundary. Synthetic held-lock tests reproduce and prevent acceptance of a challenge that expires during the wait; wall-clock rollback and older database restoration can still extend or revive challenges. See [Linux regression](../Test-Results/unreleased/replay-clock-full-test.log).
- **B04/D04, partial:** both Python engines now sample quota/history time under their serialization boundary, tested with a synthetic clock and held mutex/real SQLite writer for valid and malformed requests. This fixes stale pre-wait charges but not wall-clock jumps, restored databases or memory restart resets; no-silent-reset remains unmet. See [Linux regression](../Test-Results/unreleased/state-clock-full-test.log).
- **D06, partial:** a synthetic writer lock and a test-only 50 ms busy timeout exercise `storage_error` on normal and malformed paths, unchanged windows and recovery; injected connection-setup/close failures test cleanup. The default busy timeout is 5 seconds and is not an end-to-end request deadline. Disk-full, I/O, corruption, crash/ambiguous commit, WAL/checkpoint, long-held reader and real contention profiling remain open. [Linux regression](../Test-Results/unreleased/sqlite-fault-full-test.log).
- **D05, partial:** a capped synthetic in-process closed-loop benchmark reports p50/p95/p99, process CPU, Linux high-water RSS, outcome counts, submitted/uncollected work and controlled history recovery. [Example results](../Test-Results/unreleased/README.md) are not agreed budgets or deployment load evidence; real HTTPS/proxy, multi-process, high-cardinality, overload, lock profiling and soak remain open.
- **D03, partial:** in-memory history uses a no-tombstone indexed expiry heap and bounded per-request cleanup; seeded heap invariants and backlog recovery are in [local evidence](../Test-Results/unreleased/expiry-full-test.log). Window and SQLite cleanup and idle retention are not covered; timing, lock budgets and soak remain open.
- **A10, partial:** the Python request-service can opt into fixed-cardinality process-local decision/duration snapshots, tested for concurrency and synthetic privacy markers. No HTTP exporter is exposed; pre-gate failures, connection overload, host operations, persistent aggregation and health/readiness remain uninstrumented. See [local test record](../Test-Results/unreleased/metrics-full-test.log).
- **A06, partial:** a Linux-only CMake build installs shared/static libraries, header, probe and package targets; synthetic consumers test relocation and both linkages. No release package version is asserted; the existing ABI version is exported. Full Windows/macOS CMake builds and a `build.sh` wrapper remain outstanding.
- **A05/C02, partial:** internal signal structs and canonicalization now build without the Linux collector; the existing synthetic bounds tests are included in the experimental native primitive matrix. Linux full regression and GCC install tests passed in [local evidence](../Test-Results/unreleased/portable-canonical-full-test.log); [native synthetic fixtures](https://github.com/archnemix/Archx-RL/actions/runs/45808839990) passed Windows Server 2022 x64 and macOS 15 ARM/Intel, and [Linux CI](https://github.com/archnemix/Archx-RL/actions/runs/45808839955) passed GCC/Clang installation tests. Collection dispatch, fallback, address parsing, C ABI platform dependencies and complete native builds remain open.
- **A05/C02/B05, partial:** `src/platform.h` now isolates store mutex/clock and OS entropy; Linux uses them, and experimental Windows/macOS primitive adapters have native conformance CI. Fault injection covers init, lock, clock, unlock, entropy and JSON output-allocation failures; JSON buffer terminators, serialization failures and canonicalization truncation are now checked. Other allocation, storage and output error paths remain to be reviewed. [Native primitive tests](https://github.com/archnemix/Archx-RL/actions/runs/45665565153) passed for Windows Server x64, macOS Intel and macOS ARM including entropy; this is not complete platform support. This does not port the full core, collectors, persistence or bindings. See [platform decision](Platform-Primitives.md); native CI results and sleep/resume evidence must be checked.
- **B02, partial:** the synthetic WSGI host has optional host-owned principal and operation-authorization callbacks with denial/error fail-closed tests, including a spoofed HTTP header over loopback. The [local full test record](../Test-Results/unreleased/host-hooks-full-test.log) includes these cases. The default example is unauthenticated, the host must establish its own trusted context, and forged signals can still poison buckets after authorization. A reviewed supported integration is outstanding.
- **B03, partial:** the private demo applies process-local global connection rate, concurrency and socket-deadline controls before any route, with one request per connection. Seven loopback tests cover mixed routes, pipelining, slow clients, saturation, recovery, thread-start failure and stalled application behavior; the [local full test record](../Test-Results/unreleased/bounded-full-test.log) includes real headless Chromium. The [Linux CI run](https://github.com/archnemix/Archx-RL/actions/runs/45662241847) passed. This does not bound stalled application code, multiple processes or the supported production boundary; B03 remains open.
- **C01, partial:** the demo now defaults to loopback, with explicit host override tested. A supported bounded entrypoint and TLS/proxy/load evidence remain outstanding.
- These links are recorded here because the GitHub integration returned HTTP 403 when attempting to update or comment on the issues. The issues link back to this tracker; they should be updated and formally assigned when permissions permit.

## D02 duplicate refresh scenario

`tests/test_sqlite_engine.py::PersistentTests.test_duplicate_refresh_and_expiry_parity_with_memory` drives memory and SQLite through the same synthetic duplicate and expiry timeline. Both preserve one snapshot, refresh its expiry, match after the original expiry, and report a new observation after the refreshed expiry. Existing randomized index and concurrent duplicate tests cover additional in-memory behavior. This supports the narrow #35 acceptance but does not establish all of the broader B04 contract or release gates; #35 remains open until GitHub issue-write access is restored and evidence can be attached.

## B04 engine contract

[Engine-Contract.md](Engine-Contract.md) specifies duplicates, expiry, capacity, charging and retries for direct engine and service calls, and explicitly documents the bounded-memory/SQLite cleanup difference and storage limitations. `tests/test_sqlite_engine.py` now tests shared saturation/no-charge recovery, peer precharge, duplicate expiry and intentional cleanup divergence, alongside its seeded 450-step parity test. The stated #20 contract/testing scope is addressed; GitHub issue evidence and closure remain blocked by issue-write permissions. This does not complete the broader operational release gates or prove universal backend parity.

## B12 legacy-score explanation

ABI v1 deliberately retains the `confidence` field for compatibility, with header and README explaining the availability-weight heuristic and fallback marker. `tests/test_coverage.c` covers every synthetic signal combination and fallback; `tests/test_coverage_docs.py` checks those explanations and that the current demo UI does not present the field. This addresses the stated #28 compatibility/explanation scope, not a calibrated identity or fraud model. A future UI or versioned multi-platform schema still needs review. The GitHub issue remains open because issue-write access is denied.

## B02 host authorization boundary

The example accepts both host-owned principal resolution and operation authorization, with a host-configured operation fixed at construction. `tests/test_host_integration.py` checks spoofed identities and operation headers, non-boolean/error denial, ignored rotating account fields, and an authorized attacker using forged signals to exhaust a victim bucket. The issue-level hook and limitation tests are addressed; #18 remains open because the integration cannot update issues. This is an illustrative local WSGI example, not an authenticated or bounded production host.

## C05 guide map

The root README links separate native C, Python service, browser protocol, privacy/security and deployment-status guides under `Docs/Guides/`. No production deployment is yet supported; the deployment guide lists release boundaries rather than claiming otherwise. `tests/test_guides.py` verifies local links and key component-boundary disclaimers. This addresses the stated documentation-map scope of #33, not the unresolved release gates; issue-write permission remains necessary to attach evidence and close the issue.

## C04 provider evaluation

[Crypto-JSON ADR](Crypto-JSON-ADR.md) compares current C code, libsodium, OpenSSL and yyjson, with licensing, source-size limits, operational and migration risks. Native standalone fixtures exercise current crypto and parser behavior; native CI status must be checked. This evaluation does not replace or approve a provider, establish a total parser allocation budget, or certify cryptography. #32 remains open pending complete native test evidence and issue-write access.

## B05 JSON input bound

The C parser rejects input larger than 65,536 bytes before allocation or pointer arithmetic and fails safely for null input/output. `tests/test_json_contract.c` checks exact/over limit and null cases; `tests/test_core.c` checks public configuration at and above the limit. [Local full regression](../Test-Results/unreleased/json-input-bound-full-test.log) passed the browser, C/Python and sanitizer suite. This is an intentional compatibility restriction for oversized configurations, not comprehensive allocation-fault coverage: locale/UTF-8 and other failure paths remain open, so #21 is not complete.

## B05 parser allocation faults

`tests/test_json_faults.c` injects failure at each parser malloc/calloc/realloc in synthetic nested strings, config and both profile parses. `ax_core_new` reports a parsing allocation error and `ax_compare` returns `AX_ERR_NOMEM` with no result; tracked allocations return to zero and valid operations recover after each injection. [Local full browser and sanitizer regression](../Test-Results/unreleased/json-oom-full-test.log) passed. This covers parser allocation paths, not every core/store/persistence/output failure, and #21 remains open.

C04 native fixture evidence is now recorded in the [provider ADR](Crypto-JSON-ADR.md). The issue-level evaluation and fixture scope is addressed, but a 2026-11-22 issue-close attempt failed with GitHub integration access denied. Provider adoption, project license, package sizes, independent review and migration remain release work.
