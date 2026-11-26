# Changelog

Purpose: summarize changes by real release; no release version has been asserted here.

## Unreleased
- Added explicitly configured prototype retention operations for expired replay, recognized retired trial tables, named backup files and passive WAL checkpoints; no physical erasure is guaranteed.
- Added opt-in progressive IP challenges and explicitly privileged peer-window recovery for the Python prototype; the example is not a production recovery service.
- Added a synthetic 48-case direct/loopback traffic and state benchmark matrix; timings and sampled queues are not production capacity claims.
- Added opt-in experimental idle cleanup for expired prototype windows and observations; replay, backups, legacy tables and WAL are not erased.
- Hardened Linux C signal input against truncation, malformed machine IDs/UUIDs, embedded NULs and serial placeholders; this can change available signals and derived IDs on upgrade.
- Added a synthetic mixed-process SQLite contention, WAL and read-only fault profile with invariant smoke tests; it is not a production soak certification.
- Added a reproducible synthetic signal-stability evaluation protocol and scenario report; model assumptions are not real-world accuracy estimates.
- Expanded optional prototype metrics to fixed replay/adapter event counts and engine serialization-wait buckets, with a synthetic local alert example; snapshot schema is now version 2.
- The prototype Python engines support separate optional IP and device-signal quota thresholds; both use the existing shared window and preserve defaults.
- Added an experimental process-local WSGI request-admission and draining wrapper; it does not bound server sockets or constitute a production entrypoint.
- Fail closed on C digest/bucket formatting and fallback-file unlock/close failures; added synthetic formatting, allocation and persistence fault injection.
- Bound expired window and history cleanup in memory and SQLite; backlog fails closed and stale windows cannot be charged.
- Added synthetic memory-mutex and SQLite-writer contention profiling with concurrent quota checks and documented constraints for future sharding.
- C bucket admission now probes once instead of twice; collision-chain saturation and reset tests and synthetic bounded-scan measurements document remaining costs.
- Added a synthetic expiry-backlog measurement and accounting/recovery tests; the remaining rate-window full scan is not fixed.
- Defensively zero-initialized the SHA schedule; GCC 12.2 no longer emits the prior uninitialized-schedule warnings, though analyzer complexity cutoffs and the historical core diagnostic remain unresolved.
- Distinguish C JSON parser allocation failure from invalid JSON and propagate it through configuration/profile comparison; fault tests cover each synthetic parser allocation.
- Limit C JSON parser input to 65,536 bytes, including configuration whitespace, and fail cleanly on null or oversized input; larger previously accepted configurations are now rejected.
- Evaluated portable C crypto/JSON providers and added native standalone known-answer, differential and JSON grammar fixtures; no production provider has been selected or migrated.
- Added separate component, privacy and deployment-status guides with an accurately scoped README map.
- Let the synthetic WSGI host fix its operation identifier at construction and test host authorization separately from signal forgery and cross-account quota poisoning.
- Added regression checks for the ABI-v1 availability-heuristic explanation and the current score-free demo UI.
- Documented the Python memory/SQLite behavior contract and tested shared charging, retry, saturation and explicit cleanup differences.
- Replaced the GCC-specific C error-buffer thread-local declaration with a C11/MSVC abstraction and added simultaneous isolation tests; this alone does not port the native core.
- Added a shared memory/SQLite duplicate-snapshot refresh and expiry scenario.
- Added a hosted-runner-only disposable Windows standard-user survey with token checks; this does not establish full native support.
- Added push-only native hosted-runner availability surveys with strict sanitized output for a bounded set of Windows and macOS signals; no platform support or privacy approval is implied.
- Extended the experimental bounded SMBIOS parser with synthetic Type 2 baseboard-or-module serial handling and an explicit multi-board ambiguity status; it is not wired into the public Windows core.
- Extracted collector-independent C signal representation and canonicalization, retaining Linux behavior and adding synthetic cross-platform fixture targets; this does not add native Windows/macOS core support.
- Linked each inventoried threat to a specific synthetic regression or explicitly documented limitation, with a documentation traceability check; this is not a security audit or formal risk acceptance.
- Transactionally mark SQLite replay initialization and reject missing/changed replay schema on restart; validated pre-marker stores retain outstanding challenges. Deletion of both marker and table remains indistinguishable from first use.
- Reject existing incomplete SQLite quota/history schema or missing metadata at startup instead of silently recreating them; initialization now requires a newly created file. This is not rollback or deletion detection.
- Check sealed-request challenge expiry after acquiring the replay store lock or SQLite writer, preventing pre-wait timestamps from accepting an expired challenge. Wall-clock and restored-state rollback remain unresolved.
- Sample Python quota and history state time after acquiring the memory lock or SQLite writer, avoiding stale pre-wait timestamps under contention. Wall-clock jumps and persistent rollback remain unresolved.
- Close SQLite connections on setup failures; add synthetic busy-lock denial and recovery coverage.
- Added a bounded synthetic closed-loop gate benchmark with latency percentiles, CPU/RSS, outcomes and a clock-driven capacity recovery check; it is not a deployment capacity test.
- Added optional, process-local fixed-cardinality metrics for Python request-service checks; metrics have no endpoint and do not cover all traffic.
- Fail closed on invalid or truncated native signal canonicalization rather than hashing a partial representation; added boundary and injected-failure tests.
- Clarified the ABI-v1 `confidence` field as an availability heuristic, preserving its name and legacy fallback marker; tested every synthetic signal combination.
- Hardened C JSON emission with bounded terminator search and checked formatting/appends; synthetic output-allocation faults fail with an error.
- Added deterministic SHA-256/HMAC differential tests and documented partial GCC analyzer triage, including unresolved JSON emission concerns.
- Added bounded, incremental in-memory observation expiry with an indexed heap; a cleanup backlog fails closed, while window and SQLite cleanup remain separate.
- Added a bounded in-memory token index with deduplicated history and fail-closed history saturation; popular-token worst-case work is still bounded by capacity, not an agreed CPU budget.
- Added synthetic macOS CoreFoundation UUID-value validation and documented Apple fingerprinting and distribution risks; no macOS collector or support is implied.
- Added an experimental Windows RSMB provider and bounded SMBIOS parser with synthetic fixtures and a fuzz target; it is not integrated into the supported native core.
- Added a Linux-only CMake build, installable shared/static targets, probe, ABI metadata and relocated consumer tests; Windows/macOS full-core builds remain outstanding.
- Isolated OS randomness for fallback creation, failing closed if Linux `getrandom` is unavailable or not ready; Windows/macOS entropy adapters are experimental.
- Began the native platform abstraction with a C store clock/mutex contract and experimental Windows/macOS primitive adapters; full native platform support remains unimplemented.
- Added optional host-owned principal and operation authorization hooks to the synthetic WSGI example; Archx does not authenticate or authorize users.
- Added process-local connection rate, concurrency and socket-deadline controls to the private demo, with synthetic mixed-traffic and slow-client tests. Production entrypoint and overload validation remain open.
- Began next-version foundation: fail-closed C store saturation, loopback-by-default demo, security model, backlog and read-only PR/push CI. Windows/macOS support and the release gates remain incomplete.
- Added an optional browser sealed-v2 client and synthetic browser interoperability test with optional Turnstile.
- Hardened Python request flow: reusable host gate, single-use sealed-v2 challenges, explicit trusted single-proxy handling and verification before device-signal enrollment.
- Python prototype: optional IPsum reputation and Turnstile verification, raw or keyed-hash IP retention, sealed-box request bodies for the native client, and friendly messages for new decisions.
- Documentation: working rules, architecture and file indexes, engineering decisions and sanitized test records.

See Git history and the root README for earlier development; do not infer a version or release from this section.
