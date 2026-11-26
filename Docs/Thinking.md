# Engineering decisions

Purpose: record concise decisions, problems and outcomes rather than private reasoning.

## Experimental SMBIOS Type 2 evidence
- Parse the Type 2 serial index with the same bounded, normalized string rules as Type 1. Because SMBIOS may contain multiple baseboard/module records, treat multiple records as ambiguous instead of selecting a potentially wrong physical board; even one record may represent a module. No public Windows identity, real hardware or permission claim follows.

## Portable canonical signal boundary
- Move the existing canonical algorithm and signal structs into collector-independent C files without changing output or the public ABI. Keep Linux collection and persistence separate. Reuse synthetic malformed/bounds fixtures as an experimental native CI target with checks active even in release builds; full native cores and platform collections remain open.

## Issue evidence and threat traceability
- B01 has implemented saturation and recovery evidence, but GitHub rejected both comment and close actions due to integration permissions. The A01 threat inventory now links named regressions or explicit limitations and has a reference integrity check; a link does not establish mitigation or formal risk acceptance. Maintainer review and private reporting availability are still unverified.

## SQLite replay startup marker
- Create challenge tables and a marker together in one write transaction, validate existing schema, and adopt intact pre-marker stores without deleting challenges. Failed setup rolls back and closes; concurrent initializers serialize. Loss of both marker and tables is indistinguishable from first enablement, and rollback/downgrade or runtime tampering remain unresolved.

## SQLite startup and missing state
- Core schema and metadata are initialized only for an exclusively created file, not repaired for an existing incomplete database; known schema definitions and metadata are verified. Existing empty files, equivalent but differently written schemas and interrupted first initialization now require operator investigation. This is not database integrity checking or deletion/replacement/rollback detection; the optional replay table uses a separate marker-based check.

## Replay expiry under contention
- Sample replay issuance and consumption time inside the memory lock or SQLite writer. Tests hold the serialization boundary and advance a synthetic clock: previously an expired challenge could be consumed and a newly issued challenge could already be expired. The fix does not address wall-clock or restored-state rollback.

## Request state time under contention
- Input validation retains its own time; bucket/window and history decisions instead sample time after acquiring the memory lock or SQLite writer. Deterministic tests expose that a timestamp captured before waiting could cause a newly charged quota or observation to expire prematurely. The separate precharge remains an earlier operation, and wall-clock discontinuities and recovery from older state remain unresolved.

## SQLite busy and connection setup faults
- Connection setup closes the connection even if a pragma fails. A held writer lock causes fail-closed storage errors; a short timeout is injected only in the test, then release and no-charge recovery are checked. Default busy timeout is 5 seconds, not an overall request deadline, and ambiguous commit, disk and crash faults need separate evaluation.

## Synthetic gate benchmark
- Use a bounded submitted/uncollected workload and report latency percentiles, aggregate outcomes, process CPU and Linux peak RSS with a separate synthetic capacity/expiry recovery probe. Avoid storing identifiers or inventing latency budgets. This is closed-loop and in-process, not representative of network overload or production capacity.

## Request gate aggregate metrics
- An opt-in in-memory collector records fixed decision categories and disjoint timing buckets only. No user-supplied identifiers or exception/provider text become labels; monitoring failures never alter the gate result. Connection admission, pre-gate errors, challenge/config and host operations remain outside scope.

## Signal canonicalization failures
- A partial or invalid native signal serialization is not an identity: canonicalization now clears output and reports an internal failure on malformed values or insufficient space, preserving valid canonical bytes and ABI. Other native error and persistence paths still require fault review.

## ABI-v1 availability terminology
- Preserve the existing `confidence` field and exact numeric behavior for compatibility, but explicitly describe it as signal availability, not a calibrated probability. The fallback value 10 is a historical marker rather than a coverage percentage. Any later schema rename needs a versioned migration.

## C analyzer triage
- GCC 12 at -O0 reports schedule uses despite the first 16 words being initialized and each later word depending only on earlier indices; classify only these as likely false positives, not proof of algorithm security. The original JSON warning is not reproduced. A follow-up bounds JSON terminator search and checks serialization errors; targeted synthetic allocation faults pass, while comprehensive B05 fault injection remains open.

## In-memory observation indexing
- Index token pairs to candidate observation IDs, count each observation independently, preserve oldest-snapshot tie ordering, and track signal-name shapes for comparability. Refresh duplicates; reject new history when full without evicting live observations. SQLite and memory share these tested cases but full parity remains open.
- An indexed expiry heap holds one entry per observation even after repeated refresh. At most 64 expired histories are removed per request; if more remain, matching/enrollment fail closed while applicable buckets stay charged. This deliberately differs from SQLite cleanup. Popular tokens and window cleanup can still visit every entry under a lock; no idle cleanup or performance budget is verified, and D03–D06 remain open.

## macOS policy gate and synthetic CF validation
- Separate data validation from collection: bounded ASCII UUID validation and CoreFoundation type checking can be tested without reading a machine identifier. Apple's developer-program fingerprinting restrictions require a distribution-specific review; accessible APIs do not establish permitted use.

## Experimental Windows firmware path
- Query bounded RSMB data using the documented size-query pattern; parse the Windows header, structure bounds, UUID and selected serial with explicit absence/placeholder/invalid statuses. Clear temporary raw firmware and never log it. Native collector integration, ordinary-user and production evidence remain pending.
- Treat pre-2.6 UUID byte order as a compatibility heuristic and non-ASCII serials as unavailable under the current conservative policy, not as verified identity.

## Linux CMake packaging
- Added a Linux-only package and installation path with relative runtime paths and separate static/shared exports; synthetic consumers test both after relocation. The public header is the source of ABI metadata. No release version is invented, and Windows/macOS full builds are explicitly rejected until implemented.

## Platform entropy
- Use bounded OS randomness and propagate failure. Linux `getrandom` with GRND_NONBLOCK fails closed rather than using a potentially uninitialized early-boot fallback; this requires a compatible kernel, libc and seccomp policy. The Windows/macOS APIs are experimental and do not implement private persistence. Synthetic failures verify that no fallback ID is fabricated.

## Native store primitives
- Isolate mutex and monotonic interval clock operations behind a small internal contract. Preserve Linux sleep-excluding semantics; choose Windows unbiased interrupt time and macOS uptime raw for equivalent intended policy, subject to native sleep/resume verification. This is not a full native port.
- Platform initialization, lock and time errors deny; an unlock error may follow an already-completed mutation and does not imply rollback. Synthetic faults and common concurrent store tests cover the contract.

## Synthetic host authorization hooks
- The host resolves an already-authenticated principal and separately authorizes the fixed example operation before the signal gate. Both hooks must be supplied together; exceptions, non-booleans and denials fail closed. The standalone example still has no authentication; a real host must establish trusted context and bound every route, including rejected requests.

## Private demo connection admission
- Apply a global token bucket and concurrent socket cap before routing, one request per connection, and a monotonic absolute socket deadline enforced by the server loop. Overload drops connections without attempting a potentially blocking response. These controls do not interrupt a stuck handler or replace a supported deployment boundary.

## Next-version foundation
- To preserve the existing C decision ABI, saturation returns denial plus a thread-local capacity error rather than silently evicting buckets. No automatic reclamation is implemented; authorized resets have quota consequences.
- Demo exposure requires an explicit host override; it is not a supported deployment entrypoint. Read-only CI and write-enabled survey workflows are separate. Required branch protection and native Windows/macOS evidence remain open.

## 2026-11-22 — Browser encrypted client
- Added a browser-side sealed-v2 client using libsodium, an independently supplied public key and single-use challenges. It collects/stores no signals and has no plaintext fallback.
- Tested the same JavaScript against Python and exercised the synthetic UI in headless Chromium, with and without a mocked Turnstile widget. The page cannot access Linux machine IDs; sender-side code and all third-party scripts remain part of the trust boundary.

## 2026-11-22 — API hardening
- The first Linux CI run passed but warned that checkout v4 uses a deprecated Node runtime. Updated to pinned checkout v7.0.1 for the next workflow run.
- Added a framework-independent Python request gate and a local WSGI example that enforces decisions before its synthetic protected operation.
- IP precharging now precedes decryption and Siteverify; failed verification and blocked reputation no longer charge device buckets or enroll observations. A client that passes verification can still forge signals.
- Added peer-bound, time-limited single-use challenges for `sealed-v2`, with bounded memory or single-host SQLite replay state. This blocks a second use, not first-use races, fabricated signals or cross-host replay without shared state.
- Added an opt-in single trusted proxy contract with strict single-address header validation; it is only safe if the operator controls and sanitizes the proxy and restricts origin access.

## 2026-11-22 — Project working guidance
- Applied the user's general project prompt to the existing repository instead of switching its C/Python implementation to Rust or inventing unsupported Windows/macOS tests.
- Kept historical research and runner logs where they already live; added a lightweight documentation index, useful directory descriptions, and an unreleased test-record location.
- Secret values and real identifiers must not be copied into documentation or logs. Strict JSON cannot carry comment headers; purpose is recorded in documentation instead.

## 2026-11-22 — Optional request controls
- Added opt-in IPsum reputation and Turnstile verification to the Python prototype; external outages and false positives have explicit policies. Cloudflare proxy ranges are not threat lists.
- Chose server-side keyed device-signal storage, selectable IP storage and optional libsodium sealed-box request bodies. Raw identifiers are still transiently processed; ciphertext is replayable and independently trusted code and key delivery are necessary.
- Verified synthetic HTTP behavior locally. Live Cloudflare verification and browser encryption remain unverified/unimplemented; the C engine is separate.
