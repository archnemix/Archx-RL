# Engineering decisions

Purpose: record concise decisions, problems and outcomes rather than private reasoning.

## In-memory observation indexing
- Index token pairs to candidate observation IDs, count each observation independently, preserve oldest-snapshot tie ordering, and track signal-name shapes for comparability. Refresh duplicates; reject new history when full without evicting live observations. SQLite and memory share these tested cases but full parity remains open.
- Popular tokens can still visit every record; both expiration and window cleanup scan under a lock. These are bounded by configured capacity but not measured against a service budget; D03–D06 remain open.

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
