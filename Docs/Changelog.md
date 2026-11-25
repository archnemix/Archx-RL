# Changelog

Purpose: summarize changes by real release; no release version has been asserted here.

## Unreleased
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
