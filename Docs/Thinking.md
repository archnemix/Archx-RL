# Engineering decisions

Purpose: record concise decisions, problems and outcomes rather than private reasoning.

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
