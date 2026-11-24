# Request flows

Purpose: trace the main component calls without treating matching as identity proof.

1. Native client reads `/api/v2/config`, selects allowed signals, collects with consent and, in sealed mode, obtains a single-use `/api/v2/challenge`. It seals the challenge and signal payload to a separately trusted public key and posts `/api/v2/check`.
2. The HTTP handler resolves the peer using the TCP socket by default, or a narrowly configured trusted proxy with a single overwritten header, and parses bounded JSON. `RequestService` charges the IP once, decrypts the envelope if needed, and atomically consumes the peer-bound challenge.
3. The service validates signal shape and optional reputation, then verifies Turnstile before charging device-signal buckets or storing observations. `Engine`/`SQLiteEngine` hash device values, enforce limits and compute a relation. The host must enforce all decisions; a forged signal can still poison another user's bucket when submitted by a client that passes verification.
4. `refresh_reputation.py` or the optional server refresh thread downloads a bounded IPsum feed and atomically replaces a cache; `Reputation.lookup` marks stale/unavailable data rather than interpreting it as clean. `replay.py` keeps bounded process-local or single-host SQLite challenge state.
5. `examples/python/gated_wsgi.py` shows a local host enforcing the result before a synthetic operation. Separately, C clients call the ABI in `include/archx.h`; `src/` collects Linux signals, computes app-scoped pseudonyms and applies its own in-process limiter. It does not share the Python HTTP integration.
