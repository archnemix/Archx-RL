# Architecture and scope

Purpose: describe the current implementation, its boundaries, and the intended integration.

Archx provides request identification signals and rate limiting, not accounts, authentication, trials or entitlements. A host must call a policy engine and enforce the result on its own routes; relation labels are not proof of identity.

The C core is Linux-only: `include/archx.h` exposes app-scoped pseudonymous identification and a process-local token bucket, implemented in `src/`. C probe and Python/Node examples exercise that separate API.

The Python prototype in `demo/` has a Linux-native collector, an optional JavaScript sealed client for caller-provided browser signals, a request-policy engine and optional single-host SQLite persistence. The standalone HTTP server, synthetic dashboard and optional Turnstile widget demonstrate the protocol; they are not generic middleware or a TLS terminator. Its bounded per-process connection admission is a demo safeguard only, not a supported deployment boundary. Device values are transiently validated and stored as keyed HMACs; IP storage is configurable. A reusable request gate, optional IPsum reputation, Cloudflare verification, trusted single-proxy resolution and libsodium sealed payloads with single-use challenges wrap this prototype, not the C API.

Raw identifiers can be fabricated or replayed; forged signals and shared IPs can cause collateral limits. Sealed boxes require independently trusted code and server public key, do not authenticate clients, and do not hide HTTP metadata. Sealed-v2 adds a bounded single-use challenge but cannot prevent a first-use race or fabricated signals. The proxy option requires an independently enforced trust boundary. Real browser collection/integration, multi-host replay state, platform coverage and production hardening require separate work. See the root README for operating details and caveats.
