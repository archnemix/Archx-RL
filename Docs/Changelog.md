# Changelog

Purpose: summarize changes by real release; no release version has been asserted here.

## Unreleased
- Added optional host-owned principal and operation authorization hooks to the synthetic WSGI example; Archx does not authenticate or authorize users.
- Added process-local connection rate, concurrency and socket-deadline controls to the private demo, with synthetic mixed-traffic and slow-client tests. Production entrypoint and overload validation remain open.
- Began next-version foundation: fail-closed C store saturation, loopback-by-default demo, security model, backlog and read-only PR/push CI. Windows/macOS support and the release gates remain incomplete.
- Added an optional browser sealed-v2 client and synthetic browser interoperability test with optional Turnstile.
- Hardened Python request flow: reusable host gate, single-use sealed-v2 challenges, explicit trusted single-proxy handling and verification before device-signal enrollment.
- Python prototype: optional IPsum reputation and Turnstile verification, raw or keyed-hash IP retention, sealed-box request bodies for the native client, and friendly messages for new decisions.
- Documentation: working rules, architecture and file indexes, engineering decisions and sanitized test records.

See Git history and the root README for earlier development; do not infer a version or release from this section.
