# Security policy

Archx is an **unaudited prototype**, not an authentication, authorization, attestation or production-ready security boundary. Only Linux native collection has been implemented and tested. Windows and macOS are mandatory targets for the next version, not currently supported. See [the threat model](Docs/Threat-Model.md) for explicit limitations and [the backlog](Docs/Plan/Next-Version.md) for release gates.

## Reporting

Please do not disclose suspected vulnerabilities, secrets, raw device identifiers or working exploits in a public issue. Use GitHub's private vulnerability reporting on this repository's Security tab **if it is enabled**; otherwise contact the repository maintainers privately through a contact method they provide. The availability of a private reporting channel, response time and supported-version policy have not yet been established; do not assume a security SLA.

## Deployment and recovery

The HTTP server under `demo/` is for private experiments only, binds to loopback by default, and has no production-grade TLS, authentication or bounded worker pool. The Python request gate example is illustrative, not a supported production server. Hosts must enforce every decision, protect keys and stored pseudonyms, use HTTPS, and configure a trustworthy client IP boundary; never infer authenticated identity from signals. See the [README](README.md) for separate C and Python behavior and limitations.

The C store refuses new keys at saturation instead of evicting existing buckets. This protects those buckets but can deny legitimate traffic indefinitely; there is no automatic reclamation. An authorized operator can explicitly reset selected keys after assessing quota impact; destroying/restarting a C store resets **all** quotas and may enable abuse. Python memory state also resets on restart; SQLite has single-host limitations. Backups, logs, WAL and old tables require separate retention review. No tested rotation or migration procedure is currently available.
