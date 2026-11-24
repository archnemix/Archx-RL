# Requested changes

Purpose: track current user-requested changes and their status, not hypothetical product requirements.

- Identification/rate-limiting scope and configurable responses: implemented in the Python demo; no account/trial enforcement.
- Optional refreshable IP reputation and Turnstile, IP raw/hash selection, keyed device-signal storage and additional request encryption: implemented locally in the Python prototype; see [Roadmap](Roadmap.md) for limitations.
- Apply relevant general working rules: documented in [Rules](Rules.md), with concise project documentation and sanitized test records. Native Windows/macOS support and live Cloudflare testing are not implied.

- API hardening: a host gate/example, peer-bound sealed-v2 challenges, optional strict trusted-proxy resolution, and verification before device enrollment; tested with synthetic traffic, with production limitations retained.

- Browser sealed-v2 client and synthetic test page: implemented and tested against the Python prototype without collecting real identifiers.
