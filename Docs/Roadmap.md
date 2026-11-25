# Roadmap

Purpose: show the current, evidence-based work sequence; this is not a promise of unrequested features.

1. **Current prototype and privacy controls — implemented:** Linux C core; Python request matching and rate limiting; optional SQLite persistence, configurable responses, IP retention choice, IP reputation, Turnstile, host integration example, opt-in trusted single-proxy handling and sealed native/browser clients with single-use challenges. See the root README for scope and tests. See the [runner records](../.github/archx-runner/runs/latest.log) for the latest recorded GitHub run and its tested commit.
2. **Next-version foundation:** threat model, ordinary read-only CI, fail-closed saturation and bounded integration. Track open work and evidence in [Next-Version.md](Plan/Next-Version.md).
3. **Mandatory next-version portability:** native Windows and macOS implementations and CI, retaining Linux. A platform is not supported until its actual native builds, collectors, fallback, bindings and tests have evidence. See A03–A08 and the platform research gate.
4. **Release readiness:** operational controls, privacy, migration, representative tests and honest support matrix. A single-host profile is first; distributed enforcement is a later milestone.

Archx remains separate from account authentication, trials and entitlement enforcement.
