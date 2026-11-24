# Roadmap

Purpose: show the current, evidence-based work sequence; this is not a promise of unrequested features.

1. **Current prototype and privacy controls — implemented:** Linux C core; Python request matching and rate limiting; optional SQLite persistence, configurable responses, IP retention choice, IP reputation, Turnstile, host integration example, opt-in trusted single-proxy handling and sealed native/browser clients with single-use challenges. See the root README for scope and tests. See the [runner records](../.github/archx-runner/runs/latest.log) for the latest recorded GitHub run and its tested commit.
2. **Validate the current integration before widening scope:** review false positives, forged-signal poisoning, trusted client-IP boundaries, retention, and secure deployment. Live Turnstile, browser platform coverage beyond synthetic Chromium testing, distributed replay state, key rotation, independent security review and production load testing remain absent; prioritize only as directed.
3. **Future platforms/integrations:** only when requested, design platform-specific collectors and supported host middleware, then add the relevant platform runners and tests. Windows/macOS support is not currently implemented.

Free-trial or entitlement enforcement is a possible future host concern, not current Archx functionality.
