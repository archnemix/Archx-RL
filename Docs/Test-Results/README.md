# Test records

Purpose: preserve sanitized, reproducible test output by actual release or `unreleased`; keep the current and previous two release groups only. The existing GitHub runner logs remain under `.github/archx-runner/runs/` as historical records; they are not silently deleted or relabeled as releases. Never record secrets, real device identifiers, full sensitive requests or production data.

`unreleased/` records local runs for the currently uncommitted Python controls. The standard suite uses synthetic fixtures, and optional cryptography tests require PyNaCl. Tests not performed, including live Turnstile and Windows/macOS native checks, are not represented as passing.
