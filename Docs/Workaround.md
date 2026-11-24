# Operational workarounds

Purpose: record established repository-specific ways to run constrained tests.

The existing [GitHub Linux runner](../.github/archx-runner/README.md) can run `./test.sh` and a sanitized Linux permissions survey when local access is insufficient. Trigger instructions and direct-to-branch logs are documented there. The workflow uses one runner; keep the total concurrent runner count at or below five. It cannot validate unsupported Windows/macOS collectors or prove production performance. Do not put secrets or real identifiers in saved output, and inspect result-commit success rather than assuming it.
