# Operational workarounds

Purpose: record established repository-specific ways to run constrained tests.

The existing [GitHub Linux runner](../.github/archx-runner/README.md) can run `./test.sh` and a sanitized Linux permissions survey when local access is insufficient. Trigger instructions and direct-to-branch logs are documented there. The workflow uses one runner; keep the total concurrent runner count at or below five. It cannot validate unsupported Windows/macOS collectors or prove production performance. Do not put secrets or real identifiers in saved output, and inspect result-commit success rather than assuming it.

For local browser testing in the constrained sandbox, Chromium and its NSS libraries were not installed. A temporary `@sparticuz/chromium@158.0.0` npm package under ignored `build/local-browser/` supplied a headless binary and bundled libraries; after adding those libraries to `LD_LIBRARY_PATH`, the Chromium test passed. This is a test workaround, not a production dependency or artifact committed to the repository. The GitHub runner uses its installed Google Chrome or installs Playwright Chromium.
