# Browser sealed client

Purpose: provide a small optional browser client for the existing `sealed-v2` Python check API, plus a Chromium integration test. It collects and stores no identifiers. The embedding application supplies signals and an independently authenticated public key.

From the repository root, run `npm ci --prefix demo/browser` and `npm run build --prefix demo/browser`; the generated browser module is `build/browser/archx-client.mjs` and is intentionally not committed. The optional demo server serves it at `/browser-client.mjs` and offers a synthetic-only `/browser-test` page.

The client accepts only same-origin requests, requires HTTPS except loopback, refuses plaintext downgrade and uses an atomic one-use challenge. The embedding application must integrate the gate into its protected server action; a successful standalone check is not authentication. The code, all same-page scripts and public key need a trusted delivery boundary. Browser JavaScript cannot read Linux machine IDs; the demo uses a fixed synthetic value. See the root README for API usage, privacy and limitations.
