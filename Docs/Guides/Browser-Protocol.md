# Browser client and sealed protocol

Ordinary browser JavaScript cannot read Linux machine IDs or the C core's native hardware signals. The optional browser client encrypts **application-supplied** signals; the included dashboard and browser test use synthetic values. It does not turn browser telemetry into a hardware collector, authentication or attestation.

`sealed-v2` uses a server-issued, peer-bound single-use challenge and a public-key sealed payload. It prevents a later accepted reuse of a consumed challenge, not a first-arrival race or fabrication of a fresh payload. Sender identity is not authenticated by sealed boxes. A host must independently trust the public key and client code, use TLS, and enforce each decision on the protected operation; a previous allow is not a reusable entitlement.

Scripts on the same page or an intermediary that can replace code or keys can defeat confidentiality and integrity assumptions. The browser test mocks Turnstile; it is not evidence of a live provider deployment. Build and integration instructions are in the [README browser section](../../README.md#optional-encrypted-browser-client); privacy boundaries are in [Privacy and security](Privacy-Security.md).
