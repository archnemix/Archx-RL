# Secret names

Purpose: list secret names and intended use, never their values.

No user-configured GitHub Actions secret is established by the current repository. The workflow uses GitHub's automatically provided `GITHUB_TOKEN` for its configured repository write permission.

Local/runtime environment variables (not automatically GitHub secrets):
- `ARCHX_DEMO_SECRET`: stable, high-entropy Python SQLite HMAC secret; at least 32 bytes.
- `ARCHX_TURNSTILE_SECRET`: Cloudflare Turnstile Siteverify secret when enabled, backend only.
- `ARCHX_PEPPER`: example default name for the C core's HMAC pepper; the C API can specify a different environment variable.

Keep values in an appropriate secret manager; do not commit them, print them or send them in chat. See the root README for configuration and key-file handling.
