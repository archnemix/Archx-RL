# Opt-in Turnstile staging probe

This prepares #26 but **is not evidence of a real provider test**. No staging secret or fresh provider-issued tokens were available or used. `tools/turnstile_staging.py` is opt-in; deterministic regression uses only a fake provider. The project remains an unreleased prototype and this probe is not a supported deployment guide.

An operator controlling an isolated staging widget, authorized staging hostname and action can supply the following environment variables through their own secret-management mechanism, not chat, source files, command-line arguments, shell history, CI logs or public issue comments:

- `ARCHX_STAGING_ENABLE=1` (explicit network opt-in)
- `ARCHX_STAGING_SITEKEY`, `ARCHX_STAGING_SECRET`, `ARCHX_STAGING_HOSTNAME`, `ARCHX_STAGING_ACTION`
- `ARCHX_STAGING_TOKEN_SUCCESS`, `ARCHX_STAGING_TOKEN_HOSTNAME`, `ARCHX_STAGING_TOKEN_ACTION`, `ARCHX_STAGING_TOKEN_SECRET`: **four different, fresh, unconsumed tokens** issued by the configured widget for that hostname/action.

Run `python3 tools/turnstile_staging.py` inside that controlled environment. Cloudflare tokens are short-lived and single-use: issue them close to the run and do not submit these same tokens elsewhere. The probe consumes four tokens and sends an additional fixed synthetic invalid token. It tests real provider success, invalid token, deliberately mismatched expected hostname and action, and a deliberately invalid secret. Two additional cases simulate a timeout and upstream transport error locally; they do **not** prove behavior during a real provider outage. No real provider request is made for these two cases. Exit 0 means all seven checks matched their expected adapter decisions; it does not establish production readiness.

Output consists only of fixed scenario names and pass/fail; configuration, tokens, provider response bodies and exceptions are withheld. Python's environment, process memory, operating system, network proxies, libraries and the hosting platform can nevertheless expose secrets: use a trusted ephemeral machine, restrict process/environment visibility, follow the provider's guidance, and rotate or revoke staging credentials if exposed. Do not capture debug traces or HTTP bodies. Results may be reported only after manual review for sensitive data; never publish tokens, secrets, user identifiers or unreviewed logs. The harness does not provision a widget, automate issuance, verify browser interaction, test an actual provider outage or bypass network restrictions. An actual credentialed run and independent operational review remain necessary before #26 can be closed.

`tests/test_turnstile_staging.py` injects synthetic responses and faults, checks distinct-token enforcement and verifies that the CLI suppresses test secret/token/exception markers. It cannot validate Cloudflare's current behavior or establish staging success.
