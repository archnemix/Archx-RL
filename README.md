# Archx-RL

Milestone 1 is a **Linux-only prototype** of a shared C core for device-signal inspection, app-scoped pseudonymous identification, and an in-process token bucket. The C ABI is in [`include/archx.h`](include/archx.h); the Python and Node examples call the same library. No daemon, browser/mobile support, cross-machine rate-limit store, or other OS implementation is included yet.

## Build and try

Requires Linux, a C11 compiler, `make`-independent POSIX build tools and pthreads. No external C dependencies.

```sh
./build.sh
./test.sh
./build/archx-probe collect
ARCHX_PEPPER='replace-with-a-secret' ./build/archx-probe identify --app-id my-app
./build/archx-probe check user-42 --capacity 5 --refill-per-sec 1
python3 examples/python/demo.py
python3 examples/python/match.py
(cd examples/node && npm install)
node examples/node/demo.js
```

Build outputs are in `build/`. The probe and examples default to a **public demo pepper**; do not use that default for real identities. Prefer a randomly generated secret kept outside source code. `--pepper` exposes its value in the process command line, so the environment is preferable for this demo. CLI `check` starts a new store each time: repeat calls in the **same process** to observe depletion (as the examples do).

## What Linux information is available?

`collect` returns the OS, CPU architecture from `uname`, and signal metadata only: name, weight and whether a usable value was read. It does **not** return raw identifiers. Availability depends on the machine, permissions and container setup.

| Signal | Source | Weight | Caveats |
| --- | --- | ---: | --- |
| `machine_id` | `/etc/machine-id`, then `/var/lib/dbus/machine-id` | 60 | OS installation identifier, not proof of hardware; images or containers can share it. |
| `product_uuid` | `/sys/class/dmi/id/product_uuid` | 25 | SMBIOS value; often absent or restricted. |
| `board_serial` | `/sys/class/dmi/id/board_serial` | 15 | Often absent, restricted, or a manufacturer placeholder. |

Values are trimmed and lowercased; some common placeholders are rejected. The reported confidence is the **sum of available weights**, capped at 100: `full` means all three signals were usable, `partial` means at least one, and `fallback` means none. These scores are heuristic availability indicators, **not measured accuracy, proof of identity, or fraud resistance**. A changed permission level, hardware, OS install, or container can change which signals are readable and therefore change the resulting hash. Cloned machines can have identical IDs; hostile clients can alter their local signals. Do not use this as authentication or device attestation.

If no signal is readable, the core generates a random per-user fallback ID under `$XDG_DATA_HOME/archx/device_id` (or `$HOME/.local/share/archx/device_id`), created with mode 0600. It uses a locked file to coordinate first creation between processes. An unavailable home, invalid existing file, or failure to persist produces an error rather than an ephemeral ID. Fallback is per-user/install, not a hardware identifier; `signals_used` is zero and confidence is 10. `collect` does not create the fallback file.

## Identity and configuration

`ax_identify` computes HMAC-SHA256 using the pepper, a domain separator, app ID, and the sorted normalized readable signals (length-prefixed names and values). The result is an app-scoped pseudonym, not anonymous data. Keep the pepper stable and secret: changing it, the app ID, the set of readable signals, or their values changes the identity. A pepper embedded in a client application can be extracted. Do not log raw OS identifiers, use a demo pepper for deployment, or assume the hash cannot be linked when secrets are shared.

Example core configuration:

```json
{
  "app_id": "my-app",
  "pepper_env": "ARCHX_PEPPER",
  "rate_limit": {"capacity": 100, "refill_per_sec": 10},
  "store_capacity": 65536
}
```

Alternatively, pass `pepper` as a string. An even-length all-hex pepper of at least 32 characters is decoded as hex; other strings are treated as raw bytes. Maximum decoded length is 64 bytes. `app_id` is required, limited to 127 bytes, and cannot contain `|`. The small config parser supports objects, strings, numbers, booleans and null, not arrays; Unicode surrogate escapes are not supported. It rejects duplicate keys. The `key_scope` field is currently informational and does not choose a key automatically: **the caller chooses and supplies the rate-limit key**.

The token bucket is mutex-protected and lives only in the core handle. It is not shared across processes and is lost when the handle is freed. At capacity the oldest bucket is evicted, which can reset limits under high key churn; it is not a distributed or adversarially robust rate limiter. `retry_after_ms` is `-1` when the requested cost cannot ever be reached (including cost greater than capacity). Keys are limited to 800 bytes. Handle errors via `ax_last_error()` on the same thread, and free JSON buffers with `ax_buffer_free()`. Do not free a core while other threads are using it.

## Status

This is early, unaudited software, including its self-contained cryptography and parser. Tests cover standard SHA-256/HMAC vectors, Linux probe output, configuration failures, token-bucket exhaustion and eviction, thread contention, and concurrent fallback creation. The implementation is not a production security boundary; additional platform testing, security review, and an appropriate deployment architecture are required.

## Matching profiles across changes

The original `ax_identify` produces a single hash that changes if any contributing signal changes. For flexible matching, configure `match` when creating the core, capture an enrollment profile with `ax_profile` or `ax_profile_with_ip`, store it securely, capture a current profile, and pass both JSON buffers and their lengths to `ax_compare`. Each selected signal is stored as a separate app-scoped HMAC, or `null` when unavailable; raw values are not returned. Profiles are **linkable sensitive data**. A profile's scope detects a different app/pepper, but it is **not a signature**: keep both input profiles trusted and integrity-protected. Do not accept client-submitted profiles as proof of hardware or identity.

For example:

```json
{
  "app_id": "my-app",
  "pepper_env": "ARCHX_PEPPER",
  "match": {
    "mode": "threshold",
    "min_matches": 2,
    "signals": {
      "machine_id": "required",
      "product_uuid": "optional",
      "board_serial": "optional",
      "ip": "optional"
    }
  }
}
```

Only selected OS signals are read when capturing a profile; `collect` and the older `identify` API still inspect all three Linux OS signals. Valid roles are `required` and `optional`. `threshold` requires `min_matches` (between 1 and the number selected): every required signal must match, and at least that many signals overall must match. Optional changes can be tolerated. If too few matches remain possible or a required signal changed, the result is `no_match`; if insufficient or required evidence is unavailable, it is `inconclusive`; otherwise it is `match`. Each selected signal also reports `match`, `changed`, or `unavailable`. With `strict`, all selected signals must match regardless of role; any change is `no_match` and missing evidence is `inconclusive`. Do not set `min_matches` with strict mode. With no match configuration, strict mode selects the three Linux OS signals, so it may be inconclusive on restricted systems. Changing the selected policy can leave signals missing in older profiles; capture a fresh baseline only after an independent trust decision.

`ip` is never discovered automatically: pass an IPv4 or IPv6 address from a trusted request context to `ax_profile_with_ip`; it is canonicalized before HMAC. `ax_profile` treats it as unavailable. Configure trusted proxies carefully rather than trusting a client-supplied forwarding header. IP is easily changed or shared, and the other identifiers can also be cloned, spoofed or changed. CPU IDs are not currently collected; a CPU model would not be a reliable unique ID. Even a `match` is only a configurable friction/risk signal, not proof that the same person or physical device is present. Never use it as the sole authentication mechanism. Avoid using a single shared/low-entropy signal as your match threshold.

The optional repository-backed Linux test runner is documented in [`.github/archx-runner/README.md`](.github/archx-runner/README.md). It is not required to build locally.

## Linux frontend, backend, and explorer demo

Archx is intended as an **identification and rate-limiting layer**, not an account, authentication, trial or entitlement system. Applications decide what actions to protect. A separate **Python demonstration**, not production middleware, is in [`demo/`](demo/). It exercises a native Linux client, a server-side request policy, a sanitized GitHub runner availability survey, and a browser dashboard. It does **not** yet use the C ABI for request policy and does not replace the original C core. The current frontend integration is native Linux; the webpage is a dashboard, not a browser hardware collector.

```sh
python3 demo/server.py --host 127.0.0.1 --port 8000
# In another terminal:
python3 demo/client.py --confirm-send-raw
python3 demo/client.py --confirm-send-raw
```

Open the live preview or `http://localhost:8000` on the same machine. For a standard or hard preset, pass `--preset standard` or `--preset hard` to the server; the client automatically discovers its selected signal names; optionally use `--signals` to limit conditional collection. A fixed policy can be loaded at server startup with `--config demo/policy.example.json`. The JSON can override `required`, `conditional`, `min_matches`, `max_requests`, `window_seconds`, `history_seconds`, timezone/clock settings and friendly `messages`. A server operator sets this policy; requests cannot override it. These presets count signal names, including IP, rather than independent hardware categories; they do not yet enforce a hardware-category requirement. The dashboard preset selector and custom JSON configure only the **isolated synthetic simulation**, not the running server.

The demo exposes a JSON check interface independent of frontend type. For example, a compatible native frontend can send `{"signals":{"machine_id":"<synthetic 32-hex value>"}}` to `/api/v2/check`; no account is required. A legacy `account` field is accepted but ignored. The provided collector is Linux-native; ordinary browser JavaScript cannot read these Linux hardware values and would need a different supported collection mechanism. The demo HTTP handler is a standalone prototype: it does **not** automatically intercept or enforce requests to an existing application. A host must integrate it at the protected route and honor its decision.

Operators may set `messages` for `rate_limited`, `missing_required`, `invalid_request`, `timezone_mismatch`, `clock_out_of_range`, `capacity_exceeded` and `storage_error` in their policy JSON; omitted messages use friendly defaults. Message strings are plain text, 1–500 characters, and contain no control characters. Frontends should render them as text, never HTML. A rate-limited response carries HTTP 429, a `message`, `retry_after_seconds` and `Retry-After`; the client obtains the configured missing-required message from the policy endpoint. Message changes do not reset SQLite limits or require a new database.

**Demo security limitations:** the server has no authentication, TLS, multi-host distributed store, reverse-proxy trust configuration, automatic IP geolocation, or production-grade resource protection. It binds to all interfaces by default for the Arena preview; do not expose it publicly or deploy it as a protection boundary. In the preview, the peer IP may be the preview proxy rather than the browser. Forwarding headers are deliberately ignored, so operators must design a trusted proxy boundary before real deployment. By default the in-memory state and random secret reset on restart. An optional SQLite mode is described below; it is still a prototype, not a distributed store. The C core's separate API and policies remain unchanged.

### Signal and policy behavior

Without `--confirm-send-raw`, the client displays the recipient, selected signal names and available names without printing their values. It queries `lsblk` only for selected storage columns. The Python client obtains the service policy from `GET /api/v2/config`, collects selected identifiers without elevation and sends **raw values** to `POST /api/v2/check` only with `--confirm-send-raw`. Required signals are always included; `--signals` can restrict conditional signals. If a required value is absent, unreadable or unsupported, the client tells the user what is missing and does not send the request. The server independently enforces required fields. The client refuses non-loopback plaintext HTTP and redirects; remote HTTPS must authenticate the intended service. Never send real identifiers to the public preview or this demo server over an untrusted network: the server itself has no TLS. Protect TLS termination and intermediaries, disable request-body logging everywhere, disclose collection and obtain appropriate consent. Raw machine IDs are confidential; collecting them introduces substantial privacy risk.

The server normalizes and checks formats before using a secret HMAC per signal and IP for matching and storage. Machine IDs are 32 hexadecimal characters, installation IDs 64; product and GPU UUIDs use UUID syntax; filesystem UUIDs additionally support common FAT/NTFS formats, partition UUIDs include MBR form, WWNs are 16 or 32 hexadecimal characters, MACs are unicast, and serials use a conservative ASCII subset of 4–128 characters. Common placeholders are rejected. These are limited rules, not a complete vendor specification: legitimate identifiers can be rejected. Normalization trims and lowercases; WWN prefixes are removed. For multiple devices the client chooses the lexicographically first valid normalized value; adding or removing devices may change it. Locally administered/randomized MACs are currently skipped by the collector, though accepted by validation. The optional installation ID is a per-user application file, not hardware identity.

**Format is not authenticity:** an attacker can fabricate plausible values or replay a real one, or rotate all identifiers and IP. Server HMAC protects stored values against casual disclosure, not against a malicious client. HMACs remain linkable sensitive data. Trusted attestation or other independent controls would be necessary for stronger provenance; this prototype does not implement them. The separate C API described above still uses client-side app-scoped HMAC profiles and has not been converted to raw transport.

In the demo, `required` means **must be present** on each request. `conditional` means considered if supplied, without a missing-field error. Each observation is compared with recent individual observations: a match is `related` when at least `min_matches` selected signals, including IP, match the **same prior observation**. With basic preset (`min_matches: 1`), either a machine signal or peer IP suffices, as requested. `new`, `related`, `below_threshold`, and `inconclusive` are evidence labels, not assertions about a person. IP-only matches group unrelated users behind NAT or proxies, causing false positives; do not treat a relation as authentication or proof of the same user. Optional signals can also create relations, as configured.

Every validly shaped request consumes a fixed-window bucket for its peer IP and each supplied signal; malformed requests also charge the IP bucket. Default is five requests per 60 seconds. Denial occurs when **any** bucket exceeds its limit and returns `429` with `retry_after_seconds`; invalid or challenged attempts are charged too. The IP bucket intentionally limits unrelated users behind shared networks. Changing an unrelated account name does not change the limit, but a client that changes all observable signals and IP can bypass these prototype checks. Matching thresholds govern the relation label; independent per-signal and IP buckets enforce limits even if the relation threshold is not met. In memory mode, buckets and observations are bounded, process-local and lost on restart. In SQLite mode, they survive restart and can be shared by cooperating processes on one host. Buckets use `window_seconds` (default 60); identity observations use a separate `history_seconds` (default 86,400 seconds). This layer stores pseudonymous signal observations, not accounts, authentication or trial ownership. Bucket-capacity exhaustion fails closed, potentially denying legitimate traffic. The in-memory history evicts its oldest observation at capacity; SQLite rejects new distinct observations instead.

Timezone checks accept a client IANA timezone and optional Unix-seconds timestamp. The server will not infer a region from an IP without operator-supplied data. `--geo demo/geo.example.json` illustrates an **offline trusted CIDR-to-IANA mapping** using a documentation-only IP range; use a maintained geolocation source and trusted peer IP in a real system. With `timezone_enforce: true`, an offset mismatch beyond `timezone_tolerance_minutes` or a supplied clock outside `max_clock_skew_seconds` returns a challenge. Unknown geolocation/timezone or an omitted clock is reported unknown and is **not** treated as a match or mismatch. The comparison uses the current UTC instant and supports DST; timestamps are compared with a tolerance, not exact seconds. Geolocation is approximate, IP regions can span multiple timezones, and VPN/travel can legitimately cause mismatches. Do not infer exact location or require a user to change their system timezone automatically.

**Legacy data:** the removed experimental trial example may have created `trial_entitlements` and `trial_signals` tables in a database used with that example. Removing code does not erase those tables or backups. Operators should review their retention and securely remove legacy data as appropriate; this change does not automatically delete existing data.

### GitHub runner survey

The [saved survey](.github/archx-runner/runs/linux-permissions.json) records **availability only** for the GitHub-hosted Ubuntu VM, with the runner's normal user, a separate unprivileged user, and root; no signal values are saved. The exact environment, time and run ID are in the JSON. This is not representative of all Linux hardware, distributions, Flatpak/Snap sandboxes, VMs, or containers. The runner workflow saves test and survey output in the repository, not artifacts. [Runner instructions](.github/archx-runner/README.md).

`./test.sh` includes C AddressSanitizer/UndefinedBehaviorSanitizer checks and deterministic malformed-JSON stress, plus persistence/restart, atomic multi-process and synthetic attack/edge-case tests for matching across account/IP changes, shared IP collision, threshold behavior, missing and malformed fields, duplicate JSON keys, independent IP/device limits, concurrent requests, window expiry, timezone and clock tolerance, and capacity exhaustion. The dashboard's simulation uses only reserved documentation addresses and synthetic values, never real external services.

The deterministic [attack-lab report](reports/attack-lab.json) records both the per-signal limits that worked and the observed full-rotation bypass and shared-IP false positive. It uses synthetic traffic only.

### Optional SQLite persistence (single host)

The Python demo can persist rate-limit buckets and pseudonymous signal observations on **one host**, surviving process restarts and coordinating multiple processes through SQLite transactions. Example for a local development terminal:

```sh
mkdir -p -m 700 build/archx-private
# Generate once for this terminal; securely retain the same secret for restarts.
export ARCHX_DEMO_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 demo/server.py --host 127.0.0.1 --port 8000 --db build/archx-private/archx.sqlite
```

`--db` requires an explicitly provided secret of at least 32 bytes; length alone does not guarantee entropy, so generate it randomly. Do not commit the secret or database. Losing/changing the secret prevents reopening the database. All processes sharing it must use the same secret and the same enforcement policy; friendly messages may differ. **Policy, secret, or schema changes fail closed:** a future migration/rotation procedure is needed rather than silently changing existing identities. The raw-v2 format uses schema 3 and cannot reopen older token-mode databases: start a new database or implement a deliberate migration; previous token hashes cannot be transformed into raw-ID hashes. New database files use mode 0600; existing files must be private regular files owned by the service user, and the final path must not be a symlink. The parent directory must be trusted and private, and backups, WAL files and filesystem snapshots need the same protection.

SQLite transactions serialize per-request bucket updates and observation insertion; duplicate identical observations reuse one history slot. Both buckets and observations have a hard limit of 10,000 entries by default; when full, new work is rejected rather than silently evicting persistent history. Expired observations are ignored and cleaned during subsequent valid requests—not by a scheduled job. SQLite `secure_delete` is enabled, but this does **not** guarantee removal from backups, WAL files, snapshots or storage media. Define a retention/deletion process before any real deployment. The database contains linkable HMAC values and timestamps even though raw identifiers and account strings are not stored.

SQLite is a single-host development option, not an industry-grade distributed rate limiter. It serializes writes and has no multi-host consistency, backup/restore tooling, key rotation, authenticated users, automatic retention job, external security review, or production load testing. A synthetic 200-request sequential microbenchmark is recorded in each [runner log](.github/archx-runner/runs/latest.log); its timings depend on the host and are not throughput guarantees. A full policy, security, concurrency and load review is still needed before production use.
