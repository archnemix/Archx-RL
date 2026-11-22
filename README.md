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

A separate **Python demonstration**, not production middleware, is in [`demo/`](demo/). It exercises a native Linux client, a server-side request policy, a sanitized GitHub runner availability survey, and a browser dashboard. It does **not** yet use the C ABI for request policy and does not replace the original C core. The current frontend integration is native Linux; the webpage is a dashboard, not a browser hardware collector.

```sh
python3 demo/server.py --host 0.0.0.0 --port 8000
# In another terminal:
python3 demo/client.py --account account-a
python3 demo/client.py --account account-b
```

Open the live preview or `http://localhost:8000` on the same machine. For a standard or hard preset, pass `--preset standard` or `--preset hard` to the server; start the client with the server's selected signal names (`--signals machine_id,product_uuid,board_serial,disk_serial,disk_wwn,filesystem_uuid,partition_uuid,installation_id` for standard). A fixed policy can be loaded at server startup with `--config demo/policy.example.json`. The JSON can override `required`, `conditional`, `min_matches`, `max_requests`, `window_seconds`, `history_seconds`, and timezone/clock settings. A server operator sets this policy; requests cannot override it. These presets count signal names, including IP, rather than independent hardware categories; they do not yet enforce a hardware-category requirement. The dashboard preset selector and custom JSON configure only the **isolated synthetic simulation**, not the running server.

**Demo security limitations:** the server has no authentication, TLS, multi-host distributed store, reverse-proxy trust configuration, automatic IP geolocation, or production-grade resource protection. It binds to all interfaces by default for the Arena preview; do not expose it publicly or deploy it as a protection boundary. In the preview, the peer IP may be the preview proxy rather than the browser. Forwarding headers are deliberately ignored, so operators must design a trusted proxy boundary before real deployment. By default the in-memory state and random secret reset on restart. An optional SQLite mode is described below; it is still a prototype, not a distributed store. The C core's separate API and policies remain unchanged.

### Signal and policy behavior

The client emits per-signal app-scoped HMAC-derived tokens, rather than raw values. The app label is **not a secret**; a modified client can invent or replay tokens, and low-entropy identifiers can be guessed. Tokens are linkable sensitive data, not anonymous or authenticated. The server separately HMACs every token and peer IP with its own secret before keeping observations in memory or the optional SQLite store. Use TLS in a real integration. The client reads only requested signals and does not request elevation; unsupported, absent or unreadable values are omitted. In this prototype, when multiple disks or devices are present, one lexicographically selected derived token is sent per signal type; adding/removing devices may change that choice. The optional installation ID is a per-user application file, not a hardware identity.

In the demo, `required` means **must be present** on each request. `conditional` means considered if supplied, without a missing-field error. Each observation is compared with recent individual observations: a match is `related` when at least `min_matches` selected signals, including IP, match the **same prior observation**. With basic preset (`min_matches: 1`), either a machine signal or peer IP suffices, as requested. `new`, `related`, `below_threshold`, and `inconclusive` are evidence labels, not assertions about a person. IP-only matches group unrelated users behind NAT or proxies, causing false positives; do not treat a relation as authentication or proof of the same user. Optional signals can also create relations, as configured.

Every validly shaped request consumes a fixed-window bucket for its peer IP and each supplied signal; malformed requests also charge the IP bucket. Default is five requests per 60 seconds. Denial occurs when **any** bucket exceeds its limit and returns `429` with `retry_after_seconds`; invalid or challenged attempts are charged too. The IP bucket intentionally limits unrelated users behind shared networks. Accounts cannot avoid the limit merely by changing the account name, but a client that changes all observable signals and IP can bypass these prototype checks. In memory mode, buckets and observations are bounded, process-local and lost on restart. In SQLite mode, they survive restart and can be shared by cooperating processes on one host. Buckets use `window_seconds` (default 60); identity observations use a separate `history_seconds` (default 86,400 seconds). This is not a complete trial-account database: it stores pseudonymous signal observations, not authenticated account ownership. Bucket-capacity exhaustion fails closed, potentially denying legitimate traffic. The in-memory history evicts its oldest observation at capacity; SQLite rejects new distinct observations instead.

Timezone checks accept a client IANA timezone and optional Unix-seconds timestamp. The server will not infer a region from an IP without operator-supplied data. `--geo demo/geo.example.json` illustrates an **offline trusted CIDR-to-IANA mapping** using a documentation-only IP range; use a maintained geolocation source and trusted peer IP in a real system. With `timezone_enforce: true`, an offset mismatch beyond `timezone_tolerance_minutes` or a supplied clock outside `max_clock_skew_seconds` returns a challenge. Unknown geolocation/timezone or an omitted clock is reported unknown and is **not** treated as a match or mismatch. The comparison uses the current UTC instant and supports DST; timestamps are compared with a tolerance, not exact seconds. Geolocation is approximate, IP regions can span multiple timezones, and VPN/travel can legitimately cause mismatches. Do not infer exact location or require a user to change their system timezone automatically.

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

`--db` requires an explicitly provided secret of at least 32 bytes; length alone does not guarantee entropy, so generate it randomly. Do not commit the secret or database. Losing/changing the secret prevents reopening the database. All processes sharing it must use the same secret and exactly the same policy. **Policy or secret changes fail closed:** a future migration/rotation procedure is needed rather than silently changing existing identities. New database files use mode 0600; existing files must be private regular files owned by the service user, and the final path must not be a symlink. The parent directory must be trusted and private, and backups, WAL files and filesystem snapshots need the same protection.

SQLite transactions serialize per-request bucket updates and observation insertion; duplicate identical observations reuse one history slot. Both buckets and observations have a hard limit of 10,000 entries by default; when full, new work is rejected rather than silently evicting persistent history. Expired observations are ignored and cleaned during subsequent valid requests—not by a scheduled job. SQLite `secure_delete` is enabled, but this does **not** guarantee removal from backups, WAL files, snapshots or storage media. Define a retention/deletion process before any real deployment. The database contains linkable HMAC values and timestamps even though raw identifiers and account strings are not stored.

SQLite is a single-host development option, not an industry-grade distributed rate limiter. It serializes writes and has no multi-host consistency, backup/restore tooling, key rotation, authenticated users, automatic retention job, external security review, or production load testing. A synthetic 200-request sequential microbenchmark is recorded in each [runner log](.github/archx-runner/runs/latest.log); its timings depend on the host and are not throughput guarantees. A full policy, security, concurrency and load review is still needed before production use.
