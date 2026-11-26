# Archx-RL

Working guidance and component indexes are in [Docs/](Docs/README.md).

Milestone 1 is a **Linux-only prototype** of a shared C core for device-signal inspection, app-scoped pseudonymous identification, and an in-process token bucket. The C ABI is in [`include/archx.h`](include/archx.h); the Python and Node examples call the same library. A separate browser client encrypts caller-supplied signals; it does not collect native hardware IDs. No mobile collector, cross-machine rate-limit store, or other native OS implementation is included yet.

## Component and deployment guides

- [Native C core](Docs/Guides/Native-Core.md): Linux C ABI and its in-process limiter.
- [Python policy service](Docs/Guides/Policy-Service.md): separate request engines, memory and SQLite.
- [Browser protocol](Docs/Guides/Browser-Protocol.md): caller-supplied signals and sealed requests, not native hardware collection.
- [Privacy and security](Docs/Guides/Privacy-Security.md): trust, data and residual risks.
- [Deployment status](Docs/Guides/Deployment.md): no supported production profile yet and the outstanding release boundaries.

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

## Optional CMake build (Linux only)

The unreleased CMake build installs a shared library, static library, probe, header and relocatable package exports. It deliberately rejects non-Linux full-core builds while the native ports remain unfinished. `build.sh` remains available and does not require CMake.

```sh
cmake -S . -B build/cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PWD/build/archx-install"
cmake --build build/cmake
cmake --install build/cmake
```

Consumers use `find_package(Archx CONFIG REQUIRED)` and link `Archx::core` (shared) or `Archx::static`. `Archx_ABI_VERSION` and `AX_ABI_VERSION` expose the C ABI version; **no release/package version has been declared**. For a custom library directory outside CMake's default search paths, set `Archx_DIR` to its `cmake/Archx` folder. Install directories must be relative to the prefix. `tests/test_cmake_install.sh` tests relocation, both linkage modes and the installed probe; see its dependencies before running it.

## What Linux information is available?

`collect` returns the OS, CPU architecture from `uname`, and signal metadata only: name, weight and whether a usable value was read. It does **not** return raw identifiers. Availability depends on the machine, permissions and container setup.

| Signal | Source | Weight | Caveats |
| --- | --- | ---: | --- |
| `machine_id` | `/etc/machine-id`, then `/var/lib/dbus/machine-id` | 60 | OS installation identifier, not proof of hardware; images or containers can share it. |
| `product_uuid` | `/sys/class/dmi/id/product_uuid` | 25 | SMBIOS value; often absent or restricted. |
| `board_serial` | `/sys/class/dmi/id/board_serial` | 15 | Often absent, restricted, or a manufacturer placeholder. |

Values are trimmed and lowercased; some common placeholders are rejected. For `full` and `partial`, the legacy ABI-v1 JSON field `confidence` is an **availability-weight sum**, capped at 100: `full` means all three signals were usable, `partial` means at least one, and `fallback` means none. The field name and values remain unchanged for ABI-v1 compatibility; they are not probabilities or measured accuracy, proof of identity, or fraud resistance. `fallback` is an exception: its fixed value of 10 is a legacy marker, not a percentage of signal coverage. A changed permission level, hardware, OS install, or container can change which signals are readable and therefore change the resulting hash. Cloned machines can have identical IDs; hostile clients can alter their local signals. Do not use this as authentication or device attestation.

If no signal is readable, the core generates a random per-user fallback ID under `$XDG_DATA_HOME/archx/device_id` (or `$HOME/.local/share/archx/device_id`), created with mode 0600. It uses a locked file to coordinate first creation between processes. New fallback creation uses Linux `getrandom` in nonblocking mode and fails closed if entropy is not ready or the syscall is unavailable/blocked; an empty file can be retried later. An unavailable home, invalid existing file, or failure to persist produces an error rather than an ephemeral ID. Fallback is per-user/install, not a hardware identifier; `signals_used` is zero and confidence is 10. `collect` does not create the fallback file.

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

Alternatively, pass `pepper` as a string. An even-length all-hex pepper of at least 32 characters is decoded as hex; other strings are treated as raw bytes. Maximum decoded length is 64 bytes. `app_id` is required, limited to 127 bytes, and cannot contain `|`. The complete C configuration is limited to 65,536 bytes including whitespace. The small config parser supports objects, strings, numbers, booleans and null, not arrays; Unicode surrogate escapes are not supported. It rejects duplicate keys. The `key_scope` field is currently informational and does not choose a key automatically: **the caller chooses and supplies the rate-limit key**.

The token bucket is mutex-protected and lives only in the core handle. It is not shared across processes and is lost when the handle is freed. At capacity new keys fail closed with `AX_DENY_RATE_LIMIT` and a nonempty `ax_last_error()`; existing buckets are never evicted. Because entries are not automatically reclaimed even after refill, saturation persists until an operator explicitly resets a bucket or destroys the store (which resets all quotas). A restart also loses all limits; this is not a distributed or production-ready rate limiter. `retry_after_ms` is `-1` when the requested cost cannot ever be reached (including cost greater than capacity). Keys are limited to 800 bytes. Clock or mutex failures also deny with a nonempty error; an unlock failure may follow a charge or reset, so errors do not imply rollback. The Linux refill clock excludes system suspend. Handle errors via `ax_last_error()` on the same thread, and free JSON buffers with `ax_buffer_free()`. Do not free a core while other threads are using it.

## Status

This is early, unaudited software, including its self-contained cryptography and parser. Tests cover standard SHA-256/HMAC vectors, Linux probe output, configuration failures, token-bucket exhaustion and fail-closed saturation, thread contention, and concurrent fallback creation. The implementation is not a production security boundary; additional platform testing, security review, and an appropriate deployment architecture are required.

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

Archx is intended as an **identification and rate-limiting layer**, not an account, authentication, trial or entitlement system. Applications decide what actions to protect. A separate **Python demonstration**, not production middleware, is in [`demo/`](demo/). It exercises a native Linux client, a server-side request policy, a sanitized GitHub runner availability survey, and a browser dashboard. It does **not** yet use the C ABI for request policy and does not replace the original C core. The native collector currently supports Linux. An optional browser client can encrypt caller-supplied supported signals; the dashboard is not a browser hardware collector.

```sh
python3 demo/server.py --host 127.0.0.1 --port 8000
# In another terminal:
python3 demo/client.py --confirm-send-raw
python3 demo/client.py --confirm-send-raw
```

Open the live preview or `http://localhost:8000` on the same machine. For a standard or hard preset, pass `--preset standard` or `--preset hard` to the server; the client automatically discovers its selected signal names; optionally use `--signals` to limit conditional collection. A fixed policy can be loaded at server startup with `--config demo/policy.example.json`. The JSON can override `required`, `conditional`, `min_matches`, `max_requests`, `window_seconds`, `history_seconds`, timezone/clock settings and friendly `messages`. A server operator sets this policy; requests cannot override it. These presets count signal names, including IP, rather than independent hardware categories; they do not yet enforce a hardware-category requirement. The dashboard preset selector and custom JSON configure only the **isolated synthetic simulation**, not the running server.

The demo exposes a JSON check interface independent of frontend type. For example, a compatible native frontend can send `{"signals":{"machine_id":"<synthetic 32-hex value>"}}` to `/api/v2/check`; no account is required. A legacy `account` field is accepted but ignored. The provided collector is Linux-native; ordinary browser JavaScript cannot read these Linux hardware values and would need a different supported collection mechanism. The demo HTTP handler is a standalone prototype: it does **not** automatically intercept or enforce requests to an existing application. A host must integrate it at the protected route and honor its decision. See the [host integration example](#host-integration-example).

Operators may set `messages` for `rate_limited`, `missing_required`, `invalid_request`, `timezone_mismatch`, `clock_out_of_range`, `capacity_exceeded` and `storage_error` in their policy JSON; omitted messages use friendly defaults. Message strings are plain text, 1–500 characters, and contain no control characters. Frontends should render them as text, never HTML. A rate-limited response carries HTTP 429, a `message`, `retry_after_seconds` and `Retry-After`; the client obtains the configured missing-required message from the policy endpoint. Message changes do not reset SQLite limits or require a new database.

The private demo also bounds accepted connections in its **single process**: by default at most 32 concurrent handlers, a global burst of 50 connections replenished at 25 per second, and a 15-second absolute socket deadline. Configure these with `--max-connections`, `--connection-burst`, `--connection-rate`, and `--connection-deadline` (see `--help`). Every accepted connection is charged before parsing, irrespective of route or method; only one HTTP request is processed per connection. Overload closes the connection without an HTTP response. The deadline closes the socket even for a slow trickle, but **does not cancel a handler already executing or a stalled dependency**. These limits are not coordinated across processes, cannot bound upstream or kernel queues, and are not a supported deployment boundary. They may reject legitimate traffic during a burst.

**Demo security limitations:** the server has no authentication, TLS, multi-host distributed store, automatic IP geolocation, or production-grade resource protection. It binds to loopback by default; `--host 0.0.0.0` explicitly opts into exposure for the Arena preview. Even with that opt-in, do not expose it publicly or deploy it as a protection boundary. In the preview, the peer IP may be the preview proxy rather than the browser. Forwarding headers are ignored by default. A narrow opt-in single-proxy configuration is documented below; operators must establish and verify their own trusted proxy boundary before any real deployment. By default the in-memory state and random secret reset on restart. An optional SQLite mode is described below; it is still a prototype, not a distributed store. The C core's separate API and policies remain unchanged.

### Signal and policy behavior

Without `--confirm-send-raw`, the client displays the recipient, selected signal names and available names without printing their values. It queries `lsblk` only for selected storage columns. The Python client obtains the service policy from `GET /api/v2/config`, collects selected identifiers without elevation and sends selected identifiers to `POST /api/v2/check` only with `--confirm-send-raw`. The raw values are either placed in the JSON body or, in optional sealed mode, encrypted within the request body. Required signals are always included; `--signals` can restrict conditional signals. If a required value is absent, unreadable or unsupported, the client tells the user what is missing and does not send the request. The server independently enforces required fields. The client refuses non-loopback plaintext HTTP and redirects; remote HTTPS must authenticate the intended service. Never send real identifiers to the public preview or this demo server over an untrusted network: the server itself has no TLS. Protect TLS termination and intermediaries, disable request-body logging everywhere, disclose collection and obtain appropriate consent. Raw machine IDs are confidential; collecting them introduces substantial privacy risk.

The server normalizes and checks formats before using a secret HMAC per device signal and, by default, IP for matching and storage. The operator can instead explicitly retain raw IPs as described below; there is no raw-device-signal storage setting. Machine IDs are 32 hexadecimal characters, installation IDs 64; product and GPU UUIDs use UUID syntax; filesystem UUIDs additionally support common FAT/NTFS formats, partition UUIDs include MBR form, WWNs are 16 or 32 hexadecimal characters, MACs are unicast, and serials use a conservative ASCII subset of 4–128 characters. Common placeholders are rejected. These are limited rules, not a complete vendor specification: legitimate identifiers can be rejected. Normalization trims and lowercases; WWN prefixes are removed. For multiple devices the client chooses the lexicographically first valid normalized value; adding or removing devices may change it. Locally administered/randomized MACs are currently skipped by the collector, though accepted by validation. The optional installation ID is derived from a private per-user random seed file, not hardware identity. Older versions sent the seed itself as the ID; this version derives a different ID, so existing installation matches change. Existing seed files and backups may contain the old ID and require operator/user retention review.

**Format is not authenticity:** an attacker can fabricate plausible values or replay a real one, or rotate all identifiers and IP. Server HMAC protects stored values against casual disclosure, not against a malicious client. HMACs remain linkable sensitive data. Trusted attestation or other independent controls would be necessary for stronger provenance; this prototype does not implement them. The separate C API described above still uses client-side app-scoped HMAC profiles and has not been converted to raw transport.

In the demo, `required` means **must be present** on each request. `conditional` means considered if supplied, without a missing-field error. Each observation is compared with recent individual observations: a match is `related` when at least `min_matches` selected signals, including IP, match the **same prior observation**. With basic preset (`min_matches: 1`), either a machine signal or peer IP suffices, as requested. `new`, `related`, `below_threshold`, and `inconclusive` are evidence labels, not assertions about a person. IP-only matches group unrelated users behind NAT or proxies, causing false positives; do not treat a relation as authentication or proof of the same user. Optional signals can also create relations, as configured.

The HTTP request service charges the resolved peer IP bucket once before expensive work, including for invalid or challenged requests. Only after validation, optional reputation and optional Turnstile verification succeed does it charge each supplied device-signal bucket and record an observation. Default is five requests per 60 seconds. The Python policy optionally sets `ip_max_requests` and `device_max_requests` independently (both otherwise inherit `max_requests`); they share `window_seconds`. This does not change the C core. Denial occurs when **any** bucket exceeds its limit and returns `429` with `retry_after_seconds`. Direct engine callers use the engine API and its original combined charging behavior; integrate via the request service for the HTTP gate flow. The IP bucket intentionally limits unrelated users behind shared networks. Changing an unrelated account name does not change the limit, but a client that changes all observable signals and IP can bypass these prototype checks. Matching thresholds govern the relation label; independent per-signal and IP buckets enforce limits even if the relation threshold is not met. In memory mode, buckets and observations are bounded, process-local and lost on restart. In SQLite mode, they survive restart and can be shared by cooperating processes on one host. Buckets use `window_seconds` (default 60); identity observations use a separate `history_seconds` (default 86,400 seconds). This layer stores pseudonymous signal observations, not accounts, authentication or trial ownership. Bucket-capacity exhaustion fails closed, potentially denying legitimate traffic. Both histories refresh identical snapshots and reject new distinct observations when full rather than evicting unexpired history; charges already applied to buckets remain. In-memory matching uses a bounded inverted index; common tokens can still touch every observation. Both engines remove at most 64 expired windows and 64 expired observations per valid request; incomplete window cleanup denies before charging, while incomplete history cleanup denies after applicable charges and before matching or enrollment. Malformed precharges clean only windows. Backlogs return `capacity_exceeded` with a one-second retry. Optional [experimental idle cleanup](Docs/Guides/Idle-Cleanup.md) can drain expired windows and observations, but is not started automatically; backlogs can deny legitimate traffic until drained. SQLite transaction work and lock waits are not wall-clock bounded.

State expiry and bucket charging sample the clock after acquiring the in-memory lock or SQLite writer transaction; client timestamp/timezone checks use a separate earlier validation time. Both engines currently use wall-clock time, not a rollback-resistant persistent clock: clock jumps, restored or replaced databases, restarts in memory mode, and other operational failures can change or reset quota behavior. This does **not** meet the next release's no-silent-reset requirement. IP precharging is a separate earlier operation and may expire during slow subsequent work.

Timezone checks accept a client IANA timezone and optional Unix-seconds timestamp. The server will not infer a region from an IP without operator-supplied data. `--geo demo/geo.example.json` illustrates an **offline trusted CIDR-to-IANA mapping** using a documentation-only IP range; use a maintained geolocation source and trusted peer IP in a real system. With `timezone_enforce: true`, an offset mismatch beyond `timezone_tolerance_minutes` or a supplied clock outside `max_clock_skew_seconds` returns a challenge. Unknown geolocation/timezone or an omitted clock is reported unknown and is **not** treated as a match or mismatch. The comparison uses the current UTC instant and supports DST; timestamps are compared with a tolerance, not exact seconds. Geolocation is approximate, IP regions can span multiple timezones, and VPN/travel can legitimately cause mismatches. Do not infer exact location or require a user to change their system timezone automatically.

**Legacy data:** the removed experimental trial example may have created `trial_entitlements` and `trial_signals` tables in a database used with that example. Removing code does not erase those tables or backups. A separately [configured retention plan](Docs/Guides/Retention.md) can drop recognized retired trial tables after explicit operator authorization; this destroys all their records, not merely expired records. It is disabled by default and does not guarantee physical erasure.

### GitHub runner survey

The [saved survey](.github/archx-runner/runs/linux-permissions.json) records **availability only** for the GitHub-hosted Ubuntu VM, with the runner's normal user, a separate unprivileged user, and root; no signal values are saved. The exact environment, time and run ID are in the JSON. This is not representative of all Linux hardware, distributions, Flatpak/Snap sandboxes, VMs, or containers. The runner workflow saves test and survey output in the repository, not artifacts. [Runner instructions](.github/archx-runner/README.md).

`./test.sh` includes C AddressSanitizer/UndefinedBehaviorSanitizer checks and deterministic malformed-JSON stress, plus persistence/restart, atomic multi-process and synthetic attack/edge-case tests for matching across account/IP changes, shared IP collision, threshold behavior, missing and malformed fields, duplicate JSON keys, independent IP/device limits, concurrent requests, window expiry, timezone and clock tolerance, and capacity exhaustion. The dashboard's simulation uses only reserved documentation addresses and synthetic values, never real external services.

The deterministic [attack-lab report](reports/attack-lab.json) records both the per-signal limits that worked and the observed full-rotation bypass and shared-IP false positive. It uses synthetic traffic only.

### Optional process-local gate metrics

Hosts using the experimental Python `RequestService` may opt into a `ServiceMetrics` instance and periodically call `snapshot()` from their own trusted management context:

```python
from metrics import ServiceMetrics
from service import RequestService

metrics = ServiceMetrics()
gate = RequestService(engine, metrics=metrics)  # engine is supplied by the host
snapshot = metrics.snapshot()
```

The fixed schema counts broad check decisions and disjoint duration buckets; it stores no peer IP, signals, request body, principal, exception text, or dynamic labels. It is disabled by default, in-memory, process-local, resets on restart and has no HTTP/export endpoint. Measurement is best-effort: an instrumentation failure is discarded and does not change the gate result, so counts may be incomplete. It covers calls to `RequestService.check` only—not parsing errors rejected before that call, challenge/config routes, host authorization, connections rejected before handling, or application operations. The host must still enforce every decision and independently secure any exported aggregates. This is not production monitoring or a complete overload/readiness picture.

### Optional SQLite persistence (single host)

The Python demo can persist rate-limit buckets and pseudonymous signal observations on **one host**, surviving process restarts and coordinating multiple processes through SQLite transactions. Example for a local development terminal:

```sh
mkdir -p -m 700 build/archx-private
# Generate once for this terminal; securely retain the same secret for restarts.
export ARCHX_DEMO_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 demo/server.py --host 127.0.0.1 --port 8000 --db build/archx-private/archx.sqlite
```

`--db` requires an explicitly provided secret of at least 32 bytes; length alone does not guarantee entropy, so generate it randomly. Do not commit the secret or database. Losing/changing the secret prevents reopening the database. All processes sharing it must use the same secret and the same enforcement policy; friendly messages may differ. **Policy, secret, or schema changes fail closed:** a future migration/rotation procedure is needed rather than silently changing existing identities. The raw-v2 format uses schema 3 and cannot reopen older token-mode databases: start a new database or implement a deliberate migration; previous token hashes cannot be transformed into raw-ID hashes. New database files use mode 0600; existing files must be private regular files owned by the service user, and the final path must not be a symlink. The parent directory must be trusted and private, and backups, WAL files and filesystem snapshots need the same protection.

At startup, the demo initializes a database only when it creates the file itself. An already-existing empty or incomplete file is rejected: required core schema definitions and all three metadata values must match exactly, including on-disk SQL text, rather than being silently recreated. Even equivalent manually altered schema is rejected. A failed initial creation may leave an empty file that needs operator investigation; concurrent first starts can cause one startup to fail until initialization finishes. Startup may set WAL mode before rejecting a database. This check does not verify database content, prevent path replacement, or distinguish a deleted database from an intentional new path; a missing path still creates a fresh database. The separate replay table has its own startup marker and schema checks, described below, but does not protect against deletion or rollback of both marker and data. These limitations mean the no-silent-reset release requirement remains unmet.

SQLite transactions serialize bucket updates and observation insertion; duplicate identical observations reuse one history slot. The HTTP service charges IP in an initial transaction and later charges signal buckets and records observations in a separate transaction after external checks. An intervening failure can leave the IP charged; these two stages are not an all-or-nothing transaction. Both buckets and observations have a hard limit of 10,000 entries by default; when full, new work is rejected rather than silently evicting persistent history. Expired observations are ignored and cleaned during subsequent valid requests; an experimental host-started idle worker is optional. SQLite `secure_delete` is enabled, but this does **not** guarantee removal from backups, WAL files, snapshots or storage media. The optional [retention plan](Docs/Guides/Retention.md) offers narrowly scoped logical cleanup, not guaranteed physical erasure. Define and verify independent retention/deletion and recovery before any real deployment. The database contains linkable HMAC values and timestamps; raw device identifiers and account strings are not stored. If raw IP mode is selected, IP addresses are stored too.

SQLite is a single-host development option, not an industry-grade distributed rate limiter. It serializes writes and has no multi-host consistency, backup/restore tooling, key rotation, authenticated users, automatically started retention job, external security review, or production load testing. A synthetic 200-request sequential microbenchmark is recorded in each [runner log](.github/archx-runner/runs/latest.log); its timings depend on the host and are not throughput guarantees. A full policy, security, concurrency and load review is still needed before production use.

### Synthetic in-process gate benchmark

`python3 tools/gate_benchmark.py --mode memory --scenario shared-ip --population 200 --requests 300 --workers 4 --max-outstanding 16` runs a bounded, closed-loop workload against the Python request gate. Options also cover SQLite and unique or repeated snapshots. The JSON reports decision/error counts, p50/p95/p99/max latency and generator queue wait, process CPU time, Linux process-lifetime peak RSS, bounded submitted/uncollected work and a synthetic history-capacity recovery check. See `--help` and the [sanitized example runs](Docs/Test-Results/unreleased/README.md).

This is not a network, HTTPS, proxy, browser, open-loop, multi-process, soak or production capacity test; process CPU includes the generator and its queue is not a server queue. RSS is a lifetime high-water mark. Measurements vary by host; no budgets have been agreed, and this tool does not declare performance or security pass/fail. Real deployment budgets, workloads, contention, resource limits and recovery testing remain release blockers.

### Optional IP reputation, Turnstile and sealed requests (Python demo only)

These controls are **opt-in** and apply to `POST /api/v2/check`, not to arbitrary host application routes. The host must integrate and enforce the returned decisions. They do not turn this HTTP demonstration into production middleware. The C core is separate and does not implement them. Never send real identifiers to the public preview or directly over untrusted HTTP. A browser cannot collect Linux machine IDs; only the native Linux collector is included.

**IP retention:** `"ip_storage": "hash"` (default) or `"raw"` in the policy override chooses whether the normalized resolved client IP is retained as a domain-separated HMAC or as `raw-ip:<address>` in buckets and observations. All device signal values are always HMAC-SHA256 tokens; no option permits raw device-signal persistence in either engine. Identifiers and IPs are still processed transiently in memory, and external systems (e.g. proxies or the OS) may retain them independently. The installation collector retains a private random seed, not the derived ID it sends; system-managed hardware identifiers themselves already exist on the device. Hashed values are linkable personal data, not anonymization. Use a strong, stable secret and protect databases, seeds, backups and WAL. Switching IP modes is a policy change and requires a new SQLite database or a deliberate migration; old databases/backups are not automatically erased. Explicit `hash` is compatible with existing default-hash databases.

**IP intelligence:** [IPsum](https://github.com/stamparm/ipsum) aggregates reported IPs daily, with level N including IPs appearing on at least N source lists. The repository declares the Unlicense; assess upstream source terms, permitted use, quality and your own legal obligations before using it. This is an open-source aggregation, not a Cloudflare feed. Cloudflare's [managed threat lists](https://developers.cloudflare.com/waf/tools/lists/managed-lists/) have their own account/plan restrictions; [Cloudflare's proxy ranges](https://www.cloudflare.com/ips/) are infrastructure addresses, **not** malicious IPs.

```sh
# One-time/manual refresh; creates an atomic local cache. Keep its directory private.
python3 demo/refresh_reputation.py --cache /private/ipsum.json --level 3
# Optional automatic startup + daily refresh; inspect the process/logs and monitor freshness.
python3 demo/server.py --reputation-cache /private/ipsum.json \
  --reputation-refresh-level 3 --reputation-refresh-seconds 86400 \
  --reputation-mode observe --reputation-stale open
```

The GitHub API is fetched over HTTPS with bounded size, no redirects, validation and atomic replacement. API rate limits, network errors and upstream changes can cause refresh failure; the last good cache remains. `updated_at` is the local successful fetch time, **not** a verified upstream publication time. A cache older than `--reputation-max-age` (default 48 hours), malformed or missing is never treated as a fresh negative. `observe` annotates successful checks; `block` rejects fresh listed IPs with a friendly 403. `--reputation-stale open` permits checks to proceed with `stale`/`unavailable` status; `closed` returns 503. Choose based on your availability and false-positive risk. Even fresh listings are not proof of abuse, and shared networks, VPNs and compromised machines can affect innocent users; plan appeals and review. The demo checks the TCP peer by default, so behind a proxy it can see the proxy IP. The optional single-proxy configuration below is safe only when the operator establishes and verifies the stated trust boundary.

**Turnstile:** Configure a Cloudflare [widget](https://developers.cloudflare.com/turnstile/get-started/) and use the site key publicly, keeping the secret only on the backend. This example requires exact expected hostname and action; don't derive them from untrusted requests.

```sh
export ARCHX_TURNSTILE_SECRET='your-secret-key' # use your secret manager in deployment
python3 demo/server.py --turnstile-sitekey YOUR_SITE_KEY \
  --turnstile-hostname YOUR_WIDGET_HOSTNAME --turnstile-action archx_check
```

`GET /api/v2/config` exposes the site key and action only. `/turnstile` is a browser **synthetic-data** widget demo in raw-v2 mode; its hostname must be authorized by Cloudflare and its required policy must be `machine_id` only. On successful widget completion it sends the token with the synthetic request. Real frontends should render Cloudflare's widget and pass a fresh `turnstile_token` in the check body; it must not be logged or retained. The native client can read a token from stdin with `--turnstile-token-stdin` (a separate frontend must obtain it). The backend always calls [Siteverify](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/) over HTTPS, checks success, hostname and action, rejects invalid/expired/already-used tokens with 403, and fails closed with 503 on provider/network failure. It intentionally does not send `remoteip`. IP rate limits and reputation apply before Siteverify, so a denied request may not consume its token; get a fresh token after each check. A failed verification does not charge device buckets or record an observation; a malicious client that passes Turnstile can still submit forged victim signals and poison them. The Cloudflare dummy Siteverify keys may omit action; strict action validation intentionally rejects those dummy responses. Tests use a mocked provider; this demo has not been verified with a live Cloudflare account. Cloudflare receives widget telemetry per its terms/privacy policy.

**Application-layer encryption:** install the optional maintained libsodium binding in a virtual environment and generate an X25519 sealed-box keypair:

```sh
python3 -m venv .venv
.venv/bin/pip install -r demo/requirements-secure.txt
.venv/bin/python demo/create_sealed_keys.py --private /private/archx.key --public /private/archx.pub
.venv/bin/python demo/server.py --sealed-private-key /private/archx.key
# Deliver/pin archx.pub independently to the client, then (after consent):
.venv/bin/python demo/client.py --url https://YOUR-SERVICE/api/v2/check \
  --server-public-key /trusted/archx.pub --confirm-send-raw
```

The private key must be a service-owned mode-0600 regular file in a trusted directory, kept out of source control; key files are never overwritten. Encrypted mode requires `sealed-v2` envelopes and rejects plaintext and the older `sealed-v1` framing. The native client refuses a downgrade when a public key is configured. It requests a short-lived nonce, places it inside the sealed payload together with raw selected signals, timestamp/timezone and any Turnstile token, then sends the envelope. The backend decrypts and validates, then hashes device signals before storing. TLS remains mandatory except local loopback; the demo itself does not terminate TLS.

A successful `GET /api/v2/challenge` creates a random 256-bit challenge valid for 120 seconds and bound to the resolved peer IP. It is consumed atomically before signal processing and can be used once, even when a request subsequently fails; get a fresh challenge for each retry. Challenge state stores keyed hashes, is capped at 10,000 outstanding challenges and five per peer, and fails closed with 503 on capacity or storage failure. Shared IPs may therefore encounter contention. Memory mode coordinates only one process and loses challenges at restart; SQLite mode coordinates processes sharing the same single-host database and persists outstanding challenges. On SQLite replay startup, a marker is created transactionally with the challenge table. Existing pre-marker challenge tables are adopted only if their stored schema matches exactly, without clearing challenges. Once the marker exists, missing or changed replay tables or indexes fail startup rather than being recreated. An absent marker *and* absent table is indistinguishable from first-time enablement, including legacy data loss or simultaneous deletion of both. This check runs at initialization, not on every request; it is not database integrity, tamper, deletion, downgrade or rollback protection. Issue and consume sample expiry time after acquiring their serialization lock or SQLite writer transaction; they still use wall-clock time. A backward clock adjustment or restoring an older database can extend or revive challenges, so replay expiry is not rollback-resistant. Never run separate in-memory workers, different databases, or mixed plaintext/encrypted configurations behind one endpoint if relying on replay checks; use synchronized clocks and consistent configuration. This is not a distributed replay store, business-operation idempotency or sender authentication.

The nonce protects against a **second** accepted use of the same sealed request, not a first-use race: an interceptor who can resend the ciphertext from the same resolved IP may arrive first. Anyone with the public key can create new ciphertexts containing fabricated signals and new challenges. Sealed boxes do not authenticate a sender or prove device identity. Only someone with the server private key should be able to decrypt an intact ciphertext **if** the public key and client code are independently authenticated and the keys stay secret. A TLS terminator that can replace delivered code, configuration or public key can defeat this protection. It does not conceal IPs, request timing, size, paths, responses or other HTTP metadata. The separate `/turnstile` test page uses raw mode; `/browser-test` and the optional browser client below support sealed mode, including an optional Turnstile token. Other frontends must implement `sealed-v2` with a compatible audited library and independently trusted key. No independent security audit or key-rotation mechanism is provided.

Friendly messages for these controls can be overridden via `messages.reputation_blocked`, `reputation_unavailable`, `turnstile_invalid`, `turnstile_unavailable`, `replay_rejected` and `replay_unavailable` in policy JSON. The optional dependency can be tested with `.venv/bin/python tests/test_security.py`; the standard suite skips the encryption-specific test if PyNaCl is not installed.

For interoperability, `sealed-v2` POST bodies are JSON objects with exactly `version` set to `sealed-v2` and `ciphertext` set to standard padded Base64 of `crypto_box_seal` output. First obtain `nonce` from `GET /api/v2/challenge` using the same resolved client IP. The sealed plaintext is ASCII `archx-sealed-check-v2` followed by one zero byte, then UTF-8 JSON containing `nonce`, the usual check fields and optional `turnstile_token`. The server accepts at most 8192 bytes for the entire HTTP body; it rejects duplicate JSON keys and non-finite JSON numbers. Public and private key files contain 32 bytes encoded as 64 hexadecimal characters. The envelope does not authenticate the sender.

### Optional encrypted browser client

`demo/browser/client.js` implements the same `sealed-v2` protocol for **caller-provided** signals. It collects and persists no identifiers and never reads a server public key from the network. It requires a public key supplied by the application from an independently trusted source, rejects raw-mode downgrade, obtains a single-use challenge and seals the signals and optional Turnstile token. Requests use same-origin URLs, omit credentials, reject redirects, and require HTTPS except local loopback. A cross-origin frontend must supply its own reviewed same-origin proxy or integration; the prototype does not configure CORS or authentication.

```sh
# Node 18+; packages are locked in demo/browser/package-lock.json.
npm ci --prefix demo/browser
npm run build --prefix demo/browser
# Start the Python server in sealed mode as shown above, then open /browser-test.
```

The generated `build/browser/archx-client.mjs` is not committed; the demo server serves it at `/browser-client.mjs` only after the build. `/browser-test` uses a fixed **synthetic** machine ID and asks for the trusted public key; if Turnstile is configured, it displays that widget before sending the sealed token. This is an interoperability demonstration, not a real browser hardware collector. The page's policy must not require signals other than `machine_id` for this sample. The native Linux client remains separate.

For an application integration, import `checkEncrypted` from the generated module, then call it with `{publicKey: trustedHex, signals: applicationSuppliedSignals, turnstileToken: optionalToken}`. It returns `{status, data}`; handle errors and denial results. The server must evaluate and enforce the gate **on the protected request itself**, not treat a previous standalone `allow` as authentication or a reusable access token. Applications must obtain lawful consent, choose only applicable supported signal types and manage their own collection; a browser cannot directly read Linux machine IDs. The default basic policy requires one, so it is not suitable for an ordinary browser without a policy/collector appropriate to that environment.

This additional encryption cannot protect data from a malicious or compromised script running on the same page, including third-party widget scripts that can access or alter page execution. Nor can it protect against an intermediary that replaces the delivered JavaScript or pinned key. Independently trust and protect **all client code, dependencies and key distribution**, use HTTPS, and minimize or isolate third-party scripts. The SDK is unaudited prototype code; no device identity or sender authenticity is guaranteed. The synthetic browser test mocks Turnstile and does not constitute live Cloudflare validation.

### Optional trusted proxy boundary

By default, all forwarding headers are ignored. For a **single operator-controlled proxy** directly in front of the demo, `--trusted-proxy 192.0.2.10/32` (repeatable for explicitly controlled proxy CIDRs) enables one strictly checked `X-Forwarded-For` header. The proxy must discard any client-supplied value and **overwrite** it with exactly one validated client IP; chains, duplicate headers, missing headers and malformed addresses from trusted peers are rejected. Headers from all other peers are ignored. `/0` ranges are rejected, but any overly broad or attacker-controlled configured range remains unsafe. Restrict the backend's network access to the intended proxy, authenticate and configure the proxy separately, verify the correct IP with tests, and do not treat Cloudflare's public proxy ranges alone as proof that traffic passed through your zone. This is not general multi-proxy or CDN support. Incorrect trust can let attackers impersonate IPs or evade limits. See [MDN's X-Forwarded-For security guidance](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For).

### Host integration example

`demo/service.py` exposes `RequestService.check(envelope, peer)` and `status_for(result)`: the host must supply a trustworthy resolved peer, perform strict bounded JSON parsing, and run its protected action **only** for `decision == "allow"`. For sealed mode it must also expose `config()` and `challenge(peer)` using the same peer resolution and shared replay store. Do not allow clients to supply the peer argument or reuse a returned allow decision as authentication. The example below demonstrates enforcement on the same request, not an endorsement of WSGI's development server for production:

```sh
python3 examples/python/gated_wsgi.py
# In another terminal; this is a synthetic identifier, not a real machine ID.
curl -sS -X POST http://127.0.0.1:8081/protected -H 'Content-Type: application/json' \
  -d '{"signals":{"machine_id":"123456789abcdef0123456789abcdef0"}}'
```

The default example has **no authentication or authorization** and protects only a synthetic operation. For hosts that already authenticate and authorize, `create_application` accepts **both** `resolve_principal(environ)` and `authorize(principal, operation)` callbacks. The former must obtain the principal exclusively from a trusted server-side authentication context; never promote client headers or submitted signals to that context. The latter must return the boolean `True` to authorize the host-configured `operation` (default `synthetic.read`); this value is fixed when the application is constructed and must not be taken from client input. Missing principals, explicit denial, exceptions or non-boolean results do not invoke the action. Authentication and business authorization remain host responsibilities, and an authorized attacker can still poison forged signal buckets. Authorization failures occur before the request gate, so the host must apply its own bounded admission to **all** routes and failed authentication attempts. These hooks are illustrative, not a reviewed production integration.

The example is loopback-only, does not add TLS, and suppresses its default access log. Integrators must arrange TLS, enforce request-size/timeout rules, prevent sensitive logging, make a reliable trusted-proxy decision, configure consistent keys/policies and actually enforce the result on every protected route. `RequestService` is still prototype code and does not turn identification into authentication. The sample's `/protected` route is not the native client's `/api/v2/check` URL.
