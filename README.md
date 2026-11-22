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
