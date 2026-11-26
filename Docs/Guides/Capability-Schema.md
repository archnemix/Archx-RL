# Versioned capability metadata

`archx.capabilities` version 1 is **metadata**, not a signal value, identity, credential, attestation or promise that a signal is stable or truthful. It distinguishes firmware, OS-installation, application-installation and network evidence. It deliberately contains no raw value or pseudonym. Browser and native collection differ; neither profile should be used as a cross-platform identity claim.

The Linux C core exposes the optional `ax_collect_capabilities` ABI-v1 extension. Older ABI-v1 libraries may lack this symbol; feature-detect it rather than assuming the ABI number alone guarantees it. Returned JSON uses `ax_buffer_free`, and existing `ax_collect` remains unchanged. Repository Python/Node bindings expose `core.capabilities()` and report an explicit error when an older library lacks the extension. The browser client exports `capabilities()` without accessing device data, storage or the network; it returns fresh metadata on each call. The API only describes the implemented Linux collector and browser client: Windows/macOS primitives are not supported full collectors.

The shared object has `schema: "archx.capabilities"`, integer `version: 1`, `platform`, and a `signals` object. Each entry contains only `kind` and `status`:

| Entry | Kind | Linux | Browser |
| --- | --- | --- | --- |
| `machine_id` | `os_install` | `/etc/machine-id`, fallback `/var/lib/dbus/machine-id` | `unsupported` |
| `product_uuid`, `board_serial` | `firmware` | Linux sysfs DMI sources | `unsupported` |
| `app_install` | `app_install` | `not_collected` by this call | `not_collected` |
| `ip` | `network` | `host_provided` | `host_provided` |

`available` means a syntactically accepted value was read at that instant, not that it is authentic. `absent` means a file was absent or empty; an absent file does not prove the platform could never provide that data. `denied` means opening the source reported an access/permission denial; `read_error` means another open/read/close failure. `placeholder` means a recognized placeholder was read, and `invalid` means an incomplete, malformed or unsupported value format was rejected. `unknown` means no usable status was supplied. For the two machine-id sources, the fallback is tried even if the first is denied, invalid or a placeholder; if both fail, precedence is `read_error`, `denied`, `invalid`, `placeholder`, `absent`. This summarizes only one status and does not claim that every source failed the same way. The existing identification behavior is unchanged: a successful fallback supplies the signal and unavailable inputs are excluded.

`unsupported` describes a capability the browser client cannot collect, not a failed attempt to discover hardware. `not_collected` says this API did not inspect or create an app-installation fallback; `ax_identify` may separately create one when no native signals are usable. `host_provided` says the network address must come from a trusted host transport boundary, not that a client IP was observed, validated or supplied by the browser. A host may choose not to provide one. Mere schema availability does not authorize collection or imply permission, consent, user uniqueness, authentication, cross-device matching or secure storage. Treat status metadata and even absence/permission patterns as potentially sensitive.

Synthetic C fixtures inject unavailable, permission-denied, placeholder, malformed and read/close failures, including fallback. `tests/test_coverage.c` verifies version, categories, status serialization and absence of synthetic raw values; `tests/test_output_faults.c` injects allocation and formatting failures. The browser Node and headless-Chromium tests exercise the browser schema without collecting identifiers. Binding tests verify symbol detection and that returned entries contain no values. These tests do not establish real-hardware availability, all platform error behavior or production privacy compliance.
