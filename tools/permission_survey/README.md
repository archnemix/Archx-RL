# Linux permission survey

Purpose: collect and combine sanitized signal-availability results for the disposable GitHub Linux runner without saving identifier values.


## Windows and macOS native surveys

The read-only experimental-platform workflow runs these on **push**, not pull
requests, on three disposable GitHub-hosted runners. It prints only a strict,
validated JSON allowlist: architecture, numeric OS version, token elevation or
root status, API outcome, and property/signal categories. No identifier values,
lengths, hashes, registry paths, usernames, hardware paths, or raw firmware are
printed or uploaded. Invalid output is rejected without echoing it. Temporary
output contains only intended categories and is removed after validation; the
validator is defense in depth, not a sandbox against malicious code or host.

Windows queries firmware in process through the existing bounded RSMB parser;
raw table and parsed identifiers are transient sensitive data, never logged or
saved. Its statuses reflect parser validity/placeholder checks. The MachineGuid
query reads only value type metadata, not contents, and does not establish the
value is usable. Elevation is not the same as proving a standard-user account.

macOS transiently copies two public IOKit properties solely to check CF type;
no content is read, parsed or saved. IOKit returns null for multiple failure
causes, so absent and denied cannot be distinguished. Type metadata does not
show whether a value is meaningful. An accessible property is not permission to
fingerprint: Apple policy/distribution review remains a release blocker.

These narrowly scoped samples do not cover all signals. Hosted virtual runners
are not Windows 11 client systems, physical devices, sandboxed/notarized or App
Store distributions, or evidence for arbitrary privilege levels. API success
never establishes stability, uniqueness, consent, authorization, or suitability.
See the platform research documents for open policy and native-support work.
