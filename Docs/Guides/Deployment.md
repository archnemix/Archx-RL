# Deployment status and boundaries

**No supported production deployment profile is established yet.** The demo HTTP server and WSGI development example default to loopback and must remain private; exposing them directly or publishing their synthetic/test routes is not a production deployment. A host must apply its own admission control to every route, including authentication failures, and enforce decisions before the protected operation.

Before any supported single-host release, establish a bounded entrypoint, request/body/connection limits, timeouts, trusted authentication and authorization, TLS and a verified proxy trust boundary. Validate real overload and recovery, persistence/backup/restore, secret rotation, retention/deletion, privacy and policy requirements, and operational monitoring. The demo's connection and worker limits apply only to one process; socket deadlines cannot cancel stalled application code, and upstream or multiple processes are not globally bounded.

A [real HTTPS proxy experiment](../Research/HTTPS-Proxy-Experiment.md) confirms forwarding-header overwrites in a test topology but also demonstrates that the loopback demo origin can be impersonated by local processes. A second [Unix-socket WSGI experiment](../Research/Unix-HTTPS-Experiment.md) verifies other-UID socket denial but demonstrates that the service UID can bypass the proxy. Neither is a deployment configuration.

[`Next-Version.md`](../Plan/Next-Version.md) lists the open release gates and evidence. [README integration instructions](../../README.md#host-integration-example) illustrate the boundary without endorsing the development server. Multi-host quota and replay enforcement is a separate later milestone, not part of the current implementation.
