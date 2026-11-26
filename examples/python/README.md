# Python C API examples

Purpose: demonstrate the C library and profile matching via Python, and a separate synthetic WSGI host integration of the Python request gate. Build the C library first; see the root README. The WSGI example can receive host-owned principal and operation-authorization hooks, but its default standalone run is unauthenticated and only for synthetic local demonstrations.
 The host may supply a trusted, fixed operation identifier at construction; submitted headers and signal values never select that operation. This example does not provide authentication or a production entrypoint.

## Experimental outer admission wrapper

`boundary_wsgi.BoundaryGate` is an optional, process-local WSGI wrapper. Configure finite `max_inflight`, `requests_per_second`, and `burst`; wrap the whole host application so GET, challenge, protected and invalid routes share the limit. It denies excess calls with 503 and a one-second retry; the permit stays held until the response iterable finishes or closes. `stop_accepting()` permanently denies new calls, `is_ready()` reports an instantaneous local admission state, and `wait_drained(timeout)` reports whether existing calls finished. In-flight application code is not canceled.

This wrapper alone does **not** provide a supported production entrypoint: a real server/proxy must separately bound sockets, worker and kernel queues, header/body sizes, deadlines and slow clients; no multi-process coordination, TLS, authenticated principal or distributed quota is provided. In particular, a WSGI server that never closes an abandoned response may retain a permit. Do not expose the example server publicly. See `Docs/Guides/Deployment.md` for remaining gates.

## Optional recovery experiment

`gated_wsgi.create_application` leaves `/recovery` disabled unless the host supplies all principal, authorization, approval and audit hooks. See [Shared-IP Recovery](../../Docs/Guides/Shared-IP-Recovery.md) before considering the shared IP-window reset. The example is not a production identity, CSRF, audit or abuse-control system.

Optional startup/dependency checks and admitted liveness/readiness routes are described in [Health and draining](../../Docs/Guides/Health-Drain.md). They cannot cancel stuck work or bound network-server queues.
