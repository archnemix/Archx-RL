# Python request-policy prototype

[`demo/service.py`](../../demo/service.py) and its memory/SQLite engines are **not** the C token-bucket API. They evaluate caller-supplied signals and a peer supplied by the host; they do not authenticate an account or prove a device. See the [engine contract](../Plan/Engine-Contract.md) for charging, retries, duplicate snapshots and intentional backend differences.

The memory engine is process-local and restarts clear its state. SQLite can preserve single-host state for cooperating processes but does not protect against rollback, deletion, data tampering or multiple hosts. Both can deny legitimate users on shared networks or under capacity pressure; forged signals can poison another user's bucket. Operators need independent authentication, authorization and recovery procedures.

The [synthetic WSGI example](../../examples/python/gated_wsgi.py) demonstrates enforcing the gate on the protected request and supports host-owned principal/operation hooks. It is not a reviewed production integration. See the [README host example](../../README.md#host-integration-example) and [deployment status](Deployment.md) for constraints.
