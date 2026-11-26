# Real HTTPS proxy experiment: private demo only

This is **research, not a supported or secure deployment profile**. It advances #25 but does not satisfy its restricted-origin or supported-topology acceptance. In particular the test demonstrates a direct-origin impersonation vulnerability for local processes. Do not expose the demo or copy the test configuration into a deployment.

## Reproduce

On Linux, install nginx and OpenSSL from a source you trust and install the repository's Python test dependencies. Run as an ordinary user with nginx TLS support:

```sh
ARCHX_TEST_NGINX="$(command -v nginx)" python3 tests/test_https_proxy.py
```

The Linux CI workflow installs the distribution nginx package and runs this test explicitly. A missing or non-executable configured binary or absent OpenSSL fails the test. The test creates a temporary self-signed certificate for `localhost`, starts one nginx worker bound to IPv4 loopback and the private bounded demo origin on a different ephemeral loopback port, and cleans them up. Client TLS verifies the temporary certificate and hostname. A separate check confirms that the certificate is rejected without explicit trust. Each request uses synthetic signals; client addresses are loopback aliases, not Internet clients. CI logs identify the nginx version. The local preliminary run used nginx 1.31.3 via the third-party `nginx-wheel` binary with OpenSSL 3.3.7; this experimental tool is not a project or production dependency and is not endorsed as a trusted distribution channel.

The test nginx overwrites `X-Forwarded-For` with its actual TCP peer and removes several other forwarding headers. The origin trusts `127.0.0.1/32` as its proxy and uses only `X-Forwarded-For` for peer resolution. The test establishes a one-request quota for each of four distinct simulated clients, then sends a forged single value, duplicate fields, a comma-separated chain, or `Forwarded`/`X-Real-IP`. All four are charged to their actual peer and return 429; another peer is accepted. This configuration **overwrites or ignores** forged forwarding input rather than necessarily rejecting the HTTP request. A direct connection from a loopback alias outside the configured trust range also cannot spoof the quota.

## Critical finding and limits

A process connecting directly from `127.0.0.1` is indistinguishable from the proxy to the demo origin and can choose arbitrary `X-Forwarded-For` values. The negative test demonstrates two different forged peers are both accepted. Loopback binding does not restrict access by untrusted local processes; a firewall or namespace arrangement must be evaluated for the actual deployment, and simply assuming an origin is private is insufficient. This test does not establish an authenticated proxy-to-origin boundary, a Unix-socket implementation, remote isolation, certificate provisioning or rotation, intermediary behavior, IPv6 coverage, full ingress-header sanitization, load resilience, HTTP request-smuggling resistance, a supported WSGI server, or application authentication and authorization. Its temporary test certificate is not for production.

A future supported topology must provide and test origin isolation against the stated local and remote threat model, ensure every ingress path enforces the same trust contract, and use the supported bounded host entrypoint. It must include TLS and overload tests against that actual entrypoint, not this private demo. Accordingly #19, #25 and #29 remain open; the broader deployment caveats remain in [Deployment status](../Guides/Deployment.md).
