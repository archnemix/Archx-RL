# Release and support policy

Archx is an **unreleased, unaudited prototype**. The project makes no production-support, security-response-time or compatibility commitment. Windows/macOS product builds and a production deployment profile are not established. Do not treat this checklist or the `0.0.0` packaging placeholders as evidence of a release. The maintainer decides whether to publish a release only after reviewing the open [release gates](../Plan/Next-Version.md), including security reporting, privacy, native platform evidence and staging. [SECURITY.md](../../SECURITY.md) describes the enabled private-reporting setting and the untested end-to-end reporting and notification flow. No support SLA or supported-version schedule is promised.

Project-owned code is [0BSD](../../LICENSE), intentionally selected by the owner. That permission does not change the terms of third-party components. See [third-party notices](../../THIRD_PARTY_NOTICES.md) and [contribution guidance](../../CONTRIBUTING.md).

## Reproduce the current Linux C build

This is a **same-host, same-toolchain comparison**, not a claim that builds are bit-reproducible across operating systems, compiler versions, architectures, filesystems or environments. It covers the Linux `build.sh` shared/static libraries and probe only, not CMake installs, Python/Node distributions, browser bundles, TLS dependencies or native Windows/macOS artifacts. It uses two independent extractions of the same `git archive`; it builds the selected commit, not uncommitted working-tree edits. The archive includes tracked files only and must not be confused with the hosted GitHub source archive. The source SHA-256 is for that exact uncompressed archive with the `archx/` prefix, not for a Git commit identifier or a separately downloaded tarball.

On Linux with Git, a C11 compiler, GNU-style `ar`, `ld`, `tar`, `cmp` and `sha256sum`, from a checkout containing the commit:

```sh
git rev-parse HEAD                    # select and record the source commit
sh tools/reproduce_linux.sh HEAD       # or pass an explicit commit ID
```

The script fixes locale, timezone and umask, records commit and tool versions, hashes the source archive, builds twice in distinct temporary directories, compares all three binaries byte-for-byte and prints their SHA-256 hashes. It cleans its temporary files and exits nonzero on a failed build or mismatch. The build uses the exact options in `build.sh`; its host C library, compiler, binutils and filesystem remain inputs. Select a compiler with `CC=/absolute/path/to/compiler`. Record the OS/architecture, compiler, linker, archiver, Git, libc and environment in any evidence; for independent verification provide a genuinely pinned build environment and retain the built artifact, source archive and hashes. Never include private device data or secrets in evidence.

A [same-host example with source and artifact hashes](../Test-Results/unreleased/linux-reproducibility-2862151.md) records one actual Linux run; it is not a published release.

Browser and Node dependencies use committed lockfiles and `npm ci`; the browser bundler includes third-party code. Optional Python requirements pin direct packages but not all transitive dependencies or hashes, so they are not fully reproducible or supply-chain locked. A release must capture a resolved dependency inventory and all applicable notices for each artifact, not merely the direct lists. Artifact hashes confirm bytes only if the manifest is obtained from a trusted source; this procedure does not sign releases or establish provenance.

## Pre-release checklist

1. Confirm the owner approves a version, support scope and policy; ensure a verified private security-reporting channel and response process exist. Review all open gates rather than relying on issue closure alone.
2. Review contribution rights, source license and each exact direct/transitive dependency and bundled binary; generate and retain a dependency inventory and required notices for each platform/artifact.
3. Start from a reviewed, immutable source commit. Record its ID, an exact source archive and SHA-256, build environment and instructions. Build intended artifacts, independently compare where reproducibility is claimed, and publish SHA-256 hashes for each exact artifact alongside source hashes. Sign and distribute them through a trusted channel if a release policy requires it.
4. Run and link relevant Linux, Windows/macOS native, binding, browser, TLS/proxy, fuzz, fault, privacy, load and credentialed staging results for the advertised scope. Do not publish secrets or raw signals. Do not advertise untested platforms or claim budgets, review, provider results or reproducibility that have not been demonstrated.
5. Document version compatibility, migration, key rotation, backup/restore, deployment prerequisites, known risks, support and rollback. Verify installation and artifact loading on each advertised target. Obtain maintainer review and approval before publication.
