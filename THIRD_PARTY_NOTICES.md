# Third-party dependencies and notices

Archx's own code is licensed under [0BSD](LICENSE). Third-party software, tools, downloads and data retain their own licenses and terms; 0BSD does not relicense them. This inventory is a starting point, **not a complete SBOM, legal opinion or permission to redistribute a particular package**. Distributors must inventory the exact resolved versions, platform-specific optional packages, nested/native libraries and their licenses and notices, and include the notices required by those packages.

Known directly declared dependencies in the current source tree include:

| Component | Use and declared version | License information |
| --- | --- | --- |
| `koffi` | Node native binding, 2.16.4 | MIT; see `bindings/node/package-lock.json` and the installed package. |
| `libsodium-wrappers` and `libsodium` | Browser sealed client, 0.8.4 | ISC as recorded in `demo/browser/package-lock.json`; verify the installed distribution and bundled components. |
| `esbuild` | Browser build tool, 0.28.2; includes platform-specific optional packages | MIT as recorded in the browser lockfile; check the actual installed package and binary. |
| `playwright` and `playwright-core` | Browser tests, 1.65.1 | Apache-2.0 as recorded in the browser lockfile; downloaded browser binaries have their own terms. |
| PyNaCl | Optional Python sealed transport, 1.6.2 | Apache-2.0 in installed package metadata; dependencies and any bundled libsodium have separate notices. |
| Waitress | Experimental Unix WSGI proxy test, 3.0.2 | ZPL 2.1 in installed package metadata. |

`demo/requirements-secure.txt` and `tests/requirements-proxy.txt` pin direct Python requirements but do **not** pin or hash every transitive package. `npm ci` uses the respective package lock with integrity hashes, but exact platform-specific installed packages vary. The Linux C build uses the host C library, compiler, linker and system libraries; they are not bundled by the build script. External feeds, hosted services, CI actions, OS packages and downloaded browsers have independent terms and are not covered by this table. Review all licenses, dependencies, provenance and security before distributing any artifact.
