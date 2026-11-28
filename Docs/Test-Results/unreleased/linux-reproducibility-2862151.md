# Same-host Linux rebuild evidence for commit 2862151

Two independent `git archive` extractions of commit `28621518091c7933bf0c49390adc78e3b871b0e4` were built using `sh tools/reproduce_linux.sh 2862151`; all three resulting binaries matched byte-for-byte. This is synthetic pre-release evidence, not a published release, cross-machine reproducibility claim, or artifact signature. Source SHA-256 applies to the uncompressed `git archive` tar with prefix `archx/`; GitHub's archive may differ.

- Platform: Linux x86-64
- Compiler: Debian GCC 12.2.0-14+deb12u1
- Linker and archiver: Debian GNU binutils 2.40
- Git: 2.39.5
- Host libc: Debian glibc 2.36-9+deb12u14
- Source archive SHA-256: `efd867d15de6bb816b898d44c5fbd956bb97458dece32ffb82fb51739c40e287`
- `libarchx.so` SHA-256: `97d347f36135d3157705040644a0586474d8514721e8a5961dbbc465d8b82193`
- `libarchx.a` SHA-256: `03aa3cd45c859c67ec7b0d2b32ffae8fc690eb2032307099cadffff5a2f08f83`
- `archx-probe` SHA-256: `e38270eecfa8d849b48fde044d3aad5c3b6620d9974ee4c0f8560fceed67f379`

Flags and source lists are defined by that commit's `build.sh`. A different source, compiler, libraries or environment can change artifacts. Neither compiled artifacts nor the tar are retained here; regenerate them for independent comparison. See the [reproduction procedure and release checklist](../../Guides/Release.md) and [dependency notices](../../../THIRD_PARTY_NOTICES.md).
