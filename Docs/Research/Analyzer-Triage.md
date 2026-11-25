# GCC analyzer warning triage

## Scope and reproduction

On 2026-11-22, local Linux x86-64, GCC `12.2.0` (Debian 12.2.0-14+deb12u1), source at `84fc39f` with only new test changes: compile each unit separately, without suppression. The original warning messages/compiler version for the reported `archx.c:263` and `sha256.c:31` were not included in the issue; line numbers refer to the then-current file and can shift. Results below are not an independent audit or a proof of absence of bugs.

```sh
gcc -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -fanalyzer -O0 -Iinclude -Isrc -c src/archx.c -o build/archx-analysis.o
gcc -std=c11 -Wall -Wextra -Wpedantic -fanalyzer -O0 -Isrc -c src/sha256.c -o build/sha-analysis.o
# Repeat with -O2 and with -Wanalyzer-too-complex to identify analysis cutoffs.
```

At `-O0`, GCC emitted no warnings for `archx.c`; at `-O2` neither unit emitted warnings. With `-O0 -Wanalyzer-too-complex`, `archx.c` emitted 21 complexity warnings and `sha256.c` emitted 14 warnings including seven reported uninitialized schedule uses. This means the absence of a warning is not evidence of exhaustive analysis. GCC explicitly describes [`-fanalyzer` as neither sound nor complete](https://gcc.gnu.org/onlinedocs/gcc-13.4.0/gcc.pdf) and documents analysis-complexity limits. No warning was suppressed or globally disabled.

## SHA-256 schedule

At `-O0`, seven `-Wanalyzer-use-of-uninitialized-value` reports occur at `src/sha256.c:31`, referring to unknown elements of `w`. The first loop writes `w[0..15]`. For each ascending `i` from 16 to 63, every operand index `i-2`, `i-7`, `i-15` and `i-16` is nonnegative and strictly smaller than `i`; by induction each was initialized before read. The schedule is consistent with [RFC 6234 section 6.2](https://www.rfc-editor.org/rfc/rfc6234.html). This supports a **likely false positive for these specific reports**, contingent on a valid input block and context; it does not validate all input contracts, the entire algorithm, secure erasure or cryptographic suitability. A simplified schedule-only compilation did not reproduce the diagnostic, so it is not a minimized warning reproducer; the complete `src/sha256.c` command above reproduces it locally.

Existing FIPS/RFC known-answer vectors pass. `tests/test_crypto_differential.py` additionally compares 469 deterministic synthetic binary messages, randomized streaming partitions and HMAC keys at boundary lengths against Python's `hashlib`/`hmac` (the local Python SSL reports OpenSSL 3.0.20). This gives useful differential coverage but is neither exhaustive nor independent cryptographic certification. Full sanitized regression including these tests is `Docs/Test-Results/unreleased/analyzer-full-test.log`.

## JSON emission

The `archx.c:263` report is **unresolved, not reproduced** with this GCC and the supplied flags; its original warning and source revision are needed to classify it. Current line 263 copies the NUL-terminated source into `malloc(strlen(source)+1)` and transfers the allocation to the caller. The helper accepts `stack_len` but does not use it to bound `strlen`; its safety depends on every caller providing a terminated buffer. Some JSON-append return values are ignored; silent truncation/serialization error propagation should be independently reviewed under B05 and is not ruled out by the analyzer result. This review does not assert that a vulnerability exists or that all paths are safe. Fault-injection and boundary coverage remain release work.
