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

The `archx.c:263` report is **unresolved, not reproduced** with this GCC and the supplied flags; its original warning and source revision are needed to classify it. Current line 263 copies the NUL-terminated source into `malloc(strlen(source)+1)` and transfers the allocation to the caller. At triage time, the helper accepted `stack_len` but did not use it to bound `strlen`, and some JSON-append return values were ignored. A follow-up now bounds the terminator search, checks JSON append and formatted-output failures in these public output paths, and returns an error instead of publishing truncated output. Synthetic tests exercise unterminated buffers, exact-size/overflow boundaries and output-allocation failures; they do not force every public formatting-failure branch. Other error paths remain under B05. This review does not assert that a vulnerability exists or that all paths are safe. Fault-injection and boundary coverage remain release work.

## Follow-up: explicit schedule initialization

On 2026-11-22, the same local GCC 12.2.0 was run at `-O0` and `-O2` after explicitly zero-initializing the 64-word schedule. The first 16 words and then every later word are still assigned as before; this adds defensive initialization rather than suppressing diagnostics. At `-O0`, the original source emitted seven uninitialized-value diagnostics and the zero-initialized source emitted none; at `-O2`, current SHA and core units emitted no warnings. With `-Wanalyzer-too-complex`, the current SHA unit still reported 11 analysis-complexity warnings, and the core unit reported 13; the absence of an uninitialized warning does not make the analyzer exhaustive. These counts are compiler/configuration-specific, not proof of security.

The FIPS/RFC known-answer vectors and 469-case deterministic Python differential test passed after the change. The [local full browser/sanitizer regression](../Test-Results/unreleased/analyzer-zero-init-full-test.log) also passed. `tests/test_gcc_analyzer.sh` now compiles the current core and SHA units at `-O0` and `-O2`, making uninitialized-value analyzer reports errors without suppressing other warnings. Linux CI runs it. Analyzer versions may differ and complexity cutoffs remain.

## Minimized historical output-contract reproduction

`tests/fixtures/legacy_emit_repro.c` isolates the original helper's unbounded `strlen` followed by allocation and copying. A three-byte input without a terminator, compiled with GCC 12.2.0 and AddressSanitizer, reports a stack-buffer-overflow read in `strlen`:

```sh
gcc -std=c11 -O0 -g -fsanitize=address -fno-omit-frame-pointer \
    tests/fixtures/legacy_emit_repro.c -o /tmp/archx-legacy-emit
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 /tmp/archx-legacy-emit
# Expected: sanitizer reports stack-buffer-overflow and exits nonzero.
```

This is a **conditional helper-contract defect**: the reproduction does not establish that a public API path could supply this input, and it does not reproduce or identify the unspecified historical GCC warning. The current helper instead searches for the terminator within the provided length and fails closed if none exists. `tests/test_output_faults.c` passes that same three-byte case to the actual current helper, exercises exact boundaries, allocation and formatting failures, and runs under ASan/UBSan as part of `test.sh`.

The historical `archx.c:263` GCC warning itself remains unclassified because its original source revision, compiler and diagnostic were not provided; current runs do not reproduce it. If the original diagnostic is later recovered, it needs separate comparison with this work. No broad suppression was added, and neither analyzer silence nor this conditional reproduction is proof of the absence or presence of a remotely reachable vulnerability.
