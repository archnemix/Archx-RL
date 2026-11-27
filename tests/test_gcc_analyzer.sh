#!/bin/sh
# Focused regression for the diagnosed SHA schedule and bounded output code.
# Analyzer silence is not a proof of memory safety; no diagnostics suppressed.
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cc=${CC:-gcc}
"$cc" --version | head -n 1
for opt in 0 2; do
  "$cc" -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE \
    -Wall -Wextra -Wpedantic -fanalyzer -Werror=analyzer-use-of-uninitialized-value \
    -O"$opt" -Iinclude -Isrc -c src/archx.c -o "$work/archx-$opt.o"
  "$cc" -std=c11 -Wall -Wextra -Wpedantic -fanalyzer \
    -Werror=analyzer-use-of-uninitialized-value -O"$opt" -Isrc \
    -c src/sha256.c -o "$work/sha-$opt.o"
done
printf '%s\n' 'Focused GCC analyzer compilation passed; other analyzer limits still apply.'
