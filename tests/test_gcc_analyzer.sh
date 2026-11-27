#!/bin/sh
# Focused regression for the diagnosed SHA schedule and bounded output code.
# Analyzer silence is not a proof of memory safety; no diagnostics suppressed.
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cc=${CC:-gcc}
"$cc" --version | head -n 1
analyze() {
  name=$1
  shift
  if "$@" > "$work/$name.log" 2>&1; then
    cat "$work/$name.log"
  else
    cat "$work/$name.log"
    # CI annotations preserve concise diagnostics if full logs are unavailable.
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
      python3 - "$work/$name.log" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text(errors='replace')
# Emit bounded sections from both ends: hosted annotations have size limits.
for part in (text[:3000], text[-3000:]):
    part = part.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    print('::error::' + part)
PY
    fi
    return 1
  fi
}
for opt in 0 2; do
  analyze "archx-$opt" "$cc" -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE \
    -Wall -Wextra -Wpedantic -fanalyzer -Werror=analyzer-use-of-uninitialized-value \
    -O"$opt" -Iinclude -Isrc -c src/archx.c -o "$work/archx-$opt.o"
  analyze "sha-$opt" "$cc" -std=c11 -Wall -Wextra -Wpedantic -fanalyzer \
    -Werror=analyzer-use-of-uninitialized-value -O"$opt" -Isrc \
    -c src/sha256.c -o "$work/sha-$opt.o"
done
printf '%s\n' 'Focused GCC analyzer compilation passed; other analyzer limits still apply.'
