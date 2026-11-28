#!/bin/sh
# Partial synthetic C/Python/Node coverage reports. Linux/GCC only.
# Output path must be a new directory, never a production data directory.
set -eu
[ "$#" -eq 1 ] || { echo 'Usage: sh tools/coverage_smoke.sh NEW_REPORT_DIRECTORY' >&2; exit 2; }
root=$(pwd -P)
mkdir "$1"
out=$(cd "$1" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$out/c" "$out/python" "$out/javascript" "$work/v8"
flags='-std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Iinclude -Isrc'
sources='tests/platform/synthetic_collector.c src/archx.c src/json.c src/sha256.c src/signals.c src/store.c src/platform_posix.c src/platform_linux.c'
# Intentional word splitting of fixed flags/source lists; inputs are not user-provided.
# shellcheck disable=SC2086
gcc $flags --coverage -fprofile-abs-path -O0 -g tests/platform/test_core_synthetic.c $sources -lm -lpthread -o "$work/core"
"$work/core"
for file in "$work"/*.gcno; do
  (cd "$out/c" && gcov -b -c "$file") >> "$out/c/summary.txt"
done
# A separate uninstrumented synthetic ABI library is used by Node. No system
# identifiers or existing build/libarchx.so are read or overwritten.
# shellcheck disable=SC2086
gcc $flags -shared -fPIC -O0 $sources -lm -lpthread -o "$work/libarchx_synthetic.so"
export COVERAGE_FILE="$work/python.coverage"
for test in tests/test_limiter_model.py tests/test_sqlite_engine.py tests/test_empty_key_rotation.py \
            tests/test_sqlite_snapshot.py tests/test_security.py tests/test_transport_key_rotation.py; do
  python3 -m coverage run --branch --append --source=demo "$test"
done
python3 -m coverage report --show-missing > "$out/python/summary.txt"
python3 -m coverage xml -o "$out/python/coverage.xml"
export NODE_V8_COVERAGE="$work/v8" ARCHX_COVERAGE_LIB="$work/libarchx_synthetic.so"
node tests/coverage_node.cjs
python3 tests/test_browser.py BrowserClientTests.test_node_javascript_interoperability_with_backend \
  BrowserClientTests.test_node_javascript_v3_key_id_interoperability
python3 tools/v8_coverage_summary.py "$work/v8" "$out/javascript/summary.json"
printf 'Synthetic partial coverage reports written to %s\n' "$out"
