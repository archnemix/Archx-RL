#!/bin/sh
# Native synthetic-only install/relocation test. Not a release artifact.
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
if [ "${RUNNER_OS:-}" = Windows ]; then
  cmake --install build/platform --config Release --prefix "$tmp/initial"
else
  cmake --install build/platform --prefix "$tmp/initial"
fi
mv "$tmp/initial" "$tmp/relocated"
if [ "${RUNNER_OS:-}" = Windows ]; then
  cmake -S tests/platform/consumer -B "$tmp/consumer" -A x64 -DCMAKE_PREFIX_PATH="$tmp/relocated"
else
  cmake -S tests/platform/consumer -B "$tmp/consumer" -DCMAKE_PREFIX_PATH="$tmp/relocated"
fi
cmake --build "$tmp/consumer" --config Release --parallel 2
ctest --test-dir "$tmp/consumer" -C Release --output-on-failure
