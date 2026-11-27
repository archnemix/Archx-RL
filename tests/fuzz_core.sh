#!/bin/sh
# Fixed-duration synthetic libFuzzer smoke. Requires clang and sanitizers.
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/corpus"
printf '%s' '{"app_id":"fixture-app","pepper":"synthetic-test-pepper"}' > "$tmp/corpus/config"
printf '%s' '{"version":1,"scope":"invalid","signals":{"ip":null}}' > "$tmp/corpus/profile"
printf '%s' '{"nested":[1,true,null,{"x":"synthetic"}]}' > "$tmp/corpus/json"
printf '%s' '{"app_id":"a","app_id":"b"' > "$tmp/corpus/malformed"
clang -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -g -O1 -fno-omit-frame-pointer \
  -Iinclude -Isrc -fsanitize=fuzzer,address,undefined \
  tests/fuzz_core_inputs.c tests/platform/synthetic_collector.c src/archx.c src/json.c \
  src/signals.c src/sha256.c src/store.c src/platform_posix.c src/platform_linux.c \
  -lm -lpthread -o "$tmp/fuzz_core"
# No inherited project secrets or user-specific environment. Crashes/artifacts
# stay in the temporary directory; a nonzero exit fails the CI job.
env -i PATH="$PATH" ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  "$tmp/fuzz_core" -max_total_time=5 -max_len=8192 -timeout=5 -artifact_prefix="$tmp/" "$tmp/corpus"
