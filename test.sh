#!/bin/sh
set -eu
./build.sh
CC="${CC:-cc}"
FLAGS="-std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -Iinclude -Isrc"
$CC $FLAGS tests/test_vectors.c src/sha256.c -o build/test_vectors
$CC $FLAGS tests/test_core.c src/signals_linux.c src/sha256.c -Lbuild -larchx -lm -lpthread -Wl,-rpath,'$ORIGIN' -o build/test_core
./build/test_vectors
./build/test_core
python3 tests/test_matching.py
python3 tests/test_demo.py
python3 tests/test_sqlite_engine.py
python3 tests/test_trial_service.py
python3 tests/test_survey.py
python3 tools/attack_lab.py
python3 tools/benchmark.py
# Exercise memory safety on C paths. Requires a compiler with ASan/UBSan support.
SAN_FLAGS="$FLAGS -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined"
$CC $SAN_FLAGS tests/test_core.c src/archx.c src/signals_linux.c src/sha256.c src/json.c src/store.c -lm -lpthread -o build/test_core_san
$CC $SAN_FLAGS tests/test_json_fuzz.c src/json.c -o build/test_json_fuzz
ASAN_OPTIONS=detect_leaks=1 ./build/test_core_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_json_fuzz
./build/archx-probe collect | python3 -c 'import json,sys; assert json.load(sys.stdin)["platform"] == "linux"'
./build/archx-probe identify --app-id 'test"app' --pepper demo | python3 -c 'import json,sys; assert len(json.load(sys.stdin)["device_hash"]) == 64'
echo "probe tests passed"
