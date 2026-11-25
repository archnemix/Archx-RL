#!/bin/sh
# Build and run focused Linux regression, integration, and sanitizer tests.
set -eu
./build.sh
CC="${CC:-cc}"
FLAGS="-std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -Iinclude -Isrc"
$CC $FLAGS tests/test_vectors.c src/sha256.c -o build/test_vectors
$CC $FLAGS tests/test_core.c src/signals_linux.c src/sha256.c -Lbuild -larchx -lm -lpthread -Wl,-rpath,'$ORIGIN' -o build/test_core
$CC $FLAGS tests/test_uuid_value.c src/uuid_value.c -o build/test_uuid_value
$CC $FLAGS tests/test_smbios.c src/smbios.c -o build/test_smbios
$CC $FLAGS tests/test_coverage.c src/archx.c src/sha256.c src/json.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_coverage
$CC $FLAGS tests/test_output_faults.c src/sha256.c src/json.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_output_faults
$CC $FLAGS tests/test_platform.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_platform
$CC $FLAGS -Itests/platform tests/test_store_faults.c tests/platform/fake_platform.c src/archx.c src/signals_linux.c src/sha256.c src/json.c src/store.c -lm -lpthread -o build/test_store_faults
./build/test_vectors
./build/test_smbios
./build/test_uuid_value
./build/test_platform
./build/test_output_faults
./build/test_coverage
./build/test_store_faults
./build/test_core
python3 tests/test_crypto_differential.py
python3 tests/test_matching.py
python3 tests/test_demo.py
python3 tests/test_observation_index.py
python3 tests/test_boundaries.py
python3 tests/test_sqlite_engine.py
python3 tests/test_security.py
python3 tests/test_browser.py
python3 tests/test_replay.py
python3 tests/test_proxy.py
python3 tests/test_host_integration.py
python3 tests/test_survey.py
python3 tools/attack_lab.py
python3 tools/benchmark.py
# Exercise memory safety on C paths. Requires a compiler with ASan/UBSan support.
SAN_FLAGS="$FLAGS -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined"
$CC $SAN_FLAGS tests/test_core.c src/archx.c src/signals_linux.c src/sha256.c src/json.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_core_san
$CC $SAN_FLAGS tests/test_uuid_value.c src/uuid_value.c -o build/test_uuid_value_san
$CC $SAN_FLAGS tests/test_coverage.c src/archx.c src/sha256.c src/json.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_coverage_san
$CC $SAN_FLAGS tests/test_output_faults.c src/sha256.c src/json.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_output_faults_san
$CC $SAN_FLAGS tests/test_smbios.c src/smbios.c -o build/test_smbios_san
$CC $SAN_FLAGS tests/test_json_fuzz.c src/json.c -o build/test_json_fuzz
ASAN_OPTIONS=detect_leaks=1 ./build/test_core_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_uuid_value_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_coverage_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_output_faults_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_smbios_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_json_fuzz
./build/archx-probe collect | python3 -c 'import json,sys; assert json.load(sys.stdin)["platform"] == "linux"'
./build/archx-probe identify --app-id 'test"app' --pepper demo | python3 -c 'import json,sys; assert len(json.load(sys.stdin)["device_hash"]) == 64'
echo "probe tests passed"
