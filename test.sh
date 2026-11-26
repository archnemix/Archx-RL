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
$CC $FLAGS tests/test_json_contract.c src/json.c -lm -o build/test_json_contract
$CC $FLAGS tests/test_canonical.c src/signals.c -o build/test_canonical
$CC $FLAGS tests/test_coverage.c src/archx.c src/sha256.c src/json.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_coverage
$CC $FLAGS tests/test_output_faults.c src/sha256.c src/json.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_output_faults
$CC $FLAGS tests/test_json_faults.c src/archx.c src/sha256.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_json_faults
$CC $FLAGS tests/test_platform.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_platform
$CC $FLAGS -Itests/platform tests/test_store_faults.c tests/platform/fake_platform.c src/archx.c src/signals_linux.c src/signals.c src/sha256.c src/json.c src/store.c -lm -lpthread -o build/test_store_faults
$CC $FLAGS -Itests/platform tests/test_fallback_faults.c tests/platform/fake_platform.c src/sha256.c -o build/test_fallback_faults
$CC $FLAGS -Itests/platform tests/test_linux_signal_validation.c tests/platform/fake_platform.c src/sha256.c -o build/test_linux_signal_validation
$CC $FLAGS -Itests/platform tests/test_core_alloc_faults.c tests/platform/fake_platform.c src/sha256.c src/json.c -lm -o build/test_core_alloc_faults
./build/test_vectors
./build/test_smbios
./build/test_json_contract
./build/test_uuid_value
./build/test_platform
./build/test_output_faults
./build/test_json_faults
./build/test_coverage
./build/test_canonical
./build/test_store_faults
./build/test_fallback_faults
./build/test_linux_signal_validation
./build/test_core_alloc_faults
./build/test_core
python3 tests/test_crypto_differential.py
python3 tests/test_threat_model.py
python3 tests/test_coverage_docs.py
python3 tests/test_guides.py
python3 tests/test_matching.py
python3 tests/test_demo.py
python3 tests/test_separate_quotas.py
python3 tests/test_stability_evaluation.py
python3 tests/test_observation_index.py
python3 tests/test_metrics.py
python3 tests/test_gate_benchmark.py
python3 tests/test_expiry_benchmark.py
python3 tests/test_expiry_cleanup.py
python3 tests/test_contention_benchmark.py
python3 tests/test_boundaries.py
python3 tests/test_sqlite_engine.py
python3 tests/test_sqlite_multiprocess_probe.py
python3 tests/test_sqlite_soak_profile.py
python3 tests/test_state_clock.py
python3 tests/test_security.py
python3 tests/test_browser.py
python3 tests/test_replay.py
python3 tests/test_proxy.py
python3 tests/test_host_integration.py
python3 tests/test_wsgi_boundary.py
python3 tests/test_survey.py
python3 tools/attack_lab.py
python3 tools/benchmark.py
# Exercise memory safety on C paths. Requires a compiler with ASan/UBSan support.
SAN_FLAGS="$FLAGS -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined"
$CC $SAN_FLAGS tests/test_platform.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_platform_san
$CC $SAN_FLAGS -Itests/platform tests/test_fallback_faults.c tests/platform/fake_platform.c src/sha256.c -o build/test_fallback_faults_san
$CC $SAN_FLAGS -Itests/platform tests/test_linux_signal_validation.c tests/platform/fake_platform.c src/sha256.c -o build/test_linux_signal_validation_san
$CC $SAN_FLAGS -Itests/platform tests/test_core_alloc_faults.c tests/platform/fake_platform.c src/sha256.c src/json.c -lm -o build/test_core_alloc_faults_san
$CC $SAN_FLAGS tests/test_core.c src/archx.c src/signals_linux.c src/signals.c src/sha256.c src/json.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_core_san
$CC $SAN_FLAGS tests/test_uuid_value.c src/uuid_value.c -o build/test_uuid_value_san
$CC $SAN_FLAGS tests/test_canonical.c src/signals.c -o build/test_canonical_san
$CC $SAN_FLAGS tests/test_coverage.c src/archx.c src/sha256.c src/json.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_coverage_san
$CC $SAN_FLAGS tests/test_output_faults.c src/sha256.c src/json.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_output_faults_san
$CC $SAN_FLAGS tests/test_json_faults.c src/archx.c src/sha256.c src/store.c src/platform_posix.c src/platform_linux.c -lm -lpthread -o build/test_json_faults_san
$CC $SAN_FLAGS tests/test_smbios.c src/smbios.c -o build/test_smbios_san
$CC $SAN_FLAGS tests/test_json_fuzz.c src/json.c -o build/test_json_fuzz
$CC $SAN_FLAGS tests/test_json_contract.c src/json.c -lm -o build/test_json_contract_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_platform_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_fallback_faults_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_linux_signal_validation_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_core_alloc_faults_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_core_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_uuid_value_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_canonical_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_coverage_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_output_faults_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_json_faults_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_smbios_san
ASAN_OPTIONS=detect_leaks=1 ./build/test_json_fuzz
ASAN_OPTIONS=detect_leaks=1 ./build/test_json_contract_san
./build/archx-probe collect | python3 -c 'import json,sys; assert json.load(sys.stdin)["platform"] == "linux"'
./build/archx-probe identify --app-id 'test"app' --pepper demo | python3 -c 'import json,sys; assert len(json.load(sys.stdin)["device_hash"]) == 64'
echo "probe tests passed"
