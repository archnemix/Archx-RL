#!/bin/sh
# Fixed-duration synthetic libFuzzer smoke; requires clang and sanitizer runtime.
set -eu
mkdir -p build/fuzz-smbios-corpus
python3 - <<'PY'
from pathlib import Path
header = bytes([0, 2, 6, 0])
uuid = bytes.fromhex('33221100554477668899aabbccddeeff')
type1 = bytes([1,25,0,0,0,0,0,1]) + uuid + bytes([0]) + b'synthetic-serial\0\0'
end = bytes([127,4,0,0,0,0])
table = type1 + end
Path('build/fuzz-smbios-corpus/valid').write_bytes(header + len(table).to_bytes(4,'little') + table)
Path('build/fuzz-smbios-corpus/empty').write_bytes(header + len(end).to_bytes(4,'little') + end)
PY
clang -std=c11 -g -O1 -Isrc -fsanitize=fuzzer,address,undefined tests/fuzz_smbios.c src/smbios.c -o build/fuzz_smbios
./build/fuzz_smbios -max_total_time=5 -max_len=4096 build/fuzz-smbios-corpus
