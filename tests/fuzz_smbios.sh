#!/bin/sh
# Fixed-duration synthetic libFuzzer smoke; requires clang and sanitizers.
set -eu
seconds=${ARCHX_FUZZ_SECONDS:-5}
case "$seconds" in *[!0-9]*|'') echo 'Invalid fuzz duration' >&2; exit 2;; esac
[ "${#seconds}" -le 3 ] && [ "$seconds" -ge 1 ] && [ "$seconds" -le 300 ] || { echo 'Invalid fuzz duration' >&2; exit 2; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/corpus"
python3 - "$tmp/corpus" <<'PY'
import sys
from pathlib import Path
corpus = Path(sys.argv[1])
header = bytes([0, 2, 6, 0])
uuid = bytes.fromhex('33221100554477668899aabbccddeeff')
type1 = bytes([1,25,0,0,0,0,0,1]) + uuid + bytes([0]) + b'synthetic-serial\0\0'
end = bytes([127,4,0,0,0,0])
type2 = bytes([2,8,0,0,0,0,0,1]) + b'synthetic-board\0\0'
board_table = type2 + end
(corpus / 'board').write_bytes(header + len(board_table).to_bytes(4,'little') + board_table)
table = type1 + type2 + end
(corpus / 'valid').write_bytes(header + len(table).to_bytes(4,'little') + table)
(corpus / 'empty').write_bytes(header + len(end).to_bytes(4,'little') + end)
PY
clang -std=c11 -g -O1 -Isrc -fsanitize=fuzzer,address,undefined tests/fuzz_smbios.c src/smbios.c -o "$tmp/fuzz_smbios"
env -i PATH="$PATH" ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  "$tmp/fuzz_smbios" -max_total_time="$seconds" -max_len=4096 -timeout=5 -artifact_prefix="$tmp/" "$tmp/corpus"
