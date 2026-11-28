#!/bin/sh
# Five-second coverage-guided smoke. Requires PyNaCl and Atheris 3.0.0.
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/corpus"
# 0, 1 and 2 select normalization, v2 and v3 respectively.
printf '\000\0000123456789abcdef0123456789abcdef' > "$tmp/corpus/machine"
printf '\001archx-sealed-check-v2\000{}' > "$tmp/corpus/v2"
printf '\002archx-sealed-check-v3\000\004test{}' > "$tmp/corpus/v3"
printf '\003notbase64' > "$tmp/corpus/cipher-v2"
printf '\004notbase64' > "$tmp/corpus/cipher-v3"
python=$(command -v python3)
"$python" - "$tmp/corpus" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1])
for mode, prefix in ((1, b'archx-sealed-check-v2\0'), (2, b'archx-sealed-check-v3\0\x04test')):
    for length in (6096, 6097, 6144, 6145):
        (p / f'boundary-{mode}-{length}').write_bytes(bytes([mode]) + prefix + b'x' * (length - len(prefix)))
PY
env -i PATH="$PATH" "$python" tests/fuzz_python_inputs.py \
  -max_total_time=5 -max_len=9000 -timeout=5 -artifact_prefix="$tmp/" "$tmp/corpus"
