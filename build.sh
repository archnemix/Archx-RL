#!/bin/sh
# Build libarchx (shared + static) and the archx-probe CLI.
# Usage: ./build.sh [--release]   (default: -O2, same thing for now)
set -eu

CC="${CC:-cc}"
CFLAGS="-std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -O2 -fPIC -Iinclude -Isrc"
CORE_SRC="src/archx.c src/sha256.c src/json.c src/signals_linux.c src/signals.c src/store.c src/platform_posix.c src/platform_linux.c"
OUT="build"
mkdir -p "$OUT"

echo "== libarchx.so =="
$CC $CFLAGS -shared -o "$OUT/libarchx.so" $CORE_SRC -lm -lpthread

echo "== libarchx.a =="
for source in $CORE_SRC; do
  name=$(basename "$source" .c)
  $CC $CFLAGS -c "$source" -o "$OUT/$name.o"
done
ar rcs "$OUT/libarchx.a" "$OUT/archx.o" "$OUT/sha256.o" "$OUT/json.o" "$OUT/signals_linux.o" "$OUT/signals.o" "$OUT/store.o" "$OUT/platform_posix.o" "$OUT/platform_linux.o"

echo "== archx-probe =="
$CC $CFLAGS -o "$OUT/archx-probe" tools/archx-probe.c -L"$OUT" -larchx -lm -lpthread \
  -Wl,-rpath,'$ORIGIN'

echo "built: $OUT/libarchx.so  $OUT/libarchx.a  $OUT/archx-probe"
