#!/bin/sh
# Clean install, relocation, dynamic/static consumer and installed probe tests.
set -eu
tmp=$(mktemp -d "${TMPDIR:-/tmp}/archx-cmake-test-XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
run_case() {
  case_name=$1 bin_dir=$2 lib_dir=$3
  root="$tmp/$case_name"
  cmake -S . -B "$root/build" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$root/prefix" -DCMAKE_INSTALL_BINDIR="$bin_dir" -DCMAKE_INSTALL_LIBDIR="$lib_dir"
  cmake --build "$root/build" --parallel 2
  cmake --install "$root/build"
  cmp LICENSE "$root/prefix/share/licenses/archx/LICENSE"
  cmp THIRD_PARTY_NOTICES.md "$root/prefix/share/licenses/archx/THIRD_PARTY_NOTICES.md"
  mv "$root/prefix" "$root/relocated"
  if [ "$case_name" = default ]; then
    cmake -S tests/cmake_consumer -B "$root/consumer" -DCMAKE_PREFIX_PATH="$root/relocated"
  else
    # A custom libdir may not be in CMake's default package search paths.
    cmake -S tests/cmake_consumer -B "$root/consumer" -DArchx_DIR="$root/relocated/$lib_dir/cmake/Archx"
  fi
  cmake --build "$root/consumer" --parallel 2
  ctest --test-dir "$root/consumer" --output-on-failure
  ldd "$root/consumer/consumer_core" | grep -q 'libarchx\.so'
  if ldd "$root/consumer/consumer_static" | grep -q 'libarchx\.so'; then
    echo 'Static consumer unexpectedly uses shared Archx' >&2; exit 1
  fi
  "$root/relocated/$bin_dir/archx-probe" check synthetic --capacity 1 --refill-per-sec 0 | python3 -c 'import json,sys; assert json.load(sys.stdin)["decision"] == "allow"'
}
run_case default bin lib
run_case custom tools/bin lib64
if cmake -S . -B "$tmp/rejected" -DCMAKE_INSTALL_LIBDIR=/tmp/archx-absolute-lib > /dev/null 2>&1; then
  echo 'Absolute install directories should be rejected' >&2; exit 1
fi
echo 'CMake relocated shared/static install and probe tests passed'
