#!/bin/sh
# Compare two independent clean archive builds with the same local toolchain.
# This does not establish cross-machine reproducibility or validate releases.
set -eu
export LC_ALL=C TZ=UTC
umask 022
[ "$(uname -s)" = Linux ] || { echo 'Linux is required' >&2; exit 1; }
if [ "$#" -gt 1 ]; then echo 'Usage: sh tools/reproduce_linux.sh [commit]' >&2; exit 2; fi
revision=${1:-HEAD}
commit=$(git rev-parse --verify --end-of-options "$revision^{commit}")
compiler=${CC:-cc}
command -v "$compiler" >/dev/null || { echo 'CC must name one executable' >&2; exit 1; }
work=$(mktemp -d "${TMPDIR:-/tmp}/archx-reproduce-XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
printf 'Commit: %s\n' "$commit"
printf 'Platform: '; uname -sm
printf 'Compiler: '; "$compiler" --version | head -n 1
printf 'Linker: '; ld --version | head -n 1
printf 'Archiver: '; ar --version | head -n 1
printf 'Git: '; git --version
git archive --format=tar --prefix=archx/ "$commit" > "$work/source.tar"
printf 'Source archive SHA-256: '; sha256sum "$work/source.tar" | cut -d ' ' -f 1
for instance in one two; do
  mkdir "$work/$instance"
  tar -xf "$work/source.tar" -C "$work/$instance"
  (cd "$work/$instance/archx" && CC="$compiler" sh ./build.sh > /dev/null)
done
for file in libarchx.so libarchx.a archx-probe; do
  cmp "$work/one/archx/build/$file" "$work/two/archx/build/$file" || {
    echo "Independent local builds differ: $file" >&2; exit 1;
  }
  printf '%s SHA-256: ' "$file"
  sha256sum "$work/one/archx/build/$file" | cut -d ' ' -f 1
done
printf '%s\n' 'Two clean source-archive builds match byte-for-byte on this host.'
