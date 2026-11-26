#!/bin/sh
# Synthetic native test double; Linux only, never shipped as a library.
set -eu
mkdir -p build
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -fPIC -shared tests/fixtures/binding_fake.c -o build/binding_fake.so
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -fPIC -shared -DWRONG_ABI tests/fixtures/binding_fake.c -o build/binding_wrong_abi.so
