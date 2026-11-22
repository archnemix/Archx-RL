/* Deterministic malformed-input stress test for the bounded JSON parser. */
#include <stdint.h>
#include <stdio.h>
#include "json.h"

static uint32_t state = 0x12345678u;
static uint32_t next(void) { state ^= state << 13; state ^= state >> 17; state ^= state << 5; return state; }
int main(void) {
  char input[256];
  static const char alphabet[] = "{}:\",-0123456789.truefalsnul[]\\uabcdef \t\n";
  for (unsigned i = 0; i < 20000; i++) {
    size_t len = next() % sizeof input;
    for (size_t j = 0; j < len; j++) input[j] = (i & 1) ? alphabet[next() % (sizeof alphabet - 1)] : (char)(next() & 255);
    ax_json_value *out = NULL;
    if (ax_json_parse(input, len, &out) == 0) ax_json_free(out);
  }
  puts("bounded JSON malformed-input stress passed");
  return 0;
}
