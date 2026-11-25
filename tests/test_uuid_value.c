/* Synthetic values only. */
#include "uuid_value.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "UUID fixture failed at line %d: %s\n", __LINE__, #x); return 1; } } while (0)
static int is_clear(const char out[37]) { for (size_t i=0; i<37; i++) if (out[i]) return 0; return 1; }
int main(void) {
  static const char valid[] = "00112233-4455-6677-8899-AABBCCDDEEFF";
  char out[37];
  CHECK(ax_uuid_normalize((const unsigned char *)valid, 36, out) == AX_UUID_PRESENT);
  CHECK(strcmp(out, "00112233-4455-6677-8899-aabbccddeeff") == 0);
  const char *placeholders[] = {"00000000-0000-0000-0000-000000000000", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"};
  for (size_t i=0; i<2; i++) { memset(out, 1, sizeof out); CHECK(ax_uuid_normalize((const unsigned char *)placeholders[i], 36, out) == AX_UUID_PLACEHOLDER && is_clear(out)); }
  CHECK(ax_uuid_normalize(NULL, 0, out) == AX_UUID_INVALID && is_clear(out));
  CHECK(ax_uuid_normalize((const unsigned char *)valid, 36, NULL) == AX_UUID_INVALID);
  CHECK(ax_uuid_normalize((const unsigned char *)valid, 35, out) == AX_UUID_INVALID && is_clear(out));
  CHECK(ax_uuid_normalize((const unsigned char *)valid, 37, out) == AX_UUID_INVALID && is_clear(out));
  for (size_t i=0; i<36; i++) {
    unsigned char mutated[36]; memcpy(mutated, valid, 36);
    mutated[i] = (i == 8 || i == 13 || i == 18 || i == 23) ? '0' : '-';
    memset(out, 1, sizeof out);
    CHECK(ax_uuid_normalize(mutated, sizeof mutated, out) == AX_UUID_INVALID && is_clear(out));
    mutated[i] = 0; CHECK(ax_uuid_normalize(mutated, sizeof mutated, out) == AX_UUID_INVALID && is_clear(out));
    mutated[i] = 0xff; CHECK(ax_uuid_normalize(mutated, sizeof mutated, out) == AX_UUID_INVALID && is_clear(out));
  }
  puts("synthetic UUID validation fixtures passed");
  return 0;
}
