#include "uuid_value.h"
#include <string.h>

ax_uuid_status ax_uuid_normalize(const unsigned char *text, size_t len, char out[37]) {
  if (!out) return AX_UUID_INVALID;
  memset(out, 0, 37);
  if (!text || len != 36) return AX_UUID_INVALID;
  int all_zero = 1, all_f = 1;
  char tmp[37];
  for (size_t i = 0; i < 36; i++) {
    unsigned char c = text[i];
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (c != '-') return AX_UUID_INVALID;
      tmp[i] = '-';
      continue;
    }
    if (c >= 'A' && c <= 'F') c = (unsigned char)(c + ('a' - 'A'));
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return AX_UUID_INVALID;
    all_zero &= c == '0';
    all_f &= c == 'f';
    tmp[i] = (char)c;
  }
  if (all_zero || all_f) return AX_UUID_PLACEHOLDER;
  tmp[36] = '\0';
  memcpy(out, tmp, sizeof tmp);
  return AX_UUID_PRESENT;
}
