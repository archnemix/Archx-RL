#include "macos_cf_uuid.h"
#include <string.h>

ax_uuid_status ax_macos_cf_uuid(CFTypeRef value, char out[37]) {
  if (!out) return AX_UUID_INVALID;
  memset(out, 0, 37);
  if (!value) return AX_UUID_ABSENT;
  if (CFGetTypeID(value) != CFStringGetTypeID()) return AX_UUID_INVALID;
  CFStringRef str = (CFStringRef)value;
  if (CFStringGetLength(str) != 36) return AX_UUID_INVALID;
  UniChar chars[36];
  unsigned char bytes[36];
  CFStringGetCharacters(str, CFRangeMake(0, 36), chars);
  for (size_t i = 0; i < 36; i++) {
    if (chars[i] > 0x7f) return AX_UUID_INVALID;
    bytes[i] = (unsigned char)chars[i];
  }
  return ax_uuid_normalize(bytes, sizeof bytes, out);
}
