/* Pure synthetic CF objects. No registry, hardware or real values read. */
#include "macos_cf_uuid.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "CF UUID fixture failed at line %d: %s\n", __LINE__, #x); return 1; } } while (0)
static int is_clear(const char out[37]) { for (size_t i=0; i<37; i++) if (out[i]) return 0; return 1; }
int main(void) {
  char out[37];
  CHECK(ax_macos_cf_uuid(CFSTR("00112233-4455-6677-8899-AABBCCDDEEFF"), out) == AX_UUID_PRESENT);
  CHECK(strcmp(out, "00112233-4455-6677-8899-aabbccddeeff") == 0);
  CHECK(ax_macos_cf_uuid(NULL, out) == AX_UUID_ABSENT && is_clear(out));
  CHECK(ax_macos_cf_uuid(CFSTR("00000000-0000-0000-0000-000000000000"), out) == AX_UUID_PLACEHOLDER && is_clear(out));
  CHECK(ax_macos_cf_uuid(CFSTR("bad"), out) == AX_UUID_INVALID && is_clear(out));
  CHECK(ax_macos_cf_uuid(kCFBooleanTrue, out) == AX_UUID_INVALID && is_clear(out));
  CHECK(ax_macos_cf_uuid(CFSTR("00112233-4455-6677-8899-AABBCCDDEEFF"), NULL) == AX_UUID_INVALID);
  UniChar text[36] = {'0','0','1','1','2','2','3','3','-','4','4','5','5','-','6','6','7','7','-','8','8','9','9','-','a','a','b','b','c','c','d','d','e','e','f','f'};
  text[4] = 0x00e9;
  CFStringRef nonascii = CFStringCreateWithCharacters(kCFAllocatorDefault, text, 36);
  CHECK(nonascii != NULL);
  ax_uuid_status status = ax_macos_cf_uuid(nonascii, out);
  CFRelease(nonascii);
  CHECK(status == AX_UUID_INVALID && is_clear(out));
  text[4] = 0;
  CFStringRef embedded_null = CFStringCreateWithCharacters(kCFAllocatorDefault, text, 36);
  CHECK(embedded_null != NULL);
  status = ax_macos_cf_uuid(embedded_null, out);
  CFRelease(embedded_null);
  CHECK(status == AX_UUID_INVALID && is_clear(out));
  puts("synthetic macOS CoreFoundation UUID fixtures passed");
  return 0;
}
