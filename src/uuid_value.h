/* Internal, allocation-free UUID-text validation; not an identity guarantee. */
#ifndef AX_UUID_VALUE_H
#define AX_UUID_VALUE_H
#include <stddef.h>

typedef enum {
  AX_UUID_ABSENT = 0,
  AX_UUID_PRESENT = 1,
  AX_UUID_PLACEHOLDER = 2,
  AX_UUID_INVALID = 3
} ax_uuid_status;

/* Accept exactly 36 ASCII bytes of hyphenated hexadecimal UUID text.
 * Out must hold 37 bytes and must not overlap text. Non-present results clear the whole output. */
ax_uuid_status ax_uuid_normalize(const unsigned char *text, size_t len, char out[37]);
#endif
