/* Internal bounded SMBIOS parser for synthetic tests and a future collector.
 * It does not fetch firmware, authenticate signals or implement a public ABI.
 */
#ifndef AX_SMBIOS_H
#define AX_SMBIOS_H
#include <stddef.h>
#include <stdint.h>

#define AX_SMBIOS_MAX_RAW (1024u * 1024u)
typedef enum {
  AX_SMBIOS_ABSENT = 0,
  AX_SMBIOS_PRESENT = 1,
  AX_SMBIOS_UNSUPPORTED = 2,
  AX_SMBIOS_PLACEHOLDER = 3,
  AX_SMBIOS_INVALID = 4
} ax_smbios_status;
typedef struct {
  ax_smbios_status uuid_status;
  ax_smbios_status serial_status;
  char uuid[37];
  char serial[129];
} ax_smbios_result;

/* Parse the Windows RawSMBIOSData header and table. Returns 0 on success,
 * -1 for malformed/oversized input. On failure the entire result is cleared.
 * Values are sensitive: callers must avoid logging or persisting raw values. */
int ax_smbios_parse_rsmb(const uint8_t *raw, size_t len, ax_smbios_result *out);
#endif
