/* Internal bounded SMBIOS parser used by synthetic tests and the experimental collector.
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
  AX_SMBIOS_INVALID = 4,
  AX_SMBIOS_AMBIGUOUS = 5 /* multiple Type 2 records; do not select one */
} ax_smbios_status;
typedef struct {
  ax_smbios_status uuid_status;
  ax_smbios_status serial_status;       /* Type 1 system serial */
  ax_smbios_status board_serial_status; /* Type 2 baseboard serial */
  char uuid[37];
  char serial[129];
  char board_serial[129];
} ax_smbios_result;

/* Parse the Windows RawSMBIOSData header and Type 1/2 records. Multiple Type 2
 * records produce an ambiguous board status instead of choosing one. Returns
 * 0 on success, -1 for malformed/oversized input; on failure the result is cleared.
 * Values are sensitive: callers must avoid logging or persisting raw values. */
int ax_smbios_parse_rsmb(const uint8_t *raw, size_t len, ax_smbios_result *out);
#endif
