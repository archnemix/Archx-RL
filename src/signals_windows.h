/* Experimental Windows firmware collection, not yet wired to the public ABI. */
#ifndef AX_SIGNALS_WINDOWS_H
#define AX_SIGNALS_WINDOWS_H
#include "smbios.h"
#include <stdint.h>

typedef enum {
  AX_WINDOWS_FIRMWARE_OK = 0,
  AX_WINDOWS_FIRMWARE_DENIED = 1,
  AX_WINDOWS_FIRMWARE_UNSUPPORTED = 2,
  AX_WINDOWS_FIRMWARE_READ_ERROR = 3
} ax_windows_firmware_status;

/* Provider follows GetSystemFirmwareTable's size-query/return convention.
 * Nonzero error is consulted only on a zero return. The injection boundary
 * is internal and exists to exercise unavailable and changing firmware. */
typedef uint32_t (*ax_windows_firmware_provider)(void *context, void *buffer,
                                                  uint32_t capacity, uint32_t *error);
ax_windows_firmware_status ax_windows_collect_firmware_with_provider(
    ax_windows_firmware_provider provider, void *context, ax_smbios_result *out);
ax_windows_firmware_status ax_windows_collect_firmware(ax_smbios_result *out);
#endif
