/* libFuzzer entry point: input and identifiers are synthetic, never logged. */
#include "smbios.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
  ax_smbios_result result;
  memset(&result, 0xa5, sizeof result);
  int status = ax_smbios_parse_rsmb(data, len, &result);
  if (status == 0) {
    if (!memchr(result.uuid, 0, sizeof result.uuid) || !memchr(result.serial, 0, sizeof result.serial) || !memchr(result.board_serial, 0, sizeof result.board_serial)) abort();
    if (result.uuid_status > AX_SMBIOS_INVALID || result.serial_status > AX_SMBIOS_INVALID || result.board_serial_status > AX_SMBIOS_AMBIGUOUS) abort();
    if ((result.uuid_status != AX_SMBIOS_PRESENT && result.uuid[0]) ||
        (result.serial_status != AX_SMBIOS_PRESENT && result.serial[0]) ||
        (result.board_serial_status != AX_SMBIOS_PRESENT && result.board_serial[0])) abort();
  } else if (result.uuid_status != AX_SMBIOS_ABSENT || result.serial_status != AX_SMBIOS_ABSENT || result.board_serial_status != AX_SMBIOS_ABSENT ||
             result.uuid[0] != 0 || result.serial[0] != 0 || result.board_serial[0] != 0) abort();
  return 0;
}
