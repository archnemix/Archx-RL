/* Experimental desktop Windows RSMB collector; no raw values are logged. */
#include "signals_windows.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>

/* The documented 'RSMB' multicharacter provider, without compiler-specific
 * multichar literals. No registry, command execution or private API. */
#define AX_RSMB_PROVIDER ((DWORD)0x52534d42u)

static ax_windows_firmware_status translate_error(uint32_t error) {
  if (error == ERROR_ACCESS_DENIED) return AX_WINDOWS_FIRMWARE_DENIED;
  if (error == ERROR_NOT_SUPPORTED || error == ERROR_INVALID_FUNCTION) return AX_WINDOWS_FIRMWARE_UNSUPPORTED;
  return AX_WINDOWS_FIRMWARE_READ_ERROR;
}

ax_windows_firmware_status ax_windows_collect_firmware_with_provider(
    ax_windows_firmware_provider provider, void *context, ax_smbios_result *out) {
  if (!out) return AX_WINDOWS_FIRMWARE_READ_ERROR;
  memset(out, 0, sizeof *out);
  if (!provider) return AX_WINDOWS_FIRMWARE_READ_ERROR;
  uint32_t error = 0;
  uint32_t size = provider(context, NULL, 0, &error);
  if (!size) return translate_error(error);
  if (size < 8 || size > AX_SMBIOS_MAX_RAW) return AX_WINDOWS_FIRMWARE_READ_ERROR;
  unsigned char *raw = (unsigned char *)malloc(size);
  if (!raw) return AX_WINDOWS_FIRMWARE_READ_ERROR;
  uint32_t written = provider(context, raw, size, &error);
  ax_windows_firmware_status status;
  if (!written) status = translate_error(error);
  else if (written != size || ax_smbios_parse_rsmb(raw, written, out) != 0) status = AX_WINDOWS_FIRMWARE_READ_ERROR;
  else status = AX_WINDOWS_FIRMWARE_OK;
  SecureZeroMemory(raw, size);
  free(raw);
  if (status != AX_WINDOWS_FIRMWARE_OK) memset(out, 0, sizeof *out);
  return status;
}

static uint32_t system_provider(void *context, void *buffer, uint32_t capacity, uint32_t *error) {
  (void)context;
  UINT result = GetSystemFirmwareTable(AX_RSMB_PROVIDER, 0, buffer, (DWORD)capacity);
  if (!result) *error = GetLastError();
  return (uint32_t)result;
}

ax_windows_firmware_status ax_windows_collect_firmware(ax_smbios_result *out) {
  return ax_windows_collect_firmware_with_provider(system_provider, NULL, out);
}
