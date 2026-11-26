/* Disposable-host availability survey. Never prints identifier values. */
#include "signals_windows.h"
#include <windows.h>
#include <stdio.h>

static const char *firmware_status(ax_windows_firmware_status status) {
  switch (status) {
    case AX_WINDOWS_FIRMWARE_OK: return "ok";
    case AX_WINDOWS_FIRMWARE_DENIED: return "permission_denied";
    case AX_WINDOWS_FIRMWARE_UNSUPPORTED: return "unsupported";
    default: return "read_error";
  }
}
static const char *signal_status(ax_smbios_status status) {
  switch (status) {
    case AX_SMBIOS_ABSENT: return "absent";
    case AX_SMBIOS_PRESENT: return "present";
    case AX_SMBIOS_UNSUPPORTED: return "unsupported";
    case AX_SMBIOS_PLACEHOLDER: return "placeholder";
    case AX_SMBIOS_INVALID: return "invalid";
    case AX_SMBIOS_AMBIGUOUS: return "ambiguous";
    default: return "unknown";
  }
}
static const char *registry_metadata(void) {
  HKEY key = NULL;
  LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography",
                                0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
  if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) return "absent";
  if (status == ERROR_ACCESS_DENIED) return "permission_denied";
  if (status != ERROR_SUCCESS) return "read_error";
  DWORD type = 0;
  /* Query only the type, never the value, size, or registry contents. */
  status = RegQueryValueExW(key, L"MachineGuid", NULL, &type, NULL, NULL);
  RegCloseKey(key);
  if (status == ERROR_FILE_NOT_FOUND) return "absent";
  if (status == ERROR_ACCESS_DENIED) return "permission_denied";
  if (status != ERROR_SUCCESS) return "read_error";
  return type == REG_SZ ? "string_type_only" : "unexpected_type";
}
static const char *privilege(void) {
  HANDLE token = NULL;
  TOKEN_ELEVATION elevation;
  DWORD size = 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return "unknown";
  BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof elevation, &size);
  CloseHandle(token);
  return !ok ? "unknown" : elevation.TokenIsElevated ? "elevated" : "not_elevated";
}
static const char *architecture(void) {
  SYSTEM_INFO info;
  GetNativeSystemInfo(&info);
  switch (info.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: return "x86_64";
    case PROCESSOR_ARCHITECTURE_ARM64: return "arm64";
    case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
    default: return "unknown";
  }
}
int main(void) {
  ax_smbios_result data;
  ax_windows_firmware_status status = ax_windows_collect_firmware(&data);
  const char *uuid = status == AX_WINDOWS_FIRMWARE_OK ? signal_status(data.uuid_status) : "not_checked";
  const char *serial = status == AX_WINDOWS_FIRMWARE_OK ? signal_status(data.serial_status) : "not_checked";
  const char *board = status == AX_WINDOWS_FIRMWARE_OK ? signal_status(data.board_serial_status) : "not_checked";
  printf("{\"schema_version\":1,\"platform\":\"windows\",\"architecture\":\"%s\","
         "\"privilege\":\"%s\",\"firmware\":\"%s\",\"signals\":{"
         "\"product_uuid\":\"%s\",\"system_serial\":\"%s\",\"board_serial\":\"%s\","
         "\"machine_guid_metadata\":\"%s\"}}\n",
         architecture(), privilege(), firmware_status(status), uuid, serial, board, registry_metadata());
  SecureZeroMemory(&data, sizeof data);
  return 0;
}
