/* Synthetic provider tests plus an availability-only native Windows smoke. */
#include "signals_windows.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "Windows firmware test failed at line %d: %s\n", __LINE__, #expr); return 1; } } while (0)
typedef struct { int mode; unsigned calls; } provider_state;
static uint32_t provider(void *context, void *buffer, uint32_t capacity, uint32_t *error) {
  provider_state *s = (provider_state *)context;
  s->calls++;
  if (s->mode == 1) { *error = ERROR_ACCESS_DENIED; return 0; }
  if (s->mode == 2) { *error = ERROR_NOT_SUPPORTED; return 0; }
  if (s->mode == 3) return AX_SMBIOS_MAX_RAW + 1u;
  if (!buffer) return 14;
  if (s->mode == 4) return capacity + 1;
  if (capacity < 14) return 0;
  const unsigned char fixture[14] = {0,2,6,0,6,0,0,0,127,4,0,0,0,0};
  memcpy(buffer, fixture, sizeof fixture);
  if (s->mode == 5) ((unsigned char *)buffer)[4] = 7; /* header/table mismatch */
  return 14;
}
int main(void) {
  ax_smbios_result out;
  provider_state state = {0,0};
  CHECK(ax_windows_collect_firmware_with_provider(provider, &state, &out) == AX_WINDOWS_FIRMWARE_OK);
  CHECK(state.calls == 2 && out.uuid_status == AX_SMBIOS_ABSENT);
  state.mode=1; state.calls=0;
  CHECK(ax_windows_collect_firmware_with_provider(provider, &state, &out) == AX_WINDOWS_FIRMWARE_DENIED && state.calls == 1);
  state.mode=2; CHECK(ax_windows_collect_firmware_with_provider(provider, &state, &out) == AX_WINDOWS_FIRMWARE_UNSUPPORTED);
  for (int mode=3; mode<=5; mode++) {
    state.mode=mode; state.calls=0; memset(&out, 0xa5, sizeof out);
    CHECK(ax_windows_collect_firmware_with_provider(provider, &state, &out) == AX_WINDOWS_FIRMWARE_READ_ERROR);
    CHECK(out.uuid_status == AX_SMBIOS_ABSENT && out.serial_status == AX_SMBIOS_ABSENT && !out.uuid[0] && !out.serial[0]);
    if (mode == 3) CHECK(state.calls == 1);
  }
  CHECK(ax_windows_collect_firmware_with_provider(NULL, NULL, &out) == AX_WINDOWS_FIRMWARE_READ_ERROR);
  CHECK(ax_windows_collect_firmware(NULL) == AX_WINDOWS_FIRMWARE_READ_ERROR);
  /* Availability only: do not print, store or assert any actual identifiers. */
  ax_windows_firmware_status status = ax_windows_collect_firmware(&out);
  CHECK(status >= AX_WINDOWS_FIRMWARE_OK && status <= AX_WINDOWS_FIRMWARE_READ_ERROR);
  static const char *const names[] = {"available", "denied", "unsupported", "read-error"};
  printf("Windows RSMB availability: %s (no values logged)\n", names[status]);
  SecureZeroMemory(&out, sizeof out);
  puts("Windows firmware provider boundary tests passed");
  return 0;
}
