/* Windows exclusive SRW lock and unbiased, sleep-excluding interval clock. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <realtimeapiset.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>
#include "platform.h"

struct ax_platform_mutex { SRWLOCK native; };

ax_platform_mutex *ax_platform_mutex_new(void) {
  ax_platform_mutex *mutex = (ax_platform_mutex *)malloc(sizeof *mutex);
  if (!mutex) return NULL;
  InitializeSRWLock(&mutex->native);
  return mutex;
}
void ax_platform_mutex_free(ax_platform_mutex *mutex) { free(mutex); }
int ax_platform_mutex_lock(ax_platform_mutex *mutex) {
  if (!mutex) return -1;
  AcquireSRWLockExclusive(&mutex->native);
  return 0;
}
int ax_platform_mutex_unlock(ax_platform_mutex *mutex) {
  if (!mutex) return -1;
  ReleaseSRWLockExclusive(&mutex->native);
  return 0;
}
int ax_platform_monotonic_ms(int64_t *out) {
  ULONGLONG ticks;
  if (!out || !QueryUnbiasedInterruptTime(&ticks) || ticks / 10000 > (ULONGLONG)INT64_MAX) return -1;
  *out = (int64_t)(ticks / 10000);
  return 0;
}

int ax_platform_random(void *out, size_t len) {
  if (len == 0) return 0;
  if (!out || len > 256) return -1;
  return BCryptGenRandom(NULL, (PUCHAR)out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
}
int ax_platform_normalize_ip(const char *input, char *out, size_t out_len) {
  struct in6_addr address;
  char normalized[AX_PLATFORM_IP_TEXT_MAX];
  if (!input || !out) return -1;
  int family = strchr(input, ':') ? AF_INET6 : AF_INET;
  if (InetPtonA(family, input, &address) != 1 ||
      !InetNtopA(family, &address, normalized, (DWORD)sizeof normalized)) return -1;
  size_t len = strlen(normalized) + 1;
  if (out_len < len) return -1;
  memcpy(out, normalized, len);
  return 0;
}
