/* macOS interval clock. CLOCK_UPTIME_RAW is intended to exclude system sleep. */
#include "platform.h"
#include <time.h>
#include <Security/SecRandom.h>

int ax_platform_monotonic_ms(int64_t *out) {
  struct timespec ts;
  if (!out || clock_gettime(CLOCK_UPTIME_RAW, &ts) != 0 || ts.tv_sec < 0 ||
      ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000 ||
      (uint64_t)ts.tv_sec > (uint64_t)(INT64_MAX - 999) / 1000) return -1;
  *out = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
  return 0;
}

int ax_platform_random(void *out, size_t len) {
  if (len == 0) return 0;
  if (!out || len > 256) return -1;
  return SecRandomCopyBytes(kSecRandomDefault, len, out) == 0 ? 0 : -1;
}
