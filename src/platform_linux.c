/* Linux interval clock. CLOCK_MONOTONIC excludes suspended time. */
#include "platform.h"
#include <time.h>

int ax_platform_monotonic_ms(int64_t *out) {
  struct timespec ts;
  if (!out || clock_gettime(CLOCK_MONOTONIC, &ts) != 0 || ts.tv_sec < 0 ||
      ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000 ||
      (uint64_t)ts.tv_sec > (uint64_t)(INT64_MAX - 999) / 1000) return -1;
  *out = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
  return 0;
}
