/* Linux interval clock. CLOCK_MONOTONIC excludes suspended time. */
#include "platform.h"
#include <time.h>
#include <errno.h>
#include <sys/random.h>

int ax_platform_monotonic_ms(int64_t *out) {
  struct timespec ts;
  if (!out || clock_gettime(CLOCK_MONOTONIC, &ts) != 0 || ts.tv_sec < 0 ||
      ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000 ||
      (uint64_t)ts.tv_sec > (uint64_t)(INT64_MAX - 999) / 1000) return -1;
  *out = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
  return 0;
}

/* Fail rather than use potentially uninitialized randomness during early boot. */
int ax_platform_random(void *out, size_t len) {
  if (len == 0) return 0;
  if (!out || len > 256) return -1;
  size_t offset = 0;
  while (offset < len) {
    ssize_t count = getrandom((unsigned char *)out + offset, len - offset, GRND_NONBLOCK);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return -1;
    offset += (size_t)count;
  }
  return 0;
}
