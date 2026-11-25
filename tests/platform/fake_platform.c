#include "platform.h"
#include "fake_platform.h"
#include <stdlib.h>
#include <string.h>
struct ax_platform_mutex { int locked; };
int ax_test_fail_init, ax_test_fail_lock, ax_test_fail_unlock, ax_test_fail_clock, ax_test_fail_random;
int64_t ax_test_now = 1000;
ax_platform_mutex *ax_platform_mutex_new(void) {
  return ax_test_fail_init ? NULL : (ax_platform_mutex *)calloc(1, sizeof(ax_platform_mutex));
}
void ax_platform_mutex_free(ax_platform_mutex *mutex) { free(mutex); }
int ax_platform_mutex_lock(ax_platform_mutex *mutex) {
  if (!mutex || mutex->locked || ax_test_fail_lock) return -1;
  mutex->locked = 1; return 0;
}
int ax_platform_mutex_unlock(ax_platform_mutex *mutex) {
  if (!mutex || !mutex->locked) return -1;
  mutex->locked = 0; return ax_test_fail_unlock ? -1 : 0;
}
int ax_platform_monotonic_ms(int64_t *out) {
  if (!out || ax_test_fail_clock) return -1;
  *out = ax_test_now; return 0;
}

int ax_platform_random(void *out, size_t len) {
  if (len == 0) return 0;
  if (!out || len > 256 || ax_test_fail_random) return -1;
  memset(out, 0xa5, len); /* deterministic synthetic fixture, not real entropy */
  return 0;
}
