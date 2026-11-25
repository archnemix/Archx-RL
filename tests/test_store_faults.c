/* Deterministic platform failures and time changes for the C limiter API. */
#include "archx.h"
#include "store.h"
#include "fake_platform.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  const char *config = "{\"app_id\":\"fault-test\",\"pepper\":\"secret\",\"store_capacity\":16,\"rate_limit\":{\"capacity\":2,\"refill_per_sec\":1}}";
  ax_test_fail_init = 1;
  assert(!ax_core_new(config, strlen(config)));
  ax_test_fail_init = 0;
  ax_core *core = ax_core_new(config, strlen(config)); assert(core);
  int64_t remaining = 9, retry = 9;
  ax_test_fail_lock = 1;
  assert(ax_check(core, "victim", 1, &remaining, &retry) == AX_DENY_RATE_LIMIT);
  assert(remaining == 0 && retry == -1 && strstr(ax_last_error(), "platform failure"));
  assert(ax_reset(core, "victim") == AX_ERR_INTERNAL);
  ax_test_fail_lock = 0;
  ax_test_fail_clock = 1;
  assert(ax_check(core, "victim", 1, &remaining, &retry) == AX_DENY_RATE_LIMIT);
  assert(strstr(ax_last_error(), "platform failure"));
  ax_test_fail_clock = 0;
  /* Failed operations above did not create or charge a bucket. */
  assert(ax_check(core, "victim", 1, &remaining, &retry) == AX_ALLOW && remaining == 1);
  assert(ax_check(core, "victim", 1, &remaining, &retry) == AX_ALLOW && remaining == 0);
  ax_test_now = 500; /* backward clock observation cannot refill */
  assert(ax_check(core, "victim", 1, &remaining, &retry) == AX_DENY_RATE_LIMIT && remaining == 0);
  ax_test_now = 1500; /* fractional refill is retained */
  assert(ax_check(core, "victim", 1, &remaining, &retry) == AX_DENY_RATE_LIMIT && retry == 500);
  ax_test_now = 2000;
  assert(ax_check(core, "victim", 1, &remaining, &retry) == AX_ALLOW && remaining == 0);
  ax_test_fail_unlock = 1;
  assert(ax_check(core, "another", 1, &remaining, &retry) == AX_DENY_RATE_LIMIT);
  assert(remaining == 0 && retry == -1 && strstr(ax_last_error(), "platform failure"));
  ax_test_fail_unlock = 0;
  /* A failed unlock may occur after a charge: errors do not imply rollback. */
  assert(ax_check(core, "another", 2, &remaining, &retry) == AX_DENY_RATE_LIMIT && remaining == 1);
  ax_test_fail_unlock = 1;
  assert(ax_reset(core, "another") == AX_ERR_INTERNAL);
  ax_test_fail_unlock = 0;
  /* The failed unlock also follows an already-completed reset. */
  assert(ax_check(core, "another", 2, &remaining, &retry) == AX_ALLOW);
  ax_core_free(core);
  puts("store platform fault injection passed");
  return 0;
}
