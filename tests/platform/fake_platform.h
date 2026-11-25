/* Deterministic fault injection only; never link into a production library. */
#ifndef AX_TEST_FAKE_PLATFORM_H
#define AX_TEST_FAKE_PLATFORM_H
#include <stdint.h>
extern int ax_test_fail_init, ax_test_fail_lock, ax_test_fail_unlock, ax_test_fail_clock, ax_test_fail_random;
extern int64_t ax_test_now;
#endif
