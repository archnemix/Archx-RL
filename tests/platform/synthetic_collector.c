/* Test-only deterministic adapter. No OS or device identifier is read. */
#include "platform_signals.h"
#include <stdio.h>
#include <string.h>

static int fail_collect;
static ax_platform_scope scope = AX_PLATFORM_SCOPE_LINUX;
void ax_test_collector_failure(int value) { fail_collect = value; }
void ax_test_collector_scope(int value) { scope = (ax_platform_scope)value; }
ax_platform_scope ax_platform_profile_scope(void) { return scope; }
int ax_platform_collect_selected(ax_signal_set *out, unsigned mask) {
  static const char *const names[] = {"machine_id", "product_uuid", "board_serial"};
  static const int weights[] = {60, 25, 15};
  if (!out || fail_collect) return -1;
  memset(out, 0, sizeof *out);
  /* ABI v1 currently retains Linux schema and scope; not native support. */
  memcpy(out->os, "linux", sizeof "linux");
  memcpy(out->arch, "synthetic", sizeof "synthetic");
  for (size_t i = 0; i < 3; i++) if (mask & (1u << i)) {
    ax_signal *signal = &out->signals[out->signal_count++];
    int n = snprintf(signal->name, sizeof signal->name, "%s", names[i]);
    if (n < 0 || (size_t)n >= sizeof signal->name) return -1;
    n = snprintf(signal->value, sizeof signal->value, "synthetic-%zu", i);
    if (n < 0 || (size_t)n >= sizeof signal->value) return -1;
    signal->weight = weights[i];
    signal->readable = 1;
    signal->status = AX_SIGNAL_AVAILABLE;
  }
  return 0;
}
int ax_platform_collect_signals(ax_signal_set *out) { return ax_platform_collect_selected(out, 7u); }
int ax_platform_fallback_id(char *out, size_t out_len) {
  if (!out || out_len < 65) return -1;
  memset(out, 'a', 64); out[64] = '\0';
  return 0;
}
