/* Fail each core/store allocation; all input and signals are synthetic. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t calls, fail_at, live;
static void *fault_calloc(size_t count, size_t size);
static void fault_free(void *ptr);
#define calloc fault_calloc
#define free fault_free
#include "../src/archx.c"
#include "../src/store.c"
#undef calloc
#undef free
static void *fault_calloc(size_t n, size_t size) {
  calls++;
  if (fail_at && calls == fail_at) return NULL;
  void *p = calloc(n, size);
  if (p) live++;
  return p;
}
static void fault_free(void *p) {
  if (p) { assert(live > 0); live--; free(p); }
}
int ax_platform_collect_signals(ax_signal_set *out) { (void)out; return -1; }
int ax_platform_collect_selected(ax_signal_set *out, unsigned mask) { (void)out; (void)mask; return -1; }
size_t ax_signals_canonical(const ax_signal_set *set, char *out, size_t size) { (void)set; (void)out; (void)size; return SIZE_MAX; }
int ax_platform_fallback_id(char *out, size_t size) { (void)out; (void)size; return -1; }
int main(void) {
  const char *config = "{\"app_id\":\"test\",\"pepper\":\"synthetic\",\"store_capacity\":16}";
  calls=0; fail_at=0;
  ax_core *core=ax_core_new(config,strlen(config)); assert(core && live == 3);
  size_t allocations=calls; assert(allocations == 3);
  ax_core_free(core); assert(live == 0);
  for (size_t i=1; i<=allocations; i++) {
    calls=0; fail_at=i;
    assert(ax_core_new(config,strlen(config)) == NULL);
    assert(*ax_last_error() && live == 0);
    calls=0; fail_at=0;
    core=ax_core_new(config,strlen(config)); assert(core);
    assert(ax_check(core,"synthetic-key",1,NULL,NULL)==AX_ALLOW);
    ax_core_free(core); assert(live == 0);
  }
  puts("synthetic core/store allocation faults passed");
  return 0;
}
