/* Deterministic parser allocation faults and public error propagation.
 * The injection boundary affects only json.c, never real device signals. */
#include "archx.h"
#include "platform_signals.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t alloc_calls, fail_at, live;
static void *fault_malloc(size_t n);
static void *fault_calloc(size_t n, size_t size);
static void *fault_realloc(void *p, size_t n);
static void fault_free(void *p);
#define malloc fault_malloc
#define calloc fault_calloc
#define realloc fault_realloc
#define free fault_free
#include "../src/json.c"
#undef malloc
#undef calloc
#undef realloc
#undef free

static int should_fail(void) { alloc_calls++; return fail_at && alloc_calls == fail_at; }
static void *fault_malloc(size_t n) {
  if (should_fail()) return NULL;
  void *p = malloc(n); if (p) live++; return p;
}
static void *fault_calloc(size_t n, size_t size) {
  if (should_fail()) return NULL;
  void *p = calloc(n, size); if (p) live++; return p;
}
static void *fault_realloc(void *p, size_t n) {
  if (should_fail()) return NULL;
  int was_null = p == NULL;
  void *result = realloc(p, n);
  if (result && was_null) live++;
  return result;
}
static void fault_free(void *p) { if (p) { assert(live > 0); live--; free(p); } }
static void reset(size_t at) { assert(live == 0); alloc_calls = 0; fail_at = at; }

static void fake_signals(ax_signal_set *out) {
  memset(out, 0, sizeof *out);
  snprintf(out->os, sizeof out->os, "linux");
  snprintf(out->arch, sizeof out->arch, "synthetic");
  out->signal_count = 1;
  snprintf(out->signals[0].name, sizeof out->signals[0].name, "machine_id");
  snprintf(out->signals[0].value, sizeof out->signals[0].value, "synthetic");
  out->signals[0].readable = 1; out->signals[0].weight = 60;
}
ax_platform_scope ax_platform_profile_scope(void) { return AX_PLATFORM_SCOPE_LINUX; }
int ax_platform_collect_signals(ax_signal_set *out) { fake_signals(out); return 0; }
int ax_platform_collect_selected(ax_signal_set *out, unsigned mask) { (void)mask; fake_signals(out); return 0; }
size_t ax_signals_canonical(const ax_signal_set *set, char *out, size_t len) {
  (void)set; int n = snprintf(out, len, "synthetic"); return n < 0 ? SIZE_MAX : (size_t)n;
}
int ax_platform_fallback_id(char *out, size_t len) { (void)out; (void)len; return -1; }

int main(void) {
  const char *fixture = "{\"long\":\"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz\","
      "\"two\":\"123456789012345678901234567890\\u07ff\","
      "\"three\":\"12345678901234567890123456789\\u0800\","
      "\"obj\":{\"one\":1,\"yes\":true,\"no\":false,\"none\":null}}";
  ax_json_value *value = NULL;
  reset(0); assert(ax_json_parse(fixture, strlen(fixture), &value) == 0);
  size_t parser_allocs = alloc_calls; assert(parser_allocs > 10);
  ax_json_free(value); assert(live == 0);
  for (size_t i = 1; i <= parser_allocs; i++) {
    reset(i); value = (ax_json_value *)fixture;
    assert(ax_json_parse(fixture, strlen(fixture), &value) == AX_JSON_NOMEM);
    assert(value == NULL && live == 0);
  }
  reset(0); assert(ax_json_parse("{", 1, &value) == AX_JSON_INVALID && value == NULL && live == 0);

  const char *config = "{\"app_id\":\"test\",\"pepper\":\"synthetic\",\"store_capacity\":16,"
                       "\"extra\":\"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz\"}";
  reset(0); ax_core *core = ax_core_new(config, strlen(config)); assert(core);
  size_t config_allocs = alloc_calls; assert(live == 0);
  ax_core_free(core);
  for (size_t i = 1; i <= config_allocs; i++) {
    reset(i); core = ax_core_new(config, strlen(config));
    assert(core == NULL && strstr(ax_last_error(), "out of memory parsing config") && live == 0);
  }
  reset(0); core = ax_core_new(config, strlen(config)); assert(core && live == 0);
  char *profile = NULL; size_t profile_len = 0;
  assert(ax_profile(core, &profile, &profile_len) == AX_OK && profile);
  char *output = NULL; size_t out_len = 0;
  reset(0); assert(ax_compare(core, profile, profile_len, profile, profile_len, &output, &out_len) == AX_OK);
  size_t compare_allocs = alloc_calls; assert(live == 0 && compare_allocs > 2);
  ax_buffer_free(output);
  for (size_t i = 1; i <= compare_allocs; i++) {
    reset(i); output = profile; /* must be cleared, not returned on failure */
    ax_result status = ax_compare(core, profile, profile_len, profile, profile_len, &output, &out_len);
    assert(status == AX_ERR_NOMEM && output == NULL && strstr(ax_last_error(), "out of memory parsing profile") && live == 0);
  }
  reset(0); output = profile;
  assert(ax_compare(core, profile, profile_len, "{", 1, &output, &out_len) == AX_ERR_INVALID);
  assert(output == NULL && strstr(ax_last_error(), "invalid or incompatible profile") && live == 0);
  reset(0); output = NULL;
  assert(ax_compare(core, profile, profile_len, profile, profile_len, &output, &out_len) == AX_OK);
  ax_buffer_free(output); ax_buffer_free(profile); ax_core_free(core);
  assert(live == 0);
  puts("synthetic JSON allocation and public propagation faults passed");
  return 0;
}
