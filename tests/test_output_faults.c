/* Synthetic JSON output boundary and allocation fault tests. No OS collection. */
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail_output_allocation;
static int fail_canonical, fake_no_signals;
static size_t format_calls, fail_format_at;
static void *test_output_malloc(size_t n);
static int test_snprintf(char *out, size_t len, const char *format, ...);
#define malloc test_output_malloc
#define snprintf test_snprintf
#include "../src/archx.c"
#undef malloc
#undef snprintf

static int test_snprintf(char *out, size_t len, const char *format, ...) {
  format_calls++;
  if (fail_format_at && format_calls == fail_format_at) return -1;
  va_list ap; va_start(ap, format);
  int n = vsnprintf(out, len, format, ap);
  va_end(ap); return n;
}

static void *test_output_malloc(size_t n) {
  if (fail_output_allocation) { fail_output_allocation = 0; return NULL; }
  return malloc(n);
}

static void fake_signals(ax_signal_set *out) {
  memset(out, 0, sizeof *out);
  snprintf(out->os, sizeof out->os, "linux");
  snprintf(out->arch, sizeof out->arch, "synthetic");
  out->signal_count = 1;
  snprintf(out->signals[0].name, sizeof out->signals[0].name, "machine_id");
  snprintf(out->signals[0].value, sizeof out->signals[0].value, "synthetic");
  out->signals[0].readable = !fake_no_signals; out->signals[0].weight = 60;
}
int ax_signals_collect_linux(ax_signal_set *out) { fake_signals(out); return 0; }
int ax_signals_collect_linux_selected(ax_signal_set *out, unsigned mask) { (void)mask; fake_signals(out); return 0; }
size_t ax_signals_canonical(const ax_signal_set *set, char *out, size_t len) {
  (void)set;
  if (fail_canonical) return SIZE_MAX;
  int n = snprintf(out, len, "synthetic"); return n < 0 ? SIZE_MAX : (size_t)n;
}
int ax_signals_fallback_id(char *out, size_t len) {
  if (!fake_no_signals || len < 65) return -1;
  memset(out, 'a', 64); out[64] = '\0'; return 0;
}

static void require_oom(ax_result result, char *out) {
  assert(result == AX_ERR_NOMEM && out == NULL);
  assert(strstr(ax_last_error(), "out of memory") != NULL);
}
static ax_result call_output(int kind, ax_core *core, const char *profile, size_t len, char **out) {
  switch (kind) {
    case 0: return ax_collect(core, out, NULL);
    case 1: case 4: return ax_identify(core, out, NULL);
    case 2: return ax_profile(core, out, NULL);
    case 5: return ax_collect_capabilities(core, out, NULL);
    default: return ax_compare(core, profile, len, profile, len, out, NULL);
  }
}
static void check_format_faults(ax_core *core, const char *profile, size_t profile_len) {
  for (int kind=0; kind<6; kind++) {
    fake_no_signals = kind == 4;
    char *out = NULL; format_calls = 0; fail_format_at = 0;
    assert(call_output(kind, core, profile, profile_len, &out) == AX_OK);
    size_t count = format_calls; assert(count > 0); ax_buffer_free(out);
    for (size_t i=1; i<=count; i++) {
      format_calls=0; fail_format_at=i; out=(char *)profile;
      assert(call_output(kind, core, profile, profile_len, &out) == AX_ERR_INTERNAL);
      assert(out == NULL && *ax_last_error());
      fail_format_at=0;
      assert(call_output(kind, core, profile, profile_len, &out) == AX_OK);
      ax_buffer_free(out);
    }
  }
  fake_no_signals = 0;
  int64_t remaining=9, retry=9;
  format_calls=0; fail_format_at=1;
  assert(ax_check(core,"synthetic-format-fault",100,&remaining,&retry) == AX_DENY_RATE_LIMIT);
  assert(remaining == 0 && retry == -1 && strstr(ax_last_error(),"formatting failed"));
  fail_format_at=0;
  assert(ax_check(core,"synthetic-format-fault",100,&remaining,&retry) == AX_ALLOW && remaining == 0);
  format_calls=0; fail_format_at=1;
  assert(ax_reset(core,"synthetic-format-fault") == AX_ERR_INTERNAL);
  fail_format_at=0;
  assert(ax_check(core,"synthetic-format-fault",100,&remaining,&retry) == AX_DENY_RATE_LIMIT);
}
int main(void) {
  char guarded[] = {'A', 'B', 'C', 'D', 'E'};
  size_t pos = SIZE_MAX;
  assert(append_str(guarded, 4, &pos, "a") != 0);
  assert(json_escape_append(guarded, 4, &pos, "") != 0);
  assert(memcmp(guarded, "ABCDE", 5) == 0);
  pos = 0; guarded[0] = '\0';
  assert(append_str(guarded, 4, &pos, "abc") == 0 && pos == 3);
  assert(append_str(guarded, 4, &pos, "d") != 0 && guarded[4] == 'E');
  pos = 0; guarded[0] = '\0';
  assert(json_escape_append(guarded, 4, &pos, "\\\"") != 0 && guarded[4] == 'E');
  char unterminated[] = {'x', 'y', 'z'}; char *out = NULL; size_t out_len = 0;
  assert(emit_json(unterminated, sizeof unterminated, &out, &out_len) == AX_ERR_INTERNAL && !out);
  assert(strstr(ax_last_error(), "not terminated") != NULL);
  char valid[] = "{}";
  assert(emit_json(valid, sizeof valid, &out, &out_len) == AX_OK);
  assert(out_len == 2 && strcmp(out, "{}") == 0); ax_buffer_free(out); out = NULL;
  fail_output_allocation = 1;
  assert(emit_json(valid, sizeof valid, &out, &out_len) == AX_ERR_NOMEM && !out);

  char config[1000] = "{\"app_id\":\"";
  for (int i=0; i<127; i++) strcat(config, "\\u0001");
  strcat(config, "\",\"pepper\":\"synthetic\",\"store_capacity\":16}");
  ax_core *core = ax_core_new(config, strlen(config)); assert(core);
  fail_output_allocation = 1;
  ax_result rc = ax_collect(core, &out, &out_len); require_oom(rc, out);
  fail_output_allocation = 1;
  rc = ax_collect_capabilities(core, &out, &out_len); require_oom(rc, out);
  fail_canonical = 1;
  rc = ax_identify(core, &out, &out_len);
  assert(rc == AX_ERR_INTERNAL && out == NULL && strstr(ax_last_error(), "canonicalization failed"));
  fail_canonical = 0;
  fail_output_allocation = 1;
  rc = ax_identify(core, &out, &out_len); require_oom(rc, out);
  assert(ax_identify(core, &out, &out_len) == AX_OK);
  ax_json_value *parsed = NULL;
  assert(ax_json_parse(out, out_len, &parsed) == 0);
  const char *app_id = ax_json_get_string(parsed, "app_id");
  assert(app_id && strlen(app_id) == 127);
  for (int i=0; i<127; i++) assert(app_id[i] == 1);
  ax_json_free(parsed); ax_buffer_free(out); out = NULL;
  fail_output_allocation = 1;
  rc = ax_profile(core, &out, &out_len); require_oom(rc, out);
  assert(ax_profile(core, &out, &out_len) == AX_OK);
  char *profile = out; size_t profile_len = out_len; out = NULL;
  fail_output_allocation = 1;
  rc = ax_compare(core, profile, profile_len, profile, profile_len, &out, &out_len);
  require_oom(rc, out);
  assert(ax_compare(core, profile, profile_len, profile, profile_len, &out, &out_len) == AX_OK);
  assert(ax_json_parse(out, out_len, &parsed) == 0);
  ax_json_free(parsed); ax_buffer_free(out);
  check_format_faults(core, profile, profile_len);
  ax_buffer_free(profile); ax_core_free(core);
  puts("synthetic JSON output boundary and allocation faults passed");
  return 0;
}
