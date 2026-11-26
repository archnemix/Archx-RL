/* ABI v1 synthetic coverage-score semantics, independent of host identifiers. */
#include "archx.h"
#include "json.h"
#include "signals_linux.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned mask;
static int fallback_fails;
static ax_signal_status fake_status;
static void signals(ax_signal_set *out, unsigned selected) {
  static const char *const names[] = {"machine_id", "product_uuid", "board_serial"};
  static const int weights[] = {60, 25, 15};
  memset(out, 0, sizeof *out);
  snprintf(out->os, sizeof out->os, "linux");
  snprintf(out->arch, sizeof out->arch, "synthetic");
  for (size_t i=0; i<3; i++) if (selected & (1u << i)) {
    ax_signal *sig = &out->signals[out->signal_count++];
    snprintf(sig->name, sizeof sig->name, "%s", names[i]);
    snprintf(sig->value, sizeof sig->value, "synthetic-%zu", i);
    sig->weight = weights[i]; sig->readable = (mask & (1u << i)) != 0;
    sig->status = fake_status;
  }
}
int ax_signals_collect_linux(ax_signal_set *out) { signals(out, 7); return 0; }
int ax_signals_collect_linux_selected(ax_signal_set *out, unsigned selected) { signals(out, selected); return 0; }
size_t ax_signals_canonical(const ax_signal_set *set, char *out, size_t len) {
  (void)set; int n = snprintf(out, len, "synthetic-%u", mask); return n < 0 ? 0 : (size_t)n;
}
int ax_signals_fallback_id(char *out, size_t len) {
  if (fallback_fails || len < 65) return -1;
  memset(out, 'a', 64); out[64] = '\0'; return 0;
}

int main(void) {
  const char *config = "{\"app_id\":\"synthetic\",\"pepper\":\"synthetic\",\"store_capacity\":16}";
  ax_core *core = ax_core_new(config, strlen(config)); assert(core);
  assert(ax_abi_version() == 1);
  mask = 0; fallback_fails = 1;
  char *failed_result = (char *)config; size_t failed_len = 99;
  assert(ax_identify(core, &failed_result, &failed_len) == AX_ERR_INTERNAL);
  assert(failed_result == NULL && strstr(ax_last_error(), "fallback ID unavailable"));
  fallback_fails = 0;
  for (mask = 0; mask < 8; mask++) {
    char *result = NULL; size_t len = 0; ax_json_value *doc = NULL;
    assert(ax_identify(core, &result, &len) == AX_OK);
    assert(ax_json_parse(result, len, &doc) == 0);
    const ax_json_value *confidence = ax_json_get(doc, "confidence");
    const ax_json_value *used = ax_json_get(doc, "signals_used");
    const char *tier = ax_json_get_string(doc, "tier");
    assert(confidence && confidence->type == AX_J_NUMBER);
    assert(used && used->type == AX_J_NUMBER);
    assert(tier != NULL);
    int expected = mask ? ((mask & 1 ? 60 : 0) + (mask & 2 ? 25 : 0) + (mask & 4 ? 15 : 0)) : 10;
    int count = !!(mask & 1) + !!(mask & 2) + !!(mask & 4);
    assert(confidence->num == expected && used->num == count);
    assert(strcmp(tier, mask == 7 ? "full" : mask ? "partial" : "fallback") == 0);
    assert(ax_json_get(doc, "coverage") == NULL); /* v1 schema is unchanged */
    ax_json_free(doc); ax_buffer_free(result);
  }
  /* Schema statuses are metadata, never the synthetic raw signal value. */
  static const char *const states[] = {"unknown", "available", "absent", "denied", "placeholder", "invalid", "read_error", "unsupported"};
  for (int status=0; status<8; status++) {
    fake_status = (ax_signal_status)status;
    mask = status == AX_SIGNAL_AVAILABLE ? 7u : 0u;
    char *result = NULL; size_t len = 0; ax_json_value *doc = NULL;
    assert(ax_collect_capabilities(core, &result, &len) == AX_OK);
    assert(!strstr(result, "synthetic-0") && !strstr(result, "synthetic-1"));
    assert(ax_json_parse(result, len, &doc) == 0);
    assert(!strcmp(ax_json_get_string(doc,"schema"), "archx.capabilities"));
    assert(ax_json_get_number(doc,"version",0) == 1);
    const ax_json_value *signals = ax_json_get_object(doc,"signals");
    const ax_json_value *machine = ax_json_get_object(signals,"machine_id");
    const ax_json_value *firmware = ax_json_get_object(signals,"product_uuid");
    const ax_json_value *app = ax_json_get_object(signals,"app_install");
    const ax_json_value *ip = ax_json_get_object(signals,"ip");
    assert(!strcmp(ax_json_get_string(machine,"kind"), "os_install"));
    assert(!strcmp(ax_json_get_string(machine,"status"), states[status]));
    assert(!strcmp(ax_json_get_string(firmware,"kind"), "firmware"));
    assert(!strcmp(ax_json_get_string(firmware,"status"), states[status]));
    assert(!strcmp(ax_json_get_string(app,"status"), "not_collected"));
    assert(!strcmp(ax_json_get_string(ip,"status"), "host_provided"));
    ax_json_free(doc); ax_buffer_free(result);
  }
  fake_status = AX_SIGNAL_AVAILABLE; mask = 0;
  char *inconsistent = NULL;
  assert(ax_collect_capabilities(core, &inconsistent, NULL) == AX_OK);
  assert(strstr(inconsistent, "\"status\":\"unknown\""));
  ax_buffer_free(inconsistent);
  ax_core_free(core);
  puts("synthetic ABI-v1 availability-score semantics and capability statuses passed");
  return 0;
}
