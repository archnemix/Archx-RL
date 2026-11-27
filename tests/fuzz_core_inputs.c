/* Coverage-guided JSON/config/profile smoke. All fixed data are synthetic. */
#include "archx.h"
#include "json.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 65536) return 0;
  ax_json_value *json = NULL;
  int parsed = ax_json_parse((const char *)data, size, &json);
  if (parsed == 0 && !json) abort();
  ax_json_free(json);

  /* No collector is called by configuration parsing. */
  ax_core *maybe = ax_core_new((const char *)data, size);
  if (maybe) ax_core_free(maybe);

  /* Compare against an actual deterministic profile using a synthetic
   * collector; never read real host signals or print a fuzzed input. */
  static const char config[] = "{\"app_id\":\"fixture-app\",\"pepper\":\"synthetic-test-pepper\","
    "\"match\":{\"mode\":\"threshold\",\"min_matches\":1,\"signals\":{\"ip\":\"required\"}}}";
  ax_core *core = ax_core_new(config, sizeof config - 1);
  if (!core) abort();
  char *profile = NULL, *result = NULL;
  size_t profile_len = 0, result_len = 0;
  if (ax_profile_with_ip(core, "192.0.2.1", &profile, &profile_len) != AX_OK || !profile) abort();
  if (size <= 8192) {
    ax_result rc = ax_compare(core, profile, profile_len, (const char *)data, size, &result, &result_len);
    if (rc == AX_OK && (!result || result_len != strlen(result))) abort();
    if (rc != AX_OK && result != NULL) abort();
    ax_buffer_free(result);
  }
  ax_buffer_free(profile);
  ax_core_free(core);
  return 0;
}
