/* Synthetic installed-package consumer: no device signals are collected. */
#include <archx.h>
#include <string.h>
int main(void) {
  const char config[] = "{\"app_id\":\"consumer-test\",\"pepper\":\"synthetic\",\"rate_limit\":{\"capacity\":1,\"refill_per_sec\":0}}";
  if (ax_abi_version() != AX_ABI_VERSION) return 1;
  ax_core *core = ax_core_new(config, strlen(config));
  if (!core) return 2;
  int result = ax_check(core, "synthetic-key", 1, 0, 0) == AX_ALLOW &&
               ax_check(core, "synthetic-key", 1, 0, 0) == AX_DENY_RATE_LIMIT &&
               !*ax_last_error();
  ax_core_free(core);
  return result ? 0 : 3;
}
