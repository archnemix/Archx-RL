/* Exercises the actual ABI against a synthetic collector, not a product port. */
#include "archx.h"
#include "../../src/platform_signals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ax_test_collector_failure(int value);
void ax_test_collector_scope(int value);
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "synthetic core failed at line %d: %s\n", __LINE__, #expr); return 1; } } while (0)
int main(void) {
  const char config[] = "{\"app_id\":\"fixture-app\",\"pepper\":\"synthetic-test-pepper\","
    "\"rate_limit\":{\"capacity\":2,\"refill_per_sec\":0},"
    "\"match\":{\"mode\":\"threshold\",\"min_matches\":1,\"signals\":{\"ip\":\"required\"}}}";
  CHECK(ax_abi_version() == 1);
  ax_core *core = ax_core_new(config, strlen(config));
  CHECK(core != NULL);
  char *data = NULL, *profile = NULL, *other = NULL;
  size_t data_len = 0, profile_len = 0, other_len = 0;
  CHECK(ax_collect(core, &data, &data_len) == AX_OK && data && data_len == strlen(data));
  CHECK(strstr(data, "synthetic-0") == NULL);
  ax_buffer_free(data); data = NULL;
  CHECK(ax_identify(core, &data, &data_len) == AX_OK && strstr(data, "\"tier\":\"full\""));
  CHECK(!strstr(data, "synthetic-0"));
  ax_buffer_free(data); data = NULL;
  CHECK(ax_profile_with_ip(core, "192.0.2.1", &profile, &profile_len) == AX_OK);
  CHECK(strstr(profile, "62f93cf57207daeca51045d3bd65ae94f4fc4c1f79ed375f2f8022d5636cb566"));
  CHECK(strstr(profile, "09efab5a5e4f00bfab861eec4b52e816964f929996a35576a60fac59f3a5f2d0"));
  const char env_config[] = "{\"app_id\":\"fixture-app\",\"pepper_env\":\"ARCHX_SYNTHETIC_CORE_ENV\","
    "\"rate_limit\":{\"capacity\":2,\"refill_per_sec\":0},"
    "\"match\":{\"mode\":\"threshold\",\"min_matches\":1,\"signals\":{\"ip\":\"required\"}}}";
#ifdef _WIN32
  CHECK(_putenv_s("ARCHX_SYNTHETIC_CORE_ENV", "synthetic-test-pepper") == 0);
#else
  CHECK(setenv("ARCHX_SYNTHETIC_CORE_ENV", "synthetic-test-pepper", 1) == 0);
#endif
  ax_core *env_core = ax_core_new(env_config, strlen(env_config));
  CHECK(env_core != NULL);
  CHECK(ax_profile_with_ip(env_core, "192.0.2.1", &data, &data_len) == AX_OK);
  CHECK(data_len == profile_len && !strcmp(data, profile));
  ax_buffer_free(data); data = NULL;
  ax_core_free(env_core);
#ifdef _WIN32
  CHECK(_putenv_s("ARCHX_SYNTHETIC_CORE_ENV", "") == 0);
#else
  CHECK(unsetenv("ARCHX_SYNTHETIC_CORE_ENV") == 0);
#endif
  CHECK(ax_core_new(env_config, strlen(env_config)) == NULL);
  CHECK(ax_profile_with_ip(core, "192.0.2.2", &other, &other_len) == AX_OK);
  CHECK(ax_compare(core, profile, profile_len, profile, profile_len, &data, &data_len) == AX_OK);
  CHECK(strstr(data, "\"result\":\"match\""));
  ax_buffer_free(data); data = NULL;
  CHECK(ax_compare(core, profile, profile_len, other, other_len, &data, &data_len) == AX_OK);
  CHECK(strstr(data, "\"result\":\"no_match\""));
  ax_buffer_free(data); data = NULL;
  ax_buffer_free(other); other = NULL;
  /* Only this test mutates the scope. Real adapters must keep it fixed. */
  ax_test_collector_scope(AX_PLATFORM_SCOPE_SYNTHETIC);
  CHECK(ax_collect_capabilities(core, &data, &data_len) == AX_OK);
  CHECK(strstr(data, "\"platform\":\"synthetic\""));
  ax_buffer_free(data); data = NULL;
  CHECK(ax_compare(core, profile, profile_len, profile, profile_len, &data, &data_len) == AX_ERR_INVALID && data == NULL);
  CHECK(ax_profile_with_ip(core, "192.0.2.1", &data, &data_len) == AX_OK);
  CHECK(strstr(data, "c5c81fcebe01176f97a8d9b5ce3129d01a89cb2b92ebf30f788e5c1a8c7a09b9"));
  CHECK(ax_compare(core, data, data_len, data, data_len, &other, &other_len) == AX_OK);
  ax_buffer_free(other); other = NULL;
  ax_buffer_free(data); data = NULL;
  ax_test_collector_scope(999);
  CHECK(ax_collect_capabilities(core, &data, &data_len) == AX_ERR_INTERNAL && data == NULL);
  CHECK(ax_profile_with_ip(core, "192.0.2.1", &data, &data_len) == AX_ERR_INTERNAL && data == NULL);
  CHECK(ax_compare(core, profile, profile_len, profile, profile_len, &data, &data_len) == AX_ERR_INTERNAL && data == NULL);
  ax_test_collector_scope(AX_PLATFORM_SCOPE_LINUX);
  CHECK(ax_check(core, "synthetic-key", 1, NULL, NULL) == AX_ALLOW);
  CHECK(ax_check(core, "synthetic-key", 1, NULL, NULL) == AX_ALLOW);
  CHECK(ax_check(core, "synthetic-key", 1, NULL, NULL) == AX_DENY_RATE_LIMIT);
  CHECK(ax_reset(core, "synthetic-key") == AX_OK);
  CHECK(ax_check(core, "synthetic-key", 1, NULL, NULL) == AX_ALLOW);
  ax_test_collector_failure(1);
  CHECK(ax_collect(core, &data, &data_len) == AX_ERR_INTERNAL && data == NULL);
  CHECK(ax_identify(core, &data, &data_len) == AX_ERR_INTERNAL && data == NULL);
  ax_test_collector_failure(0);
  CHECK(ax_collect(core, &data, &data_len) == AX_OK && data);
  ax_buffer_free(data);
  ax_buffer_free(profile);
  ax_buffer_free(other);
  ax_core_free(core);
  puts("synthetic collector and actual core ABI passed");
  return 0;
}
