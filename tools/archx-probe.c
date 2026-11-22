/*
 * archx-probe — tiny CLI over the archx C ABI.
 *
 *   archx-probe collect
 *   archx-probe identify [--app-id ID] [--pepper HEX-OR-RAW]
 *   archx-probe check KEY [--cost N] [--capacity N] [--refill-per-sec N]
 *
 * The pepper defaults to a demo value so the tool runs with zero setup;
 * real deployments must supply their own (or ARCHX_PEPPER in the env).
 * This is a debugging/inspection tool, not the production daemon.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "archx.h"

static void usage(const char *prog) {
  fprintf(stderr,
    "usage:\n"
    "  %s collect\n"
    "  %s identify [--app-id ID] [--pepper SECRET]\n"
    "  %s check KEY [--cost N] [--capacity N] [--refill-per-sec N]\n",
    prog, prog, prog);
}

static const char *get_opt(int argc, char **argv, const char *name, const char *def) {
  for (int i = 0; i + 1 < argc; i++) {
    if (strcmp(argv[i], name) == 0) return argv[i + 1];
  }
  return def;
}

static int json_string(char *dst, size_t cap, const char *src) {
  size_t j = 0;
  for (const unsigned char *p = (const unsigned char *)src; *p; p++) {
    if (*p < 0x20) {
      if (j + 6 >= cap) return -1;
      snprintf(dst + j, cap - j, "\\u%04x", *p); j += 6;
    } else {
      if (j + ((*p == '\"' || *p == '\\') ? 2 : 1) >= cap) return -1;
      if (*p == '\"' || *p == '\\') dst[j++] = '\\';
      dst[j++] = (char)*p;
    }
  }
  dst[j] = '\0'; return 0;
}

static ax_core *make_core(const char *app_id, const char *pepper,
                          double capacity, double refill) {
  char cfg[2048], app_escaped[768], pepper_escaped[768];
  if (json_string(app_escaped, sizeof app_escaped, app_id) ||
      json_string(pepper_escaped, sizeof pepper_escaped, pepper)) {
    fprintf(stderr, "archx-probe: app id or pepper too long\n"); exit(1);
  }
  snprintf(cfg, sizeof cfg,
           "{\"app_id\":\"%s\",\"pepper\":\"%s\","
           "\"rate_limit\":{\"capacity\":%g,\"refill_per_sec\":%g}}",
           app_escaped, pepper_escaped, capacity, refill);
  ax_core *core = ax_core_new(cfg, strlen(cfg));
  if (!core) {
    fprintf(stderr, "archx-probe: %s\n", ax_last_error());
    exit(1);
  }
  return core;
}

static void print_json_result(ax_result r, char *json, size_t len) {
  if (r != AX_OK || !json) {
    fprintf(stderr, "archx-probe: %s\n", ax_last_error());
    exit(1);
  }
  printf("%.*s\n", (int)len, json);
  ax_buffer_free(json);
}

int main(int argc, char **argv) {
  if (argc < 2) { usage(argv[0]); return 2; }
  const char *cmd = argv[1];
  const char *app_id = get_opt(argc, argv, "--app-id", "archx-probe");
  const char *pepper = get_opt(argc, argv, "--pepper",
                               getenv("ARCHX_PEPPER") ? getenv("ARCHX_PEPPER")
                                                      : "demo-pepper-change-me");

  if (strcmp(cmd, "collect") == 0) {
    ax_core *core = make_core(app_id, pepper, 100, 10);
    char *json = NULL; size_t len = 0;
    ax_result r = ax_collect(core, &json, &len);
    print_json_result(r, json, len);
    ax_core_free(core);
    return 0;
  }

  if (strcmp(cmd, "identify") == 0) {
    ax_core *core = make_core(app_id, pepper, 100, 10);
    char *json = NULL; size_t len = 0;
    ax_result r = ax_identify(core, &json, &len);
    print_json_result(r, json, len);
    ax_core_free(core);
    return 0;
  }

  if (strcmp(cmd, "check") == 0) {
    if (argc < 3) { usage(argv[0]); return 2; }
    const char *key = argv[2];
    long cost = atol(get_opt(argc, argv, "--cost", "1"));
    double capacity = atof(get_opt(argc, argv, "--capacity", "5"));
    double refill = atof(get_opt(argc, argv, "--refill-per-sec", "1"));
    ax_core *core = make_core(app_id, pepper, capacity, refill);
    int64_t remaining = -1, retry = -1;
    ax_decision d = ax_check(core, key, cost, &remaining, &retry);
    if (*ax_last_error()) { fprintf(stderr, "archx-probe: %s\n", ax_last_error()); ax_core_free(core); return 1; }
    printf("{\"decision\":\"%s\",\"remaining\":%lld,\"retry_after_ms\":%lld}\n",
           d == AX_ALLOW ? "allow" : "deny_rate_limit",
           (long long)remaining, (long long)retry);
    ax_core_free(core);
    return 0;
  }

  usage(argv[0]);
  return 2;
}
