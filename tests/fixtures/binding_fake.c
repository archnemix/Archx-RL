/* Synthetic ABI harness, never used as a real core. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int mode, live, core_frees;
static int fake_core;
uint32_t ax_abi_version(void) {
#ifdef WRONG_ABI
  return 2;
#else
  return 1;
#endif
}
void fixture_mode(int n) { mode = n; }
int fixture_live(void) { return live; }
int fixture_core_frees(void) { return core_frees; }
const char *ax_last_error(void) { return "synthetic native error"; }
void *ax_core_new(const char *data, size_t n) { (void)data; (void)n; return &fake_core; }
void ax_core_free(void *c) { if (c) core_frees++; }
void ax_buffer_free(void *p) { if (p) { free(p); live--; } }
static int result(char **out, size_t *len) {
  if (mode == 3) { *out = NULL; *len = 0; return 0; }
  const char *value = mode == 1 ? "not JSON" : "{\"ok\":true}";
  size_t n = strlen(value);
  *out = malloc(n + 1);
  if (!*out) return -2;
  memcpy(*out, value, n + 1);
  *len = mode == 4 ? 1048577 : n; live++;
  return mode == 2 ? -1 : 0;
}
int ax_collect(void *c, char **out, size_t *len) { (void)c; return result(out, len); }
int ax_identify(void *c, char **out, size_t *len) { return ax_collect(c, out, len); }
int ax_profile(void *c, char **out, size_t *len) { return ax_collect(c, out, len); }
int ax_profile_with_ip(void *c, const char *ip, char **out, size_t *len) { (void)ip; return ax_collect(c, out, len); }
int ax_compare(void *c, const char *a, size_t an, const char *b, size_t bn, char **out, size_t *len) {
  (void)a; (void)an; (void)b; (void)bn; return ax_collect(c, out, len);
}
int ax_check(void *c, const char *key, int64_t cost, int64_t *remaining, int64_t *retry) {
  (void)c; (void)key; (void)cost; *remaining = 0; *retry = 0; return 1;
}
int ax_reset(void *c, const char *key) { (void)c; (void)key; return -1; }
