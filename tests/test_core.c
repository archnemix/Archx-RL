#include "archx.h"
#include "signals_linux.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static ax_core *new_core(const char *json) { return ax_core_new(json, strlen(json)); }
static void invalid(const char *json) { ax_core *c = new_core(json); if (c) fprintf(stderr, "unexpected valid: %s\n", json); assert(!c); }
static void *spend(void *arg) {
  int *count = malloc(sizeof *count); assert(count); *count = 0;
  for (int i = 0; i < 50; i++) *count += ax_check(arg, "concurrent", 1, NULL, NULL) == AX_ALLOW;
  return count;
}
int main(void) {
  invalid("{\"app_id\":\"x\",\"pepper\":\"a\",\"store_capacity\":-1}");
  invalid("{\"app_id\":\"x\",\"pepper\":\"a\",\"store_capacity\":1e999}");
  invalid("{\"app_id\":\"x\",\"pepper\":\"a\",\"rate_limit\":{\"capacity\":\"bad\"}}");
  invalid("{\"app_id\":\"x\",\"app_id\":\"y\",\"pepper\":\"a\"}");
  invalid("{\"app_id\":\"x|y\",\"pepper\":\"a\"}");
  invalid("{\"app_id\":\"x\",\"pepper\":\"a\",\"n\":01}");
  invalid("{\"app_id\":\"x\",\"pepper\":\"a\",\"n\":\"unclosed}");
  const char config[] = "{\"app_id\":\"test\",\"pepper\":\"secret\",\"store_capacity\":16,\"rate_limit\":{\"capacity\":2,\"refill_per_sec\":0}}";
  char bounded[sizeof config - 1]; memcpy(bounded, config, sizeof bounded);
  ax_core *c = ax_core_new(bounded, sizeof bounded); assert(c);
  char *json = NULL; size_t len = 0;
  assert(ax_collect(c, &json, &len) == AX_OK && len == strlen(json)); ax_buffer_free(json);
  assert(ax_identify(c, &json, &len) == AX_OK && strstr(json, "\"device_hash\":"));
  char *first = strdup(json); assert(first); ax_buffer_free(json);
  assert(ax_identify(c, &json, &len) == AX_OK && strcmp(first, json) == 0);
  free(first); ax_buffer_free(json);
  int64_t rem, retry;
  assert(ax_check(c, "user", 1, &rem, &retry) == AX_ALLOW && rem == 1);
  assert(ax_check(c, "user", 1, &rem, &retry) == AX_ALLOW && rem == 0);
  assert(ax_check(c, "user", 1, &rem, &retry) == AX_DENY_RATE_LIMIT && retry == -1);
  assert(ax_reset(c, "user") == AX_OK);
  assert(ax_check(c, "user", 3, &rem, &retry) == AX_DENY_RATE_LIMIT && retry == -1);
  for (int i = 0; i < 200; i++) { char key[32]; snprintf(key, sizeof key, "key-%d", i); assert(ax_check(c, key, 1, NULL, NULL) == AX_ALLOW); }
  assert(ax_reset(c, "key-199") == AX_OK);
  assert(ax_check(c, "key-199", 1, &rem, NULL) == AX_ALLOW && rem == 1);
  ax_core_free(c);
  c = new_core("{\"app_id\":\"test\",\"pepper\":\"secret\",\"rate_limit\":{\"capacity\":100,\"refill_per_sec\":0}}"); assert(c);
  pthread_t threads[8]; for (int i=0; i<8; i++) assert(!pthread_create(&threads[i], NULL, spend, c));
  int total = 0; for (int i=0; i<8; i++) { void *v; assert(!pthread_join(threads[i], &v)); total += *(int *)v; free(v); }
  assert(total == 100); ax_core_free(c);
  char dir[] = "/tmp/archx-test-XXXXXX"; assert(mkdtemp(dir)); assert(!setenv("XDG_DATA_HOME", dir, 1));
  int fds[2]; assert(!pipe(fds));
  for (int i = 0; i < 8; i++) { pid_t p = fork(); assert(p >= 0); if (!p) { close(fds[0]); char id[65]; if (ax_signals_fallback_id(id, sizeof id)) _exit(1); if (write(fds[1], id, sizeof id) != sizeof id) _exit(2); _exit(0); } }
  close(fds[1]); char ids[8][65]; size_t off=0; while (off < sizeof ids) { ssize_t n = read(fds[0], (char *)ids + off, sizeof ids - off); assert(n > 0); off += (size_t)n; } close(fds[0]);
  for (int i=0;i<8;i++) { int st; assert(wait(&st)>0 && WIFEXITED(st) && WEXITSTATUS(st)==0); assert(!strcmp(ids[0], ids[i])); }
  char path[512]; snprintf(path, sizeof path, "%s/archx/device_id", dir); unlink(path); snprintf(path, sizeof path, "%s/archx", dir); rmdir(path); rmdir(dir);
  puts("core tests passed"); return 0;
}
