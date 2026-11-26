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
typedef struct { ax_core *core; int id; int allowed; } insert_arg;
static void *insert_unique(void *data) {
  insert_arg *arg = data;
  char key[32]; snprintf(key, sizeof key, "parallel-%d", arg->id);
  ax_decision result = ax_check(arg->core, key, 1, NULL, NULL);
  arg->allowed = result == AX_ALLOW;
  if (!arg->allowed) assert(strstr(ax_last_error(), "capacity exceeded"));
  return NULL;
}
typedef struct { pthread_barrier_t *barrier; int first; } tls_error_arg;
static void *check_tls_error(void *data) {
  tls_error_arg *arg = data;
  if (arg->first) {
    assert(!ax_core_new(NULL, 0));
  } else {
    assert(!ax_core_new("{", 1));
  }
  int result = pthread_barrier_wait(arg->barrier);
  assert(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
  assert(strstr(ax_last_error(), arg->first ? "NULL or empty" : "not valid JSON"));
  return NULL;
}
int main(void) {
  /* Simultaneous distinct errors must not overwrite another thread's state. */
  pthread_barrier_t error_barrier; assert(!pthread_barrier_init(&error_barrier, NULL, 2));
  tls_error_arg error_args[2] = {{&error_barrier, 0}, {&error_barrier, 1}};
  pthread_t error_threads[2];
  assert(!ax_core_new(NULL, 0));
  for (int i=0; i<2; i++) assert(!pthread_create(&error_threads[i], NULL, check_tls_error, &error_args[i]));
  for (int i=0; i<2; i++) assert(!pthread_join(error_threads[i], NULL));
  assert(strstr(ax_last_error(), "NULL or empty"));
  assert(!pthread_barrier_destroy(&error_barrier));
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
  /* Fill the table, then churn new keys: the exhausted victim must survive. */
  assert(ax_check(c, "user", 2, &rem, &retry) == AX_ALLOW && rem == 0);
  for (int i = 0; i < 15; i++) { char key[32]; snprintf(key, sizeof key, "key-%d", i); assert(ax_check(c, key, 1, NULL, NULL) == AX_ALLOW); }
  for (int i = 0; i < 200; i++) {
    char key[32]; snprintf(key, sizeof key, "churn-%d", i);
    rem = 9; retry = 9;
    assert(ax_check(c, key, 1, &rem, &retry) == AX_DENY_RATE_LIMIT);
    assert(rem == 0 && retry == -1 && strstr(ax_last_error(), "capacity exceeded"));
    assert(ax_check(c, "user", 1, &rem, &retry) == AX_DENY_RATE_LIMIT && retry == -1);
    assert(!*ax_last_error()); /* real quota denial, not saturation */
  }
  assert(ax_check(c, "key-14", 1, &rem, NULL) == AX_ALLOW && rem == 0);
  assert(ax_reset(c, "key-14") == AX_OK);
  assert(ax_check(c, "new-key", 1, &rem, NULL) == AX_ALLOW && rem == 1);
  assert(ax_check(c, "user", 1, &rem, &retry) == AX_DENY_RATE_LIMIT);
  ax_core_free(c);
  c = new_core(config); assert(c);
  assert(ax_check(c, "victim", 2, NULL, NULL) == AX_ALLOW);
  pthread_t inserts[32]; insert_arg args[32];
  for (int i=0; i<32; i++) { args[i] = (insert_arg){c, i, 0}; assert(!pthread_create(&inserts[i], NULL, insert_unique, &args[i])); }
  int admitted = 0;
  for (int i=0; i<32; i++) { assert(!pthread_join(inserts[i], NULL)); admitted += args[i].allowed; }
  assert(admitted == 15);
  assert(ax_check(c, "victim", 1, &rem, &retry) == AX_DENY_RATE_LIMIT && !*ax_last_error());
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
