/* Actual ABI error isolation under native threads; synthetic collector only. */
#include "archx.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
typedef HANDLE test_thread;
#define THREAD_RESULT DWORD WINAPI
#define THREAD_RETURN return 0
#else
#include <pthread.h>
#include <time.h>
typedef pthread_t test_thread;
#define THREAD_RESULT void *
#define THREAD_RETURN return NULL
#endif
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "core thread-local test failed at line %d: %s\n", __LINE__, #expr); return 1; } } while (0)
typedef struct {
  ax_core *core;
  ax_platform_mutex *mutex;
  int *ready;
  int invalid;
  int failed;
} worker_arg;
static THREAD_RESULT worker(void *context) {
  worker_arg *arg = (worker_arg *)context;
  if (arg->invalid) {
    if (ax_check(arg->core, NULL, 1, NULL, NULL) != AX_DENY_RATE_LIMIT) arg->failed = 1;
  } else if (ax_check(arg->core, "thread-key", 1, NULL, NULL) != AX_ALLOW) arg->failed = 1;
  if (ax_platform_mutex_lock(arg->mutex)) { arg->failed = 1; THREAD_RETURN; }
  (*arg->ready)++;
  if (ax_platform_mutex_unlock(arg->mutex)) { arg->failed = 1; THREAD_RETURN; }
  int both = 0;
  for (int i = 0; i < 5000 && !both; i++) {
    if (ax_platform_mutex_lock(arg->mutex)) { arg->failed = 1; THREAD_RETURN; }
    both = *arg->ready == 2;
    if (ax_platform_mutex_unlock(arg->mutex)) { arg->failed = 1; THREAD_RETURN; }
    if (!both) {
#ifdef _WIN32
      Sleep(1);
#else
      struct timespec pause = {0, 1000000};
      nanosleep(&pause, NULL);
#endif
    }
  }
  if (!both || (arg->invalid ? strstr(ax_last_error(), "invalid core, key, or cost") == NULL : *ax_last_error() != '\0')) arg->failed = 1;
  THREAD_RETURN;
}
int main(void) {
  const char config[] = "{\"app_id\":\"thread-test\",\"pepper\":\"synthetic\",\"rate_limit\":{\"capacity\":2,\"refill_per_sec\":0}}";
  ax_core *core = ax_core_new(config, strlen(config));
  CHECK(core != NULL);
  ax_platform_mutex *mutex = ax_platform_mutex_new();
  CHECK(mutex != NULL);
  int ready = 0;
  worker_arg args[2] = {{core, mutex, &ready, 0, 0}, {core, mutex, &ready, 1, 0}};
  test_thread threads[2];
  CHECK(ax_check(core, NULL, 1, NULL, NULL) == AX_DENY_RATE_LIMIT);
  for (int i = 0; i < 2; i++) {
#ifdef _WIN32
    threads[i] = CreateThread(NULL, 0, worker, &args[i], 0, NULL);
    CHECK(threads[i] != NULL);
#else
    CHECK(pthread_create(&threads[i], NULL, worker, &args[i]) == 0);
#endif
  }
  for (int i = 0; i < 2; i++) {
#ifdef _WIN32
    CHECK(WaitForSingleObject(threads[i], 6000) == WAIT_OBJECT_0);
    CHECK(CloseHandle(threads[i]));
#else
    CHECK(pthread_join(threads[i], NULL) == 0);
#endif
    CHECK(!args[i].failed);
  }
  CHECK(strstr(ax_last_error(), "invalid core, key, or cost") != NULL);
  ax_platform_mutex_free(mutex);
  ax_core_free(core);
  puts("actual core thread-local error isolation passed");
  return 0;
}
