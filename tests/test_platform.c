/* Portable store/clock/mutex conformance, not native collector support. */
#include "platform.h"
#include "store.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
typedef HANDLE test_thread;
#define THREAD_RESULT DWORD WINAPI
#define THREAD_RETURN return 0
#else
#include <pthread.h>
typedef pthread_t test_thread;
#define THREAD_RESULT void *
#define THREAD_RETURN return NULL
#endif

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "platform conformance failed at line %d: %s\n", __LINE__, #expr); return 1; } } while (0)

typedef struct { ax_store *store; int allowed; int errors; } worker_arg;
static THREAD_RESULT worker(void *context) {
  worker_arg *arg = (worker_arg *)context;
  uint8_t key[32] = {0};
  for (int i=0; i<200; i++) {
    int result = ax_store_token_bucket(arg->store, key, 100, 0, 1, NULL, NULL);
    if (result == 1) arg->allowed++;
    else if (result != 0) arg->errors++;
  }
  THREAD_RETURN;
}

int main(void) {
  int64_t before, after;
  CHECK(ax_platform_monotonic_ms(NULL) == -1);
  CHECK(ax_platform_monotonic_ms(&before) == 0 && before >= 0);
  for (int i=0; i<5000; i++) {
    CHECK(ax_platform_monotonic_ms(&after) == 0 && after >= before);
    before = after;
  }
  CHECK(ax_platform_mutex_lock(NULL) == -1 && ax_platform_mutex_unlock(NULL) == -1);
  ax_platform_mutex *mutex = ax_platform_mutex_new();
  CHECK(mutex && ax_platform_mutex_lock(mutex) == 0 && ax_platform_mutex_unlock(mutex) == 0);
  ax_platform_mutex_free(mutex);
  ax_store *store = ax_store_new(16);
  CHECK(store);
  test_thread threads[8]; worker_arg args[8];
  for (int i=0; i<8; i++) {
    args[i].store=store; args[i].allowed=0; args[i].errors=0;
#ifdef _WIN32
    threads[i] = CreateThread(NULL, 0, worker, &args[i], 0, NULL);
    CHECK(threads[i] != NULL);
#else
    CHECK(pthread_create(&threads[i], NULL, worker, &args[i]) == 0);
#endif
  }
  int total = 0;
  for (int i=0; i<8; i++) {
#ifdef _WIN32
    CHECK(WaitForSingleObject(threads[i], INFINITE) == WAIT_OBJECT_0);
    CHECK(CloseHandle(threads[i]));
#else
    CHECK(pthread_join(threads[i], NULL) == 0);
#endif
    CHECK(args[i].errors == 0);
    total += args[i].allowed;
  }
  CHECK(total == 100);
  for (int i=1; i<16; i++) {
    uint8_t key[32] = {0}; key[0] = (uint8_t)i;
    CHECK(ax_store_token_bucket(store, key, 100, 0, 1, NULL, NULL) == 1);
  }
  uint8_t absent[32] = {0}; absent[0] = 99;
  int64_t retry = 0; double remaining = 2;
  CHECK(ax_store_token_bucket(store, absent, 100, 0, 1, &remaining, &retry) == -1);
  CHECK(remaining == 0 && retry == -1);
  uint8_t victim[32] = {0};
  CHECK(ax_store_token_bucket(store, victim, 100, 0, 1, NULL, NULL) == 0);
  uint8_t reset[32] = {0}; reset[0] = 15;
  CHECK(ax_store_reset(store, reset) == 0);
  CHECK(ax_store_token_bucket(store, absent, 100, 0, 1, NULL, NULL) == 1);
  size_t size = 0;
  CHECK(ax_store_size(store, &size) == 0 && size == 16);
  ax_store_free(store);
  puts("platform clock/mutex/store conformance passed");
  return 0;
}
