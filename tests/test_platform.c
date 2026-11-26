/* Portable store/clock/mutex conformance, not native collector support. */
#include "platform.h"
#include "store.h"
#include "thread_local.h"
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
#include <time.h>
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

/* Keep all threads alive with their distinct values until every worker wrote.
 * Each worker only touches its own thread-local slot. */
static AX_THREAD_LOCAL int tls_test_value;
typedef struct { ax_platform_mutex *mutex; int *ready; int id; int failed; } tls_arg;
static THREAD_RESULT tls_worker(void *context) {
  tls_arg *arg = (tls_arg *)context;
  if (tls_test_value != 0) arg->failed = 1;
  tls_test_value = arg->id;
  if (ax_platform_mutex_lock(arg->mutex)) { arg->failed = 1; THREAD_RETURN; }
  (*arg->ready)++;
  if (ax_platform_mutex_unlock(arg->mutex)) { arg->failed = 1; THREAD_RETURN; }
  for (;;) {
    if (ax_platform_mutex_lock(arg->mutex)) { arg->failed = 1; THREAD_RETURN; }
    int ready = *arg->ready;
    if (ax_platform_mutex_unlock(arg->mutex)) { arg->failed = 1; THREAD_RETURN; }
    if (ready == 8) break;
#ifdef _WIN32
    Sleep(1);
#else
    struct timespec pause = {0, 1000000};
    nanosleep(&pause, NULL);
#endif
  }
  if (tls_test_value != arg->id) arg->failed = 1;
  THREAD_RETURN;
}

int main(void) {
  int64_t before, after;
  unsigned char random_bytes[256];
  CHECK(ax_platform_random(NULL, 0) == 0);
  CHECK(ax_platform_random(NULL, 1) == -1);
  CHECK(ax_platform_random(random_bytes, sizeof random_bytes + 1) == -1);
  CHECK(ax_platform_random(random_bytes, sizeof random_bytes) == 0);
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
  int ready = 0;
  test_thread tls_threads[8]; tls_arg tls_args[8];
  mutex = ax_platform_mutex_new(); CHECK(mutex);
  tls_test_value = 99;
  for (int i=0; i<8; i++) {
    tls_args[i] = (tls_arg){mutex, &ready, i+1, 0};
#ifdef _WIN32
    tls_threads[i] = CreateThread(NULL, 0, tls_worker, &tls_args[i], 0, NULL);
    CHECK(tls_threads[i] != NULL);
#else
    CHECK(pthread_create(&tls_threads[i], NULL, tls_worker, &tls_args[i]) == 0);
#endif
  }
  for (int i=0; i<8; i++) {
#ifdef _WIN32
    CHECK(WaitForSingleObject(tls_threads[i], INFINITE) == WAIT_OBJECT_0);
    CHECK(CloseHandle(tls_threads[i]));
#else
    CHECK(pthread_join(tls_threads[i], NULL) == 0);
#endif
    CHECK(!tls_args[i].failed);
  }
  CHECK(tls_test_value == 99);
  ax_platform_mutex_free(mutex);
  CHECK(ax_store_new(SIZE_MAX) == NULL);
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
  /* Same first eight key bytes create a worst-case collision chain. Verify
   * full-table saturation, backwards-shift deletion and existing balances. */
  store = ax_store_new(16); CHECK(store);
  uint8_t collided[17][32] = {{0}};
  for (int i = 0; i < 17; i++) collided[i][31] = (uint8_t)i;
  for (int i = 0; i < 16; i++)
    CHECK(ax_store_token_bucket(store, collided[i], 2, 0, 1, NULL, NULL) == 1);
  CHECK(ax_store_token_bucket(store, collided[16], 2, 0, 1, NULL, NULL) == -1);
  for (int i = 0; i < 16; i++) {
    CHECK(ax_store_token_bucket(store, collided[i], 2, 0, 1, NULL, NULL) == 1);
    CHECK(ax_store_token_bucket(store, collided[i], 2, 0, 1, NULL, NULL) == 0);
  }
  CHECK(ax_store_reset(store, collided[4]) == 0);
  CHECK(ax_store_token_bucket(store, collided[16], 2, 0, 1, NULL, NULL) == 1);
  for (int i = 0; i < 16; i++) if (i != 4)
    CHECK(ax_store_token_bucket(store, collided[i], 2, 0, 1, NULL, NULL) == 0);
  CHECK(ax_store_token_bucket(store, collided[4], 2, 0, 1, NULL, NULL) == -1);
  CHECK(ax_store_size(store, &size) == 0 && size == 16);
  ax_store_free(store);
  puts("platform entropy/clock/mutex/thread-local/store conformance passed");
  return 0;
}
