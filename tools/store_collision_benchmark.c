/* Linux-only synthetic worst-case C store microbenchmark; no capacity claims.
 * Build: cc -O2 -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Isrc
 * tools/store_collision_benchmark.c src/store.c src/platform_posix.c
 * src/platform_linux.c -lm -lpthread -o build/store_collision_benchmark
 */
#include "store.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SAMPLES 1000
#define RESET_SAMPLES 100
static void key_for(size_t n, uint8_t key[32]) {
  memset(key, 0, 32); /* same first eight bytes -> identical home slot */
  for (unsigned i = 0; i < 8; i++) key[16+i] = (uint8_t)((uint64_t)n >> (i*8));
}
static uint64_t nanos(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) { perror("clock_gettime"); exit(1); }
  return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}
static int compare_u64(const void *a, const void *b) {
  uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}
static void stats(const char *name, uint64_t *values, size_t count) {
  qsort(values, count, sizeof *values, compare_u64);
  printf("\"%s\":{\"p50_us\":%.3f,\"p95_us\":%.3f,\"p99_us\":%.3f,\"max_us\":%.3f}",
         name, values[(count*50+99)/100-1]/1000.0, values[(count*95+99)/100-1]/1000.0,
         values[(count*99+99)/100-1]/1000.0, values[count-1]/1000.0);
}
static void run(size_t n) {
  ax_store *s = ax_store_new(n);
  uint8_t key[32];
  uint64_t missing[SAMPLES], tail[SAMPLES], resets[RESET_SAMPLES];
  if (!s) { fprintf(stderr, "store allocation failed\n"); exit(1); }
  for (size_t i = 0; i < n; i++) {
    key_for(i, key);
    if (ax_store_token_bucket(s, key, 1, 0, 0, NULL, NULL) != 1) exit(2);
  }
  for (size_t i = 0; i < SAMPLES; i++) {
    key_for(n, key); uint64_t start = nanos();
    int result = ax_store_token_bucket(s, key, 1, 0, 0, NULL, NULL);
    missing[i] = nanos() - start; if (result != -1) exit(3);
    key_for(n-1, key); start = nanos();
    result = ax_store_token_bucket(s, key, 1, 0, 0, NULL, NULL);
    tail[i] = nanos() - start; if (result != 1) exit(4);
  }
  for (size_t i = 0; i < RESET_SAMPLES; i++) {
    key_for(i % n, key); uint64_t start = nanos();
    int result = ax_store_reset(s, key);
    resets[i] = nanos() - start; if (result != 0) exit(5);
    if (ax_store_token_bucket(s, key, 1, 0, 0, NULL, NULL) != 1) exit(6);
  }
  size_t size;
  if (ax_store_size(s, &size) != 0 || size != n) exit(7);
  printf("{\"capacity\":%zu,", n); stats("full_missing", missing, SAMPLES);
  putchar(','); stats("full_last_hit", tail, SAMPLES); putchar(',');
  stats("reset_and_shift", resets, RESET_SAMPLES); putchar('}');
  ax_store_free(s);
}
int main(void) {
  printf("{\"schema\":1,\"samples_per_lookup\":%d,\"samples_per_reset\":%d,"
         "\"note\":\"synthetic colliding keys, single thread; microseconds include lock and clock; setup excluded; no production budget\",\"results\":[", SAMPLES, RESET_SAMPLES);
  run(16); putchar(','); run(1024); putchar(','); run(8192); puts("]}");
  return 0;
}
