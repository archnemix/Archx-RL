/* Portable synthetic regression for invalid C token-bucket inputs. */
#include "store.h"
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "nonfinite store failure at line %d\n", __LINE__); return 1; } } while (0)
int main(void) {
  ax_store *store = ax_store_new(16);
  CHECK(store != NULL);
  uint8_t key[32] = {1};
  const double invalid[] = {NAN, INFINITY, -INFINITY};
  for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    for (int which = 0; which < 3; ++which) {
      double capacity = which == 0 ? invalid[i] : 2.0;
      double refill = which == 1 ? invalid[i] : 1.0;
      double cost = which == 2 ? invalid[i] : 1.0;
      double balance = 99; int64_t delay = 99; size_t count = 99;
      CHECK(ax_store_token_bucket(store, key, capacity, refill, cost, &balance, &delay) == -2);
      CHECK(balance == 0 && delay == -1);
      CHECK(ax_store_size(store, &count) == 0 && count == 0);
    }
  }
  double balance; int64_t delay;
  CHECK(ax_store_token_bucket(store, key, 2.0, 1.0, 1.0, &balance, &delay) == 1 && balance == 1);
  CHECK(ax_store_token_bucket(store, key, NAN, 1.0, 1.0, &balance, &delay) == -2);
  CHECK(ax_store_token_bucket(store, key, 2.0, 1.0, 1.0, &balance, &delay) == 1 && balance == 0);
  ax_store_free(store);
  puts("synthetic token-bucket non-finite rejection passed");
  return 0;
}
