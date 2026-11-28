/* Independent quarter-token model for a synthetic C token bucket store. */
#include "store.h"
#include "fake_platform.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "store model failure at line %d, step %d\n", __LINE__, step); return 1; } } while (0)
#define KEYS 24

typedef struct { int live, quarters; int64_t last; } model_entry;
static uint32_t random_state = 0x913ac7u;
static uint32_t next_random(void) {
  random_state = random_state * 1664525u + 1013904223u;
  return random_state;
}

int main(void) {
  int step = 0, size = 0, backward = 0, reset = 0, full = 0, denied = 0, allowed = 0;
  int existing_at_full = 0, overcapacity = 0;
  model_entry model[KEYS] = {{0}};
  ax_store *store = ax_store_new(16);
  CHECK(store != NULL);
  ax_test_now = 100000;
  for (step = 0; step < 30000; ++step) {
    uint32_t r = next_random();
    int index = (int)((r >> 8) % KEYS);
    uint8_t key[32] = {0};
    key[31] = (uint8_t)index; /* Identical first eight bytes force collisions. */
    if ((r & 15u) == 0) {
      /* Model backward observations as no refill, just like the contract. */
      ax_test_now -= 250; ++backward;
    } else if ((r & 7u) == 1) {
      ax_test_now += (int64_t)((r >> 16) % 8u) * 250;
    } else if ((r & 7u) == 2) {
      CHECK(ax_store_reset(store, key) == 0);
      if (model[index].live) { model[index].live = 0; --size; ++reset; }
    } else {
      int cost = 1 + (int)((r >> 20) % 5u);
      double balance = -1;
      int64_t delay = -99;
      int expected;
      int64_t retry = -1;
      model_entry *entry = &model[index];
      if (!entry->live && size == 16) {
        expected = -1; ++full;
      } else {
        if (entry->live && size == 16) ++existing_at_full;
        if (cost > 4) ++overcapacity;
        if (!entry->live) {
          entry->live = 1; entry->quarters = 16; entry->last = ax_test_now; ++size;
        }
        if (ax_test_now > entry->last) {
          int64_t increment = (ax_test_now - entry->last) / 250;
          entry->quarters = increment >= 16 ? 16 : entry->quarters + (int)increment;
          if (entry->quarters > 16) entry->quarters = 16;
          entry->last = ax_test_now;
        }
        if (entry->quarters >= 4 * cost) {
          expected = 1; entry->quarters -= 4 * cost; retry = 0; ++allowed;
        } else {
          expected = 0; ++denied;
          if (cost <= 4) retry = (int64_t)(4 * cost - entry->quarters) * 250;
        }
      }
      int actual = ax_store_token_bucket(store, key, 4.0, 1.0, (double)cost, &balance, &delay);
      CHECK(actual == expected && delay == retry);
      if (expected == -1) CHECK(balance == 0.0);
      else CHECK(balance == (double)entry->quarters / 4.0);
    }
    size_t actual_size = 99;
    CHECK(ax_store_size(store, &actual_size) == 0 && actual_size == (size_t)size);
  }
  CHECK(backward > 0 && reset > 0 && full > 0 && denied > 0 && allowed > 0 &&
        existing_at_full > 0 && overcapacity > 0);
  ax_store_free(store);
  puts("synthetic colliding token-bucket reference trace passed");
  return 0;
}
