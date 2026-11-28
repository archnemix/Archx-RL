/* Bounded in-memory token-bucket store. See store.h for the design notes. */
#include "store.h"
#include "platform.h"

#include <math.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint8_t  key[32];
  double   tokens;
  int64_t  last_refill_ms;
  int      occupied;
} ax_entry;

struct ax_store {
  ax_entry      *entries;
  size_t         capacity;   /* power of two */
  size_t         size;       /* occupied count */
  ax_platform_mutex *lock;
};

/* Keys are HMAC outputs (uniform), so a Fibonacci multiply of the first
 * 8 bytes is a perfectly good hash. */
static size_t hash_key(const uint8_t key[32]) {
  uint64_t x;
  memcpy(&x, key, sizeof x);
  return (size_t)((x * 11400714819323198485ull) >> 32);
}

static size_t next_pow2(size_t n) {
  size_t p = 16;
  while (p < n) {
    if (p > SIZE_MAX / 2) return 0;
    p <<= 1;
  }
  return p;
}

ax_store *ax_store_new(size_t capacity) {
  if (capacity < 16) capacity = 16;
  size_t rounded = next_pow2(capacity);
  if (!rounded || rounded > SIZE_MAX / sizeof(ax_entry)) return NULL;
  ax_store *s = (ax_store *)calloc(1, sizeof *s);
  if (!s) return NULL;
  s->capacity = rounded;
  s->entries = (ax_entry *)calloc(s->capacity, sizeof(ax_entry));
  if (!s->entries) { free(s); return NULL; }
  s->lock = ax_platform_mutex_new();
  if (!s->lock) { free(s->entries); free(s); return NULL; }
  return s;
}

void ax_store_free(ax_store *s) {
  if (!s) return;
  ax_platform_mutex_free(s->lock);
  free(s->entries);
  free(s);
}

/* Find entry for key, or NULL. Caller holds the lock. */
static ax_entry *find_entry(ax_store *s, const uint8_t key[32]) {
  size_t mask = s->capacity - 1;
  size_t i = hash_key(key) & mask;
  for (size_t probes = 0; probes < s->capacity && s->entries[i].occupied; probes++) {
    if (memcmp(s->entries[i].key, key, 32) == 0) return &s->entries[i];
    i = (i + 1) & mask;
  }
  return NULL;
}

/* Delete with backward shifting, preserving probe chains even when full. */
static void delete_entry(ax_store *s, size_t hole) {
  size_t mask = s->capacity - 1;
  s->entries[hole].occupied = 0;
  s->size--;
  for (size_t n = 0, i = (hole + 1) & mask; n < s->capacity - 1; n++, i = (i + 1) & mask) {
    if (!s->entries[i].occupied) break;
    size_t home = hash_key(s->entries[i].key) & mask;
    if (((hole - home) & mask) < ((i - home) & mask)) {
      s->entries[hole] = s->entries[i];
      s->entries[i].occupied = 0;
      hole = i;
    }
  }
}

/* Find or insert in one probe traversal. Caller holds the lock. Existing
 * entries remain usable when full; missing keys never evict them. */
static ax_entry *find_or_insert(ax_store *s, const uint8_t key[32], double capacity, int64_t now) {
  size_t mask = s->capacity - 1;
  size_t i = hash_key(key) & mask;
  for (size_t probes = 0; probes < s->capacity; probes++, i = (i + 1) & mask) {
    ax_entry *e = &s->entries[i];
    if (e->occupied) {
      if (memcmp(e->key, key, 32) == 0) return e;
      continue;
    }
    memcpy(e->key, key, 32);
    e->tokens = capacity;
    e->last_refill_ms = now;
    e->occupied = 1;
    s->size++;
    return e;
  }
  return NULL;
}

int ax_store_token_bucket(ax_store *s, const uint8_t key[32],
                          double capacity, double refill_per_sec, double cost,
                          double *remaining, int64_t *retry_after_ms) {
  if (remaining) *remaining = 0;
  if (retry_after_ms) *retry_after_ms = -1;
  if (!s || !key || !isfinite(capacity) || !isfinite(refill_per_sec) || !isfinite(cost)) return -2;
  if (capacity < 0) capacity = 0;
  if (refill_per_sec < 0) refill_per_sec = 0;
  if (cost < 0) cost = 0;

  if (ax_platform_mutex_lock(s->lock) != 0) return -2;
  int64_t now;
  if (ax_platform_monotonic_ms(&now) != 0 || now < 0) {
    ax_platform_mutex_unlock(s->lock);
    return -2;
  }
  ax_entry *e = find_or_insert(s, key, capacity, now);
  if (!e) {
    return ax_platform_mutex_unlock(s->lock) == 0 ? -1 : -2;
  }

  double elapsed = now >= e->last_refill_ms ? (double)(now - e->last_refill_ms) / 1000.0 : 0.0;
  if (elapsed > 0) {
    e->tokens += elapsed * refill_per_sec;
    if (e->tokens > capacity) e->tokens = capacity;
    e->last_refill_ms = now;
  }

  int allowed;
  if (e->tokens >= cost) {
    e->tokens -= cost;
    allowed = 1;
    if (retry_after_ms) *retry_after_ms = 0;
  } else {
    allowed = 0;
    if (retry_after_ms) {
      if (cost <= capacity && refill_per_sec > 0) {
        double need_ms = ceil((cost - e->tokens) / refill_per_sec * 1000.0);
        *retry_after_ms = need_ms >= (double)INT64_MAX ? INT64_MAX : (int64_t)need_ms;
      } else {
        *retry_after_ms = -1; /* never refills */
      }
    }
  }
  if (remaining) *remaining = e->tokens;
  if (ax_platform_mutex_unlock(s->lock) != 0) {
    if (remaining) *remaining = 0;
    if (retry_after_ms) *retry_after_ms = -1;
    return -2;
  }
  return allowed;
}

int ax_store_reset(ax_store *s, const uint8_t key[32]) {
  if (!s || !key || ax_platform_mutex_lock(s->lock) != 0) return -1;
  ax_entry *e = find_entry(s, key);
  if (e) delete_entry(s, (size_t)(e - s->entries));
  return ax_platform_mutex_unlock(s->lock);
}

int ax_store_size(ax_store *s, size_t *out) {
  if (!s || !out || ax_platform_mutex_lock(s->lock) != 0) return -1;
  size_t result = s->size;
  if (ax_platform_mutex_unlock(s->lock) != 0) return -1;
  *out = result;
  return 0;
}
