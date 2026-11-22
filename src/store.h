/* Bounded in-memory token-bucket store.
 *
 * - Open-addressing table, power-of-two size, 32-byte keys (already
 *   HMAC'd by the caller — raw user keys never land here).
 * - Shard-free but globally mutex-guarded: the hot path is a few dozen
 *   instructions; contention only matters at very high concurrency, at
 *   which point per-shard locking can be added without ABI changes.
 * - Capacity is hard-capped: when full, the stalest entry (by last_refill)
 *   is evicted. Memory stays flat no matter how hostile the key churn is. */
#ifndef AX_STORE_H
#define AX_STORE_H

#include <stddef.h>
#include <stdint.h>

typedef struct ax_store ax_store;

ax_store *ax_store_new(size_t capacity); /* rounded up to power of two */
void      ax_store_free(ax_store *s);

/*
 * Consume `cost` tokens from the bucket at `key`.
 * capacity / refill_per_sec describe the bucket shape.
 * *remaining (optional) gets the post-operation balance.
 * *retry_after_ms (optional) gets ms until at least `cost` tokens are
 *   available when denied (0 when allowed).
 * Returns 1 = allowed, 0 = denied.
 */
int ax_store_token_bucket(ax_store *s, const uint8_t key[32],
                          double capacity, double refill_per_sec, double cost,
                          double *remaining, int64_t *retry_after_ms);

void ax_store_reset(ax_store *s, const uint8_t key[32]);

/* entry count (diagnostics/tests) */
size_t ax_store_size(const ax_store *s);

#endif
