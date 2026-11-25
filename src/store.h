/* Bounded in-memory token-bucket store.
 *
 * - Open-addressing table, power-of-two size, 32-byte keys (already
 *   HMAC'd by the caller — raw user keys never land here).
 * - Shard-free and globally mutex-guarded. Lookup and deletion can scan up
 *   to the table capacity, particularly near saturation; no latency bound
 *   or contention profile has been established.
 * - Capacity is hard-capped. A new key is refused at capacity; an existing
 *   bucket is never silently evicted, including when it has refilled. */
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
 * Returns 1 = allowed, 0 = rate limited, -1 = store saturated,
 * -2 = platform error (deny; a failed unlock may follow a charge).
 */
int ax_store_token_bucket(ax_store *s, const uint8_t key[32],
                          double capacity, double refill_per_sec, double cost,
                          double *remaining, int64_t *retry_after_ms);

int ax_store_reset(ax_store *s, const uint8_t key[32]);

/* entry count (diagnostics/tests) */
int ax_store_size(ax_store *s, size_t *out);

#endif
