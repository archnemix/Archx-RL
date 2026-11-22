/* SHA-256 (FIPS 180-4) + HMAC-SHA256 (RFC 2104). Self-contained, no
 * external dependencies. Written against the public-domain-style API:
 * sha256_ctx / sha256_update / sha256_final. */
#ifndef AX_SHA256_H
#define AX_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t h[8];
  uint64_t len_bytes;
  uint8_t  block[64];
  size_t   block_len;
} ax_sha256_ctx;

void ax_sha256_init(ax_sha256_ctx *ctx);
void ax_sha256_update(ax_sha256_ctx *ctx, const void *data, size_t len);
void ax_sha256_final(ax_sha256_ctx *ctx, uint8_t out[32]);
void ax_sha256(const void *data, size_t len, uint8_t out[32]);

/* HMAC-SHA256. key may be any length. */
void ax_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len,
                    uint8_t out[32]);

/* Lowercase hex helpers. */
void ax_hex_encode(const uint8_t *in, size_t len, char *out); /* out: 2*len+1 */
int  ax_hex_decode(const char *hex, uint8_t *out, size_t out_len); /* 0 on success */

#endif
