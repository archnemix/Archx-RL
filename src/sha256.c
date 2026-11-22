#include "sha256.h"

#include <string.h>

static const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTRIGHT(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)      (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)     (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)         (ROTRIGHT(x,2)  ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x)         (ROTRIGHT(x,6)  ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x)        (ROTRIGHT(x,7)  ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x)        (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static void sha256_compress(ax_sha256_ctx *ctx, const uint8_t block[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
           ((uint32_t)block[i*4+2] << 8) |  (uint32_t)block[i*4+3];
  }
  for (int i = 16; i < 64; i++) {
    w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];
  }
  uint32_t a=ctx->h[0], b=ctx->h[1], c=ctx->h[2], d=ctx->h[3],
           e=ctx->h[4], f=ctx->h[5], g=ctx->h[6], h=ctx->h[7];
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = h + EP1(e) + CH(e,f,g) + K[i] + w[i];
    uint32_t t2 = EP0(a) + MAJ(a,b,c);
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  ctx->h[0]+=a; ctx->h[1]+=b; ctx->h[2]+=c; ctx->h[3]+=d;
  ctx->h[4]+=e; ctx->h[5]+=f; ctx->h[6]+=g; ctx->h[7]+=h;
}

void ax_sha256_init(ax_sha256_ctx *ctx) {
  static const uint32_t H0[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
  };
  memcpy(ctx->h, H0, sizeof ctx->h);
  ctx->len_bytes = 0;
  ctx->block_len = 0;
}

void ax_sha256_update(ax_sha256_ctx *ctx, const void *data, size_t len) {
  const uint8_t *p = (const uint8_t *)data;
  ctx->len_bytes += len;
  while (len > 0) {
    size_t take = 64 - ctx->block_len;
    if (take > len) take = len;
    memcpy(ctx->block + ctx->block_len, p, take);
    ctx->block_len += take;
    p += take;
    len -= take;
    if (ctx->block_len == 64) {
      sha256_compress(ctx, ctx->block);
      ctx->block_len = 0;
    }
  }
}

void ax_sha256_final(ax_sha256_ctx *ctx, uint8_t out[32]) {
  uint64_t bit_len = ctx->len_bytes * 8;
  uint8_t pad = 0x80;
  ax_sha256_update(ctx, &pad, 1);
  uint8_t zero = 0x00;
  while (ctx->block_len != 56) ax_sha256_update(ctx, &zero, 1);
  uint8_t lenbuf[8];
  for (int i = 0; i < 8; i++) lenbuf[7 - i] = (uint8_t)((bit_len >> (i * 8)) & 0xff);
  /* bypass the len_bytes accounting for the trailer */
  memcpy(ctx->block + ctx->block_len, lenbuf, 8);
  ctx->block_len = 64;
  sha256_compress(ctx, ctx->block);
  for (int i = 0; i < 8; i++) {
    out[i*4]   = (uint8_t)(ctx->h[i] >> 24);
    out[i*4+1] = (uint8_t)(ctx->h[i] >> 16);
    out[i*4+2] = (uint8_t)(ctx->h[i] >> 8);
    out[i*4+3] = (uint8_t)(ctx->h[i]);
  }
  memset(ctx, 0, sizeof *ctx);
}

void ax_sha256(const void *data, size_t len, uint8_t out[32]) {
  ax_sha256_ctx ctx;
  ax_sha256_init(&ctx);
  ax_sha256_update(&ctx, data, len);
  ax_sha256_final(&ctx, out);
}

void ax_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len,
                    uint8_t out[32]) {
  uint8_t k0[64];
  memset(k0, 0, sizeof k0);
  if (key_len > 64) {
    ax_sha256(key, key_len, k0);
  } else {
    memcpy(k0, key, key_len);
  }
  uint8_t ipad[64], opad[64];
  for (int i = 0; i < 64; i++) {
    ipad[i] = k0[i] ^ 0x36;
    opad[i] = k0[i] ^ 0x5c;
  }
  ax_sha256_ctx ctx;
  uint8_t inner[32];
  ax_sha256_init(&ctx);
  ax_sha256_update(&ctx, ipad, 64);
  ax_sha256_update(&ctx, msg, msg_len);
  ax_sha256_final(&ctx, inner);
  ax_sha256_init(&ctx);
  ax_sha256_update(&ctx, opad, 64);
  ax_sha256_update(&ctx, inner, 32);
  ax_sha256_final(&ctx, out);
  memset(k0, 0, sizeof k0);
  memset(ipad, 0, sizeof ipad);
  memset(opad, 0, sizeof opad);
  memset(inner, 0, sizeof inner);
}

void ax_hex_encode(const uint8_t *in, size_t len, char *out) {
  static const char *hexd = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i*2]   = hexd[in[i] >> 4];
    out[i*2+1] = hexd[in[i] & 0xf];
  }
  out[len*2] = '\0';
}

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int ax_hex_decode(const char *hex, uint8_t *out, size_t out_len) {
  size_t n = strlen(hex);
  if (n != out_len * 2) return -1;
  for (size_t i = 0; i < out_len; i++) {
    int hi = hexval(hex[i*2]), lo = hexval(hex[i*2+1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}
