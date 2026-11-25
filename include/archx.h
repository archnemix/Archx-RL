/*
 * archx.h — public C ABI for archx-core (milestone 1: Linux).
 *
 * Design contract:
 *   - Opaque handles only; no Rust/C++ types cross the ABI.
 *   - All rich data moves through JSON buffers owned by the core;
 *     caller frees them with ax_buffer_free().
 *   - No global mutable state except a thread-local error string.
 *   - Thread-safe: one ax_core handle may be used from multiple threads.
 *   - AX_ABI_VERSION lets wrappers detect incompatible cores.
 */
#ifndef ARCHX_H
#define ARCHX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AX_ABI_VERSION 1

/* Opaque core handle. */
typedef struct ax_core ax_core;

/* Result codes. Non-negative = fine (and meaning-dependent per call). */
typedef enum {
  AX_OK = 0,             /* operation succeeded                       */
  AX_ERR_INVALID = -1,   /* bad argument / malformed config           */
  AX_ERR_NOMEM = -2,     /* allocation failed                         */
  AX_ERR_INTERNAL = -3   /* unexpected internal failure               */
} ax_result;

/* Decision returned by ax_check(). */
typedef enum {
  AX_ALLOW = 0,          /* request may proceed                       */
  AX_DENY_RATE_LIMIT = 1 /* over limit; retry after ax_retry_after_ms */
} ax_decision;

/* ---- lifecycle ---- */

/* Version of the ABI the loaded core implements. Always >= 1. */
uint32_t ax_abi_version(void);

/*
 * Create a core from a JSON config document:
 * {
 *   "app_id": "my-app",                  (required)
 *   "pepper": "hex-or-raw-secret",       (required, or use pepper_env)
 *   "pepper_env": "ARCHX_PEPPER",        (optional env var to read pepper from)
 *   "rate_limit": {
 *     "capacity": 100,                   (max burst tokens)
 *     "refill_per_sec": 10.0,            (tokens regained per second)
 *     "key_scope": "device"              (reserved; currently informational)
 *   }
 * }
 * Returns NULL on failure; call ax_last_error() for details.
 * On success the handle owns all compiled state; it does NOT own the
 * strings inside `config_json` (it copies what it needs).
 */
ax_core *ax_core_new(const char *config_json, size_t config_len);
void     ax_core_free(ax_core *core);

/* ---- identification (Linux) ---- */

/*
 * Collect normalized, privacy-preserving signal metadata for this machine
 * (no raw IDs — names + stability classes only) and return a JSON object:
 * {"platform":"linux","arch":"x86_64","signals":[{name,weight,readable},...]}
 * The caller frees *out_json with ax_buffer_free().
 */
ax_result ax_collect(const ax_core *core, char **out_json, size_t *out_len);

/*
 * Build the device identity: collect signals, normalize, HMAC-SHA256 them
 * app-scoped, and return:
 * {"device_hash":"<64 hex>","signals_used":3,"confidence":100,
 *  "tier":"full|partial|fallback","app_id":"my-app"}
 * If no OS signal is readable (containers, odd sysfs perms), a generated
 * random ID is persisted under $XDG_DATA_HOME/archx/device_id (fallback
 * tier, confidence 10). *out_json freed with ax_buffer_free().
 */
ax_result ax_identify(const ax_core *core, char **out_json, size_t *out_len);

/* Capture only policy-selected Linux signals as app-scoped HMAC tokens.
 * Store the returned profile securely; it is linkable and not self-authenticating.
 * Unavailable signals are null. The caller frees the output. */
ax_result ax_profile(const ax_core *core, char **out_json, size_t *out_len);
/* Same as ax_profile, with an optional IPv4/IPv6 address from a trusted
 * request context. If ip is not selected it is ignored; if omitted it is
 * unavailable. Never pass an untrusted forwarding header as the client IP. */
ax_result ax_profile_with_ip(const ax_core *core, const char *ip, char **out_json, size_t *out_len);

/* Compare two trusted profiles under the core's configured match policy.
 * Returns JSON with result match / no_match / inconclusive and per-signal
 * match / changed / unavailable. Does not establish identity or authentication.
 * Profiles from a different app or pepper are rejected. */
ax_result ax_compare(const ax_core *core, const char *baseline, size_t baseline_len,
                     const char *current, size_t current_len, char **out_json, size_t *out_len);

/* ---- rate limiting ---- */

/*
 * Token-bucket check for `key`. Consumes `cost` tokens (cost>=1).
 * Returns AX_ALLOW or AX_DENY_RATE_LIMIT. On either outcome the token
 * balance and retry delay are written to *remaining / *retry_after_ms
 * (both optional, may be NULL). A retry delay of -1 means impossible.
 * Keys are limited to 800 bytes. Invalid arguments return a denial and set
 * the thread-local error; check ax_last_error() to distinguish failures.
 * Store saturation returns AX_DENY_RATE_LIMIT with a nonempty error, remaining
 * 0 and retry -1; no existing bucket is evicted. Callers must fail closed on
 * errors and should inspect ax_last_error() on the calling thread. Platform
 * clock or mutex errors also deny; an unlock failure may follow a charge.
 */
ax_decision ax_check(ax_core *core, const char *key, int64_t cost,
                     int64_t *remaining, int64_t *retry_after_ms);

/* Reset the bucket for `key`. On mutex error returns AX_ERR_INTERNAL; an
 * unlock error can occur after the bucket was already reset. */
ax_result ax_reset(ax_core *core, const char *key);

/* ---- misc ---- */

/* Thread-local description of the last failure ("" if none). */
const char *ax_last_error(void);
void        ax_buffer_free(char *buf);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* ARCHX_H */
