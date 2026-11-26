/*
 * archx.c — archx-core implementation (milestone 1: Linux).
 *
 * One core, every language: this file + sha256.c + json.c + signals.c
 * + signals_linux.c + store.c compile into libarchx.so / libarchx.a. All language wrappers
 * (Python ctypes, Node koffi, ...) call the ABI in include/archx.h.
 *
 * Privacy model:
 *   - Raw OS identifiers never leave this process and are never stored.
 *   - The device identity is HMAC-SHA256(pepper, app_id || canonical signals)
 *     hex-encoded — a pseudonymous, app-scoped, non-reversible handle.
 *   - Rate-limit keys are HMAC'd before they touch the bucket store, so the
 *     store only ever holds opaque 32-byte digests.
 */
#include "archx.h"

#include <ctype.h>
#include <arpa/inet.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "sha256.h"
#include "signals_linux.h"
#include "store.h"
#include "thread_local.h"

#define AX_DEFAULT_CAPACITY      100.0
#define AX_DEFAULT_REFILL_PER_SEC 10.0
#define AX_DEFAULT_STORE_CAPACITY 65536

static const char *const match_names[] = {"machine_id", "product_uuid", "board_serial", "ip"};
#define AX_MATCH_SIGNALS 4
#define AX_DEFAULT_MATCH_SIGNALS 3

struct ax_core {
  char     app_id[128];
  uint8_t  pepper[64];
  size_t   pepper_len;
  double   capacity;
  double   refill_per_sec;
  ax_store *store;
  int match_roles[AX_MATCH_SIGNALS]; /* 0 ignored, 1 optional, 2 required */
  int match_strict;
  int min_matches;
};

/* Thread-local last-error string (the only global mutable state). */
static AX_THREAD_LOCAL char tls_error[256];

static void set_error(const char *msg) {
  snprintf(tls_error, sizeof tls_error, "%s", msg ? msg : "unknown error");
}

uint32_t ax_abi_version(void) { return AX_ABI_VERSION; }

const char *ax_last_error(void) { return tls_error; }

void ax_buffer_free(char *buf) { free(buf); }

/* ------------------------------------------------------------------ */
/* config                                                              */
/* ------------------------------------------------------------------ */

static int is_hex_string(const char *s, size_t len) {
  if (len < 32 || (len % 2) != 0) return 0;
  for (size_t i = 0; i < len; i++) {
    if (!isxdigit((unsigned char)s[i])) return 0;
  }
  return 1;
}

ax_core *ax_core_new(const char *config_json, size_t config_len) {
  tls_error[0] = '\0';
  if (!config_json || config_len == 0) {
    set_error("ax_core_new: config_json is NULL or empty");
    return NULL;
  }

  ax_json_value *root = NULL;
  if (ax_json_parse(config_json, config_len, &root) != 0) {
    set_error("ax_core_new: config is not valid JSON");
    return NULL;
  }

  if (root->type != AX_J_OBJECT) {
    ax_json_free(root); set_error("ax_core_new: config must be an object"); return NULL;
  }
  ax_core *core = (ax_core *)calloc(1, sizeof *core);
  if (!core) {
    ax_json_free(root);
    set_error("ax_core_new: out of memory");
    return NULL;
  }
  core->capacity = AX_DEFAULT_CAPACITY;
  core->refill_per_sec = AX_DEFAULT_REFILL_PER_SEC;
  core->match_strict = 1;
  for (size_t i = 0; i < AX_DEFAULT_MATCH_SIGNALS; i++) core->match_roles[i] = 2;

  const char *app_id = ax_json_get_string(root, "app_id");
  if (!app_id || !*app_id) {
    set_error("ax_core_new: config requires a non-empty \"app_id\"");
    goto fail;
  }
  if (strlen(app_id) >= sizeof core->app_id || strchr(app_id, '|')) {
    set_error("ax_core_new: app_id too long or contains | "); goto fail;
  }
  snprintf(core->app_id, sizeof core->app_id, "%s", app_id);

  /* pepper: explicit string, or name of an env var to read it from. */
  const char *pepper = ax_json_get_string(root, "pepper");
  const char *pepper_env = ax_json_get_string(root, "pepper_env");
  if (!pepper && pepper_env) pepper = getenv(pepper_env);
  if (!pepper || !*pepper) {
    set_error("ax_core_new: config requires \"pepper\" or \"pepper_env\"");
    goto fail;
  }
  {
    size_t plen = strlen(pepper);
    if (is_hex_string(pepper, plen)) {
      size_t nbytes = plen / 2;
      if (nbytes > sizeof core->pepper) {
        set_error("ax_core_new: pepper too long (max 64 bytes)");
        goto fail;
      }
      if (ax_hex_decode(pepper, core->pepper, nbytes) != 0) {
        set_error("ax_core_new: pepper is not valid hex");
        goto fail;
      }
      core->pepper_len = nbytes;
    } else {
      if (plen > sizeof core->pepper) {
        set_error("ax_core_new: pepper too long (max 64 bytes)");
        goto fail;
      }
      memcpy(core->pepper, pepper, plen);
      core->pepper_len = plen;
    }
  }

  const ax_json_value *rl = ax_json_get(root, "rate_limit");
  if (rl && rl->type != AX_J_OBJECT) { set_error("ax_core_new: rate_limit must be an object"); goto fail; }
  const ax_json_value *cap = ax_json_get(rl, "capacity");
  const ax_json_value *refill = ax_json_get(rl, "refill_per_sec");
  const ax_json_value *store_cap = ax_json_get(root, "store_capacity");
  if ((cap && (cap->type != AX_J_NUMBER || cap->num < 0 || cap->num > 1000000000.0)) ||
      (refill && (refill->type != AX_J_NUMBER || refill->num < 0 || refill->num > 1000000000.0)) ||
      (store_cap && (store_cap->type != AX_J_NUMBER || store_cap->num < 16 ||
                     store_cap->num > 1048576 || floor(store_cap->num) != store_cap->num))) {
    set_error("ax_core_new: invalid rate limit or store capacity"); goto fail;
  }
  if (cap) core->capacity = cap->num;
  if (refill) core->refill_per_sec = refill->num;
  core->store = ax_store_new(store_cap ? (size_t)store_cap->num : AX_DEFAULT_STORE_CAPACITY);
  if (!core->store) { set_error("ax_core_new: could not allocate bucket store"); goto fail; }

  const ax_json_value *match = ax_json_get(root, "match");
  if (match) {
    if (match->type != AX_J_OBJECT) { set_error("ax_core_new: match must be an object"); goto fail; }
    for (size_t i = 0; i < match->child_count; i++) {
      if (strcmp(match->keys[i], "mode") && strcmp(match->keys[i], "signals") && strcmp(match->keys[i], "min_matches")) {
        set_error("ax_core_new: unknown match setting"); goto fail;
      }
    }
    const ax_json_value *mode = ax_json_get(match, "mode");
    if (mode) {
      if (mode->type != AX_J_STRING || (strcmp(mode->str, "strict") && strcmp(mode->str, "threshold"))) {
        set_error("ax_core_new: invalid match mode"); goto fail;
      }
      core->match_strict = !strcmp(mode->str, "strict");
    }
    const ax_json_value *signals = ax_json_get(match, "signals");
    if (signals) {
      if (signals->type != AX_J_OBJECT) { set_error("ax_core_new: match signals must be an object"); goto fail; }
      memset(core->match_roles, 0, sizeof core->match_roles);
      for (size_t i = 0; i < signals->child_count; i++) {
        size_t j;
        for (j = 0; j < AX_MATCH_SIGNALS; j++) if (!strcmp(signals->keys[i], match_names[j])) break;
        const ax_json_value *v = signals->children[i];
        if (j == AX_MATCH_SIGNALS || v->type != AX_J_STRING ||
            (strcmp(v->str, "required") && strcmp(v->str, "optional"))) {
          set_error("ax_core_new: unknown signal or role"); goto fail;
        }
        core->match_roles[j] = !strcmp(v->str, "required") ? 2 : 1;
      }
    }
    int selected = 0;
    for (size_t i = 0; i < AX_MATCH_SIGNALS; i++) if (core->match_roles[i]) selected++;
    const ax_json_value *min = ax_json_get(match, "min_matches");
    if (!selected || (min && (min->type != AX_J_NUMBER || min->num < 1 || min->num > selected || floor(min->num) != min->num)) ||
        (!core->match_strict && !min) || (core->match_strict && min)) {
      set_error("ax_core_new: invalid match selection or min_matches"); goto fail;
    }
    core->min_matches = min ? (int)min->num : selected;
  } else core->min_matches = AX_DEFAULT_MATCH_SIGNALS;

  ax_json_free(root);
  return core;

fail:
  ax_json_free(root);
  ax_core_free(core);
  return NULL;
}

void ax_core_free(ax_core *core) {
  if (!core) return;
  ax_store_free(core->store);
  free(core);
}

/* ------------------------------------------------------------------ */
/* JSON output helpers                                                 */
/* ------------------------------------------------------------------ */

/* Append s (JSON-escaped) to buf at *pos. Returns 0 on success. */
static int json_escape_append(char *buf, size_t buf_len, size_t *pos, const char *s) {
  if (*pos >= buf_len) return -1;
  for (const char *p = s; *p; p++) {
    char tmp[8];
    const char *esc = NULL;
    switch (*p) {
      case '"':  esc = "\\\""; break;
      case '\\': esc = "\\\\"; break;
      case '\n': esc = "\\n";  break;
      case '\r': esc = "\\r";  break;
      case '\t': esc = "\\t";  break;
      default:
        if ((unsigned char)*p < 0x20) {
          snprintf(tmp, sizeof tmp, "\\u%04x", (unsigned char)*p);
          esc = tmp;
        }
        break;
    }
    const char *piece = esc ? esc : p;
    size_t n = esc ? strlen(esc) : 1;
    if (n >= buf_len - *pos) return -1;
    memcpy(buf + *pos, piece, n);
    *pos += n;
  }
  buf[*pos] = '\0';
  return 0;
}

static int append_str(char *buf, size_t buf_len, size_t *pos, const char *s) {
  size_t n = strlen(s);
  if (*pos >= buf_len || n >= buf_len - *pos) return -1;
  memcpy(buf + *pos, s, n);
  *pos += n;
  buf[*pos] = '\0';
  return 0;
}

/* Hand the stack buffer to the caller as a heap allocation. */
static ax_result emit_json(char *stack_buf, size_t stack_len,
                           char **out_json, size_t *out_len) {
  const char *end = (const char *)memchr(stack_buf, '\0', stack_len);
  if (!end) {
    set_error("result JSON is not terminated within its buffer");
    return AX_ERR_INTERNAL;
  }
  size_t n = (size_t)(end - stack_buf);
  char *heap = (char *)malloc(n + 1);
  if (!heap) {
    set_error("out of memory building result JSON");
    return AX_ERR_NOMEM;
  }
  memcpy(heap, stack_buf, n + 1);
  *out_json = heap;
  if (out_len) *out_len = n;
  return AX_OK;
}

/* ------------------------------------------------------------------ */
/* ax_collect                                                          */
/* ------------------------------------------------------------------ */

ax_result ax_collect(const ax_core *core, char **out_json, size_t *out_len) {
  tls_error[0] = '\0';
  if (!core || !out_json) {
    set_error("ax_collect: core or out_json is NULL");
    return AX_ERR_INVALID;
  }
  *out_json = NULL;

  ax_signal_set set;
  if (ax_signals_collect_linux(&set) != 0) {
    set_error("ax_collect: signal collection failed");
    return AX_ERR_INTERNAL;
  }

  char buf[2048];
  size_t pos = 0;
  buf[0] = '\0';
  if (append_str(buf, sizeof buf, &pos, "{\"platform\":\"") ||
      json_escape_append(buf, sizeof buf, &pos, set.os) ||
      append_str(buf, sizeof buf, &pos, "\",\"arch\":\"") ||
      json_escape_append(buf, sizeof buf, &pos, set.arch) ||
      append_str(buf, sizeof buf, &pos, "\",\"signals\":[")) {
    set_error("ax_collect: output too long"); return AX_ERR_INTERNAL;
  }
  for (size_t i = 0; i < set.signal_count; i++) {
    char piece[256];
    int n = snprintf(piece, sizeof piece, "%s{\"name\":\"%s\",\"weight\":%d,\"readable\":%s}",
                     i == 0 ? "" : ",", set.signals[i].name, set.signals[i].weight,
                     set.signals[i].readable ? "true" : "false");
    if (n < 0 || (size_t)n >= sizeof piece || append_str(buf, sizeof buf, &pos, piece)) {
      set_error("ax_collect: output too long"); return AX_ERR_INTERNAL;
    }
  }
  if (append_str(buf, sizeof buf, &pos, "]}")) {
    set_error("ax_collect: output too long"); return AX_ERR_INTERNAL;
  }
  return emit_json(buf, sizeof buf, out_json, out_len);
}

/* ------------------------------------------------------------------ */
/* ax_identify                                                         */
/* ------------------------------------------------------------------ */

ax_result ax_identify(const ax_core *core, char **out_json, size_t *out_len) {
  tls_error[0] = '\0';
  if (!core || !out_json) {
    set_error("ax_identify: core or out_json is NULL");
    return AX_ERR_INVALID;
  }
  *out_json = NULL;

  ax_signal_set set;
  if (ax_signals_collect_linux(&set) != 0) {
    set_error("ax_identify: signal collection failed");
    return AX_ERR_INTERNAL;
  }

  char canonical[1024];
  size_t canon_len = ax_signals_canonical(&set, canonical, sizeof canonical);
  if (canon_len == SIZE_MAX) {
    set_error("ax_identify: signal canonicalization failed"); return AX_ERR_INTERNAL;
  }

  int confidence = 0;
  size_t signals_used = 0;
  for (size_t i = 0; i < set.signal_count; i++) {
    if (set.signals[i].readable) {
      confidence += set.signals[i].weight;
      signals_used++;
    }
  }

  const char *tier;
  if (signals_used == set.signal_count && signals_used > 0) {
    tier = "full";
  } else if (signals_used > 0) {
    tier = "partial";
  } else {
    /* No OS signal readable (container, locked-down sysfs): fall back to a
     * generated random ID persisted per-user. Confidence stays low — this
     * is a per-install pseudonym, not a hardware anchor. */
    char fallback[80];
    if (ax_signals_fallback_id(fallback, sizeof fallback) != 0) {
      set_error("ax_identify: no readable signals and fallback ID unavailable");
      return AX_ERR_INTERNAL;
    }
    snprintf(canonical, sizeof canonical, "fallback=%s", fallback);
    canon_len = strlen(canonical);
    confidence = 10;
    tier = "fallback";
  }
  if (confidence > 100) confidence = 100;

  /* device_hash = HMAC-SHA256(pepper, "archx-device-v1|<app_id>|<canonical>") */
  char msg[1408];
  int msg_len = snprintf(msg, sizeof msg, "archx-device-v1|%s|%s",
                         core->app_id, canonical);
  if (msg_len < 0 || (size_t)msg_len >= sizeof msg) {
    set_error("ax_identify: canonical signal string too long");
    return AX_ERR_INTERNAL;
  }
  (void)canon_len;

  uint8_t digest[32];
  ax_hmac_sha256(core->pepper, core->pepper_len,
                 (const uint8_t *)msg, (size_t)msg_len, digest);
  char device_hash[65];
  ax_hex_encode(digest, sizeof digest, device_hash);

  char buf[1024];
  size_t pos = 0;
  buf[0] = '\0';
  char piece[256];
  int n = snprintf(piece, sizeof piece, "\",\"signals_used\":%zu,\"confidence\":%d,\"tier\":\"%s\",\"app_id\":\"",
                   signals_used, confidence, tier);
  if (n < 0 || (size_t)n >= sizeof piece ||
      append_str(buf, sizeof buf, &pos, "{\"device_hash\":\"") ||
      append_str(buf, sizeof buf, &pos, device_hash) ||
      append_str(buf, sizeof buf, &pos, piece) ||
      json_escape_append(buf, sizeof buf, &pos, core->app_id) ||
      append_str(buf, sizeof buf, &pos, "\"}")) {
    set_error("ax_identify: output too long"); return AX_ERR_INTERNAL;
  }
  return emit_json(buf, sizeof buf, out_json, out_len);
}

/* Per-signal HMACs permit comparison without publishing raw identifiers. */
static void match_digest(const ax_core *core, const char *name, const char *value, char hex[65]) {
  char msg[600];
  int n = snprintf(msg, sizeof msg, "archx-profile-v1|%s|%zu:%s%zu:%s", core->app_id,
                   strlen(name), name, strlen(value), value);
  uint8_t digest[32];
  ax_hmac_sha256(core->pepper, core->pepper_len, (const uint8_t *)msg, (size_t)n, digest);
  ax_hex_encode(digest, sizeof digest, hex);
}

ax_result ax_profile_with_ip(const ax_core *core, const char *ip, char **out_json, size_t *out_len) {
  tls_error[0] = '\0';
  if (!core || !out_json) { set_error("ax_profile: invalid arguments"); return AX_ERR_INVALID; }
  *out_json = NULL;
  char normalized_ip[INET6_ADDRSTRLEN];
  if (ip && core->match_roles[3]) {
    unsigned char addr[16];
    int family = strchr(ip, ':') ? AF_INET6 : AF_INET;
    if (inet_pton(family, ip, addr) != 1 || !inet_ntop(family, addr, normalized_ip, sizeof normalized_ip)) {
      set_error("ax_profile_with_ip: invalid IP address"); return AX_ERR_INVALID;
    }
  }
  unsigned mask = 0;
  for (size_t i = 0; i < AX_DEFAULT_MATCH_SIGNALS; i++) if (core->match_roles[i]) mask |= 1u << i;
  ax_signal_set set;
  if (ax_signals_collect_linux_selected(&set, mask)) { set_error("ax_profile: collection failed"); return AX_ERR_INTERNAL; }
  char scope[65], buf[1024]; size_t pos = 0;
  match_digest(core, "scope", "linux", scope);
  int n = snprintf(buf, sizeof buf, "{\"version\":1,\"scope\":\"%s\",\"signals\":{", scope);
  if (n < 0 || (size_t)n >= sizeof buf) { set_error("ax_profile: output too long"); return AX_ERR_INTERNAL; }
  pos = (size_t)n;
  int first = 1;
  for (size_t i = 0; i < AX_MATCH_SIGNALS; i++) if (core->match_roles[i]) {
    const ax_signal *sig = NULL;
    for (size_t j = 0; j < set.signal_count; j++)
      if (!strcmp(match_names[i], set.signals[j].name)) sig = &set.signals[j];
    const char *value = i == 3 ? (ip ? normalized_ip : NULL) : (sig && sig->readable ? sig->value : NULL);
    char hex[65];
    if (value) match_digest(core, match_names[i], value, hex);
    n = snprintf(buf + pos, sizeof buf - pos, "%s\"%s\":%s%s%s", first ? "" : ",", match_names[i],
                 value ? "\"" : "", value ? hex : "null", value ? "\"" : "");
    if (n < 0 || (size_t)n >= sizeof buf - pos) { set_error("ax_profile: output too long"); return AX_ERR_INTERNAL; }
    pos += (size_t)n; first = 0;
  }
  if (append_str(buf, sizeof buf, &pos, "}}")) { set_error("ax_profile: output too long"); return AX_ERR_INTERNAL; }
  return emit_json(buf, sizeof buf, out_json, out_len);
}

ax_result ax_profile(const ax_core *core, char **out_json, size_t *out_len) {
  return ax_profile_with_ip(core, NULL, out_json, out_len);
}

/* Profiles must be supplied from a trusted store: the scope is not a signature. */
static int validate_profile(const ax_core *core, const ax_json_value *profile) {
  if (!profile || profile->type != AX_J_OBJECT || profile->child_count != 3) return 0;
  const ax_json_value *version = ax_json_get(profile, "version");
  const ax_json_value *scope = ax_json_get(profile, "scope");
  const ax_json_value *signals = ax_json_get(profile, "signals");
  char expected[65]; match_digest(core, "scope", "linux", expected);
  if (!version || version->type != AX_J_NUMBER || version->num != 1 ||
      !scope || scope->type != AX_J_STRING || strcmp(scope->str, expected) ||
      !signals || signals->type != AX_J_OBJECT) return 0;
  for (size_t i = 0; i < signals->child_count; i++) {
    size_t j; for (j = 0; j < AX_MATCH_SIGNALS; j++) if (!strcmp(signals->keys[i], match_names[j])) break;
    const ax_json_value *v = signals->children[i];
    if (j == AX_MATCH_SIGNALS || (v->type != AX_J_NULL && v->type != AX_J_STRING)) return 0;
    if (v->type == AX_J_STRING) {
      if (strlen(v->str) != 64) return 0;
      for (size_t k = 0; k < 64; k++) if (!((v->str[k] >= '0' && v->str[k] <= '9') || (v->str[k] >= 'a' && v->str[k] <= 'f'))) return 0;
    }
  }
  return 1;
}

ax_result ax_compare(const ax_core *core, const char *baseline, size_t baseline_len,
                     const char *current, size_t current_len, char **out_json, size_t *out_len) {
  tls_error[0] = '\0';
  if (!core || !baseline || !current || !out_json || baseline_len > 8192 || current_len > 8192) {
    set_error("ax_compare: invalid arguments"); return AX_ERR_INVALID;
  }
  *out_json = NULL;
  ax_json_value *a = NULL, *b = NULL;
  if (ax_json_parse(baseline, baseline_len, &a) || ax_json_parse(current, current_len, &b) ||
      !validate_profile(core, a) || !validate_profile(core, b)) {
    ax_json_free(a); ax_json_free(b); set_error("ax_compare: invalid or incompatible profile"); return AX_ERR_INVALID;
  }
  const ax_json_value *as = ax_json_get(a, "signals"), *bs = ax_json_get(b, "signals");
  char details[512] = ""; size_t pos = 0;
  int matches = 0, changed = 0, unavailable = 0, required_changed = 0, required_missing = 0, first = 1;
  for (size_t i = 0; i < AX_MATCH_SIGNALS; i++) if (core->match_roles[i]) {
    const ax_json_value *x = ax_json_get(as, match_names[i]), *y = ax_json_get(bs, match_names[i]);
    const char *state;
    if (!x || !y || x->type == AX_J_NULL || y->type == AX_J_NULL) {
      state = "unavailable"; unavailable++; if (core->match_strict || core->match_roles[i] == 2) required_missing++;
    } else if (!strcmp(x->str, y->str)) { state = "match"; matches++; }
    else { state = "changed"; changed++; if (core->match_strict || core->match_roles[i] == 2) required_changed++; }
    char piece[96];
    int n = snprintf(piece, sizeof piece, "%s\"%s\":\"%s\"", first ? "" : ",", match_names[i], state);
    if (n < 0 || (size_t)n >= sizeof piece || append_str(details, sizeof details, &pos, piece)) {
      ax_json_free(a); ax_json_free(b); set_error("ax_compare: output too long"); return AX_ERR_INTERNAL;
    }
    first = 0;
  }
  const char *result = required_changed || matches + unavailable < core->min_matches ? "no_match" :
                       required_missing || matches < core->min_matches ? "inconclusive" : "match";
  char buf[1024];
  int n = snprintf(buf, sizeof buf, "{\"result\":\"%s\",\"matched\":%d,\"changed\":%d,\"unavailable\":%d,\"signals\":{%s}}",
                   result, matches, changed, unavailable, details);
  ax_json_free(a); ax_json_free(b);
  if (n < 0 || (size_t)n >= sizeof buf) { set_error("ax_compare: output too long"); return AX_ERR_INTERNAL; }
  return emit_json(buf, sizeof buf, out_json, out_len);
}

/* ------------------------------------------------------------------ */
/* ax_check / ax_reset                                                 */
/* ------------------------------------------------------------------ */

/* bucket_key = HMAC-SHA256(pepper, "archx-bucket-v1|<app_id>|<key>") */
static void bucket_key(const ax_core *core, const char *key, uint8_t out[32]) {
  char msg[1024];
  int n = snprintf(msg, sizeof msg, "archx-bucket-v1|%s|%s", core->app_id, key);
  if (n < 0) n = 0;
  if ((size_t)n >= sizeof msg) n = (int)sizeof msg - 1;
  ax_hmac_sha256(core->pepper, core->pepper_len,
                 (const uint8_t *)msg, (size_t)n, out);
}

ax_decision ax_check(ax_core *core, const char *key, int64_t cost,
                     int64_t *remaining, int64_t *retry_after_ms) {
  tls_error[0] = '\0';
  if (!core || !key || strlen(key) > 800 || cost < 1) {
    set_error("ax_check: invalid core, key, or cost (key limit 800 bytes)");
    if (remaining) *remaining = 0;
    if (retry_after_ms) *retry_after_ms = 0;
    return AX_DENY_RATE_LIMIT;
  }

  uint8_t bk[32];
  bucket_key(core, key, bk);

  double rem = 0.0;
  int64_t retry = 0;
  int allowed = ax_store_token_bucket(core->store, bk, core->capacity,
                                      core->refill_per_sec, (double)cost,
                                      &rem, &retry);
  if (allowed == -1) set_error("ax_check: bucket store capacity exceeded");
  else if (allowed < 0) set_error("ax_check: bucket store platform failure");
  if (remaining) *remaining = (int64_t)rem; /* floor for positive values */
  if (retry_after_ms) *retry_after_ms = retry;
  return allowed > 0 ? AX_ALLOW : AX_DENY_RATE_LIMIT;
}

ax_result ax_reset(ax_core *core, const char *key) {
  tls_error[0] = '\0';
  if (!core || !key || strlen(key) > 800) {
    set_error("ax_reset: invalid core or key (key limit 800 bytes)");
    return AX_ERR_INVALID;
  }
  uint8_t bk[32];
  bucket_key(core, key, bk);
  if (ax_store_reset(core->store, bk) != 0) {
    set_error("ax_reset: bucket store platform failure");
    return AX_ERR_INTERNAL;
  }
  return AX_OK;
}
