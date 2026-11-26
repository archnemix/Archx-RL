#include "json.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AX_JSON_MAX_DEPTH 8
#define AX_JSON_MAX_CHILDREN 16

typedef struct {
  const char *p, *end;
  int depth;
  int out_of_memory;
} parser;

static void skip_ws(parser *ps) {
  while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\n' || *ps->p == '\r' || *ps->p == '\t')) ps->p++;
}

static ax_json_value *new_value(parser *ps, ax_json_type t) {
  ax_json_value *v = calloc(1, sizeof *v);
  if (v) v->type = t;
  else ps->out_of_memory = 1;
  return v;
}

void ax_json_free(ax_json_value *v) {
  if (!v) return;
  for (size_t i = 0; i < v->child_count; i++) {
    free(v->keys[i]);
    ax_json_free(v->children[i]);
  }
  free(v->str);
  free(v);
}

static ax_json_value *parse_value(parser *ps);

static char *parse_string_raw(parser *ps) {
  /* ps->p at opening quote */
  ps->p++;
  size_t cap = 32, n = 0;
  char *buf = malloc(cap);
  if (!buf) { ps->out_of_memory = 1; return NULL; }
  int closed = 0;
  while (ps->p < ps->end) {
    char c = *ps->p++;
    if (c == '"') { closed = 1; break; }
    if ((unsigned char)c < 0x20) { free(buf); return NULL; }
    if (c == '\\' && ps->p >= ps->end) { free(buf); return NULL; }
    if (c == '\\') {
      char esc = *ps->p++;
      switch (esc) {
        case 'n': c = '\n'; break;
        case 't': c = '\t'; break;
        case 'r': c = '\r'; break;
        case 'b': c = '\b'; break;
        case 'f': c = '\f'; break;
        case '"': c = '"';  break;
        case '/': c = '/';  break;
        case '\\': c = '\\'; break;
        case 'u': {
          if (ps->end - ps->p < 4) { free(buf); return NULL; }
          unsigned cp = 0;
          for (int i = 0; i < 4; i++) {
            char h = *ps->p++;
            cp <<= 4;
            if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
            else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
            else { free(buf); return NULL; }
          }
          /* Reject NUL and surrogate code points; strings are C strings. */
          if (cp == 0 || (cp >= 0xd800 && cp <= 0xdfff)) { free(buf); return NULL; }
          /* encode as UTF-8 (BMP only; surrogate pairs out of scope) */
          if (cp < 0x80) { c = (char)cp; }
          else if (cp < 0x800) {
            if (n + 2 >= cap) { cap *= 2; char *nb = realloc(buf, cap); if (!nb) { ps->out_of_memory = 1; free(buf); return NULL; } buf = nb; }
            buf[n++] = (char)(0xC0 | (cp >> 6));
            c = (char)(0x80 | (cp & 0x3F));
          } else {
            if (n + 3 >= cap) { cap *= 2; char *nb = realloc(buf, cap); if (!nb) { ps->out_of_memory = 1; free(buf); return NULL; } buf = nb; }
            buf[n++] = (char)(0xE0 | (cp >> 12));
            buf[n++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            c = (char)(0x80 | (cp & 0x3F));
          }
          break;
        }
        default: free(buf); return NULL;
      }
    }
    if (n + 1 >= cap) { cap *= 2; char *nb = realloc(buf, cap); if (!nb) { ps->out_of_memory = 1; free(buf); return NULL; } buf = nb; }
    buf[n++] = c;
  }
  if (!closed) { free(buf); return NULL; }
  buf[n] = '\0';
  return buf;
}

static ax_json_value *parse_object(parser *ps) {
  ps->p++; /* { */
  ax_json_value *obj = new_value(ps, AX_J_OBJECT);
  if (!obj) return NULL;
  skip_ws(ps);
  if (ps->p < ps->end && *ps->p == '}') { ps->p++; return obj; }
  while (ps->p < ps->end) {
    skip_ws(ps);
    if (ps->p >= ps->end || *ps->p != '"') goto fail;
    char *key = parse_string_raw(ps);
    if (!key) goto fail;
    skip_ws(ps);
    if (ps->p >= ps->end || *ps->p != ':') { free(key); goto fail; }
    ps->p++;
    ax_json_value *val = parse_value(ps);
    if (!val) { free(key); goto fail; }
    if (obj->child_count >= AX_JSON_MAX_CHILDREN) { free(key); ax_json_free(val); goto fail; }
    for (size_t i = 0; i < obj->child_count; i++) {
      if (strcmp(obj->keys[i], key) == 0) { free(key); ax_json_free(val); goto fail; }
    }
    obj->keys[obj->child_count] = key;
    obj->children[obj->child_count] = val;
    obj->child_count++;
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == ',') { ps->p++; continue; }
    if (ps->p < ps->end && *ps->p == '}') { ps->p++; return obj; }
    goto fail;
  }
fail:
  ax_json_free(obj);
  return NULL;
}

static ax_json_value *parse_value(parser *ps) {
  if (ps->depth > AX_JSON_MAX_DEPTH) return NULL;
  skip_ws(ps);
  if (ps->p >= ps->end) return NULL;
  char c = *ps->p;
  if (c == '{') {
    ps->depth++;
    ax_json_value *v = parse_object(ps);
    ps->depth--;
    return v;
  }
  if (c == '"') {
    ax_json_value *v = new_value(ps, AX_J_STRING);
    if (!v) return NULL;
    v->str = parse_string_raw(ps);
    if (!v->str) { ax_json_free(v); return NULL; }
    return v;
  }
  if (c == '-' || (c >= '0' && c <= '9')) {
    const char *start = ps->p;
    if (*ps->p == '-') ps->p++;
    if (ps->p >= ps->end) return NULL;
    if (*ps->p == '0') ps->p++;
    else if (*ps->p >= '1' && *ps->p <= '9') {
      while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    } else return NULL;
    if (ps->p < ps->end && *ps->p == '.') {
      ps->p++;
      if (ps->p >= ps->end || *ps->p < '0' || *ps->p > '9') return NULL;
      while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    }
    if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
      ps->p++;
      if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-')) ps->p++;
      if (ps->p >= ps->end || *ps->p < '0' || *ps->p > '9') return NULL;
      while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    }
    size_t len = (size_t)(ps->p - start);
    if (len >= 128) return NULL;
    char tmp[128]; memcpy(tmp, start, len); tmp[len] = '\0';
    double d = strtod(tmp, NULL);
    if (!isfinite(d)) return NULL;
    ax_json_value *v = new_value(ps, AX_J_NUMBER);
    if (!v) return NULL;
    v->num = d;
    return v;
  }
  if (ps->end - ps->p >= 4 && memcmp(ps->p, "true", 4) == 0) {
    ps->p += 4;
    ax_json_value *v = new_value(ps, AX_J_BOOL);
    if (!v) return NULL;
    v->boolean = 1;
    return v;
  }
  if (ps->end - ps->p >= 5 && memcmp(ps->p, "false", 5) == 0) {
    ps->p += 5;
    ax_json_value *v = new_value(ps, AX_J_BOOL);
    if (!v) return NULL;
    v->boolean = 0;
    return v;
  }
  if (ps->end - ps->p >= 4 && memcmp(ps->p, "null", 4) == 0) {
    ps->p += 4;
    return new_value(ps, AX_J_NULL);
  }
  return NULL;
}

int ax_json_parse(const char *json, size_t len, ax_json_value **out) {
  if (!out) return -1;
  *out = NULL;
  if (!json || len > AX_JSON_MAX_INPUT) return -1;
  parser ps = { json, json + len, 0, 0 };
  ax_json_value *v = parse_value(&ps);
  if (!v) return ps.out_of_memory ? AX_JSON_NOMEM : AX_JSON_INVALID;
  skip_ws(&ps);
  if (ps.p != ps.end) { ax_json_free(v); return -1; } /* trailing garbage */
  *out = v;
  return 0;
}

const ax_json_value *ax_json_get(const ax_json_value *obj, const char *key) {
  if (!obj || obj->type != AX_J_OBJECT) return NULL;
  for (size_t i = 0; i < obj->child_count; i++) {
    if (strcmp(obj->keys[i], key) == 0) return obj->children[i];
  }
  return NULL;
}

const char *ax_json_get_string(const ax_json_value *obj, const char *key) {
  const ax_json_value *v = ax_json_get(obj, key);
  return (v && v->type == AX_J_STRING) ? v->str : NULL;
}

double ax_json_get_number(const ax_json_value *obj, const char *key, double fallback) {
  const ax_json_value *v = ax_json_get(obj, key);
  return (v && v->type == AX_J_NUMBER) ? v->num : fallback;
}

int ax_json_get_bool(const ax_json_value *obj, const char *key, int fallback) {
  const ax_json_value *v = ax_json_get(obj, key);
  return (v && v->type == AX_J_BOOL) ? v->boolean : fallback;
}

const ax_json_value *ax_json_get_object(const ax_json_value *obj, const char *key) {
  const ax_json_value *v = ax_json_get(obj, key);
  return (v && v->type == AX_J_OBJECT) ? v : NULL;
}
