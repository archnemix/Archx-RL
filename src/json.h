/* Minimal JSON parser — just enough for archx config documents.
 * Supports objects (nested, depth-limited), strings with escapes,
 * numbers, true/false/null. No arrays-of-objects needed for now.
 * Not a general-purpose JSON library. */
#ifndef AX_JSON_H
#define AX_JSON_H

#include <stddef.h>

typedef enum { AX_J_STRING, AX_J_NUMBER, AX_J_BOOL, AX_J_NULL, AX_J_OBJECT } ax_json_type;

typedef struct ax_json_value ax_json_value;
struct ax_json_value {
  ax_json_type type;
  double       num;
  int          boolean;
  char        *str;                 /* owned, for AX_J_STRING (unescaped) */
  ax_json_value *children[16];      /* object pairs (key/value interleaved
                                       via key_str) */
  char         *keys[16];           /* owned, object keys (parallel array) */
  size_t        child_count;
};

/* Parse `len` bytes of JSON into *out (owned). Returns 0 on success. */
int  ax_json_parse(const char *json, size_t len, ax_json_value **out);
void ax_json_free(ax_json_value *v);

const ax_json_value *ax_json_get(const ax_json_value *obj, const char *key);

/* Tiny accessors (all return NULL / fallback when absent). */
const char      *ax_json_get_string(const ax_json_value *obj, const char *key);
double           ax_json_get_number(const ax_json_value *obj, const char *key, double fallback);
int              ax_json_get_bool(const ax_json_value *obj, const char *key, int fallback);
const ax_json_value *ax_json_get_object(const ax_json_value *obj, const char *key);

#endif
