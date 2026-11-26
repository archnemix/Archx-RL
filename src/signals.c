/* Platform-independent canonical form for synthetic or collected signals. */
#include "signals.h"
#include <stdio.h>
#include <string.h>

size_t ax_signals_canonical(const ax_signal_set *set, char *out, size_t out_len) {
  if (out && out_len) out[0] = '\0';
  if (!set || !out || !out_len || set->signal_count > AX_MAX_SIGNALS) return SIZE_MAX;
  /* Copy readable signal pointers and sort by name, preserving input order
   * for equal names. The canonical format is independent of the collector. */
  const ax_signal *items[AX_MAX_SIGNALS];
  size_t n = 0;
  for (size_t i = 0; i < set->signal_count; i++) {
    if (set->signals[i].readable) {
      if (!memchr(set->signals[i].name, '\0', sizeof set->signals[i].name) ||
          !memchr(set->signals[i].value, '\0', sizeof set->signals[i].value)) return SIZE_MAX;
      items[n++] = &set->signals[i];
    }
  }
  for (size_t i = 1; i < n; i++) {
    const ax_signal *t = items[i];
    size_t j = i;
    while (j > 0 && strcmp(items[j - 1]->name, t->name) > 0) { items[j] = items[j - 1]; j--; }
    items[j] = t;
  }
  size_t written = 0;
  out[0] = '\0';
  for (size_t i = 0; i < n; i++) {
    int r = snprintf(out + written, out_len - written, "%zu:%s%zu:%s", strlen(items[i]->name),
                     items[i]->name, strlen(items[i]->value), items[i]->value);
    if (r < 0 || (size_t)r >= out_len - written) { out[0] = '\0'; return SIZE_MAX; }
    written += (size_t)r;
  }
  return written;
}
