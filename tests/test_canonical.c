/* Synthetic canonicalization bounds and error propagation; no OS signals. */
#include "signals.h"
#include <stdio.h>
#include <string.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "canonical fixture failed at line %d: %s\n", __LINE__, #expr); return 1; } } while (0)

int main(void) {
  ax_signal_set set; memset(&set, 0, sizeof set);
  set.signal_count = 2;
  snprintf(set.signals[0].name, sizeof set.signals[0].name, "z");
  snprintf(set.signals[0].value, sizeof set.signals[0].value, "last");
  set.signals[0].readable = 1;
  snprintf(set.signals[1].name, sizeof set.signals[1].name, "a");
  snprintf(set.signals[1].value, sizeof set.signals[1].value, "first");
  set.signals[1].readable = 1;
  const char expected[] = "1:a5:first1:z4:last";
  char out[sizeof expected + 2]; memset(out, 'X', sizeof out);
  CHECK(ax_signals_canonical(&set, out, sizeof expected) == strlen(expected));
  CHECK(strcmp(out, expected) == 0 && out[sizeof expected] == 'X');
  memset(out, 'X', sizeof out);
  CHECK(ax_signals_canonical(&set, out, sizeof expected - 1) == SIZE_MAX);
  CHECK(out[0] == 0 && out[sizeof expected - 1] == 'X');
  memset(out, 'X', sizeof out);
  CHECK(ax_signals_canonical(&set, out, 0) == SIZE_MAX && out[0] == 'X');
  CHECK(ax_signals_canonical(&set, NULL, 1) == SIZE_MAX);
  CHECK(ax_signals_canonical(NULL, out, sizeof out) == SIZE_MAX && out[0] == 0);
  memset(set.signals[0].name, 'x', sizeof set.signals[0].name);
  CHECK(ax_signals_canonical(&set, out, sizeof out) == SIZE_MAX && out[0] == 0);
  set.signals[0].readable = 0;
  CHECK(ax_signals_canonical(&set, out, sizeof out) == strlen("1:a5:first"));
  CHECK(strcmp(out, "1:a5:first") == 0);
  memset(set.signals[1].value, 'x', sizeof set.signals[1].value);
  CHECK(ax_signals_canonical(&set, out, sizeof out) == SIZE_MAX && out[0] == 0);
  set.signal_count = AX_MAX_SIGNALS + 1;
  CHECK(ax_signals_canonical(&set, out, sizeof out) == SIZE_MAX && out[0] == 0);
  puts("synthetic canonicalization bounds and failure tests passed");
  return 0;
}
