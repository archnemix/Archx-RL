/* Synthetic canonicalization bounds and error propagation; no OS signals. */
#include "signals_linux.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

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
  assert(ax_signals_canonical(&set, out, sizeof expected) == strlen(expected));
  assert(strcmp(out, expected) == 0 && out[sizeof expected] == 'X');
  memset(out, 'X', sizeof out);
  assert(ax_signals_canonical(&set, out, sizeof expected - 1) == SIZE_MAX);
  assert(out[0] == 0 && out[sizeof expected - 1] == 'X');
  memset(out, 'X', sizeof out);
  assert(ax_signals_canonical(&set, out, 0) == SIZE_MAX && out[0] == 'X');
  assert(ax_signals_canonical(&set, NULL, 1) == SIZE_MAX);
  assert(ax_signals_canonical(NULL, out, sizeof out) == SIZE_MAX && out[0] == 0);
  memset(set.signals[0].name, 'x', sizeof set.signals[0].name);
  assert(ax_signals_canonical(&set, out, sizeof out) == SIZE_MAX && out[0] == 0);
  set.signals[0].readable = 0;
  assert(ax_signals_canonical(&set, out, sizeof out) == strlen("1:a5:first"));
  assert(strcmp(out, "1:a5:first") == 0);
  memset(set.signals[1].value, 'x', sizeof set.signals[1].value);
  assert(ax_signals_canonical(&set, out, sizeof out) == SIZE_MAX && out[0] == 0);
  set.signal_count = AX_MAX_SIGNALS + 1;
  assert(ax_signals_canonical(&set, out, sizeof out) == SIZE_MAX && out[0] == 0);
  puts("synthetic canonicalization bounds and failure tests passed");
  return 0;
}
