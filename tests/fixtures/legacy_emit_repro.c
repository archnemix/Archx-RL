/* Minimal reproduction of the original emit_json's unbounded strlen contract.
 * Synthetic input only. This is historical, intentionally unsafe test code,
 * NOT a copy of the current implementation or proof of the original GCC
 * report's cause; see Docs/Research/Analyzer-Triage.md.
 */
#include <stdlib.h>
#include <string.h>

static char *legacy_emit(char *stack_buf, size_t stack_len) {
  size_t n = strlen(stack_buf);
  char *heap = malloc(n + 1);
  if (!heap) return NULL;
  memcpy(heap, stack_buf, n + 1);
  (void)stack_len;
  return heap;
}

int main(void) {
  char unterminated[] = {'x', 'y', 'z'};
  char *result = legacy_emit(unterminated, sizeof unterminated);
  free(result);
  return 0;
}
