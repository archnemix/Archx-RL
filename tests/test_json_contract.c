/* Native synthetic contract fixtures; no external provider or raw user data. */
#include "json.h"
#include <stdio.h>
#include <string.h>
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "JSON contract failure at line %d: %s\n", __LINE__, #expr); return 1; } } while (0)

static int check(const char *text, int expected) {
  ax_json_value *value = NULL;
  int status = ax_json_parse(text, strlen(text), &value);
  int ok = expected ? status == 0 && value != NULL : status != 0 && value == NULL;
  ax_json_free(value);
  return ok;
}
int main(void) {
  CHECK(check("{\"a\":1,\"b\":true,\"c\":{\"d\":\"x\"}}", 1));
  CHECK(check("{\"a\":1,\"a\":2}", 0));
  CHECK(check("{\"a\":1,\"\\u0061\":2}", 0));
  CHECK(check("{\"x\":[1]}", 0));
  CHECK(check("{\"x\":\"\\u0000\"}", 0));
  CHECK(check("{\"x\":\"\\ud83d\\ude00\"}", 0));
  CHECK(check("{\"x\":1e999}", 0));
  CHECK(check("{\"x\":01}", 0));
  CHECK(check("{\"x\":1} trailing", 0));
  CHECK(check("{\"x\":\"unterminated}", 0));
  CHECK(check("{\"a\":1,\"b\":1,\"c\":1,\"d\":1,\"e\":1,\"f\":1,\"g\":1,\"h\":1,\"i\":1,\"j\":1,\"k\":1,\"l\":1,\"m\":1,\"n\":1,\"o\":1,\"p\":1}", 1));
  CHECK(check("{\"a\":1,\"b\":1,\"c\":1,\"d\":1,\"e\":1,\"f\":1,\"g\":1,\"h\":1,\"i\":1,\"j\":1,\"k\":1,\"l\":1,\"m\":1,\"n\":1,\"o\":1,\"p\":1,\"q\":1}", 0));
  puts("Synthetic JSON contract fixtures passed");
  return 0;
}
