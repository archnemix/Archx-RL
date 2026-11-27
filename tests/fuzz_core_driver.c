/* Deterministic standalone smoke for the libFuzzer entry point. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int main(void) {
  static const char *const seeds[] = {
    "{}", "[]", "null", "[1,2,3]", "{\"a\":1,\"a\":2}",
    "{\"app_id\":\"test\",\"pepper\":\"synthetic\"}",
    "{\"version\":1,\"scope\":\"broken\",\"signals\":{\"ip\":null}}",
    "{\"nested\":[[[[[{\"bad\":\"\\ud800\"}]]]]]}"
  };
  for (size_t i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    LLVMFuzzerTestOneInput((const uint8_t *)seeds[i], strlen(seeds[i]));
  uint32_t state = 0x76af21u;
  uint8_t bytes[512];
  for (size_t i = 0; i < 500; i++) {
    size_t length = i % sizeof bytes;
    for (size_t j = 0; j < length; j++) {
      state ^= state << 13; state ^= state >> 17; state ^= state << 5;
      bytes[j] = (uint8_t)state;
    }
    LLVMFuzzerTestOneInput(bytes, length);
  }
  uint8_t *large = (uint8_t *)malloc(65537);
  if (!large) return 1;
  memset(large, ' ', 65537);
  LLVMFuzzerTestOneInput(large, 65536);
  LLVMFuzzerTestOneInput(large, 65537);
  free(large);
  puts("synthetic JSON/config/profile fuzz entry smoke passed");
  return 0;
}
