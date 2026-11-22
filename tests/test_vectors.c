/* Crypto test vectors: FIPS 180-4 examples + RFC 4231 HMAC cases.
 * Run: cc -Iinclude -Isrc tests/test_vectors.c src/sha256.c -o /tmp/tv && /tmp/tv */
#include <stdio.h>
#include <string.h>

#include "sha256.h"

static int failures = 0;

static void check_hex(const char *name, const uint8_t digest[32], const char *want) {
  char got[65];
  ax_hex_encode(digest, 32, got);
  if (strcmp(got, want) == 0) {
    printf("PASS %s\n", name);
  } else {
    printf("FAIL %s\n  got  %s\n  want %s\n", name, got, want);
    failures++;
  }
}

int main(void) {
  uint8_t d[32];

  /* FIPS 180-4: SHA-256("") */
  ax_sha256("", 0, d);
  check_hex("sha256 empty", d,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  /* FIPS 180-4: SHA-256("abc") */
  ax_sha256("abc", 3, d);
  check_hex("sha256 abc", d,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  /* FIPS 180-4: 56-byte message (exercises padding edge) */
  const char *m56 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  ax_sha256(m56, strlen(m56), d);
  check_hex("sha256 56-byte", d,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

  /* RFC 4231 test case 1: key = 0x0b * 20, data = "Hi There" */
  uint8_t key1[20];
  memset(key1, 0x0b, sizeof key1);
  ax_hmac_sha256(key1, sizeof key1, (const uint8_t *)"Hi There", 8, d);
  check_hex("hmac rfc4231 case1", d,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

  /* RFC 4231 test case 2: key = "Jefe" */
  ax_hmac_sha256((const uint8_t *)"Jefe", 4,
                 (const uint8_t *)"what do ya want for nothing?", 28, d);
  check_hex("hmac rfc4231 case2", d,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

  /* RFC 4231 test case 6: key longer than block size (131 bytes of 0xaa) */
  uint8_t key6[131];
  memset(key6, 0xaa, sizeof key6);
  ax_hmac_sha256(key6, sizeof key6,
                 (const uint8_t *)"Test Using Larger Than Block-Sized Key - Hash Key First",
                 55, d);
  check_hex("hmac rfc4231 case6", d,
            "ad47763c29284e9399feab51e0e79c9c5869cd06617d14fe69f0af19ffbd51cd");

  if (failures) {
    printf("%d vector(s) FAILED\n", failures);
    return 1;
  }
  printf("all vectors passed\n");
  return 0;
}
