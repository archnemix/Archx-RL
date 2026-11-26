/* Synthetic SMBIOS fixtures only. Never logs firmware identifiers. */
#include "smbios.h"
#include <stdio.h>
#include <string.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "SMBIOS fixture failed at line %d: %s\n", __LINE__, #expr); return 1; } } while (0)

/* Raw header, one Type 1 structure, one Type 127 end marker. */
static size_t fixture(unsigned char *raw, const char *serial) {
  memset(raw, 0, 512);
  raw[1] = 2; raw[2] = 6;
  raw[8] = 1; raw[9] = 25; raw[15] = 1;
  static const unsigned char uuid[16] = {0x33,0x22,0x11,0x00,0x55,0x44,0x77,0x66,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  memcpy(raw + 16, uuid, sizeof uuid);
  size_t pos = 33, n = strlen(serial);
  memcpy(raw + pos, serial, n); pos += n;
  raw[pos++] = 0; raw[pos++] = 0;
  raw[pos++] = 127; raw[pos++] = 4; raw[pos++] = 0; raw[pos++] = 0; raw[pos++] = 0; raw[pos++] = 0;
  unsigned length = (unsigned)(pos - 8);
  raw[4]=(unsigned char)length; raw[5]=(unsigned char)(length>>8);
  return pos;
}

/* One minimal Type 2 and a terminator; values are synthetic. */
static size_t board_fixture(unsigned char *raw, const char *serial) {
  memset(raw, 0, 512);
  raw[1] = 2; raw[2] = 6;
  raw[8] = 2; raw[9] = 8; raw[15] = 1;
  size_t pos = 16, n = strlen(serial);
  memcpy(raw + pos, serial, n); pos += n;
  raw[pos++] = 0; raw[pos++] = 0;
  raw[pos++] = 127; raw[pos++] = 4; raw[pos++] = 0; raw[pos++] = 0; raw[pos++] = 0; raw[pos++] = 0;
  unsigned length = (unsigned)(pos - 8);
  raw[4] = (unsigned char)length; raw[5] = (unsigned char)(length >> 8);
  return pos;
}

int main(void) {
  unsigned char data[512]; ax_smbios_result out;
  size_t len = fixture(data, "  Synthetic-Serial-1  ");
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0);
  CHECK(out.uuid_status == AX_SMBIOS_PRESENT && strcmp(out.uuid, "00112233-4455-6677-8899-aabbccddeeff") == 0);
  CHECK(out.serial_status == AX_SMBIOS_PRESENT && strcmp(out.serial, "synthetic-serial-1") == 0);
  data[2] = 5;
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0 && strcmp(out.uuid,"33221100-5544-7766-8899-aabbccddeeff") == 0);
  data[2] = 6;
  for (size_t i=0; i<len; i++) {
    memset(&out, 0xaa, sizeof out);
    CHECK(ax_smbios_parse_rsmb(data, i, &out) == -1);
    CHECK(out.uuid_status == AX_SMBIOS_ABSENT && out.serial_status == AX_SMBIOS_ABSENT && !out.uuid[0] && !out.serial[0]);
  }
  CHECK(ax_smbios_parse_rsmb(NULL, len, &out) == -1);
  CHECK(ax_smbios_parse_rsmb(data, len, NULL) == -1);
  data[4]++; CHECK(ax_smbios_parse_rsmb(data, len, &out) == -1); data[4]--;
  data[9]=3; CHECK(ax_smbios_parse_rsmb(data, len, &out) == -1); data[9]=25;
  data[15]=2; CHECK(ax_smbios_parse_rsmb(data, len, &out) == -1); data[15]=1;
  memset(data + 16, 0, 16);
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0 && out.uuid_status == AX_SMBIOS_PLACEHOLDER && !out.uuid[0]);
  memset(data + 16, 0xff, 16);
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0 && out.uuid_status == AX_SMBIOS_PLACEHOLDER);
  const char *vendor_placeholders[] = {"  To Be Filled By O.E.M. ", "To Be Filled By OEM", "N/A", "Uninitialized", "OEM", "Default String"};
  for (size_t i=0; i<sizeof vendor_placeholders / sizeof vendor_placeholders[0]; i++) {
    len = fixture(data, vendor_placeholders[i]);
    CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0 && out.serial_status == AX_SMBIOS_PLACEHOLDER && !out.serial[0]);
  }
  len = fixture(data, "serial"); data[33] = 0xc3;
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0 && out.serial_status == AX_SMBIOS_INVALID && !out.serial[0]);
  len = fixture(data, "serial"); data[15] = 0;
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0 && out.serial_status == AX_SMBIOS_ABSENT);
  len = fixture(data, "serial"); data[len-6] = 1; /* duplicate Type 1 */
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == -1);
  len = fixture(data, "serial"); data[len-1] = 1; /* missing end terminator */
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == -1);
  len = fixture(data, "serial"); data[len-6] = 126; /* no end marker */
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == -1);
  CHECK(ax_smbios_parse_rsmb(data, AX_SMBIOS_MAX_RAW + 1u, &out) == -1);
  len = fixture(data, "serial");
  /* Even if a malicious length field follows the truncation, no incomplete
   * record or missing end marker may yield a partial successful parse. */
  for (size_t i=8; i<len; i++) {
    unsigned n = (unsigned)(i - 8);
    data[4]=(unsigned char)n; data[5]=(unsigned char)(n >> 8);
    CHECK(ax_smbios_parse_rsmb(data, i, &out) == -1);
  }
  len = fixture(data, "serial");
  /* Append an entire duplicate Type 1 before the real end marker. */
  size_t type1_len = len - 8 - 6;
  memmove(data + 8 + 2*type1_len, data + 8 + type1_len, 6);
  memcpy(data + 8 + type1_len, data + 8, type1_len);
  len += type1_len;
  data[4]=(unsigned char)(len-8); data[5]=(unsigned char)((len-8)>>8);
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == -1);
  char long_serial[160]; memset(long_serial, 'x', sizeof long_serial - 1); long_serial[sizeof long_serial - 1] = 0;
  len = fixture(data, long_serial);
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0 && out.serial_status == AX_SMBIOS_INVALID && !out.serial[0]);
  len = fixture(data, "serial");
  /* Test the second string number without relying on unbounded strlen. */
  memmove(data + 37, data + 33, len - 33);
  memcpy(data + 33, "one", 3); data[36] = 0; len += 4;
  data[15]=2; data[4]=(unsigned char)(len-8); data[5]=(unsigned char)((len-8)>>8);
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0 && strcmp(out.serial, "serial") == 0);
  /* Valid old type-1 structure has no UUID field and no serial. */
  memset(data, 0, sizeof data); data[1]=2; data[2]=0; data[4]=16;
  data[8]=1; data[9]=8; data[18]=127; data[19]=4;
  CHECK(ax_smbios_parse_rsmb(data, 24, &out) == 0 && out.uuid_status == AX_SMBIOS_UNSUPPORTED && out.serial_status == AX_SMBIOS_ABSENT);
  /* A valid table can omit Type 1; this is absence, not a fabricated value. */
  memset(data, 0, sizeof data); data[1]=2; data[2]=6; data[4]=6; data[8]=127; data[9]=4;
  CHECK(ax_smbios_parse_rsmb(data, 14, &out) == 0 && out.uuid_status == AX_SMBIOS_ABSENT);
  /* Type 2 serial is distinct from Type 1 system serial. */
  len = board_fixture(data, "  Synthetic-Board-1  ");
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0);
  CHECK(out.board_serial_status == AX_SMBIOS_PRESENT && strcmp(out.board_serial, "synthetic-board-1") == 0);
  CHECK(out.serial_status == AX_SMBIOS_ABSENT && out.uuid_status == AX_SMBIOS_ABSENT);
  data[15] = 0;
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0 && out.board_serial_status == AX_SMBIOS_ABSENT && !out.board_serial[0]);
  data[15] = 2;
  memset(&out, 0xaa, sizeof out);
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == -1 && out.board_serial_status == AX_SMBIOS_ABSENT && !out.board_serial[0]);
  data[15] = 1; data[9] = 7;
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == -1 && !out.board_serial[0]);
  len = board_fixture(data, "  To Be Filled By O.E.M.  ");
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0 && out.board_serial_status == AX_SMBIOS_PLACEHOLDER && !out.board_serial[0]);
  len = board_fixture(data, "board"); data[16] = 0xc3;
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0 && out.board_serial_status == AX_SMBIOS_INVALID && !out.board_serial[0]);
  len = board_fixture(data, long_serial);
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0 && out.board_serial_status == AX_SMBIOS_INVALID && !out.board_serial[0]);
  /* System and board serials remain separate when both records exist. */
  unsigned char board_data[512];
  len = fixture(data, "system-synthetic");
  size_t board_len = board_fixture(board_data, "board-synthetic");
  size_t single_board_len = board_len - 8 - 6;
  memmove(data + len - 6 + single_board_len, data + len - 6, 6);
  memcpy(data + len - 6, board_data + 8, single_board_len);
  len += single_board_len;
  data[4] = (unsigned char)(len-8); data[5] = (unsigned char)((len-8)>>8);
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0);
  CHECK(out.serial_status == AX_SMBIOS_PRESENT && strcmp(out.serial, "system-synthetic") == 0);
  CHECK(out.board_serial_status == AX_SMBIOS_PRESENT && strcmp(out.board_serial, "board-synthetic") == 0);
  len = board_fixture(data, "board");
  size_t type2_len = len - 8 - 6;
  memmove(data + 8 + 2*type2_len, data + 8 + type2_len, 6);
  memcpy(data + 8 + type2_len, data + 8, type2_len);
  len += type2_len;
  data[4] = (unsigned char)(len-8); data[5] = (unsigned char)((len-8)>>8);
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == 0 && out.board_serial_status == AX_SMBIOS_AMBIGUOUS && !out.board_serial[0]);
  data[8 + type2_len + 7] = 2; /* Invalid string in another Type 2 is still malformed. */
  CHECK(ax_smbios_parse_rsmb(data, len, &out) == -1 && out.board_serial_status == AX_SMBIOS_ABSENT && !out.board_serial[0]);
  len = board_fixture(data, "board");
  for (size_t i=0; i<len; i++) {
    memset(&out, 0xaa, sizeof out);
    CHECK(ax_smbios_parse_rsmb(data, i, &out) == -1 && out.board_serial_status == AX_SMBIOS_ABSENT && !out.board_serial[0]);
  }
  /* Deterministic malformed bytes smoke, not a coverage-guided fuzz campaign. */
  unsigned state = 7;
  for (unsigned n=0; n<5000; n++) {
    for (size_t i=0; i<sizeof data; i++) { state = state * 1664525u + 1013904223u; data[i]=(unsigned char)(state >> 24); }
    (void)ax_smbios_parse_rsmb(data, (size_t)(n % sizeof data), &out);
  }
  for (unsigned n=0; n<5000; n++) {
    len = fixture(data, "synthetic-fixture");
    state = state * 1664525u + 1013904223u;
    size_t index = (size_t)(state % (unsigned)len);
    data[index] ^= (unsigned char)(1u << ((state >> 8) & 7u));
    if (ax_smbios_parse_rsmb(data, len, &out) == 0) {
      CHECK(memchr(out.uuid, 0, sizeof out.uuid) != NULL);
      CHECK(memchr(out.serial, 0, sizeof out.serial) != NULL);
      CHECK(memchr(out.board_serial, 0, sizeof out.board_serial) != NULL);
    }
  }
  puts("synthetic SMBIOS parser fixtures passed");
  return 0;
}
