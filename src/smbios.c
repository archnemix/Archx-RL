/* Strictly bounded SMBIOS Type 1/2 parser. No OS calls or logging. */
#include "smbios.h"
#include <string.h>

static int placeholder(const char *s) {
  static const char *const values[] = {
    "0", "none", "unknown", "not specified", "not applicable",
    "to be filled by o.e.m.", "default string", "system serial number"
  };
  for (size_t i = 0; i < sizeof values / sizeof values[0]; i++)
    if (strcmp(s, values[i]) == 0) return 1;
  return 0;
}

static void parse_uuid(const uint8_t *p, int little_fields, ax_smbios_result *out) {
  int zeros = 1, ones = 1;
  for (size_t i = 0; i < 16; i++) { zeros &= p[i] == 0; ones &= p[i] == 0xff; }
  if (zeros || ones) { out->uuid_status = AX_SMBIOS_PLACEHOLDER; return; }
  static const uint8_t wire_order[16] = {3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
  static const char hex[] = "0123456789abcdef";
  size_t pos = 0;
  for (size_t i = 0; i < 16; i++) {
    if (i == 4 || i == 6 || i == 8 || i == 10) out->uuid[pos++] = '-';
    uint8_t byte = p[little_fields ? wire_order[i] : i];
    out->uuid[pos++] = hex[byte >> 4]; out->uuid[pos++] = hex[byte & 15];
  }
  out->uuid[pos] = '\0';
  out->uuid_status = AX_SMBIOS_PRESENT;
}

/* `end` is the first zero byte of the final double-null. */
static int parse_serial(const uint8_t *data, size_t start, size_t end,
                        unsigned index, char *out, size_t out_size,
                        ax_smbios_status *status) {
  if (!index) { *status = AX_SMBIOS_ABSENT; return 0; }
  size_t cur = start;
  unsigned current = 1;
  while (cur < end) {
    size_t next = cur;
    while (next < end && data[next] != 0) next++;
    if (current == index) {
      size_t left = cur, right = next;
      while (left < right && data[left] == ' ') left++;
      while (right > left && data[right - 1] == ' ') right--;
      size_t length = right - left;
      if (!length) { *status = AX_SMBIOS_PLACEHOLDER; return 0; }
      if (length > out_size - 1) { *status = AX_SMBIOS_INVALID; return 0; }
      for (size_t i = 0; i < length; i++) {
        unsigned char c = data[left + i];
        if (c < 0x20 || c > 0x7e) { *status = AX_SMBIOS_INVALID; memset(out, 0, out_size); return 0; }
        out[i] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
      }
      out[length] = '\0';
      if (placeholder(out)) { memset(out, 0, out_size); *status = AX_SMBIOS_PLACEHOLDER; }
      else *status = AX_SMBIOS_PRESENT;
      return 0;
    }
    current++;
    cur = next + 1;
  }
  return -1; /* index references a nonexistent string */
}

int ax_smbios_parse_rsmb(const uint8_t *raw, size_t len, ax_smbios_result *out) {
  if (!out) return -1;
  memset(out, 0, sizeof *out);
  if (!raw || len < 8 || len > AX_SMBIOS_MAX_RAW || raw[1] < 2) return -1;
  uint32_t table_len = (uint32_t)raw[4] | ((uint32_t)raw[5] << 8) |
                       ((uint32_t)raw[6] << 16) | ((uint32_t)raw[7] << 24);
  if ((size_t)table_len != len - 8) return -1;
  ax_smbios_result result;
  memset(&result, 0, sizeof result);
  int found_type1 = 0, found_type2 = 0, found_end = 0;
  size_t pos = 8;
  while (pos < len) {
    if (len - pos < 4) return -1;
    unsigned type = raw[pos], formatted = raw[pos + 1];
    if (formatted < 4 || formatted > len - pos) return -1;
    size_t strings = pos + formatted, end = strings;
    while (end < len && len - end >= 2 && !(raw[end] == 0 && raw[end + 1] == 0)) end++;
    if (end >= len || len - end < 2) return -1;
    if (type == 1) {
      if (found_type1 || formatted < 8) return -1;
      found_type1 = 1;
      if (formatted >= 24) parse_uuid(raw + pos + 8, raw[1] > 2 || (raw[1] == 2 && raw[2] >= 6), &result);
      else result.uuid_status = AX_SMBIOS_UNSUPPORTED;
      if (parse_serial(raw, strings, end, raw[pos + 7], result.serial,
                       sizeof result.serial, &result.serial_status) != 0) return -1;
    } else if (type == 2) {
      if (formatted < 8) return -1;
      /* Multiple Type 2 entries are valid in SMBIOS. Do not guess which
       * physical board the caller meant, even when their serials match. */
      char board[sizeof result.board_serial] = {0};
      ax_smbios_status status = AX_SMBIOS_ABSENT;
      if (parse_serial(raw, strings, end, raw[pos + 7], board, sizeof board, &status) != 0) return -1;
      if (!found_type2) {
        memcpy(result.board_serial, board, sizeof board);
        result.board_serial_status = status;
      } else {
        memset(result.board_serial, 0, sizeof result.board_serial);
        result.board_serial_status = AX_SMBIOS_AMBIGUOUS;
      }
      found_type2 = 1;
    }
    pos = end + 2;
    if (type == 127) {
      if (formatted != 4 || end != strings) return -1;
      found_end = 1;
      while (pos < len) if (raw[pos++] != 0) return -1;
      break;
    }
  }
  if (!found_end) return -1;
  *out = result;
  return 0;
}
