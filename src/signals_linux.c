#include "signals_linux.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "sha256.h"
#include "platform.h"

static void normalize(char *s) {
  for (char *p = s; *p; p++) {
    if (*p >= 'A' && *p <= 'Z') *p = (char)(*p - 'A' + 'a');
  }
  /* trim leading/trailing whitespace/newlines */
  char *start = s;
  while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r') start++;
  if (!*s) return;
  char *end = s + strlen(s) - 1;
  while (end > start && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
    *end = '\0';
    end--;
  }
  if (start != s) memmove(s, start, strlen(start) + 1);
}

/* Read a complete bounded first line. Partial reads, NULs and a truncated
 * first line are never accepted as a different identity. */
static int read_first_line(const char *path, char *out, size_t out_len) {
  if (!out || out_len == 0) return 0;
  out[0] = '\0';
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0;
  char buf[512];
  size_t used = 0, length = 0;
  int complete = 0, valid = 1;
  while (!complete) {
    if (used == sizeof buf) { valid = 0; break; }
    ssize_t n = read(fd, buf + used, sizeof buf - used);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) { valid = 0; break; }
    if (n == 0) { length = used; complete = 1; break; }
    size_t end = used + (size_t)n;
    for (size_t i = used; i < end; i++) {
      if (buf[i] == '\n') { length = i; complete = 1; break; }
      if (buf[i] == '\0') { valid = 0; complete = 1; break; }
    }
    used = end;
  }
  if (close(fd) != 0) valid = 0;
  if (!valid || !complete || !length || length >= out_len) return 0;
  memcpy(out, buf, length); out[length] = '\0';
  normalize(out);
  return out[0] != '\0';
}

static int lower_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }

static int valid_machine_id(const char *v) {
  if (strlen(v) != 32) return 0;
  int all_zero = 1, all_f = 1;
  for (size_t i = 0; i < 32; i++) {
    if (!lower_hex(v[i])) return 0;
    all_zero &= v[i] == '0'; all_f &= v[i] == 'f';
  }
  return !all_zero && !all_f;
}

static int valid_product_uuid(const char *v) {
  if (strlen(v) != 36) return 0;
  int all_zero = 1, all_f = 1;
  for (size_t i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23) { if (v[i] != '-') return 0; continue; }
    if (!lower_hex(v[i])) return 0;
    all_zero &= v[i] == '0'; all_f &= v[i] == 'f';
  }
  return !all_zero && !all_f;
}

static int valid_board_serial(const char *v) {
  size_t n = strlen(v);
  if (n < 4 || n > 128) return 0;
  int all_zero = 1;
  for (size_t i = 0; i < n; i++) {
    char c = v[i];
    int alnum = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    if ((!i && !alnum) || (!alnum && c != ' ' && c != '.' && c != '_' && c != ':' && c != '/' && c != '-')) return 0;
    all_zero &= c == '0';
  }
  return !all_zero;
}

static void add_signal(ax_signal_set *set, const char *name, const char *value,
                       int weight, int readable) {
  if (set->signal_count >= AX_MAX_SIGNALS) return;
  ax_signal *s = &set->signals[set->signal_count++];
  memset(s, 0, sizeof *s);
  snprintf(s->name, sizeof s->name, "%s", name);
  if (value) snprintf(s->value, sizeof s->value, "%s", value);
  s->weight = weight;
  s->readable = readable;
}

/* Reject obviously-placeholder values some vendors ship. */
static int looks_placeholder(const char *v) {
  static const char *bad[] = {
    "00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "00000000000000000000000000000000", "ffffffffffffffffffffffffffffffff",
    "uninitialized", "to be filled by o.e.m.", "to be filled by oem", "not specified",
    "not applicable", "none", "unknown", "n/a", "default string", "system serial number", "oem", "0", NULL
  };
  for (int i = 0; bad[i]; i++) if (strcmp(v, bad[i]) == 0) return 1;
  return 0;
}

int ax_signals_collect_linux_selected(ax_signal_set *out, unsigned mask) {
  memset(out, 0, sizeof *out);
  snprintf(out->os, sizeof out->os, "linux");
  struct utsname uts;
  if (uname(&uts) == 0) {
    snprintf(out->arch, sizeof out->arch, "%.31s", uts.machine);
  } else {
    snprintf(out->arch, sizeof out->arch, "unknown");
  }

  char value[256];

  if (mask & 1u) {
    value[0] = '\0';
    int ok = read_first_line("/etc/machine-id", value, sizeof value) && valid_machine_id(value);
    if (!ok) ok = read_first_line("/var/lib/dbus/machine-id", value, sizeof value) && valid_machine_id(value);
    add_signal(out, "machine_id", ok ? value : "", 60, ok);
  }
  if (mask & 2u) {
    value[0] = '\0';
    int ok = read_first_line("/sys/class/dmi/id/product_uuid", value, sizeof value) && valid_product_uuid(value);
    add_signal(out, "product_uuid", ok ? value : "", 25, ok);
  }
  if (mask & 4u) {
    value[0] = '\0';
    int ok = read_first_line("/sys/class/dmi/id/board_serial", value, sizeof value) && !looks_placeholder(value) && valid_board_serial(value);
    add_signal(out, "board_serial", ok ? value : "", 15, ok);
  }

  return 0;
}

int ax_signals_collect_linux(ax_signal_set *out) {
  return ax_signals_collect_linux_selected(out, 7u);
}

static int mkdir_p(const char *path) {
  char tmp[512];
  if (strlen(path) >= sizeof tmp) return -1;
  memcpy(tmp, path, strlen(path) + 1);
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return -1;
      *p = '/';
    }
  }
  if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return -1;
  return 0;
}

int ax_signals_fallback_id(char *out, size_t out_len) {
  if (!out || out_len < 65) return -1;
  const char *xdg = getenv("XDG_DATA_HOME");
  const char *home = getenv("HOME");
  char dir[512], path[600];
  int n;
  if (xdg && *xdg == '/') n = snprintf(dir, sizeof dir, "%s/archx", xdg);
  else if (home && *home == '/') n = snprintf(dir, sizeof dir, "%s/.local/share/archx", home);
  else return -1;
  if (n < 0 || (size_t)n >= sizeof dir || mkdir_p(dir) != 0) return -1;
  n = snprintf(path, sizeof path, "%s/device_id", dir);
  if (n < 0 || (size_t)n >= sizeof path || out_len < 65) return -1;
  int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) return -1;
  int result = -1;
  if (flock(fd, LOCK_EX) != 0) { close(fd); return -1; }
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 077) != 0) goto done;
  char hex[65];
  if (st.st_size == 0) {
    uint8_t raw[32];
    if (ax_platform_random(raw, sizeof raw) != 0) goto done;
    ax_hex_encode(raw, sizeof raw, hex);
    size_t offset = 0;
    while (offset < 64) {
      ssize_t count = write(fd, hex + offset, 64 - offset);
      if (count < 0 && errno == EINTR) continue;
      if (count <= 0) goto done;
      offset += (size_t)count;
    }
    if (fsync(fd) != 0) goto done;
  } else {
    if (st.st_size != 64) goto done;
    size_t offset = 0;
    while (offset < 64) {
      ssize_t count = read(fd, hex + offset, 64 - offset);
      if (count < 0 && errno == EINTR) continue;
      if (count <= 0) goto done;
      offset += (size_t)count;
    }
    hex[64] = '\0';
    for (size_t i = 0; i < 64; i++)
      if (!((hex[i] >= '0' && hex[i] <= '9') || (hex[i] >= 'a' && hex[i] <= 'f'))) goto done;
  }
  result = 0;
done:
  /* Do not expose an ID when unlocking or closing reports failure. These
   * failures may follow writes and do not imply durable-state rollback. */
  if (flock(fd, LOCK_UN) != 0) result = -1;
  if (close(fd) != 0) result = -1;
  if (result == 0) memcpy(out, hex, 65);
  return result;
}
