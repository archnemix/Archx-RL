#include "signals_linux.h"
#include "platform_signals.h"
#include "fallback_posix.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

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
static ax_signal_status read_first_line(const char *path, char *out, size_t out_len) {
  if (!out || out_len == 0) return AX_SIGNAL_INVALID;
  out[0] = '\0';
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    if (errno == EACCES || errno == EPERM) return AX_SIGNAL_DENIED;
    if (errno == ENOENT || errno == ENOTDIR) return AX_SIGNAL_ABSENT;
    return AX_SIGNAL_READ_ERROR;
  }
  char buf[512];
  size_t used = 0, length = 0;
  int complete = 0;
  ax_signal_status status = AX_SIGNAL_AVAILABLE;
  while (!complete) {
    if (used == sizeof buf) { status = AX_SIGNAL_INVALID; break; }
    ssize_t n = read(fd, buf + used, sizeof buf - used);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) { status = AX_SIGNAL_READ_ERROR; break; }
    if (n == 0) { length = used; complete = 1; break; }
    size_t end = used + (size_t)n;
    for (size_t i = used; i < end; i++) {
      if (buf[i] == '\n') { length = i; complete = 1; break; }
      if (buf[i] == '\0') { status = AX_SIGNAL_INVALID; complete = 1; break; }
    }
    used = end;
  }
  if (close(fd) != 0) status = AX_SIGNAL_READ_ERROR;
  if (status != AX_SIGNAL_AVAILABLE) return status;
  if (!complete || length >= out_len) return AX_SIGNAL_INVALID;
  if (!length) return AX_SIGNAL_ABSENT;
  memcpy(out, buf, length); out[length] = '\0';
  normalize(out);
  return out[0] ? AX_SIGNAL_AVAILABLE : AX_SIGNAL_ABSENT;
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
                       int weight, ax_signal_status status) {
  if (set->signal_count >= AX_MAX_SIGNALS) return;
  ax_signal *s = &set->signals[set->signal_count++];
  memset(s, 0, sizeof *s);
  snprintf(s->name, sizeof s->name, "%s", name);
  if (value) snprintf(s->value, sizeof s->value, "%s", value);
  s->weight = weight;
  s->status = status;
  s->readable = status == AX_SIGNAL_AVAILABLE;
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

static ax_signal_status read_validated(const char *path, char *value, size_t size,
                                       int (*validator)(const char *)) {
  ax_signal_status status = read_first_line(path, value, size);
  if (status != AX_SIGNAL_AVAILABLE) return status;
  int all_zero = 1;
  for (const char *p = value; *p; p++) if (*p != '0') all_zero = 0;
  if (all_zero || looks_placeholder(value)) status = AX_SIGNAL_PLACEHOLDER;
  else if (!validator(value)) status = AX_SIGNAL_INVALID;
  if (status != AX_SIGNAL_AVAILABLE) value[0] = '\0';
  return status;
}

/* Report the most significant failure when both machine-id sources fail. */
static int status_priority(ax_signal_status status) {
  switch (status) {
    case AX_SIGNAL_READ_ERROR: return 4;
    case AX_SIGNAL_DENIED: return 3;
    case AX_SIGNAL_INVALID: return 2;
    case AX_SIGNAL_PLACEHOLDER: return 1;
    default: return 0;
  }
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
    ax_signal_status status = read_validated("/etc/machine-id", value, sizeof value, valid_machine_id);
    if (status != AX_SIGNAL_AVAILABLE) {
      ax_signal_status alternate = read_validated("/var/lib/dbus/machine-id", value, sizeof value, valid_machine_id);
      if (alternate == AX_SIGNAL_AVAILABLE || status_priority(alternate) > status_priority(status)) status = alternate;
    }
    add_signal(out, "machine_id", status == AX_SIGNAL_AVAILABLE ? value : "", 60, status);
  }
  if (mask & 2u) {
    ax_signal_status status = read_validated("/sys/class/dmi/id/product_uuid", value, sizeof value, valid_product_uuid);
    add_signal(out, "product_uuid", status == AX_SIGNAL_AVAILABLE ? value : "", 25, status);
  }
  if (mask & 4u) {
    ax_signal_status status = read_validated("/sys/class/dmi/id/board_serial", value, sizeof value, valid_board_serial);
    add_signal(out, "board_serial", status == AX_SIGNAL_AVAILABLE ? value : "", 15, status);
  }

  return 0;
}

int ax_signals_collect_linux(ax_signal_set *out) {
  return ax_signals_collect_linux_selected(out, 7u);
}

/* Adapt the unchanged Linux collector and fallback to the common core. */
int ax_platform_collect_signals(ax_signal_set *out) {
  return ax_signals_collect_linux(out);
}
int ax_platform_collect_selected(ax_signal_set *out, unsigned mask) {
  return ax_signals_collect_linux_selected(out, mask);
}
int ax_platform_fallback_id(char *out, size_t out_len) {
  return ax_signals_fallback_id(out, out_len);
}
