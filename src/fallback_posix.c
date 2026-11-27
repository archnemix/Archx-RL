/* Private per-user prototype fallback for POSIX hosts. Parent paths are trusted. */
#include "fallback_posix.h"
#include "platform.h"
#include "sha256.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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
