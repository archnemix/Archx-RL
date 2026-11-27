/* Test POSIX fallback with disposable files and synthetic directory only. */
#include "fallback_posix.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "POSIX fallback failed at line %d: %s\n", __LINE__, #expr); return 1; } } while (0)
int main(void) {
  char dir[] = "/tmp/archx-posix-fallback-XXXXXX";
  CHECK(mkdtemp(dir) != NULL);
  CHECK(setenv("XDG_DATA_HOME", dir, 1) == 0);
  int fds[2]; CHECK(pipe(fds) == 0);
  pid_t children[8];
  for (int i = 0; i < 8; i++) {
    children[i] = fork();
    CHECK(children[i] >= 0);
    if (children[i] == 0) {
      char id[65]; close(fds[0]);
      if (ax_signals_fallback_id(id, sizeof id) != 0 || write(fds[1], id, sizeof id) != sizeof id) _exit(1);
      close(fds[1]); _exit(0);
    }
  }
  close(fds[1]);
  char ids[8][65]; size_t used = 0;
  while (used < sizeof ids) {
    ssize_t n = read(fds[0], (char *)ids + used, sizeof ids - used);
    if (n < 0 && errno == EINTR) continue;
    CHECK(n > 0); used += (size_t)n;
  }
  close(fds[0]);
  for (int i = 0; i < 8; i++) {
    int status; CHECK(waitpid(children[i], &status, 0) == children[i]);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(strlen(ids[i]) == 64 && strcmp(ids[i], ids[0]) == 0);
  }
  char path[512], subdir[512], output[65];
  int n = snprintf(path, sizeof path, "%s/archx/device_id", dir);
  CHECK(n > 0 && (size_t)n < sizeof path);
  n = snprintf(subdir, sizeof subdir, "%s/archx", dir);
  CHECK(n > 0 && (size_t)n < sizeof subdir);
  struct stat st;
  CHECK(lstat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == getuid() && (st.st_mode & 077) == 0);
  CHECK(ax_signals_fallback_id(output, sizeof output) == 0 && strcmp(output, ids[0]) == 0);
  CHECK(chmod(path, 0644) == 0);
  memset(output, 'Z', sizeof output);
  CHECK(ax_signals_fallback_id(output, sizeof output) != 0 && output[0] == 'Z');
  CHECK(unlink(path) == 0);
  CHECK(symlink("/dev/null", path) == 0);
  CHECK(ax_signals_fallback_id(output, sizeof output) != 0 && output[0] == 'Z');
  CHECK(unlink(path) == 0);
  int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
  CHECK(fd >= 0 && write(fd, "bad", 3) == 3 && close(fd) == 0);
  CHECK(ax_signals_fallback_id(output, sizeof output) != 0 && output[0] == 'Z');
  CHECK(unlink(path) == 0 && rmdir(subdir) == 0 && rmdir(dir) == 0);
  CHECK(unsetenv("XDG_DATA_HOME") == 0);
  puts("POSIX synthetic private fallback and concurrent first use passed");
  return 0;
}
