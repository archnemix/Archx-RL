/* Fault injection for a synthetic per-user fallback file, never OS identifiers. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static int fail_kind, calls, fail_at, partial_write;
enum { INJECT_MKDIR=1, INJECT_OPEN, INJECT_LOCK, INJECT_STAT, INJECT_READ, INJECT_WRITE, INJECT_SYNC, INJECT_UNLOCK, INJECT_CLOSE };
static int inject(int kind) { return fail_kind == kind && ++calls == fail_at; }
static int test_mkdir(const char *path, mode_t mode);
static int test_open(const char *path, int flags, ...);
static int test_flock(int fd, int operation);
static int test_fstat(int fd, struct stat *st);
static ssize_t test_read(int fd, void *buf, size_t n);
static ssize_t test_write(int fd, const void *buf, size_t n);
static int test_fsync(int fd);
static int test_close(int fd);
#define mkdir test_mkdir
#define open test_open
#define flock test_flock
#define fstat test_fstat
#define read test_read
#define write test_write
#define fsync test_fsync
#define close test_close
#include "../src/fallback_posix.c"
#undef mkdir
#undef open
#undef flock
#undef fstat
#undef read
#undef write
#undef fsync
#undef close

static int test_mkdir(const char *path, mode_t mode) {
  if (inject(INJECT_MKDIR)) { errno=EACCES; return -1; }
  return mkdir(path,mode);
}
static int test_open(const char *path, int flags, ...) {
  if (inject(INJECT_OPEN)) { errno=EIO; return -1; }
  if (flags & O_CREAT) {
    va_list ap; va_start(ap,flags); mode_t mode=(mode_t)va_arg(ap,int); va_end(ap);
    return open(path,flags,mode);
  }
  return open(path,flags);
}
static int test_flock(int fd, int op) {
  int kind = op == LOCK_UN ? INJECT_UNLOCK : INJECT_LOCK;
  if (inject(kind)) {
    if (op == LOCK_UN) (void)flock(fd, op); /* release actual test lock */
    errno=EIO; return -1;
  }
  return flock(fd,op);
}
static int test_fstat(int fd, struct stat *st) {
  if (inject(INJECT_STAT)) { errno=EIO; return -1; }
  return fstat(fd,st);
}
static ssize_t test_read(int fd, void *buf, size_t n) {
  if (inject(INJECT_READ)) { errno=EIO; return -1; }
  return read(fd,buf,n);
}
static ssize_t test_write(int fd, const void *buf, size_t n) {
  if (partial_write && n > 7) { partial_write = 0; return write(fd,buf,7); }
  if (inject(INJECT_WRITE)) { errno=EIO; return -1; }
  return write(fd,buf,n);
}
static int test_fsync(int fd) {
  if (inject(INJECT_SYNC)) { errno=EIO; return -1; }
  return fsync(fd);
}
static int test_close(int fd) {
  if (inject(INJECT_CLOSE)) { (void)close(fd); errno=EIO; return -1; }
  return close(fd);
}
static void cleanup(const char *dir) {
  char path[512]; snprintf(path,sizeof path,"%s/archx/device_id",dir);
  if (unlink(path) != 0) assert(errno == ENOENT);
  snprintf(path,sizeof path,"%s/archx",dir);
  if (rmdir(path) != 0) assert(errno == ENOENT);
  assert(rmdir(dir) == 0);
}
static void fail_for(int kind) {
  char dir[]="/tmp/archx-fallback-fault-XXXXXX"; assert(mkdtemp(dir));
  assert(setenv("XDG_DATA_HOME",dir,1)==0);
  char saved[80];
  if (kind == INJECT_READ) assert(ax_signals_fallback_id(saved,sizeof saved) == 0);
  char output[80]; memset(output, 'Z',sizeof output);
  fail_kind=kind; calls=0; fail_at=1;
  assert(ax_signals_fallback_id(output,sizeof output) != 0);
  assert(calls >= 1);
  for (size_t i=0;i<sizeof output;i++) assert(output[i]=='Z');
  fail_kind=0;
  /* No lock or descriptor remains held; readable existing IDs are stable. */
  assert(ax_signals_fallback_id(output,sizeof output) == 0);
  assert(strlen(output)==64);
  if (kind == INJECT_READ) assert(strcmp(saved,output)==0);
  cleanup(dir);
}
int main(void) {
  assert(ax_signals_fallback_id(NULL, 65) != 0);
  for (int kind=INJECT_MKDIR;kind<=INJECT_CLOSE;kind++) fail_for(kind);
  char dir[]="/tmp/archx-fallback-partial-XXXXXX"; assert(mkdtemp(dir));
  assert(setenv("XDG_DATA_HOME",dir,1)==0);
  char output[80]; memset(output,'Z',sizeof output);
  partial_write=1; fail_kind=INJECT_WRITE; calls=0; fail_at=1;
  assert(ax_signals_fallback_id(output,sizeof output) != 0);
  fail_kind=0;
  for (size_t i=0;i<sizeof output;i++) assert(output[i]=='Z');
  /* Incomplete persisted files must fail closed, not silently rotate IDs. */
  assert(ax_signals_fallback_id(output,sizeof output) != 0);
  cleanup(dir);
  puts("synthetic fallback persistence fault injection passed");
  return 0;
}
