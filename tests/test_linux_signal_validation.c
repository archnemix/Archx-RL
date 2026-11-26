/* Synthetic fixture bytes only; no native identifiers are read. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

static const unsigned char *input;
static size_t input_len, input_pos, read_chunk;
static int injected_read_error, injected_close_error, interrupt_once;
static const char *source_machine, *source_fallback, *source_uuid, *source_board;
static int fake_open(const char *path, int flags, ...);
static ssize_t fake_read(int fd, void *buf, size_t len);
static int fake_close(int fd);
static int fake_uname(struct utsname *uts);
#define open fake_open
#define read fake_read
#define close fake_close
#define uname fake_uname
#include "../src/signals_linux.c"
#undef open
#undef read
#undef close
#undef uname

static int fake_open(const char *path, int flags, ...) {
  (void)flags;
  const char *text = NULL;
  if (!strcmp(path,"/etc/machine-id")) text=source_machine;
  else if (!strcmp(path,"/var/lib/dbus/machine-id")) text=source_fallback;
  else if (!strcmp(path,"/sys/class/dmi/id/product_uuid")) text=source_uuid;
  else if (!strcmp(path,"/sys/class/dmi/id/board_serial")) text=source_board;
  else if (!strcmp(path,"synthetic")) { input_pos=0; return 42; }
  if (!text) { errno=ENOENT; return -1; }
  input=(const unsigned char *)text; input_len=strlen(text); input_pos=0; return 42;
}
static ssize_t fake_read(int fd, void *buf, size_t len) {
  (void)fd;
  if (interrupt_once) { interrupt_once=0; errno=EINTR; return -1; }
  if (injected_read_error) { errno=EIO; return -1; }
  size_t n=input_len-input_pos;
  if (n>len) n=len;
  if (read_chunk && n>read_chunk) n=read_chunk;
  memcpy(buf,input+input_pos,n); input_pos+=n;
  return (ssize_t)n;
}
static int fake_close(int fd) { (void)fd; if (injected_close_error) { errno=EIO; return -1; } return 0; }
static int fake_uname(struct utsname *uts) { memset(uts,0,sizeof *uts); strcpy(uts->machine,"synthetic"); return 0; }
static void fixture(const unsigned char *data, size_t len) { input=data; input_len=len; input_pos=0; }

int main(void) {
  char out[256];
  const char good[]="  AbCd-1234  \r\nignored";
  fixture((const unsigned char *)good,strlen(good)); read_chunk=1; interrupt_once=1;
  assert(read_first_line("synthetic",out,sizeof out) && !strcmp(out,"abcd-1234"));
  const unsigned char embedded[]={'a','b','c','d',0,'e','f','\n'};
  fixture(embedded,sizeof embedded); assert(!read_first_line("synthetic",out,sizeof out) && !out[0]);
  unsigned char big[600]; memset(big,'a',sizeof big);
  fixture(big,sizeof big); read_chunk=0; assert(!read_first_line("synthetic",out,sizeof out) && !out[0]);
  fixture((const unsigned char *)good,strlen(good)); injected_read_error=1;
  assert(!read_first_line("synthetic",out,sizeof out) && !out[0]); injected_read_error=0;
  fixture((const unsigned char *)good,strlen(good)); injected_close_error=1;
  assert(!read_first_line("synthetic",out,sizeof out) && !out[0]); injected_close_error=0;
  assert(!read_first_line("synthetic",out,0)); assert(!read_first_line("synthetic",NULL,0));
  assert(valid_machine_id("abcdef0123456789abcdef0123456789"));
  assert(!valid_machine_id("abcdef0123456789abcdef012345678g"));
  assert(!valid_machine_id("00000000000000000000000000000000"));
  assert(!valid_machine_id("ffffffffffffffffffffffffffffffff"));
  assert(!valid_machine_id("abcdef0123456789abcdef012345678"));
  assert(valid_product_uuid("00112233-4455-6677-8899-aabbccddeeff"));
  assert(!valid_product_uuid("00112233-4455-6677-8899-aabbccddeefg"));
  assert(!valid_product_uuid("00000000-0000-0000-0000-000000000000"));
  assert(!valid_product_uuid("ffffffff-ffff-ffff-ffff-ffffffffffff"));
  assert(!valid_product_uuid("00112233-4455-6677-8899-aabbccddeef"));
  assert(valid_board_serial("synthetic-123"));
  assert(!valid_board_serial("xy")); assert(!valid_board_serial("0000"));
  assert(!valid_board_serial("bad\tvalue")); assert(!valid_board_serial("bad\xc3\xa9value"));
  char serial[130]; memset(serial,'x',128); serial[128]='\0'; assert(valid_board_serial(serial));
  serial[128]='x'; serial[129]='\0'; assert(!valid_board_serial(serial));
  assert(looks_placeholder("to be filled by oem") && looks_placeholder("unknown") && looks_placeholder("default string"));
  source_machine="00000000000000000000000000000000\n";
  source_fallback="  ABCDEF0123456789ABCDEF0123456789\n";
  source_uuid="00112233-4455-6677-8899-AABBCCDDEEFF\n";
  source_board="  To Be Filled By O.E.M.  \n";
  ax_signal_set set;
  assert(ax_signals_collect_linux_selected(&set,7)==0 && set.signal_count==3);
  assert(set.signals[0].readable && !strcmp(set.signals[0].value,"abcdef0123456789abcdef0123456789"));
  assert(set.signals[1].readable && !strcmp(set.signals[1].value,"00112233-4455-6677-8899-aabbccddeeff"));
  assert(!set.signals[2].readable && !set.signals[2].value[0]);
  source_machine="bad"; source_fallback=NULL; source_uuid="not-a-uuid"; source_board="bad\xc3\xa9value";
  assert(ax_signals_collect_linux_selected(&set,7)==0 && set.signal_count==3);
  for (size_t i=0; i<3; i++) assert(!set.signals[i].readable && !set.signals[i].value[0]);
  puts("synthetic Linux signal normalization fixtures passed");
  return 0;
}
