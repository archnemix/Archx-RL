/* Private POSIX fallback; trusted parent directories and local filesystem required. */
#ifndef AX_FALLBACK_POSIX_H
#define AX_FALLBACK_POSIX_H
#include <stddef.h>
int ax_signals_fallback_id(char *out, size_t out_len);
#endif
