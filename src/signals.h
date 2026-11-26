/* Internal signal representation and deterministic canonicalization.
 * Collection, availability semantics and persistence are platform-specific.
 */
#ifndef AX_SIGNALS_H
#define AX_SIGNALS_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  AX_SIGNAL_UNKNOWN = 0,
  AX_SIGNAL_AVAILABLE,
  AX_SIGNAL_ABSENT,
  AX_SIGNAL_DENIED,
  AX_SIGNAL_PLACEHOLDER,
  AX_SIGNAL_INVALID,
  AX_SIGNAL_READ_ERROR,
  AX_SIGNAL_UNSUPPORTED
} ax_signal_status;

typedef struct {
  char name[32];
  char value[256];   /* normalized (trimmed, lowercased) */
  int  weight;       /* availability weight when readable */
  int  readable;     /* 1 if a value is available for canonicalization */
  ax_signal_status status; /* internal capability status; no raw data in reports */
} ax_signal;

#define AX_MAX_SIGNALS 8

typedef struct {
  ax_signal signals[AX_MAX_SIGNALS];
  size_t    signal_count;
  char      arch[32];        /* x86_64, aarch64, ... */
  char      os[16];          /* OS name from the platform collector */
} ax_signal_set;

/* Deterministic length-prefixed name/value pairs sorted by name.
 * Returns bytes written on success, or SIZE_MAX for invalid input or
 * insufficient space. On failure, a nonempty valid output buffer is cleared. */
size_t ax_signals_canonical(const ax_signal_set *set, char *out, size_t out_len);

#endif
