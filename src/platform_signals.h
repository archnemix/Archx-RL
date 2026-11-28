/* Internal collection boundary for the current ABI-v1 Linux semantics.
 * Native collectors and secure fallback storage remain OS-specific.
 * No Windows/macOS product collector is supplied by this interface alone.
 */
#ifndef AX_PLATFORM_SIGNALS_H
#define AX_PLATFORM_SIGNALS_H
#include "signals.h"

/* Profile scopes are domain separators, not signatures or proof of identity.
 * Every adapter returns a fixed scope for its entire lifetime. Synthetic is
 * reserved for isolated tests; no additional OS support is implied. */
typedef enum {
  AX_PLATFORM_SCOPE_LINUX = 1,
  AX_PLATFORM_SCOPE_SYNTHETIC = 2
} ax_platform_scope;
ax_platform_scope ax_platform_profile_scope(void);

/* Mask bits 0..2 select machine ID, product UUID and board serial. */
int ax_platform_collect_signals(ax_signal_set *out);
int ax_platform_collect_selected(ax_signal_set *out, unsigned mask);
int ax_platform_fallback_id(char *out, size_t out_len);
#endif
