/* Internal collection boundary for the current ABI-v1 Linux semantics.
 * Native collectors and secure fallback storage remain OS-specific.
 * No Windows/macOS product collector is supplied by this interface alone.
 */
#ifndef AX_PLATFORM_SIGNALS_H
#define AX_PLATFORM_SIGNALS_H
#include "signals.h"

/* Mask bits 0..2 select machine ID, product UUID and board serial. */
int ax_platform_collect_signals(ax_signal_set *out);
int ax_platform_collect_selected(ax_signal_set *out, unsigned mask);
int ax_platform_fallback_id(char *out, size_t out_len);
#endif
