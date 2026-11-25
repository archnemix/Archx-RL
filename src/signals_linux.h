/* Linux signal collection. Targets the OS-provided, rootless-readable
 * machine identifiers and reports what this host can actually offer:
 *
 *   machine_id    (weight 60)  /etc/machine-id, fallback /var/lib/dbus/machine-id
 *   product_uuid  (weight 25)  /sys/class/dmi/id/product_uuid   (often 0400, may need root)
 *   board_serial  (weight 15)  /sys/class/dmi/id/board_serial   (often 0400, may need root)
 *
 * Anything unreadable is reported as readable=0 with weight excluded from
 * the ABI-v1 availability heuristic — it is not measured identity confidence. */
#ifndef AX_SIGNALS_H
#define AX_SIGNALS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  char name[32];
  char value[256];   /* normalized (trimmed, lowercased) */
  int  weight;       /* availability weight when readable */
  int  readable;     /* 1 if value was obtained from the OS */
} ax_signal;

#define AX_MAX_SIGNALS 8

typedef struct {
  ax_signal signals[AX_MAX_SIGNALS];
  size_t    signal_count;
  char      arch[32];        /* x86_64, aarch64, ... */
  char      os[16];          /* "linux" */
} ax_signal_set;

/* Populate *out. Returns 0 on success. Unavailable signals are still
 * present in the array with readable=0 and value="" so callers can report
 * the full picture. */
int  ax_signals_collect_linux(ax_signal_set *out);
/* Bit 0 machine_id, bit 1 product_uuid, bit 2 board_serial. */
int  ax_signals_collect_linux_selected(ax_signal_set *out, unsigned mask);

/* Deterministic length-prefixed name/value pairs sorted by name.
 * Returns bytes written on success, or SIZE_MAX for invalid input or
 * insufficient space. On failure, a nonempty valid output buffer is cleared. */
size_t ax_signals_canonical(const ax_signal_set *set, char *out, size_t out_len);

/* Read or create the persisted fallback ID ($XDG_DATA_HOME/archx/device_id).
 * Returns 0 on success. */
int ax_signals_fallback_id(char *out, size_t out_len);

#endif
