/* Internal portability contract for the C bucket store.
 * A complete collector/persistence abstraction is not implemented yet.
 * Mutexes are exclusive, non-recursive and must not be destroyed while in use.
 * Time is an arbitrary-origin monotonic interval clock, in milliseconds. The
 * intended policy excludes system sleep; it is not a wall clock or durable ID.
 * Operations return 0 on success, -1 on failure, and never fabricate time.
 */
#ifndef AX_PLATFORM_H
#define AX_PLATFORM_H
#include <stdint.h>
#include <stddef.h>

typedef struct ax_platform_mutex ax_platform_mutex;
ax_platform_mutex *ax_platform_mutex_new(void);
void ax_platform_mutex_free(ax_platform_mutex *mutex);
int ax_platform_mutex_lock(ax_platform_mutex *mutex);
int ax_platform_mutex_unlock(ax_platform_mutex *mutex);
int ax_platform_monotonic_ms(int64_t *out);
/* Request 1..256 bytes of OS randomness; zero bytes is a no-op. On failure
 * the output must be discarded, including any partially written bytes. */
int ax_platform_random(void *out, size_t len);
#endif
