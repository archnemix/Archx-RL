/* POSIX exclusive mutex implementation shared by Linux and macOS adapters. */
#include "platform.h"
#include <pthread.h>
#include <stdlib.h>

struct ax_platform_mutex { pthread_mutex_t native; };

ax_platform_mutex *ax_platform_mutex_new(void) {
  ax_platform_mutex *mutex = (ax_platform_mutex *)malloc(sizeof *mutex);
  if (!mutex) return NULL;
  if (pthread_mutex_init(&mutex->native, NULL) != 0) { free(mutex); return NULL; }
  return mutex;
}
void ax_platform_mutex_free(ax_platform_mutex *mutex) {
  if (!mutex) return;
  pthread_mutex_destroy(&mutex->native);
  free(mutex);
}
int ax_platform_mutex_lock(ax_platform_mutex *mutex) {
  return mutex && pthread_mutex_lock(&mutex->native) == 0 ? 0 : -1;
}
int ax_platform_mutex_unlock(ax_platform_mutex *mutex) {
  return mutex && pthread_mutex_unlock(&mutex->native) == 0 ? 0 : -1;
}
