/* POSIX exclusive mutex implementation shared by Linux and macOS adapters. */
#include "platform.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

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
int ax_platform_secret_env(const char *name, char *out, size_t out_len) {
  if (!name || !*name || !out) return -1;
  const char *value = getenv(name);
  if (!value || !*value) return -1;
  size_t n = 0;
  while (n < AX_PLATFORM_SECRET_ENV_MAX && value[n]) n++;
  if (n == AX_PLATFORM_SECRET_ENV_MAX || n + 1 > out_len) return -1;
  memcpy(out, value, n + 1);
  return 0;
}
int ax_platform_normalize_ip(const char *input, char *out, size_t out_len) {
  struct in6_addr address;
  char normalized[AX_PLATFORM_IP_TEXT_MAX];
  if (!input || !out || strchr(input, '%')) return -1;
  int family = strchr(input, ':') ? AF_INET6 : AF_INET;
  if (inet_pton(family, input, &address) != 1 ||
      !inet_ntop(family, &address, normalized, sizeof normalized)) return -1;
  size_t len = strlen(normalized) + 1;
  if (out_len < len) return -1;
  memcpy(out, normalized, len);
  return 0;
}
