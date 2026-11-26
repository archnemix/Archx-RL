/* Disposable-host property-type survey, not an identification collector.
 * Copies two IOKit properties transiently but never extracts their contents.
 * This is not permission to use device fingerprinting in a distributed app.
 */
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <unistd.h>

static const char *property_type(io_service_t service, CFStringRef key) {
  CFTypeRef value = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
  if (!value) return "unavailable_or_denied";
  const char *status = CFGetTypeID(value) == CFStringGetTypeID() ? "string_type_only" : "unexpected_type";
  CFRelease(value);
  return status;
}
static const char *architecture(void) {
#if defined(__arm64__) || defined(__aarch64__)
  return "arm64";
#elif defined(__x86_64__)
  return "x86_64";
#else
  return "unknown";
#endif
}
int main(void) {
  const char *service_status = "unavailable";
  const char *uuid = "not_checked", *serial = "not_checked";
  CFMutableDictionaryRef matching = IOServiceMatching("IOPlatformExpertDevice");
  if (matching) {
    /* IOServiceGetMatchingService consumes the dictionary reference. */
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (service != IO_OBJECT_NULL) {
      service_status = "found";
      uuid = property_type(service, CFSTR("IOPlatformUUID"));
      serial = property_type(service, CFSTR("IOPlatformSerialNumber"));
      IOObjectRelease(service);
    }
  } else {
    service_status = "read_error";
  }
  printf("{\"schema_version\":1,\"platform\":\"macos\",\"architecture\":\"%s\","
         "\"privilege\":\"%s\",\"platform_service\":\"%s\",\"signals\":{"
         "\"platform_uuid_property\":\"%s\",\"platform_serial_property\":\"%s\"}}\n",
         architecture(), geteuid() == 0 ? "root" : "nonroot", service_status, uuid, serial);
  return 0;
}
