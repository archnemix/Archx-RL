/* Synthetic-testable CoreFoundation type boundary; no registry access. */
#ifndef AX_MACOS_CF_UUID_H
#define AX_MACOS_CF_UUID_H
#include "uuid_value.h"
#include <CoreFoundation/CoreFoundation.h>
/* Borrows value; does not retain or release it. NULL is absent. */
ax_uuid_status ax_macos_cf_uuid(CFTypeRef value, char out[37]);
#endif
