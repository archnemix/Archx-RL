# Privacy and security boundaries

Raw signal values are sensitive and can be supplied transiently by clients. App-scoped HMACs and persisted observations remain **linkable pseudonymous data**, not anonymous records; raw-IP mode stores IPs. Hosts must minimize collection, obtain appropriate authority, restrict access, avoid sensitive logs and protect keys, databases, WAL, backups and downstream services. Key rotation and recovery are not fully implemented. Optional, narrowly scoped [retention controls](Retention.md) provide logical cleanup only, not guaranteed physical erasure.

A client can fabricate or rotate signals, poison another user's bucket, or share an IP with unrelated users. Signal matches are not authentication or proof of a unique person. A legitimate user can be denied due to shared quotas, saturation or false positives. Independently authenticate and authorize protected operations and provide a reviewed recovery path.

The [security policy](../../SECURITY.md) and [threat model](../Threat-Model.md) describe current assumptions, tests and unresolved risks. Apple distribution rules concerning fingerprinting remain an unresolved macOS release blocker even when an API is readable. See [macOS research](../Research/MacOS.md) and [Windows research](../Research/Windows.md); do not infer production approval from CI surveys.
