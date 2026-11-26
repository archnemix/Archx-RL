# Native hosted-runner availability survey — 2026-11-22

[Experimental platform primitives, run 45812797348](https://github.com/archnemix/Archx-RL/actions/runs/45812797348), commit `1dd1f0e`: all three native primitive/fixture and survey jobs passed. Results below reproduce validated check annotations only, not identifiers. This is a snapshot of three disposable hosted machines, not a support matrix or comparison of ordinary versus privileged users.

| GitHub runner | Observed execution | Result |
| --- | --- | --- |
| Windows Server 2022 x64, OS 10.0.20348 | Elevated token | RSMB fetch/parser succeeded; product UUID, Type 1 system serial and Type 2 board/module serial categorized present. MachineGuid registry metadata reported string type only. |
| macOS 15.7.9 Intel | Nonroot | Platform expert service found; platform UUID and serial properties were CFString type. |
| macOS 15.8.2 ARM64 | Nonroot | Platform expert service found; platform UUID and serial properties were CFString type. |

The Windows result does **not** establish standard-user access, Windows 11 behavior, actual motherboard identity or uniqueness, or that MachineGuid contents were read or useful. The macOS result establishes property type only, not nonempty/valid/stable contents; null results would conflate absent and denied. These probes do not test sandboxed, notarized, App Store, physical-device or other privilege scenarios. Virtual firmware can differ greatly from physical hardware. No conclusion about persistence, full collectors, legal authority or production suitability follows. Apple's fingerprinting rules remain an unresolved distribution blocker even where properties are technically accessible.

Linux regression for the preceding survey implementation, [run 45812602403](https://github.com/archnemix/Archx-RL/actions/runs/45812602403), passed; `tests/test_survey.py` exercises the native output allowlist, rejection of unexpected fields, inconsistent statuses, duplicate fields, oversize input and secret-marker non-echo. These tests do not prove the host or binary is trustworthy. See `tools/permission_survey/README.md` for processing and collection limitations.
