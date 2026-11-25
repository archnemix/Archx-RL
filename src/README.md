# C core

Purpose: Linux signal collection, bounded JSON parsing, cryptographic primitives, identification and the in-process rate-limit store. The public ABI is in `../include/`. `platform.h` currently abstracts only store mutex/time and entropy; experimental Windows/macOS primitive adapters do not implement native collection or establish platform support.
