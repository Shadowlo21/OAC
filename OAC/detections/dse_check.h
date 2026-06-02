#pragma once
#include <ntddk.h>

// Run all DSE integrity checks at PASSIVE_LEVEL:
//   1. g_CiOptions live value (patched = DSE was disabled)
//   2. SeCiCallbacks hook detection (function pointers outside ci.dll)
//   3. System-wide test-signing mode (SeValidateImageFlags bit 0)
//   4. Full loaded-module scan:
//        - File deleted from disk after load  (ghost driver)
//        - Missing / invalid Authenticode signature
//        - Test-signed certificate
NTSTATUS RunDseChecks(VOID);
