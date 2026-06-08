#pragma once
#include <ntddk.h>

// Metadata scan: Win32StartAddress, StartAddress, HideFromDebugger on all threads.
NTSTATUS RunThreadCheck(VOID);

// Stack-walk scan: copies each system thread's kernel stack, unwinds with
// RtlLookupFunctionEntry + RtlVirtualUnwind, flags any frame RIP not backed
// by a loaded module (GhostFrame detection).
// Returns the count of flagged threads.  Called automatically by RunThreadCheck.
ULONG RunSystemThreadScan(VOID);
