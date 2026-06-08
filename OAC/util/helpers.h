#pragma once
#include <ntddk.h>

// =============================================================================
// OAC shared helper utilities — single home for cross-cutting helpers that
// would otherwise be duplicated as statics in multiple translation units.
// =============================================================================

// ── Address-space predicates ──────────────────────────────────────────────────

FORCEINLINE BOOLEAN IsKernelAddress(_In_ PVOID Addr)
{
    return (ULONG_PTR)Addr > 0x00007FFFFFFFFFFFull;
}

FORCEINLINE BOOLEAN IsUserModeAddress(_In_ PVOID Addr)
{
    return (ULONG_PTR)Addr > 0x10000ull && (ULONG_PTR)Addr <= 0x00007FFFFFFFFFFFull;
}

// ── Module range helpers (PASSIVE_LEVEL, requires PsLoadedModuleList) ─────────

// Returns TRUE if Addr falls inside any loaded kernel module's image range.
BOOLEAN IsInAnyModule(_In_ PVOID Addr);

// Writes the ASCII BaseDllName of the module containing Addr into Buf.
// Writes "?" on failure.  Buf is always NUL-terminated.
VOID ModuleNameOfAddr(_In_ PVOID Addr, _Out_writes_z_(Cch) CHAR *Buf, _In_ ULONG Cch);

// ── Safe memory access ────────────────────────────────────────────────────────

// Validates every page in [Src, Src+Size) with MmIsAddressValid before copying.
// Returns FALSE without touching Dst if any page is non-resident.
BOOLEAN SafeReadMemory(_In_ PVOID Src, _Out_ PVOID Dst, _In_ SIZE_T Size);

// ── Memory protection ─────────────────────────────────────────────────────────

// Returns TRUE if the page at Addr is committed and has any execute permission.
BOOLEAN IsAddressExecutable(_In_ PVOID Addr);

// ── String helpers ────────────────────────────────────────────────────────────

// Case-sensitive ASCII string equality (no CRT dependency).
BOOLEAN AsciiStrEq(_In_ const CHAR *A, _In_ const CHAR *B);

// ── KTHREAD.PreviousMode helpers ──────────────────────────────────────────────
// Flip PreviousMode to UserMode(1) so win32k/NT functions that probe output
// buffers treat the caller as a user-mode thread.  ALWAYS restore the returned
// old value before leaving the critical section.
//
// Usage:
//   UCHAR Old = OacSetPreviousMode(UserMode);
//   // ... call win32k or NT functions ...
//   OacSetPreviousMode(Old);

// Offset of PreviousMode inside _KTHREAD (stable across Win10/11 x64).
#define KTHREAD_PREVIOUS_MODE_OFFSET 0x232

// Sets KTHREAD.PreviousMode to NewMode; returns the previous value.
FORCEINLINE UCHAR OacSetPreviousMode(_In_ UCHAR NewMode)
{
    PUCHAR p    = (PUCHAR)((PUCHAR)KeGetCurrentThread() + KTHREAD_PREVIOUS_MODE_OFFSET);
    UCHAR  Old  = *p;
    *p          = NewMode;
    return Old;
}
