#pragma once
#include <ntddk.h>

// =============================================================================
// OAC_OFFSETS — single source of truth for all EPROCESS / ETHREAD / KTHREAD
// field offsets.  Populated once at DriverEntry by InitializeOffsets().
//
// Strategy (three layers, highest confidence wins):
//   1. Pattern scan: decode MOV [RCX+disp32] in PsSetThreadWin32StartAddress
//      to find ETHREAD.Win32StartAddress at runtime (zero hardcoded values).
//   2. NtBuildNumber version table: per-build values sourced from Vergilius
//      Project (vergiliusproject.com) for every major x64 Windows release.
//   3. Hard fallback: Windows 10 22H2 values (Vergilius-confirmed).
// =============================================================================
typedef struct _OAC_OFFSETS
{
    ULONG NtBuildNumber;             // build that was matched

    // ── _KPROCESS (embedded at EPROCESS+0x0 as .Pcb) ────────────────────────
    ULONG Kprocess_DirectoryTableBase;   // stable: always 0x28

    // ── _EPROCESS ─────────────────────────────────────────────────────────────
    ULONG Eprocess_UniqueProcessId;
    ULONG Eprocess_ActiveProcessLinks;
    ULONG Eprocess_ImageFileName;        // CHAR[15] image name
    ULONG Eprocess_ThreadListHead;       // LIST_ENTRY of all threads

    // ── _ETHREAD ──────────────────────────────────────────────────────────────
    ULONG Ethread_StartAddress;          // set once at creation; no public setter
    ULONG Ethread_Win32StartAddress;     // settable via NtSetInformationThread(9)
    ULONG Ethread_ThreadListEntry;       // LIST_ENTRY into EPROCESS.ThreadListHead
    ULONG Ethread_CrossThreadFlags;      // ULONG; HideFromDebugger = bit 2
    ULONG Ethread_Cid;                   // CLIENT_ID; +0 = UniqueProcess, +8 = UniqueThread

    // ── _KTHREAD (first member of _ETHREAD at offset 0) ──────────────────────
    ULONG Kthread_StackLimit;            // stable: always 0x30
    ULONG Kthread_StackBase;             // stable: always 0x38
    ULONG Kthread_KernelStack;           // stable: always 0x58
    ULONG Kthread_TrapFrame;             // stable: always 0x90

} OAC_OFFSETS;

extern OAC_OFFSETS G_Offsets;

// Call once from DriverEntry.  Finds ntoskrnl base internally.
VOID InitializeOffsets(VOID);
