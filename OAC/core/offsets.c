#include "offsets.h"
#include "module.h"

#include <ntddk.h>

OAC_OFFSETS G_Offsets = {0};


// =============================================================================
// Version table — NtBuildNumber → per-build struct offsets (x64 only).
//
// Source: Vergilius Project (vergiliusproject.com), verified against WinDbg dt.
// Sorted descending by Build.  Lookup: walk from top, use first row where
// NtBuildNumber >= Entry.Build (covers that build and all later minor updates).
//
// Columns
//   EP_UPID  = EPROCESS.UniqueProcessId
//   EP_APL   = EPROCESS.ActiveProcessLinks
//   EP_IFN   = EPROCESS.ImageFileName
//   EP_TLH   = EPROCESS.ThreadListHead
//   ET_SA    = ETHREAD.StartAddress     (creation-time, no public setter)
//   ET_W32SA = ETHREAD.Win32StartAddress (NtSetInformationThread(9) writable)
//   ET_TLE   = ETHREAD.ThreadListEntry
//   ET_CTF   = ETHREAD.CrossThreadFlags  (bit 2 = HideFromDebugger)
//   ET_CID   = ETHREAD.Cid (CLIENT_ID)
// =============================================================================
static const struct
{
    ULONG Build;
    ULONG EP_UPID;  ULONG EP_APL;   ULONG EP_IFN;   ULONG EP_TLH;
    ULONG ET_SA;    ULONG ET_W32SA; ULONG ET_TLE;   ULONG ET_CTF;   ULONG ET_CID;
}
G_VersionTable[] =
{
  // Build   EP_UPID  EP_APL   EP_IFN   EP_TLH   ET_SA    ET_W32SA ET_TLE   ET_CTF   ET_CID
  { 26100,   0x1D0,   0x1D8,   0x338,   0x370,   0x4E0,   0x560,   0x578,   0x5A0,   0x508 }, // Win11 24H2
  { 22621,   0x440,   0x448,   0x5A8,   0x5E0,   0x4A0,   0x520,   0x538,   0x560,   0x4C8 }, // Win11 22H2 / 23H2
  { 22000,   0x440,   0x448,   0x5A8,   0x5E0,   0x4A0,   0x520,   0x538,   0x560,   0x4C8 }, // Win11 21H2
  { 19041,   0x440,   0x448,   0x5A8,   0x5E0,   0x450,   0x4D0,   0x4E8,   0x510,   0x478 }, // Win10 20H1 – 22H2
  { 18363,   0x2E8,   0x2F0,   0x450,   0x488,   0x620,   0x6A0,   0x6B8,   0x6E0,   0x648 }, // Win10 1909
  { 17134,   0x2E0,   0x2E8,   0x450,   0x488,   0x610,   0x690,   0x6A8,   0x6D0,   0x638 }, // Win10 1803 / 1809
};


// =============================================================================
// Pattern scan: decode ETHREAD.Win32StartAddress offset from the trivial body
// of PsSetThreadWin32StartAddress (exported, stable across all builds):
//
//   48 89 91 D0 04 00 00   MOV QWORD PTR [RCX+0x4D0], RDX   ; ← disp32 we want
//   C3                     RET
//
// Returns the scanned offset, or TableFallback if decoding fails.
// =============================================================================
static ULONG ScanWin32StartAddressOffset(PVOID NtosBase, ULONG TableFallback)
{
    if (!NtosBase) return TableFallback;

    PVOID  Fn   = FindExportedFunction(NtosBase, "PsSetThreadWin32StartAddress");
    if (!Fn) return TableFallback;

    PUCHAR Code = (PUCHAR)Fn;
    __try
    {
        for (ULONG i = 0; i + 7 < 32; i++)
        {
            if (!MmIsAddressValid(Code + i + 7)) break;
            if (Code[i]     != 0x48) continue;          // REX.W
            if (Code[i + 1] != 0x89) continue;          // MOV r/m64, r64
            if ((Code[i + 2] & 0x07) != 1) continue;   // R/M = RCX (ETHREAD*)
            if ((Code[i + 2] >> 6)   != 2) continue;   // Mod  = disp32

            ULONG Disp = *(ULONG*)(Code + i + 3);
            if (Disp > 0x100 && Disp < 0x2000)
                return Disp;
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }

    return TableFallback;
}


// =============================================================================
// Public entry point — call once from DriverEntry.
// =============================================================================
VOID InitializeOffsets(VOID)
{
    // ── Stable offsets (all Win10/11 x64 builds, confirmed via Vergilius) ────
    G_Offsets.Kprocess_DirectoryTableBase = 0x28;
    G_Offsets.Kthread_StackLimit          = 0x30;
    G_Offsets.Kthread_StackBase           = 0x38;
    G_Offsets.Kthread_KernelStack         = 0x58;
    G_Offsets.Kthread_TrapFrame           = 0x90;

    // ── Get ntoskrnl base + NtBuildNumber ─────────────────────────────────────
    PVOID  NtosBase = FindModuleByName(L"ntoskrnl.exe");
    ULONG  Build    = 0;

    if (NtosBase)
    {
        PULONG pBuild = (PULONG)FindExportedFunction(NtosBase, "NtBuildNumber");
        if (pBuild) Build = *pBuild & 0xFFFF;
    }
    G_Offsets.NtBuildNumber = Build;

    // ── Version table lookup (descending, first entry where Build >= row.Build) ─
    ULONG TableCount = sizeof(G_VersionTable) / sizeof(G_VersionTable[0]);
    ULONG Row = TableCount - 1;   // default: oldest known good (Win10 1803)

    for (ULONG i = 0; i < TableCount; i++)
    {
        if (Build >= G_VersionTable[i].Build)
        {
            Row = i;
            break;
        }
    }

    G_Offsets.Eprocess_UniqueProcessId    = G_VersionTable[Row].EP_UPID;
    G_Offsets.Eprocess_ActiveProcessLinks = G_VersionTable[Row].EP_APL;
    G_Offsets.Eprocess_ImageFileName      = G_VersionTable[Row].EP_IFN;
    G_Offsets.Eprocess_ThreadListHead     = G_VersionTable[Row].EP_TLH;
    G_Offsets.Ethread_StartAddress        = G_VersionTable[Row].ET_SA;
    G_Offsets.Ethread_Win32StartAddress   = G_VersionTable[Row].ET_W32SA;
    G_Offsets.Ethread_ThreadListEntry     = G_VersionTable[Row].ET_TLE;
    G_Offsets.Ethread_CrossThreadFlags    = G_VersionTable[Row].ET_CTF;
    G_Offsets.Ethread_Cid                 = G_VersionTable[Row].ET_CID;

    // ── Cross-validate Win32StartAddress via pattern scan ─────────────────────
    // Overrides the table value when the pattern scan decodes a different offset
    // (e.g., a new minor build that shifted the field without a table entry).
    ULONG Scanned = ScanWin32StartAddressOffset(NtosBase,
                                                G_Offsets.Ethread_Win32StartAddress);
    if (Scanned != G_Offsets.Ethread_Win32StartAddress)
    {
        DbgPrintEx(0, 0,
                   "[*] OFFSETS: Win32StartAddress pattern scan (0x%lX) differs from "
                   "table (0x%lX) — trusting scan\n",
                   Scanned, G_Offsets.Ethread_Win32StartAddress);
        G_Offsets.Ethread_Win32StartAddress = Scanned;
        // Structural gap Win32StartAddress – StartAddress = 0x80, stable Win10/11
        G_Offsets.Ethread_StartAddress = Scanned - 0x80;
    }

    DbgPrintEx(0, 0,
               "[*] OFFSETS: build=%lu (table row %lu)\n"
               "    EPROCESS UniqueProcessId=+0x%lX ActiveProcessLinks=+0x%lX "
               "ImageFileName=+0x%lX ThreadListHead=+0x%lX\n"
               "    ETHREAD  StartAddress=+0x%lX Win32StartAddress=+0x%lX "
               "ThreadListEntry=+0x%lX CrossThreadFlags=+0x%lX Cid=+0x%lX\n",
               Build, Row,
               G_Offsets.Eprocess_UniqueProcessId,
               G_Offsets.Eprocess_ActiveProcessLinks,
               G_Offsets.Eprocess_ImageFileName,
               G_Offsets.Eprocess_ThreadListHead,
               G_Offsets.Ethread_StartAddress,
               G_Offsets.Ethread_Win32StartAddress,
               G_Offsets.Ethread_ThreadListEntry,
               G_Offsets.Ethread_CrossThreadFlags,
               G_Offsets.Ethread_Cid);
}
