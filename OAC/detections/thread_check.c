#include "thread_check.h"
#include "globals.h"
#include "module.h"
#include "offsets.h"
#include "helpers.h"
#include <ntddk.h>
#include <ntimage.h>

#define ThreadQuerySetWin32StartAddress  9
#define ThreadHideFromDebugger           17
#define THREAD_QUERY_INFORMATION         0x0040

#define KTHREAD_STATE_OFFSET    0x184
#define KTHREAD_STATE_WAITING   5

#define SYSTHREAD_MAX_FRAMES    32
#define SYSTHREAD_STACK_CAP     0x1000  // copy up to 4 KB of kernel stack per thread
#define SYSTHREAD_STACK_GUARD   0x1000  // zero guard page after copy — prevents RtlpUnwindPrologue
                                        // from faulting when it reads [Rsp+offset] near the boundary
#define SYSTHREAD_MAX_TID       0x3000  // scan TIDs 4, 8, ... , 0x2FFC
#define SYSTHREAD_STACK_TAG     'kwtS'

NTKERNELAPI NTSTATUS ObOpenObjectByPointer(
    PVOID           Object,
    ULONG           HandleAttributes,
    PACCESS_STATE   PassedAccessState,
    ACCESS_MASK     DesiredAccess,
    POBJECT_TYPE    ObjectType,
    KPROCESSOR_MODE AccessMode,
    PHANDLE         Handle
);

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationThread(
    HANDLE  ThreadHandle,
    ULONG   ThreadInformationClass,
    PVOID   ThreadInformation,
    ULONG   ThreadInformationLength,
    PULONG  ReturnLength OPTIONAL
);

NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(
    _In_  HANDLE   ThreadId,
    _Out_ PETHREAD *Thread
);

// RtlLookupFunctionEntry and RtlVirtualUnwind are already declared in ntddk.h
// for x64 builds — do not re-declare them (DWORD vs ULONG conflict).

NTKERNELAPI PEPROCESS PsGetThreadProcess(_In_ PETHREAD Thread);

typedef PEPROCESS (*FN_PsGetNextProcess)(_In_opt_ PEPROCESS);
typedef PETHREAD  (*FN_PsGetNextProcessThread)(_In_ PEPROCESS, _In_opt_ PETHREAD);


static FN_PsGetNextProcess       G_PsGetNextProcess       = NULL;
static FN_PsGetNextProcessThread G_PsGetNextProcessThread = NULL;

// Cached ntoskrnl .text section range for walk-start validation
static ULONG64 G_NtTextBase = 0;
static ULONG64 G_NtTextEnd  = 0;

static VOID ResolvePsEnumerationApis(VOID)
{
    UNICODE_STRING Name;
    RtlInitUnicodeString(&Name, L"PsGetNextProcess");
    G_PsGetNextProcess = (FN_PsGetNextProcess)MmGetSystemRoutineAddress(&Name);

    RtlInitUnicodeString(&Name, L"PsGetNextProcessThread");
    G_PsGetNextProcessThread = (FN_PsGetNextProcessThread)MmGetSystemRoutineAddress(&Name);
}



static VOID CheckThread(PETHREAD Thread)
{
    HANDLE   Handle = NULL;
    NTSTATUS Status;

    Status = ObOpenObjectByPointer(Thread,
                                   OBJ_KERNEL_HANDLE, NULL,
                                   THREAD_QUERY_INFORMATION,
                                   *PsThreadType, KernelMode,
                                   &Handle);
    if (!NT_SUCCESS(Status)) return;

    PVOID Win32Start = NULL;
    ZwQueryInformationThread(Handle, ThreadQuerySetWin32StartAddress,
                             &Win32Start, sizeof(Win32Start), NULL);

    BOOLEAN HideFromDbg = FALSE;
    ZwQueryInformationThread(Handle, ThreadHideFromDebugger,
                             &HideFromDbg, sizeof(HideFromDbg), NULL);

    ZwClose(Handle);

    PVOID StartAddr = NULL;
    __try
    {
        PVOID *Field = (PVOID*)((PUCHAR)Thread + G_Offsets.Ethread_StartAddress);
        if (MmIsAddressValid(Field))
            StartAddr = *Field;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }

    ULONG64 TID = (ULONG64)(ULONG_PTR)PsGetThreadId(Thread);

    // Detection 1: GhostThread — Win32StartAddress is a kernel address not backed
    // by any loaded module (manually mapped driver created a system thread).
    if (Win32Start && IsKernelAddress(Win32Start) && !IsInAnyModule(Win32Start))
    {
        DbgPrintEx(0, 0,
                   "[!] THREAD CHECK [GhostThread]: TID=%llu Win32Start=0x%p "
                   "— kernel address NOT in any loaded module\n",
                   TID, Win32Start);
    }

    // Detection 2: SpoofedStart — Win32StartAddress was overwritten to look legit
    // after creation, but StartAddress (set once at creation) still points outside.
    if (StartAddr && Win32Start && StartAddr != Win32Start && IsKernelAddress(StartAddr))
    {
        if (IsInAnyModule(Win32Start) && !IsInAnyModule(StartAddr))
        {
            CHAR Mod[64] = {0};
            ModuleNameOfAddr(Win32Start, Mod, sizeof(Mod));
            DbgPrintEx(0, 0,
                       "[!] THREAD CHECK [SpoofedStart]: TID=%llu "
                       "Win32Start=0x%p (%s) but StartAddress=0x%p NOT in module "
                       "— start address was spoofed\n",
                       TID, Win32Start, Mod, StartAddr);
        }
    }

    // Detection 3: HideFromDebugger set on a kernel thread — never legitimate.
    if (HideFromDbg && Win32Start && IsKernelAddress(Win32Start))
    {
        DbgPrintEx(0, 0,
                   "[!] THREAD CHECK [HideFromDebugger]: TID=%llu Win32Start=0x%p "
                   "— kernel thread has HideFromDebugger set\n",
                   TID, Win32Start);
    }
}



typedef struct { ULONG64 Rip; ULONG64 Rsp; } SYSTHREAD_FRAME;

typedef struct {
    SYSTHREAD_FRAME Frames[SYSTHREAD_MAX_FRAMES];
    ULONG           Count;
    BOOLEAN         Succeeded;
} SYSTHREAD_WALK;

static BOOLEAN FindKernelTextSection(VOID)
{
    PVOID Base = FindModuleByName(L"ntoskrnl.exe");
    if (!Base) return FALSE;
    __try
    {
        PIMAGE_DOS_HEADER   Dos = (PIMAGE_DOS_HEADER)Base;
        if (Dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
        PIMAGE_NT_HEADERS64 Nt  = (PIMAGE_NT_HEADERS64)((PUCHAR)Base + Dos->e_lfanew);
        if (!MmIsAddressValid(Nt)) return FALSE;

        PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION(Nt);
        for (USHORT i = 0; i < Nt->FileHeader.NumberOfSections; i++, Sec++)
        {
            // Exact 6-byte match (name + NUL) so ".textbss" or ".text$mn" don't hit.
            if (!memcmp(Sec->Name, ".text\0", 6) && Sec->Misc.VirtualSize)
            {
                G_NtTextBase = (ULONG64)Base + Sec->VirtualAddress;
                G_NtTextEnd  = G_NtTextBase + Sec->Misc.VirtualSize;
                return TRUE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
    return FALSE;
}

// Copy Thread's live kernel stack into a pool buffer and walk it with
// RtlLookupFunctionEntry + RtlVirtualUnwind, collecting up to SYSTHREAD_MAX_FRAMES
// RIP values.
//
// The key heuristic (matching the reference implementation): when a thread enters
// KiSwapThread/KiSwapContext to yield, it saves a KSWITCHFRAME followed by saved
// non-volatile registers onto the kernel stack.  Empirically, [RSP+0x38] holds
// the return RIP of the first real frame above the scheduler, with the owning
// RSP at RSP+0x40.  We copy the stack, point Ctx.Rsp into the copy at +0x40,
// set Ctx.Rip = copy[7], and let RtlVirtualUnwind do proper exception-directory
// unwinding from there.
static BOOLEAN WalkKernelThreadStack(PETHREAD Thread, SYSTHREAD_WALK *Walk)
{
    // Only walk waiting threads — Waiting(5) means the kernel stack is quiescent.
    __try
    {
        if (*(UCHAR*)((PUCHAR)Thread + KTHREAD_STATE_OFFSET) != KTHREAD_STATE_WAITING)
            return FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return FALSE; }

    ULONG64 StackBase = 0, StackLim = 0, KernStk = 0;
    __try
    {
        PUCHAR kt = (PUCHAR)Thread;
        StackBase = *(ULONG64*)(kt + G_Offsets.Kthread_StackBase);
        StackLim  = *(ULONG64*)(kt + G_Offsets.Kthread_StackLimit);
        KernStk   = *(ULONG64*)(kt + G_Offsets.Kthread_KernelStack);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return FALSE; }

    if (!KernStk || KernStk <= StackLim || KernStk >= StackBase) return FALSE;
    if (!MmIsAddressValid((PVOID)KernStk)) return FALSE;

    SIZE_T CopySz = (SIZE_T)(StackBase - KernStk);
    if (CopySz < 0x48) return FALSE;
    if (CopySz > SYSTHREAD_STACK_CAP) CopySz = SYSTHREAD_STACK_CAP;

    PULONG64 Buf = (PULONG64)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                              SYSTHREAD_STACK_CAP + SYSTHREAD_STACK_GUARD,
                                              SYSTHREAD_STACK_TAG);
    if (!Buf) return FALSE;
    // ExAllocatePool2 zeroes the allocation — no RtlZeroMemory needed

    SIZE_T Copied = 0;
    __try { RtlCopyMemory(Buf, (PVOID)KernStk, CopySz); Copied = CopySz; }
    __except (EXCEPTION_EXECUTE_HANDLER) { }

    BOOLEAN Ok = FALSE;
    if (Copied < 0x48) goto Fin;

    if (!G_NtTextBase && !FindKernelTextSection()) goto Fin;

    ULONG64 StartRip = Buf[7];
    if (StartRip < G_NtTextBase || StartRip >= G_NtTextEnd) goto Fin;

    CONTEXT Ctx;
    RtlZeroMemory(&Ctx, sizeof(CONTEXT));
    Ctx.ContextFlags = CONTEXT_FULL;
    Ctx.Rip = StartRip;
    Ctx.Rsp = (ULONG64)(Buf + 8); // RSP into our copy; RtlVirtualUnwind reads from it

    RtlZeroMemory(Walk, sizeof(SYSTHREAD_WALK));

    __try
    {
        for (ULONG i = 0; i < SYSTHREAD_MAX_FRAMES; i++)
        {
            ULONG64 Rip0 = Ctx.Rip;
            ULONG64 Rsp0 = Ctx.Rsp;

            if (Rip0 < (ULONG64)MmSystemRangeStart) break;
            if (Rsp0 < (ULONG64)MmSystemRangeStart) break;
            // Keep RSP inside our buffer so unwind reads are bounded
            if (Rsp0 < (ULONG64)Buf || Rsp0 >= (ULONG64)Buf + Copied) break;

            Walk->Frames[Walk->Count].Rip = Rip0;
            Walk->Frames[Walk->Count].Rsp = Rsp0;
            Walk->Count++;

            ULONG64           ImgBase = 0;
            PRUNTIME_FUNCTION Fe      = RtlLookupFunctionEntry(Rip0, &ImgBase, NULL);
            if (!Fe) break;

            PVOID   HandlerData = NULL;
            ULONG64 EstFrame    = 0;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, ImgBase, Rip0, Fe, &Ctx,
                             &HandlerData, &EstFrame, NULL);

            if (!Ctx.Rip) { Walk->Succeeded = TRUE; break; }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }

    Ok = (Walk->Count > 0);
Fin:
    ExFreePoolWithTag(Buf, SYSTHREAD_STACK_TAG);
    return Ok;
}

// Walk one system thread's stack and flag any frame whose RIP is not backed by
// a loaded kernel module (ghost / manually mapped driver code).
static VOID CheckSystemThread(PETHREAD Thread, ULONG64 TID, PULONG OutFlagged)
{
    SYSTHREAD_WALK Walk = {0};
    if (!WalkKernelThreadStack(Thread, &Walk)) return;

    for (ULONG i = 0; i < Walk.Count; i++)
    {
        ULONG64 Rip = Walk.Frames[i].Rip;
        if (!Rip || !IsKernelAddress((PVOID)Rip)) continue;

        if (!IsInAnyModule((PVOID)Rip))
        {
            DbgPrintEx(0, 0,
                "[!] THREAD CHECK [GhostFrame]: TID=%llu frame[%lu] RIP=0x%016llX "
                "— not backed by any loaded module\n",
                TID, i, Rip);
            (*OutFlagged)++;
            break; // one unresolved frame per thread is enough to flag it
        }
    }
}

// Iterate TIDs 4, 8, ... up to SYSTHREAD_MAX_TID.  For each thread that belongs
// to PsInitialSystemProcess, copy its kernel stack and walk it looking for return
// addresses that fall outside every loaded kernel module.
ULONG RunSystemThreadScan(VOID)
{
    PAGED_CODE();

    DbgPrintEx(0, 0,
               "[*] THREAD CHECK [SysScan]: walking system thread stacks "
               "(TID 4..0x%X step 4)...\n", SYSTHREAD_MAX_TID);

    ULONG Checked = 0, Flagged = 0;

    for (ULONG64 Tid = 4; Tid < SYSTHREAD_MAX_TID; Tid += 4)
    {
        PETHREAD Thread = NULL;
        if (!NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)Tid, &Thread)) || !Thread)
            continue;

        __try
        {
            if (PsGetThreadProcess(Thread) != PsInitialSystemProcess) goto Next;
            if ((PETHREAD)KeGetCurrentThread() == Thread)             goto Next;

            Checked++;
            // Metadata check + stack walk in one pass — no separate enumeration needed.
            CheckThread(Thread);
            CheckSystemThread(Thread, Tid, &Flagged);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { }
Next:
        ObDereferenceObject(Thread);
    }

    DbgPrintEx(0, 0,
               "[*] THREAD CHECK [SysScan]: done — checked=%lu flagged=%lu\n",
               Checked, Flagged);
    return Flagged;
}

NTSTATUS RunThreadCheck(VOID)
{
    PAGED_CODE();

    if (!G_PsGetNextProcess)
        ResolvePsEnumerationApis();

    DbgPrintEx(0, 0, "[*] THREAD CHECK: scanning all threads "
               "(Win32SA=+0x%lX SA=+0x%lX)...\n",
               G_Offsets.Ethread_Win32StartAddress,
               G_Offsets.Ethread_StartAddress);

    ULONG Scanned = 0;

    if (G_PsGetNextProcess && G_PsGetNextProcessThread)
    {
        PEPROCESS Process = G_PsGetNextProcess(NULL);
        while (Process)
        {
            // System process threads are owned by RunSystemThreadScan (TID iteration,
            // DKOM-resistant) which also runs CheckThread on them — skip here.
            if (Process != PsInitialSystemProcess)
            {
                PETHREAD Thread = G_PsGetNextProcessThread(Process, NULL);
                while (Thread)
                {
                    __try { CheckThread(Thread); }
                    __except (EXCEPTION_EXECUTE_HANDLER) { }
                    Scanned++;
                    Thread = G_PsGetNextProcessThread(Process, Thread);
                }
            }
            Process = G_PsGetNextProcess(Process);
        }
        DbgPrintEx(0, 0, "[*] THREAD CHECK: user-process metadata scan complete — %lu threads\n",
                   Scanned);
    }
    else
    {
        DbgPrintEx(0, 0, "[-] THREAD CHECK: PsGetNextProcess/Thread not available — skipping user-process scan\n");
    }

    // RunSystemThreadScan uses only PsLookupThreadByThreadId (always-present
    // NTKERNELAPI) — runs unconditionally regardless of PsGetNextProcess availability.
    RunSystemThreadScan();

    return STATUS_SUCCESS;
}
