#include "helpers.h"
#include "module.h"

#include <ntddk.h>

// ZwQueryVirtualMemory and supporting types are not declared in ntddk.h
// (they live in ntifs.h which conflicts with ntddk.h).
typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID  BaseAddress;
    PVOID  AllocationBase;
    ULONG  AllocationProtect;
    SIZE_T RegionSize;
    ULONG  State;
    ULONG  Protect;
    ULONG  Type;
} MEMORY_BASIC_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0
} MEMORY_INFORMATION_CLASS;

NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(
    _In_      HANDLE                   ProcessHandle,
    _In_opt_  PVOID                    BaseAddress,
    _In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_     PVOID                    MemoryInformation,
    _In_      SIZE_T                   MemoryInformationLength,
    _Out_opt_ PSIZE_T                  ReturnLength
);


// =============================================================================
// IsInAnyModule
// =============================================================================
BOOLEAN IsInAnyModule(_In_ PVOID Addr)
{
    if (!Addr || !PsLoadedModuleList) return FALSE;
    __try
    {
        PLIST_ENTRY E = PsLoadedModuleList;
        do
        {
            PLDR_DATA_TABLE_ENTRY M =
                CONTAINING_RECORD(E, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (M->DllBase && M->SizeOfImage &&
                (UINT8*)Addr >= (UINT8*)M->DllBase &&
                (UINT8*)Addr <  (UINT8*)M->DllBase + M->SizeOfImage)
                return TRUE;
            E = E->Flink;
        } while (E && E != PsLoadedModuleList);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
    return FALSE;
}


// =============================================================================
// ModuleNameOfAddr
// =============================================================================
VOID ModuleNameOfAddr(_In_ PVOID Addr, _Out_writes_z_(Cch) CHAR *Buf, _In_ ULONG Cch)
{
    Buf[0] = '?'; Buf[1] = '\0';
    if (!Addr || !Cch || !PsLoadedModuleList) return;
    __try
    {
        PLIST_ENTRY E = PsLoadedModuleList;
        do
        {
            PLDR_DATA_TABLE_ENTRY M =
                CONTAINING_RECORD(E, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (M->DllBase && M->SizeOfImage &&
                (UINT8*)Addr >= (UINT8*)M->DllBase &&
                (UINT8*)Addr <  (UINT8*)M->DllBase + M->SizeOfImage)
            {
                UNICODE_STRING *US  = &M->BaseDllName;
                ULONG           Len = US->Length / sizeof(WCHAR);
                if (Len >= Cch) Len = Cch - 1;
                for (ULONG i = 0; i < Len; i++) Buf[i] = (CHAR)US->Buffer[i];
                Buf[Len] = '\0';
                return;
            }
            E = E->Flink;
        } while (E && E != PsLoadedModuleList);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}


// =============================================================================
// SafeReadMemory
// =============================================================================
BOOLEAN SafeReadMemory(_In_ PVOID Src, _Out_ PVOID Dst, _In_ SIZE_T Size)
{
    if (Size == 0) return TRUE;

    PVOID StartPage   = (PVOID)((UINT64)Src & ~(PAGE_SIZE - 1));
    PVOID EndPage     = (PVOID)(((UINT64)Src + Size - 1) & ~(PAGE_SIZE - 1));
    PVOID CurrentPage = StartPage;

    while (CurrentPage <= EndPage)
    {
        if (!MmIsAddressValid(CurrentPage)) return FALSE;
        CurrentPage = (PVOID)((UINT64)CurrentPage + PAGE_SIZE);
    }

    RtlCopyMemory(Dst, Src, Size);
    return TRUE;
}


// =============================================================================
// IsAddressExecutable
// =============================================================================
BOOLEAN IsAddressExecutable(_In_ PVOID Addr)
{
    MEMORY_BASIC_INFORMATION Info;
    SIZE_T                   RetLen;
    NTSTATUS Status = ZwQueryVirtualMemory(ZwCurrentProcess(), Addr,
                                           MemoryBasicInformation,
                                           &Info, sizeof(Info), &RetLen);
    if (!NT_SUCCESS(Status) || RetLen != sizeof(Info)) return FALSE;
    return (Info.State == MEM_COMMIT &&
            (Info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                             PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
}


// =============================================================================
// AsciiStrEq
// =============================================================================
BOOLEAN AsciiStrEq(_In_ const CHAR *A, _In_ const CHAR *B)
{
    while (*A && *B && *A == *B) { A++; B++; }
    return *A == '\0' && *B == '\0';
}
