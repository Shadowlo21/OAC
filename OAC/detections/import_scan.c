#include "import_scan.h"
#include "globals.h"
#include "module.h"

#include <ntddk.h>
#include <ntimage.h>


// =============================================================================
// Suspicious process/memory primitive list
//
// A driver importing > SUSP_THRESHOLD of these has strong cheat-enabling
// capability and should be flagged for further review.
// =============================================================================
static const char* const G_SuspiciousImports[] =
{
    "MmCopyVirtualMemory",
    "PsLookupProcessByProcessId",
    "PsGetProcessSectionBaseAddress",
    "KeStackAttachProcess",
    "MmMapIoSpace",
    "PsGetProcessWow64Process",
    "PsGetProcessPeb",
    "PsGetProcessImageFileName",
    "ZwAllocateVirtualMemory",
    "ZwWriteVirtualMemory",
    "ZwProtectVirtualMemory",
    "MmAllocateContiguousMemory",
    "PsSuspendProcess",
    "PsResumeProcess",
    "MmUnmapLockedPages",
    "ZwReadVirtualMemory",
};

#define SUSP_LIST_COUNT   (sizeof(G_SuspiciousImports) / sizeof(G_SuspiciousImports[0]))
#define SUSP_THRESHOLD    6  // more than this many matches → flag


// =============================================================================
// Internal helpers
// =============================================================================

static BOOLEAN RvaInBounds(ULONG Rva, SIZE_T ImageSize)
{
    return Rva != 0 && Rva < (ULONG)ImageSize;
}

static BOOLEAN NameEqual(const char* a, const char* b)
{
    while (*a && *b && *a == *b) { ++a; ++b; }
    return (*a == '\0') && (*b == '\0');
}


// =============================================================================
// Per-module import table scanner
// =============================================================================
static VOID ScanModuleImports(PLDR_DATA_TABLE_ENTRY Mod)
{
    PVOID  Base      = Mod->DllBase;
    SIZE_T ImageSize = Mod->SizeOfImage;

    ULONG        TotalImports      = 0;
    ULONG        MatchCount        = 0;
    ULONG        DescriptorCount   = 0;
    BOOLEAN      DescTableReadable = FALSE;  // TRUE only if first descriptor page was mapped
    const char*  Matched[SUSP_LIST_COUNT];

    __try
    {
        // ── Validate DOS + NT headers ──────────────────────────────────────
        if (!MmIsAddressValid(Base)) __leave;

        PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Base;
        if (Dos->e_magic != IMAGE_DOS_SIGNATURE) __leave;

        if (!RvaInBounds((ULONG)Dos->e_lfanew, ImageSize)) __leave;

        PIMAGE_NT_HEADERS64 Nt = (PIMAGE_NT_HEADERS64)((PUCHAR)Base + Dos->e_lfanew);
        if (!MmIsAddressValid(Nt)) __leave;
        if (Nt->Signature != IMAGE_NT_SIGNATURE) __leave;
        if (Nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) __leave;

        // ── Locate import directory ────────────────────────────────────────
        ULONG ImportRva =
            Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

        if (!ImportRva)
        {
            // No import table at all — strong signal of manual mapping/obfuscation.
            DbgPrintEx(0, 0, "[!] IMPORT SCAN [NoImportTable]: %wZ has no import directory "
                       "(manually mapped or obfuscated driver)\n", &Mod->BaseDllName);
            __leave;
        }

        if (!RvaInBounds(ImportRva, ImageSize)) __leave;

        // ── Walk IMAGE_IMPORT_DESCRIPTOR array (null-terminated by Name==0) ─
        PIMAGE_IMPORT_DESCRIPTOR Desc =
            (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)Base + ImportRva);

        DescTableReadable = MmIsAddressValid(Desc);
        while (DescTableReadable && Desc->Name != 0)
        {
            DescriptorCount++;

            // Prefer OriginalFirstThunk (INT, names intact); fall back to
            // FirstThunk only when INT is absent (rare linker quirk).
            ULONG IntRva = Desc->OriginalFirstThunk
                           ? Desc->OriginalFirstThunk
                           : Desc->FirstThunk;

            if (!RvaInBounds(IntRva, ImageSize)) { Desc++; continue; }

            PIMAGE_THUNK_DATA64 Thunk =
                (PIMAGE_THUNK_DATA64)((PUCHAR)Base + IntRva);

            while (MmIsAddressValid(Thunk) && Thunk->u1.AddressOfData != 0)
            {
                // High bit set → ordinal-only import, no name to compare.
                if (!(Thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
                {
                    ULONG IbnRva = (ULONG)(Thunk->u1.AddressOfData & 0xFFFFFFFF);

                    if (RvaInBounds(IbnRva, ImageSize))
                    {
                        PIMAGE_IMPORT_BY_NAME Ibn =
                            (PIMAGE_IMPORT_BY_NAME)((PUCHAR)Base + IbnRva);

                        if (MmIsAddressValid(Ibn))
                        {
                            TotalImports++;

                            for (ULONG i = 0; i < SUSP_LIST_COUNT; i++)
                            {
                                if (NameEqual((const char*)Ibn->Name,
                                              G_SuspiciousImports[i]))
                                {
                                    if (MatchCount < SUSP_LIST_COUNT)
                                        Matched[MatchCount] = G_SuspiciousImports[i];
                                    MatchCount++;
                                    break;
                                }
                            }
                        }
                    }
                }
                Thunk++;
            }
            Desc++;
            if (!MmIsAddressValid(Desc)) break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }

    // ── Report ────────────────────────────────────────────────────────────────
    if (MatchCount > SUSP_THRESHOLD)
    {
        DbgPrintEx(0, 0, "[!] IMPORT SCAN [SuspiciousDriver]: %wZ — %lu/%lu suspicious "
                   "imports matched (total imports=%lu)\n",
                   &Mod->BaseDllName, MatchCount, (ULONG)SUSP_LIST_COUNT, TotalImports);

        for (ULONG i = 0; i < MatchCount && i < SUSP_LIST_COUNT; i++)
            DbgPrintEx(0, 0, "    [>] %s\n", Matched[i]);
    }

    if (DescTableReadable && DescriptorCount == 0)
        DbgPrintEx(0, 0, "[!] IMPORT SCAN [MinimalImports]: %wZ has import directory but "
                   "no valid import descriptors (empty or corrupt import table)\n",
                   &Mod->BaseDllName);
}


// =============================================================================
// Public entry point — walks PsLoadedModuleList
// =============================================================================
NTSTATUS RunImportScan(VOID)
{
    PAGED_CODE();

    if (!PsLoadedModuleList) return STATUS_NOT_FOUND;

    DbgPrintEx(0, 0, "[*] IMPORT SCAN: scanning loaded kernel modules...\n");

    __try
    {
        PLIST_ENTRY Entry = PsLoadedModuleList;
        do
        {
            PLDR_DATA_TABLE_ENTRY Mod =
                CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (Mod->DllBase && Mod->SizeOfImage)
                ScanModuleImports(Mod);

            Entry = Entry->Flink;
        } while (Entry && Entry != PsLoadedModuleList);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }

    DbgPrintEx(0, 0, "[*] IMPORT SCAN: complete.\n");
    return STATUS_SUCCESS;
}
