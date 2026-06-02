#include "dse_check.h"
#include "ci.h"
#include "globals.h"
#include "module.h"
#include "pattern_scanner.h"
#include "serial_logger.h"
#include <ntddk.h>
#include <ntimage.h>

static PVOID  G_CiBase   = NULL;
static SIZE_T G_CiSize   = 0;
static PVOID  G_NtosBase = NULL;
static SIZE_T G_NtosSize = 0;

static VOID EnsureModuleBases(VOID)
{
    if (!G_CiBase)   G_CiBase   = FindModuleByName2(L"ci.dll",       &G_CiSize);
    if (!G_NtosBase) G_NtosBase = FindModuleByName2(L"ntoskrnl.exe", &G_NtosSize);
}

static BOOLEAN IsPtrInCiDll(PVOID Ptr)
{
    if (!Ptr || !G_CiBase || !G_CiSize) return FALSE;
    return ((UINT8*)Ptr >= (UINT8*)G_CiBase &&
            (UINT8*)Ptr <  (UINT8*)G_CiBase + G_CiSize);
}



// =============================================================================
// Check 1 — SeCiCallbacks hook detection
//
// ntoskrnl maintains a table of CI callbacks.  Every slot must point inside
// ci.dll.  A pointer outside ci.dll means the callback was hooked.
//
// Finds the table by scanning SeValidateImageData's prologue for an indirect
// CALL through the table (FF 15 or MOV RAX + CALL RAX).
// =============================================================================
static VOID CheckCiCallbackHooks(VOID)
{
    if (!G_CiBase || !G_CiSize || !G_NtosBase) return;

    UNICODE_STRING Name;
    RtlInitUnicodeString(&Name, L"SeValidateImageData");
    PVOID SeValidate = MmGetSystemRoutineAddress(&Name);
    if (!SeValidate) return;

    // Try FF 15 [disp32] — CALL [rip+disp32]  (6 bytes)
    UINT64 Hit = PatternScan((UINT64)SeValidate, 0x100, "FF 15 ? ? ? ?");
    if (Hit)
    {
        INT32  Disp      = *(INT32*)(Hit + 2);
        PVOID* TableSlot = (PVOID*)((UINT8*)(Hit + 6) + Disp);

        if (!MmIsAddressValid(TableSlot)) goto TryMovCall;

        __try
        {
            for (ULONG i = 0; i < 8; i++)
            {
                if (!MmIsAddressValid(&TableSlot[i])) break;
                PVOID Fn = TableSlot[i];
                if (!Fn) break;

                if (!IsPtrInCiDll(Fn))
                    DbgPrintEx(0, 0, "[!] DSE VIOLATION [CiCallbacks]: slot[%lu]=0x%p is "
                               "OUTSIDE ci.dll — HOOKED\n", i, Fn);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { }
        return;
    }

TryMovCall:
    // Try 48 8B 05 [disp32] FF D0 — MOV RAX,[rip+disp32]; CALL RAX  (9 bytes)
    Hit = PatternScan((UINT64)SeValidate, 0x100, "48 8B 05 ? ? ? ? FF D0");
    if (!Hit) return;

    INT32  Disp    = *(INT32*)(Hit + 3);
    PVOID* PtrSlot = (PVOID*)((UINT8*)(Hit + 7) + Disp);

    if (!MmIsAddressValid(PtrSlot)) return;

    __try
    {
        PVOID Fn = *PtrSlot;
        if (Fn && !IsPtrInCiDll(Fn))
            DbgPrintEx(0, 0, "[!] DSE VIOLATION [CiCallbacks]: callback 0x%p is "
                       "OUTSIDE ci.dll — HOOKED\n", Fn);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}


// =============================================================================
// Check 2 — System-wide test-signing mode
//
// ZwQuerySystemInformation(SystemCodeIntegrityInformation) returns the live
// CodeIntegrityOptions bitmask maintained by CI.  Bit 0x02 = TESTSIGN.
// This is the same value the kernel consults internally — stable across all
// builds, no pattern scanning required.
// =============================================================================
#define SystemCodeIntegrityInformation_Class 103

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION;

#define CODEINTEGRITY_OPTION_TESTSIGN 0x02

// ntddk.h does not expose ZwQuerySystemInformation — declare it manually.
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

static VOID CheckTestSigningMode(VOID)
{
    SYSTEM_CODEINTEGRITY_INFORMATION CiInfo = { .Length = sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) };
    ULONG ReturnLength = 0;

    NTSTATUS Status = ZwQuerySystemInformation(
        SystemCodeIntegrityInformation_Class,
        &CiInfo,
        sizeof(CiInfo),
        &ReturnLength
    );

    if (!NT_SUCCESS(Status)) return;

    if (CiInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN)
        DbgPrintEx(0, 0, "[!] DSE WARNING [TestSigning]: system is in TEST-SIGNING MODE — "
                   "test-signed drivers are allowed to load (CodeIntegrityOptions=0x%lX)\n",
                   CiInfo.CodeIntegrityOptions);
}


// =============================================================================
// Check 3 — Per-module scan
//
// For every entry in PsLoadedModuleList:
//   (a) Ghost driver  — file missing from disk after load
//   (b) Invalid sig   — CiValidateFileObject fails (unsigned / no valid chain)
//   (c) Test-signed   — CI policy flags indicate test certificate\Invalid\Expired Cert 
// =============================================================================

#define CI_POLICY_FLAG_TEST_SIGNED 0x08
static VOID CheckSingleModule(PLDR_DATA_TABLE_ENTRY Mod)
{
    if (!Mod->FullDllName.Buffer || !Mod->DllBase || !Mod->SizeOfImage) return;

    NTSTATUS          Status;
    HANDLE            File          = NULL;
    PFILE_OBJECT      FileObj       = NULL;
    IO_STATUS_BLOCK   Iosb          = {0};
    OBJECT_ATTRIBUTES Oa            = {0};
    POLICY_INFO       SignerPol     = { .StructSize = sizeof(POLICY_INFO) };
    POLICY_INFO       TsPol         = { .StructSize = sizeof(POLICY_INFO) };
    LARGE_INTEGER     SigningTime   = {0};
    INT               DigestId      = 0;
    INT               DigestSize    = 64;
    UCHAR             DigestBuf[64] = {0};

    InitializeObjectAttributes(&Oa, &Mod->FullDllName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);
    __try
    {
        Status = ZwCreateFile(&File,
                              FILE_READ_DATA | SYNCHRONIZE,
                              &Oa, &Iosb, NULL,
                              FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                              FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
                              NULL, 0);

        if (Status == STATUS_OBJECT_NAME_NOT_FOUND ||
            Status == STATUS_NO_SUCH_FILE          ||
            Status == STATUS_OBJECT_PATH_NOT_FOUND)
        {
            DbgPrintEx(0, 0, "[!] DSE VIOLATION [Ghost]: %wZ is loaded but file is "
                       "MISSING from disk (deleted after load)\n", &Mod->BaseDllName);
            __leave;
        }

        if (!NT_SUCCESS(Status)) __leave;  // path format issue, not a ghost

        Status = ObReferenceObjectByHandle(File, FILE_READ_DATA,
                                           *IoFileObjectType, KernelMode,
                                           (PVOID*)&FileObj, NULL);
        if (!NT_SUCCESS(Status) || !FileObj) __leave;

        if (!G_CiValidateFileObject || !G_CiFreePolicyInfo) __leave;

        Status = G_CiValidateFileObject(FileObj, 0, 0,
                                         &SignerPol, &TsPol,
                                         &SigningTime, DigestBuf,
                                         &DigestSize, &DigestId);

        if (!NT_SUCCESS(Status))
        {
            DbgPrintEx(0, 0, "[!] DSE VIOLATION [Signature]: %wZ has NO valid signature "
                       "(status=0x%X)\n", &Mod->BaseDllName, Status);
            __leave;
        }

        if (SignerPol.Flags & CI_POLICY_FLAG_TEST_SIGNED)
            DbgPrintEx(0, 0, "[!] DSE WARNING [TestCert]: %wZ is TEST-SIGNED "
                       "(policy flags=0x%X)\n", &Mod->BaseDllName, SignerPol.Flags);
    }
    __finally
    {
        if (G_CiFreePolicyInfo)
        {
            if (SignerPol.CertChainInfo) G_CiFreePolicyInfo(&SignerPol);
            if (TsPol.CertChainInfo)     G_CiFreePolicyInfo(&TsPol);
        }
        if (FileObj) ObDereferenceObject(FileObj);
        if (File)    ZwClose(File);
    }
}

static VOID ScanAllLoadedModules(VOID)
{
    if (!PsLoadedModuleList) return;

    __try
    {
        PLIST_ENTRY Entry = PsLoadedModuleList;
        do
        {
            PLDR_DATA_TABLE_ENTRY Mod =
                CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            CheckSingleModule(Mod);
            Entry = Entry->Flink;
        } while (Entry && Entry != PsLoadedModuleList);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}


// =============================================================================
// Public entry point
// =============================================================================
NTSTATUS RunDseChecks(VOID)
{
    PAGED_CODE();

    EnsureModuleBases();
    CheckCiCallbackHooks();     // SeCiCallbacks hooked outside ci.dll
    CheckTestSigningMode();     // OS in test-signing mode
    ScanAllLoadedModules();     // ghost driver / invalid sig / test cert

    return STATUS_SUCCESS;
}
