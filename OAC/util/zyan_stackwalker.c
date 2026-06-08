/**
 * @file zyan_stackwalker.c
 *
 * @brief Implementation of a stack walker using Zydis for instruction decoding.
 */
#include <ntddk.h>
#include "zyan_stackwalker.h"
#include "internals.h"
#include "helpers.h"


/**
 * @brief Checks if the instruction at Address is preceded by a CALL instruction.
 *
 * This function disassembles backwards from the given address to find a CALL
 * instruction that targets the address. It uses Zydis for decoding and checks
 * execute permissions for the memory range being analyzed.
 *
 * @param[in]  Address      The address to check.
 * @param[in]  Decoder      A pointer to an initialized ZydisDecoder.
 * @param[in]  SearchBytes  The number of bytes to search backwards from Address.
 * @return TRUE if a preceding CALL instruction is found, FALSE otherwise.
 */
static BOOLEAN IsPrecededByCall(
    _In_ UINT64        Address,
    _In_ ZydisDecoder* Decoder,
    _In_ SIZE_T        SearchBytes
)
{
    if (SearchBytes < ZYDIS_MAX_INSTRUCTION_LENGTH * 2)
    {
        SearchBytes = ZYDIS_MAX_INSTRUCTION_LENGTH * 3; // ~45 bytes for more context
    }

    if (Address < (UINT64)SearchBytes) return FALSE; // Invalid address

    // Check execute permission for the range (addr - search_bytes) to addr
    UINT64 StartAddress = Address - SearchBytes;
    UINT64 Current      = StartAddress & ~(PAGE_SIZE - 1);
    while (Current < Address)
    {
        if (!IsAddressExecutable((PVOID)Current))
        {
            return FALSE;
        }
        Current += PAGE_SIZE;
    }

    UINT8 Buffer[128]; // Buffer for up to 128 bytes
    if (SearchBytes > sizeof(Buffer)) SearchBytes = sizeof(Buffer);

    // Safely read the preceding bytes
    if (!SafeReadMemory((PVOID)StartAddress, Buffer, SearchBytes))
    {
        return FALSE;
    }

    // Limit decode failures to avoid infinite loops
    const SIZE_T MaxDecodeFailures = 3; // Stop if too many decode failures (non-code region)


    ZydisDecodedInstruction Instruction;
    ZydisDecodedOperand     Operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanUSize               Offset         = 0;
    SIZE_T                  DecodeFailures = 0;


    while (Offset < SearchBytes)
    {
        ZyanStatus Status = ZydisDecoderDecodeFull(Decoder, Buffer + Offset, SearchBytes - Offset,
                                                   &Instruction, Operands);
        if (!ZYAN_SUCCESS(Status))
        {
            DecodeFailures++;
            if (DecodeFailures >= MaxDecodeFailures)
            {
                return FALSE; // Likely not code
            }
            Offset++; // Skip byte (heuristic for misalignment)
            continue;
        }

        UINT64 InstructionStart = Address - SearchBytes + Offset;
        UINT64 InstructionEnd   = InstructionStart + Instruction.length;

        if (InstructionEnd == Address)
        {
            if (Instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
                Instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
            {
                // Relative near calls
                if (Instruction.operand_count_visible > 0 &&
                    (Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER ||
                        Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY))
                {
                    // For relative calls, validate target address
                    if (Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                        Operands[0].imm.is_relative)
                    {
                        UINT64 call_target = InstructionEnd + (INT64)Operands[0].imm.value.s;
                        if (!IsUserModeAddress((PVOID)call_target))
                        {
                            return FALSE;
                        }
                    }
                    return TRUE;
                }
            }
        }

        Offset += Instruction.length;
        DecodeFailures = 0; // Reset on successful decode
    }

    return FALSE;
}

/**
 * @brief Performs a stack walk using Zydis for instruction decoding and heuristics.
 *
 * This function attempts to reconstruct the call stack by scanning the stack memory
 * for potential return addresses. It uses several heuristics to validate candidates:
 * 1. Address space check (user-mode only).
 * 2. Execute permission check.
 * 3. Preceded by a CALL instruction.
 * If a candidate passes all checks, it is accepted as a valid frame.
 *
 * @param[in]  InitialRip     The initial instruction pointer (RIP) to start the stack walk from.
 * @param[in]  InitialRsp     The initial stack pointer (RSP) to start scanning the stack.
 * @param[out] OutFrames      An array to store the captured stack frames (RIP values).
 * @param[in]  MaxFrames      The maximum number of stack frames to capture.
 * @param[out] OutFramesCount The actual number of frames captured.
 *
 * @return TRUE if at least one frame was captured, FALSE otherwise.
 */
BOOLEAN StackWalkWithZydis(
    _In_ UINT64   InitialRip,
    _In_ UINT64   InitialRsp,
    _Out_ PUINT64 OutFrames,
    _In_ SIZE_T   MaxFrames,
    _Out_ PSIZE_T OutFramesCount
)
{
    if (MaxFrames == 0 || OutFrames == NULL)
    {
        return FALSE;
    }
    // Initialize OutFrames to zero
    RtlZeroMemory(OutFrames, MaxFrames * sizeof(UINT64));

    // Initialize Zydis decoder for x64
    ZydisDecoder Decoder;
    ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    DbgPrintEx(0,0,"Stack trace (heuristic):\n");

    // Validate initial RIP
    if (IsUserModeAddress((PVOID)InitialRip) &&
        IsAddressExecutable((PVOID)InitialRip))
    {
        // Add to OutFrames
        OutFrames[0] = InitialRip;
    }
    else
    {
        DbgPrintEx(0,0,"Invalid initial RIP: %p\n", (PVOID)InitialRip);
        return FALSE;
    }

    // Heuristic scanning parameters
    const SIZE_T MaxStackSearch         = 65536;          // 64KB max stack scan
    const SIZE_T Step                   = sizeof(UINT64); // 8-byte alignment
    const SIZE_T MaxConsecutiveFailures = 5;              // Stop after too many invalid candidates


    SIZE_T FrameCount          = 1; // Already have initial frame
    SIZE_T Offset              = 0; // Offset from InitialRsp
    SIZE_T ConsecutiveFailures = 0; // Count of consecutive invalid candidates


    while (Offset < MaxStackSearch && FrameCount < MaxFrames)
    {
        UINT64 Candidate;
        PVOID  StackAddress = (PVOID)(InitialRsp + Offset);

        // Safely read candidate
        if (!SafeReadMemory(StackAddress, &Candidate, sizeof(Candidate)))
        {
            ConsecutiveFailures++;
            if (ConsecutiveFailures >= MaxConsecutiveFailures)
            {
                break; // Likely end of valid stack
            }
            Offset += Step;
            continue;
        }

        // Heuristics chain:
        // 1. Address space check
        if (!IsUserModeAddress((PVOID)Candidate))
        {
            Offset += Step;
            continue;
        }

        // 2. Execute permission check
        if (!IsAddressExecutable((PVOID)Candidate))
        {
            Offset += Step;
            continue;
        }

        // 3. Preceded by CALL
        if (!IsPrecededByCall(Candidate, &Decoder, 64))
        {
            Offset += Step;
            continue;
        }

        // All heuristics passed; accept as frame
        DbgPrintEx(0,0,"Frame %llu: %p\n", FrameCount, (PVOID)Candidate);
        OutFrames[FrameCount] = Candidate;
        FrameCount++;
        ConsecutiveFailures = 0;

        // Heuristic: Jump to estimated next frame (skip shadow space + locals)
        Offset += 32;                               // Assume 32-128 bytes per frame
        Offset = (Offset + Step - 1) & ~(Step - 1); // Re-align
    }

    if (FrameCount < 2)
    {
        return FALSE;
    }

    *OutFramesCount = FrameCount;

    return TRUE;
}
