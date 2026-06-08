/**
 * @file isr.h
 * @brief Header file for the custom Page Fault ISR used in CR3 thrashing and safe unwinding.
 *
 * This header declares the external assembly ISR function and the recovery ISR used
 * for safe unwinding during stack walking. The actual implementations are in assembly
 * files (isr.asm and stackwalk_saferecovery.asm).
 */

#pragma once
#include "internals.h" // For RUNTIME_FUNCTION, CONTEXT, etc.

#include <ntddk.h>

// Our assembly ISR. Tells the C compiler it exists elsewhere.
extern VOID PageFaultIsr(VOID); // Defined in isr.asm

// Implemented in stackwalk_saferecovery.asm
extern VOID PageFaultRecoveryIsr(VOID);

// Hypervisor opcode probes — defined in isr.asm.
// Both raise #UD (STATUS_ILLEGAL_INSTRUCTION) on bare metal when called from
// a context where VMX is not active.  Wrap each call in __try/__except.
extern VOID VmfuncProbe(VOID);  // executes: VMFUNC (0F 01 D4) ecx=edx=0
extern VOID VmreadProbe(VOID);  // executes: VMREAD rax, rax (0F 78 C0) field=0
