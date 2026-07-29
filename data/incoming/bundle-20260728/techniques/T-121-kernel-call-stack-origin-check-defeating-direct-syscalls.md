---
id: T-121
name: Kernel Call-Stack Origin Check Defeating Direct Syscalls
category: syscalls
tier: S
crate: none
source_file: none
mitre: T1106
mitre_secondary: []
tags: [syscalls, kernel-callback, etw-ti, call-stack-walk, ntdll-origin-check, ktrap-frame, rtlvirtualunwind, direct-syscall-detection, defender-technique, x64-unwind]
origin: atlas-synthesis
member_notes: ['lgtm:direct-vs-indirect-syscall-callstack-detection']
---

# Kernel Call-Stack Origin Check Defeating Direct Syscalls — Defensive inspection of the syscall return address and surrounding call-stack frames to distinguish direct-from-implant syscalls from legitimate ntdll-originated syscalls

## Summary

A defensive mechanism deployed by EDR kernel drivers (and, in lower fidelity, by user-mode hook engines) to defeat direct-syscall evasion. At the moment a syscall of interest is dispatched, the defender reads the user-mode return address — saved by the CPU/kernel in `_KTRAP_FRAME.Rip` during the `KiSystemCall64` transition — and verifies that the immediately-preceding frame lies within the loaded image range of `ntdll.dll`. Direct syscalls (where the implant executes the `syscall` instruction from its own `.text` section, an RWX heap allocation, or a manually mapped image) leave a return address pointing back into implant-owned memory rather than into `ntdll_base + [0..SizeOfImage)`. The check fails; the syscall is flagged. The ntdll range itself is recorded per-process via `PsSetLoadImageNotifyRoutine` (the callback's `IMAGE_INFO.ImageBase` and `IMAGE_INFO.ImageSize` are delivered for every user image load, and ntdll loads exactly once per process during `LdrpInitializeProcess` phase 1). Failing syscalls are routed into a deeper pipeline that walks surrounding frames via `RtlVirtualUnwind` over the originating module's `.pdata` unwind tables, fetches the bytes at the saved RIP, and compares the originating address against all known loaded-image ranges. Two trigger paths exist: in-kernel callbacks (`ObRegisterCallbacks` on `PsProcessType`/`PsThreadType`, `PsSetCreateProcessNotifyRoutineEx`, minifilter `FLT_PRE_OPERATION` callbacks) that already run in the calling thread's context, and the `Microsoft-Windows-Threat-Intelligence` (ETW-TI) kernel ETW provider that emits events from inside the syscall handlers for `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtMapViewOfSection`, `NtQueueApcThread`, `NtSetContextThread`, and similar high-risk surfaces. This mechanism is the operational justification for indirect syscalls (T-002): routing the `syscall` instruction through a genuine ntdll `syscall; ret` gadget places the saved RIP inside ntdll's image range and the frame[0] check passes. The vault's T-001 card documents direct syscalls as a userland-hook bypass; T-002 documents indirect syscalls as the bypass for this defense; this card documents the defense itself — the missing middle of the syscall-evasion triad.

## Mechanism

The defense executes in three phases: trigger at the syscall of interest, read user-mode RIP from the trap frame or captured stack, and verify against ntdll's image range. Variants differ in trigger mechanism and fidelity.

### Variant 1: Kernel-callback frame inspection

Runs when an EDR driver is already in the calling thread's context by virtue of an in-kernel callback firing on the syscall path.

1. The EDR driver registers `PsSetLoadImageNotifyRoutine` at boot. Each callback invocation receives `PUNICODE_STRING FullImageName`, `HANDLE ProcessId`, and `PIMAGE_INFO ImageInfo`.
2. The driver filters on `wcsstr(FullImageName->Buffer, L"ntdll.dll")` (case-insensitive; both `\SystemRoot\System32\ntdll.dll` and the WOW64 `\SystemRoot\SysWOW64\ntdll.dll` must be recognized). It stores, per-process, in a hash table keyed by `ProcessId`, the tuple `(ntdll_base, ntdll_size, wow64_ntdll_base, wow64_ntdll_size)`. `IMAGE_INFO.ImageBase` and `IMAGE_INFO.ImageSize` provide the range directly — no PE parsing needed.
3. The driver separately registers `ObRegisterCallbacks` against `PsProcessType` and `PsThreadType` (for `OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE`), `PsSetCreateProcessNotifyRoutineEx` (for process create/exit), `CmRegisterCallbackEx` (for `RegNtPreSetValueKey` and `RegNtPreDeleteKey`), and any minifilter altitudes relevant to its file-monitoring scope. Each of these callbacks runs in the calling thread's context at `IRQL == PASSIVE_LEVEL`.
4. When a syscall such as `NtOpenProcess` is invoked via a direct-syscall stub, the syscall transitions to kernel mode via `KiSystemCall64`. Inside the handler, `ObpCallPreOperationCallbacks` invokes the EDR's `PreOperationCallback` for `OB_OPERATION_HANDLE_CREATE` with `OB_PRE_OPERATION_PARAMETERS.CreateHandleInformation`. The driver is now executing in the originating thread's context.
5. The driver retrieves the current `ETHREAD*` via `PsGetCurrentThread()` and reads `Thread->Tcb.TrapFrame`. On x64, this is a pointer to a `_KTRAP_FRAME` structure allocated on the kernel stack by `KiSystemCall64`'s prologue. The pointer is valid for the duration of the syscall.
6. From `_KTRAP_FRAME`, the driver extracts `Rip` (the user-mode return address — the instruction immediately following the `syscall` instruction) and `Rsp` (user stack pointer). It verifies `SegCs & 0x3 == 0x3` (RPL = `MODE_USER_MODE`) to confirm the trap frame is a user-mode transition; kernel-mode-originating syscalls (e.g., a driver calling `ZwOpenProcess`) have `SegCs` RPL `0x0` and must be skipped.
7. The driver performs the range check: `ntdll_base <= Rip < (ntdll_base + ntdll_size)`. If false, the syscall is classified as direct (the executing `syscall` instruction sits outside ntdll's image range).
8. (Optional higher-fidelity pass.) The driver walks N additional user-mode frames via `RtlVirtualUnwind`, starting from the saved `Rip`/`Rsp`. For each frame it locates the containing `RUNTIME_FUNCTION` entry in the image's `.pdata` (referenced by `IMAGE_DIRECTORY_ENTRY_EXCEPTION`, `DataDirectory[3]`), applies the unwind codes to a synthetic `CONTEXT`, and produces the previous frame's `Rip`/`Rsp`. Frames that fail to resolve into a known loaded image range — even if frame[0] is in ntdll — flag the call as suspicious. This catches poorly-implemented indirect syscalls that leave a non-ntdll caller one frame up.
9. The driver reports up to the EDR user-mode service via a shared ring buffer, `FltSendMessage`, or IOCTL — including the stack trace, saved `Rip`, the originating image name (resolved by walking `PEB.Ldr` via `KeStackAttachProcess` or by the driver's own image-cache built from `PsSetLoadImageNotifyRoutine`), and the syscall number (extracted from `KTRAP_FRAME.R10` or from the `EAX` register snapshot).

### Variant 2: ETW-TI consumer

Covers syscalls that do not pass through a kernel callback the EDR has registered. The `Microsoft-Windows-Threat-Intelligence` kernel ETW provider emits events from inside the syscall handlers for the high-risk syscall surface.

1. The EDR driver opens a kernel ETW consumer session against the threat-intelligence provider, with `ENABLE_TRACE_PARAMETERS` including `EVENT_ENABLE_PROPERTY_STACK_TRACE` (this flag instructs the kernel to capture a stack walk at each event, which the consumer reads via `EXTENDED_EVENT_HEADER`). Consumer registration requires the driver to be signed with ELAM or a Microsoft anti-malware class signature; this is the strictest signing requirement of any variant.
2. When `NtAllocateVirtualMemory` is invoked with `PAGE_EXECUTE_READWRITE = 0x40` (or `PAGE_EXECUTE = 0x10`, `PAGE_EXECUTE_WRITECOPY = 0x80`), the kernel's `MiAllocateVad` path fires the `AllocVm` event. Payload includes `ProcessId`, `ThreadId`, `BaseAddress`, `RegionSize`, `AllocationType`, `Protection`, and the captured stack snapshot.
3. `ProtectVm` fires from `NtProtectVirtualMemory` when the new protection includes an executable page (`PAGE_EXECUTE*`). `MapViewOfSection` fires from `NtMapViewOfSection` when the section's `AllocationAttributes` includes `SEC_IMAGE = 0x01000000`. `QueueUserApc` fires from `NtQueueApcThread`. `SetThreadContext` fires from `NtSetContextThread`. The `CreateThread`/`CreateThreadEx` events fire from `NtCreateThreadEx`.
4. The kernel-side stack capture walks the kernel stack via `RtlWalkFrameChain`, crosses the user-mode boundary by reading `_KTRAP_FRAME.Rip`/`Rsp`, and continues with `RtlVirtualUnwind` over the user-mode frames. The capture happens at `IRQL == PASSIVE_LEVEL` in the originating thread's context; user pages are touched under `__try / __except (EXCEPTION_EXECUTE_HANDLER)` because the originating image's `.pdata` may be paged out.
5. The consumer checks the topmost user-mode frame (frame[0] = the syscall-return site) against the recorded ntdll range for the originating process. Identical flag-and-report pipeline as Variant 1 step 9.

### Variant 3: User-mode hook stack inspection (the variant direct syscalls already defeat)

A lower-privilege fallback for EDRs without a kernel driver, or for fail-open mode when the driver is uninstalled. *This variant does not catch direct syscalls — it is included here to document the contrast and to explain why direct syscalls emerged as a bypass in the first place.*

1. The EDR injects a user-mode DLL into every process at startup via `PsSetCreateProcessNotifyRoutineEx` (with the registration flag preventing notification for system-critical processes). Injection is via `QueueUserApc` to a hijacked thread, or via `CreateRemoteThread` + `LoadLibraryW`.
2. On attach, the injected DLL walks `PEB.Ldr.InLoadOrderModuleList`, locates the `ntdll.dll` entry, and records `LDR_DATA_TABLE_ENTRY.DllBase` and `LDR_DATA_TABLE_ENTRY.SizeOfImage`.
3. The DLL installs inline hooks on selected `Nt*` exports. The hook prologue is typically a 5-byte `JMP rel32` (if `ntdll!NtXxx + 0x05` is reachable) or a 12-byte `MOV RAX, imm64; JMP RAX` for absolute jumps. The trampoline allocates a small executable stub (typically within 2 GB of ntdll to keep the `rel32` reachable) holding the original 5–12 overwritten bytes plus a `JMP` back to `ntdll!NtXxx + N`.
4. On hook invocation, the handler calls `RtlCaptureStackBackTrace` (which internally invokes `RtlVirtualUnwind` over the caller's own context). The topmost returned frame (frame[0]) is the caller of the hooked stub.
5. The check verifies frame[0] is in a known-good image range (kernel32, kernelbase, user32, or the EDR's own injected DLL). A frame outside this set flags the call as suspicious — but only if the call *arrived* at the hook. Direct syscalls execute the `syscall` instruction from implant memory and never traverse the hooked ntdll stub at all; they bypass this variant entirely. This is the operational reason direct syscalls defeated first-generation EDRs and motivated the kernel-side Variants 1 and 2.

## OS Internals Context

The mechanism relies on three kernel-internals pieces: (a) how the `syscall` transition saves user-mode state, (b) how a kernel-mode driver safely inspects user-mode call-stack frames, and (c) how the defender obtains a per-process map of legit syscall-source image ranges.

**The syscall transition.** On x64 Windows, the user-mode `syscall` instruction reads `IA32_LSTAR MSR` (model-specific register `0xC0000082`), which Windows initializes at boot to the address of `nt!KiSystemCall64`. The CPU does not save the user-mode `RIP` in a register — it relies on the kernel prologue to do so. `KiSystemCall64`'s prologue swaps `SS:RSP` to the per-CPU kernel stack (`TSS.SP0` from the GDT's `TSS` entry, i.e., `KeGetPcr()->TSS.SP0`), saves the user `RSP` into the new kernel stack's `_KTRAP_FRAME.HardwareSegSs`/`HardwareEsp` slots, and saves the user `RIP` into `_KTRAP_FRAME.Rip` and `SegCs`. The trap frame is allocated by the prologue itself by subtracting `sizeof(_KTRAP_FRAME)` from the freshly-loaded kernel `RSP`. The thread's `ETHREAD.Tcb.TrapFrame` is then set to this address. Any kernel code running in the thread's context — including the EDR's notification callbacks — can dereference `PsGetCurrentThread()->Tcb.TrapFrame` to read the saved user `RIP`. PatchGuard does not protect `_KTRAP_FRAME`; it is per-thread kernel-stack memory and is freely readable.

**Where the trap-frame read happens.** An EDR driver that has registered `ObRegisterCallbacks` for `PsProcessType`/`PsThreadType` runs its `PreOperationCallback` synchronously inside the calling thread's context at `IRQL == PASSIVE_LEVEL`, before the underlying `NtOpenProcess`/`NtOpenThread`/`NtDuplicateObject` operation completes. The trigger flow is: user `syscall` → `KiSystemCall64` → SSDT lookup into `Nt*` syscall handler → `ObOpenObjectByPointerWithTag` → `ObpCallPreOperationCallbacks` → EDR's `PreOperationCallback`. At this point `PsGetCurrentThread()->Tcb.TrapFrame` is the user-mode syscall trap frame. Kernel-initiated operations (a driver calling `ZwOpenProcess`) have a kernel-mode trap frame whose `SegCs` RPL is `0x0`; the EDR must distinguish these via the `SegCs` low bits and skip them — the check applies only to user-originated syscalls.

**ETW-TI's role and constraints.** The `Microsoft-Windows-Threat-Intelligence` provider is enabled by a PPL (Protected Process Light) signature requirement — only ELAM-class or Microsoft-signed drivers can register as consumers. The provider fires from inside the syscall handlers themselves: for the `AllocVm` event, the call site is inside `NtAllocateVirtualMemory` after the VAD insertion but before the function returns. The event payload carries `BaseAddress`, `RegionSize`, `AllocationType`, `Protection`, and (when `EVENT_ENABLE_PROPERTY_STACK_TRACE` is set in the `ENABLE_TRACE_PARAMETERS` passed to `StartTraceW`) a captured stack snapshot. The kernel-side stack capture uses `KeStackAttachProcess` to switch into the originating process's address context, `RtlWalkFrameChain` to walk kernel frames, then continues into user-mode via `_KTRAP_FRAME.Rip`/`Rsp` and `RtlVirtualUnwind`. The capture happens at `IRQL == PASSIVE_LEVEL`; the originating thread is the current thread. The ETW-TI event surface is bounded — it covers only the explicitly-instrumented syscalls, not every syscall. An attacker can probe which syscalls emit events by reading the syscall handler disassembly or by inferring from the provider documentation.

**RtlVirtualUnwind on user-mode frames.** `RtlVirtualUnwind` is exported by `ntoskrnl.exe` and is the canonical x64-frame-unwinder. Given a control PC (an RIP) and the image base containing it, it locates the `RUNTIME_FUNCTION` entry in the image's `.pdata` section (the `IMAGE_DIRECTORY_ENTRY_EXCEPTION` data directory, `DataDirectory[3]`, of type `IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3`). It applies the unwind codes — a compact bytecode describing the prologue's effects on `RSP`, saved registers, frame pointer chaining — to a synthetic `CONTEXT` structure, and produces the previous frame's `Rsp` and `Rip`. From kernel mode, calling `RtlVirtualUnwind` on a user-mode `ControlPc` requires that the unwind tables be accessible — they live in user pages of the image section, so the driver must `KeStackAttachProcess(Process)` first. The walk must be wrapped in `__try / __except (EXCEPTION_EXECUTE_HANDLER)` because user pages may be paged out, the `ControlPc` may be invalid, or the image may have been unloaded (race with `NtUnmapViewOfSection`). A well-implemented EDR caps the walk at N frames (typically 8–16) to bound the inspection cost — and this same cap bounds what an indirect-syscall implementation must spoof.

**The ntdll range map.** Three sources, in descending order of reliability:

1. `PsSetLoadImageNotifyRoutine`. The callback's `IMAGE_INFO` exposes `ImageBase` and `ImageSize` directly, no PE parsing required. The driver filters on `FullImageName` ending in `ntdll.dll`. ntdll loads exactly once per process during `LdrpInitializeProcess` phase 1 (the import-resolution phase, after `Peb->Ldr` is initialized but before any user code in the EXE runs), so the callback fires once per process creation and the driver captures the range before the process's first syscall of interest can occur. This is what production EDRs use.
2. `PEB.Ldr.InLoadOrderModuleList` walk from kernel mode. The driver calls `KeStackAttachProcess(TargetProcess)`, reads `PEB->Ldr->InLoadOrderModuleList` (a `LIST_ENTRY` whose head is `&Ldr->InLoadOrderModuleList`), walks the list comparing `LDR_DATA_TABLE_ENTRY.BaseDllName` against `ntdll.dll`, and reads `DllBase` and `SizeOfImage`. Requires page-fault-safe access via `MmCopyVirtualMemory` or `ProbeForRead` under `__try`. This is the fallback when the EDR was loaded after the process started and missed the image-load callback.
3. User-mode self-query. A user-mode EDR component walks its own `PEB.Ldr`, finds `ntdll.dll`, reads `DllBase`, then calls `RtlImageNtHeader(DllBase)` to obtain the `IMAGE_NT_HEADERS64.OptionalHeader.SizeOfImage`. Note: `NtQueryInformationProcess(ProcessImageFileName = 27)` returns the *main executable's* path, not ntdll's — the user-mode component must walk `PEB.Ldr` rather than relying on the info class alone.

**What makes the check discriminating.** A genuine ntdll syscall stub for `NtAllocateVirtualMemory` on Windows 10 1903+ disassembles as:

```
ntdll!NtAllocateVirtualMemory:
  4C 8B D1                          mov  r10, rcx              ; 3 bytes  @ +0x00
  B8 18 00 00 00                    mov  eax, 18h              ; 5 bytes  @ +0x03  (SSN, varies by build)
  F6 04 25 08 03 FE 7F 01           test byte ptr [0x7FFE0308], 1  ; 8 bytes  @ +0x08
  75 03                             jne  short +3              ; 2 bytes  @ +0x10
  0F 05                             syscall                    ; 2 bytes  @ +0x12
  C3                                ret                        ; 1 byte   @ +0x14
  CD 2E                             int  2Eh                   ; 2 bytes  @ +0x15  (legacy fallback)
  C3                                ret                        ; 1 byte   @ +0x17
```

The `test byte ptr [0x7FFE0308], 1` reads the `KUSER_SHARED_DATA.SystemCall` flag (the user-mode mapping of `KUSER_SHARED_DATA` is at the fixed virtual address `0x7FFE0000`; the byte at offset `0x308` is the `SystemCallPad` field that selects between `syscall` and `int 2Eh`). The `syscall` instruction is at `ntdll_base + stub_offset + 0x12`. A legitimate caller transitions to the kernel from this address; the saved `_KTRAP_FRAME.Rip` points to the instruction after `syscall`, i.e., `ntdll_base + stub_offset + 0x14` (the `ret`). This is inside ntdll's range.

A direct-syscall implant's stub is structurally identical but located in implant-owned memory:

```
implant!DirectNtAllocateVirtualMemory:
  4C 8B D1                          mov  r10, rcx
  B8 18 00 00 00                    mov  eax, 18h
  0F 05                             syscall
  C3                                ret
```

The saved `Rip` is `implant_base + offset`, outside ntdll's range — caught by the frame[0] check.

An indirect-syscall implant rewrites the stub so the `syscall` instruction executes from inside ntdll:

```
implant!IndirectNtAllocateVirtualMemory:
  4C 8B D1                          mov  r10, rcx
  B8 18 00 00 00                    mov  eax, 18h
  FF 25 xx xx xx xx                 jmp  qword ptr [rel ntdll_syscall_gadget]
                                                    ; points to ntdll!NtAllocateVirtualMemory + 0x12
                                                    ; i.e., the `syscall; ret` gadget
```

The `Rip` saved in the trap frame is now `ntdll_base + stub_offset + 0x14` — inside ntdll's range. The frame[0] check passes. *This is the entire operational purpose of indirect syscalls (T-002).*

**Multi-frame variants.** Higher-fidelity EDRs walk N frames and verify that *every* frame falls in a known image range, not just frame[0]. The simplest check is "frame[0] in ntdll"; the harder check is "frame[0] in ntdll, frame[1] in {kernel32.dll, kernelbase.dll, user32.dll, advapi32.dll, ...}, frame[2]+ resolves through known modules". A direct syscall trivially fails the first check; a naive indirect syscall fails the second check because frame[1] is in implant memory. Defeating the multi-frame variant requires either (a) a full ROP chain through legitimate modules between the implant code and the ntdll gadget — typically impractical without losing the hook-bypass benefit, or (b) the implant calls into `kernelbase`/`kernel32` legitimately and lets those modules call into ntdll — accepting the userland-hook exposure as the cost of stack hygiene. This is why the multi-frame variant is the most aggressive form of the check and is rarely deployed in its strictest form on the entire syscall surface; defenders typically apply it to a small high-risk subset (`NtAllocateVirtualMemory` with executable protections, `NtCreateThreadEx`, `NtMapViewOfSection` with `SEC_IMAGE`).

## Variant Comparison Table

| Variant | Trigger Surface | Privilege Required | Covers All Syscalls? | Multi-Frame Walk? | Bypassed By |
|---|---|---|---|---|---|
| 1. Kernel callback | `ObRegisterCallbacks`, `PsSetCreateProcessNotifyRoutineEx`, `CmRegisterCallbackEx`, MiniFilter | Kernel driver (normal signature) | No — only syscalls routed through registered callbacks | Optional | T-002 indirect syscalls |
| 2. ETW-TI consumer | Kernel ETW provider events from inside `Mm`/`Nt` syscall handlers | ELAM or Microsoft anti-malware class signature | No — only the high-risk syscall subset instrumented by the provider | Yes (when `EVENT_ENABLE_PROPERTY_STACK_TRACE` enabled) | T-002 indirect syscalls (frame[0]); multi-frame requires ROP through legit modules |
| 3. User-mode hook | Inline hooks on `ntdll!Nt*` exports | None (user-mode DLL injection) | Only hooked exports | Limited (no trap-frame access) | T-001 direct syscalls (bypass hooks entirely) |

## Byte-Level Layout

The detection hinges on the exact byte layout of an ntdll syscall stub. The canonical x64 ntdll stub (Windows 10 1903 through Windows 11 23H2):

```
Offset  Bytes                           Disassembly
+0x00   4C 8B D1                        mov  r10, rcx
+0x03   B8 SSN 00 00 00                 mov  eax, <SSN>     ; SSN varies by build, e.g. 0x18 for NtAllocateVirtualMemory
+0x08   F6 04 25 08 03 FE 7F 01         test byte ptr [KUSER_SHARED_DATA+0x308], 1
+0x10   75 03                           jne  short skip     ; if SystemCall flag set, jump to int 2Eh fallback
+0x12   0F 05                           syscall
+0x14   C3                              ret
+0x15   CD 2E                           int  2Eh            ; legacy fallback path (Win10+ keeps for compat)
+0x17   C3                              ret
```

The detection primitive reads `_KTRAP_FRAME.Rip` after the syscall transition. For a legit ntdll-originated syscall, `Rip = ntdll_base + stub_offset + 0x14` (the `ret` immediately after `syscall`). For a direct-syscall stub in implant memory, `Rip = implant_base + stub_offset + 0x06` (assuming the implant omits the `test`/`jne`/`int 2Eh` fallback, leaving only `mov r10, rcx; mov eax, SSN; syscall; ret`). The `Rip` falls outside `[ntdll_base, ntdll_base + SizeOfImage)`. Caught.

For an indirect-syscall stub, the implant's stub ends with a `JMP` into the ntdll gadget at offset `+0x12` (the `0F 05 0F 05` — wait, `0F 05 C3` is the actual gadget: `syscall; ret`). The `syscall` instruction executed is the one inside ntdll; the saved `Rip` is `ntdll_base + stub_offset + 0x14`. The check passes.

## Key Implementation Details

**Prerequisites.** Variant 1 requires a kernel-mode driver with normal EV signing; `PsSetLoadImageNotifyRoutine` requires no special privilege beyond driver loading. `ObRegisterCallbacks` requires the driver to set `OB_CF_FLAG_KERNEL_MODE_CALLBACKS` in its `OB_CALLBACK_REGISTRATION.Version` field (or use the version-aware registration path) and to be in the `PsProcessType`/`PsThreadType` `ObjectType`'s callback list (it is by default for any driver that calls `ObRegisterCallbacks` with a valid `Altitude` string). Variant 2 (ETW-TI) requires either ELAM or Microsoft anti-malware class signature; this is the strictest requirement and is the reason many second-tier EDRs do not deploy Variant 2.

**Per-process state.** The driver must maintain a per-process hash table of `(ntdll_base, ntdll_size, wow64_ntdll_base, wow64_ntdll_size)`. The table must be populated lazily on first syscall from a process whose entry is missing — typically by walking `PEB.Ldr` via `KeStackAttachProcess`. Race conditions exist between process creation (`PsSetCreateProcessNotifyRoutineEx` fires), `PsSetLoadImageNotifyRoutine` firing for ntdll, and the first syscall of interest. The check should treat "no recorded range" as ambiguous (do not flag) until the range is established.

**WOW64.** On a 32-bit process under WoW64, there are two ntdlls: the 64-bit `\SystemRoot\System32\ntdll.dll` (which actually performs the syscall transition) and the 32-bit `\SystemRoot\SysWOW64\ntdll.dll` (which the 32-bit code links against). The `syscall`-from-ntdll check is on the 64-bit ntdll because that is where the actual `syscall` instruction executes. A 32-bit direct-syscall implant that issues `int 2Eh` or `sysenter` from 32-bit code transitions through `Wow64Transition` (dispatched via `wow64cpu!TurboDispatch` into the 64-bit `ntdll!Nt*` stubs), and the check applies at the 64-bit boundary. The 64-bit ntdll is always loaded — even in pure-WOW64 processes — so the range map always has an entry.

**ETW-TI is bounded.** Not every syscall emits an ETW-TI event — only the dangerous ones do. Direct syscalls to e.g. `NtQueryInformationProcess(ProcessBasicInformation = 0)` do not fire an ETW-TI event and are only catchable via Variant 1 if the EDR happens to have a relevant callback (it does not, for `NtQueryInformationProcess`). The defender's coverage is partial; an attacker can choose direct syscalls for low-signal syscalls and indirect syscalls for high-signal ones, trading complexity for coverage where it matters.

**`_KTRAP_FRAME.SegCs` RPL check.** The driver must verify `_KTRAP_FRAME.SegCs & 0x3 == 0x3` (`UserMode`) before treating the saved `Rip` as a user-mode return address. Kernel-mode calls into the syscall path (from drivers, e.g., a driver calling `ZwClose`) have `SegCs` RPL `0x0` and a different trap frame layout. Mis-reading a kernel-mode trap frame as user-mode is a classic blue-screen bug because the saved `Rip` then points at kernel memory which is later dereferenced as a user address under `ProbeForRead`, faulting.

**Alignment.** On x64, valid user-mode `Rip` values from ntdll are 16-byte aligned (the `syscall; ret` gadget sits at an aligned stub offset). Implant direct-syscall stubs may be unaligned. This is a weak signal — many legitimate ntdll stubs aren't aligned either (the `mov r10, rcx` prologue starts at the function entry, and `syscall` lands at `entry + 0x12`) — but is occasionally used as a secondary heuristic.

## Why It Matters

This is the single defensive mechanism that defines the modern direct-vs-indirect-syscall distinction. Without it, direct syscalls would be strictly superior to indirect syscalls (simpler, smaller, equally effective against userland hooks, no reliance on a particular ntdll layout). With it, an EDR that deploys Variant 1 or 2 renders direct syscalls unsafe for any monitored syscall — every direct `NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE)`, every direct `NtCreateThreadEx`, every direct `NtMapViewOfSection(SEC_IMAGE)` is flagged. The card exists so operators understand *why* their direct-syscall implants get caught by advanced EDRs even when their userland-hook bypass works.

The mechanism composes with T-001 (direct syscalls — the thing being caught), T-002 (indirect syscalls — the bypass), and T-016 (likely ETW-TI bypass / patching — the meta-bypass). The composition order for an operator evaluating an environment is: probe for ETW-TI consumer registration (T-016) → if present, assume Variant 2 coverage of the high-risk syscall subset → fall back to indirect syscalls (T-002) for the monitored set → for unmonitored syscalls (discovery, query class), direct syscalls (T-001) remain safe. The defender's incomplete coverage — only the high-risk subset is instrumented — is the attacker's leverage point.

## Composition with Other Techniques

A concrete kill chain when this defense is in place:

1. **Reconnaissance.** The operator probes for the defense by issuing a benign direct syscall to a low-signal syscall (`NtQuerySystemInformation(SystemPerformanceInformation = 2)`) and a benign direct syscall to a high-signal syscall (`NtAllocateVirtualMemory` with `PAGE_READWRITE`). If the second flags and the first does not, Variant 2 (ETW-TI) is in place. If both flag, Variant 1 (Ob-callback) is broadly registered. If neither flags, the defense is not deployed and direct syscalls (T-001) suffice for everything.
2. **Bypass decision.** If Variant 2 is confirmed in place, apply T-016 to disable the ETW-TI provider (patch `EtwTiLog*` references in `nt!EtwTraceKernelEvent`) — this knocks out Variant 2 globally, leaving Variant 1 only.
3. **Syscall strategy.** For Variant 1's covered surface (handle operations, registry writes, file creation, process create/exit), use indirect syscalls (T-002): locate `ntdll!NtAllocateVirtualMemory + 0x12` (or the equivalent offset for each target stub), build an implant stub that loads the SSN into EAX and `JMP`s into the ntdll `syscall; ret` gadget. For syscalls outside Variant 1's covered surface (`NtQueryInformationProcess`, `NtQueryVirtualMemory`, `NtQuerySystemInformation`, `NtReadVirtualMemory` against the operator's own process), direct syscalls (T-001) remain safe — the cost-benefit favors the simpler primitive.
4. **Coverage for multi-frame checks.** If reconnaissance reveals multi-frame verification (test by chaining through an unknown image), route the indirect-syscall call through `kernelbase!VirtualAllocEx` rather than invoking `NtAllocateVirtualMemory` directly. The userland hook exposure on `kernelbase!VirtualAllocEx` is acceptable because `kernelbase`'s export simply wraps the syscall with parameter marshaling — there is no EDR hook to bypass because the EDR has already moved its detection into kernel mode.

## Common Mistakes

1. **Defender mistake: skipping the `SegCs` RPL check.** A driver that reads `_KTRAP_FRAME.Rip` without verifying `SegCs & 0x3 == 0x3` will misread kernel-mode trap frames as user-mode, dereferencing kernel pointers as user addresses and faulting under `ProbeForRead`. This is a classic blue-screen bug.
2. **Defender mistake: missing the WOW64 64-bit ntdll.** A driver that records only the 32-bit ntdll in `SysWOW64` will fail every check on a 32-bit process because the actual `syscall` transition happens in the 64-bit ntdll. Both ranges must be recorded per-process.
3. **Defender mistake: not capping the `RtlVirtualUnwind` walk.** A malformed `.pdata` (e.g., a manually-mapped implant with corrupted unwind codes) can send `RtlVirtualUnwind` into an infinite loop or out-of-bounds reads. The walk must be capped at N frames (typically 8–16) and wrapped in `__try / __except`.
4. **Attacker mistake: trusting the ntdll `syscall; ret` gadget offset.** The gadget is at `ntdll!NtXxx + 0x12` only for Windows 10 1903+. Earlier builds (and some Server variants) place the `syscall` instruction at different offsets because the prologue omits the `test byte ptr [KUSER_SHARED_DATA+0x308], 1` branch. The operator must dynamically disassemble the stub to locate the `0F 05` byte rather than hardcoding `+0x12`.
5. **Attacker mistake: leaving the caller frame in implant memory.** An indirect syscall that places the `syscall` in ntdll but leaves frame[1] in implant memory defeats only the frame[0] check. Multi-frame EDRs flag the call. The operator must either accept this risk (most EDRs do not deploy multi-frame in strict form) or chain through `kernelbase`/`kernel32` for hygiene.
6. **Attacker mistake: using a non-ntdll gadget for the `syscall` instruction.** Some operators, fearing that ntdll might be patched by the EDR, locate the `syscall; ret` gadget in another signed module (`kernelbase`, `win32u.dll`, a kernel-mode component reachable via `int 2Eh`...). The check is specifically `Rip in ntdll range` — a `kernelbase` gadget will be flagged. The gadget must be in ntdll to pass the check as specified.

## Detection Considerations

- **Telemetry sources (attacker detecting the defense)**: An attacker cannot enumerate `PsSetLoadImageNotifyRoutine` registrations from user mode — the kernel arrays `nt!PspLoadImageNotifyRoutine` and `PspCreateProcessNotifyRoutine` are not user-readable. The presence is inferred behaviorally: the operator loads a small test DLL via `LoadLibraryW`, then issues a benign `NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE)` and observes (via network proxy or EDR console reachability) whether the EDR's user-mode service logs a stack-walk-derived alert correlated to the test. ETW-TI consumer registration can be enumerated from kernel mode by walking `nt!EtwConsumerInfo` or by checking the provider's `RegEntry` against `Microsoft-Windows-Threat-Intelligence` (the provider's GUID is stable across builds). Ob-callback registration is enumerable from kernel mode via `nt!ObjectType.TypeList` walking for `PsProcessType` and `PsThreadType`. From user mode, no enumeration is possible — the operator must infer from behavioral telemetry.
- **Bypass options**: (a) Indirect syscalls (T-002) place the `syscall` instruction inside ntdll's range, satisfying the frame[0] check trivially. (b) Multi-frame checks are bypassed by routing the call through a legitimate intermediate (`kernelbase!VirtualAllocEx` rather than `NtAllocateVirtualMemory` directly), accepting userland-hook exposure as the cost of stack hygiene — but since the EDR has moved detection to kernel mode, the userland hooks are typically absent and this is strictly a win. (c) Direct syscalls to non-ETW-TI-monitored syscalls bypass Variant 2 entirely; combined with step (a) for the monitored set, this is the standard evasion pattern. (d) T-016 (ETW-TI patching) defeats Variant 2 globally by patching `nt!EtwTiLogProvider` references or unregistering the consumer — leaves Variant 1 only.
- **Residual artifacts**: Variant 1 leaves no user-mode artifact (the callback runs in kernel context); the only evidence is the EDR driver's registered callbacks in `nt!PspCreateProcessNotifyRoutine` / `nt!PspLoadImageNotifyRoutine` arrays (kernel debugger visible). Variant 2 leaves the consumer driver registered in the ETW `LoggerContext` for the threat-intelligence provider; querying `EtwConsumer` from a kernel debugger reveals the driver. Variant 3 (the user-mode hook variant) leaves inline hooks — detectable by hashing the ntdll `.text` section and comparing against a clean baseline (the vault's T-095 NTDLL Unhook card documents the equivalent baseline-check from the attacker side). The defense's per-process ntdll range cache leaves no on-disk artifact; it is purely in-memory state held by the EDR driver.

## Related Techniques

- **T-001 Direct Syscalls** — the offensive technique that this defense is designed to catch; reading T-001 alongside this card makes the defense/bypass duality explicit.
- **T-002 Indirect Syscalls** — the bypass for Variants 1 and 2; routing the `syscall` instruction through a genuine ntdll `syscall; ret` gadget places the saved `Rip` inside ntdll's range and the frame[0] check passes.
- **T-016 ETW-TI Bypass / Patching** — defeats Variant 2 by disabling the ETW-TI provider (patching `EtwTiLog*` references) or unregistering the consumer driver; composes with T-002 to fully unmonitor the syscall surface.