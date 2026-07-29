---
id: T-122
name: Heaven's Gate 32→64-bit WOW64 Syscall Bridge
category: syscalls
tier: A
crate: none
source_file: none
mitre: T1106
mitre_secondary: [T1562.001]
tags: [syscalls, wow64, segment-selector, far-ret, edr-bypass, 32-to-64, ntdll-hooks, ring-3, wow64cpu]
origin: atlas-synthesis
member_notes: ['lgtm:vault-gap-heavens-gate']
---

# Heaven's Gate 32→64-bit WOW64 Syscall Bridge — Crossing the Bitness Boundary to Bypass 32-bit User-Mode Hooks

## Summary

Heaven's Gate is a syscall evasion technique that exploits the x86-64 architecture's ability to execute both 32-bit (compatibility mode) and 64-bit (long mode) code within a single WOW64 process. A 32-bit process running under WOW64 has CS=0x23 (32-bit user-mode code segment). By performing a FAR control transfer — typically a FAR RET (opcode 0xCB) with a crafted stack frame containing the segment selector 0x33 (64-bit user-mode code segment) — the process switches the CPU into 64-bit long mode and can execute native `syscall` instructions that bypass all 32-bit ntdll.dll hooks installed by EDR products. The transition leverages the same CPU mechanism that `ntdll.dll!Wow64Transition` uses to thunk 32-bit syscall stubs into the 64-bit `ntdll.dll` via `wow64cpu.dll!TurboDispatch`, but repurposed for direct syscall execution. The technique requires no additional privileges — it operates entirely at ring 3 — and works on any 64-bit Windows system running a 32-bit process. EDR vendors that hook only the 32-bit `ntdll.dll` export table or function prologues are blind to syscalls issued through the 0x33 segment. The technique was first publicly described circa 2008-2009 and was later operationalized in tools like SysWhispers3 (WoW64 stub variant) and combined with Hells Gate-style SSN extraction (T-001). The vault's T-001 card documents direct syscall execution from native 64-bit processes and T-002 covers NTDLL unhooking, but neither covers the cross-bitness WOW64 transition that is this card's unique contribution.

## Mechanism

### Variant 1: Classic Heaven's Gate via Wow64Transition

1. Compile or load a 32-bit payload into a WOW64 process. The process CS register is 0x23 (32-bit compatibility mode).
2. Allocate a `PAGE_EXECUTE_READWRITE` (0x40) memory region using `VirtualAlloc` or `NtAllocateVirtualMemory` — this region will hold the 64-bit syscall stub. The allocation can be anywhere in the low 4GB of the process address space; the stub will be reached via a 64-bit RIP zero-extended from a 32-bit EIP.
3. Write a 64-bit syscall stub into the allocated region. The canonical stub mirrors the 64-bit `ntdll.dll` syscall prologue:
   ```asm
   ; 64-bit code (CS=0x33)
   mov r10, rcx          ; 4C 89 CA         — move RCX (1st arg) into R10 per syscall ABI
   mov eax, <SSN>        ; B8 XX XX 00 00   — load syscall service number into EAX
   syscall               ; 0F 05            — transition to kernel via KiSystemCall64
   ret                   ; C3               — return to caller (still in 64-bit mode)
   ```
   The SSN value must be extracted from the 64-bit `ntdll.dll` (not the 32-bit one) — the 64-bit SSNs index into `KiServiceTable`, which is a different table from the 32-bit WOW64 dispatch path.
4. Construct the FAR RET stack frame on the 32-bit stack:
   ```
   [ESP+0]: <low 32 bits of 64-bit stub address>  ; target EIP/RIP
   [ESP+4]: 0x00000033                            ; target CS (64-bit code segment)
   ```
5. Execute `RETF` (opcode 0xCB, FAR RET). The CPU pops 4 bytes into EIP and the low 16 bits of the next 4 bytes into CS. Because CS=0x33 selects a long-mode code segment descriptor (L=1, D=0 in the GDT), the processor immediately switches to 64-bit execution. RIP is zero-extended from the 32-bit EIP.
6. The 64-bit syscall stub executes. `syscall` transfers control to `KiSystemCall64` (the kernel syscall entry point pointed to by IA32_LSTAR MSR at address 0xC0000082). The kernel executes in full 64-bit context. Arguments passed via RCX/RDX/R8/R9 (Windows x64 calling convention) or via the 32-bit stack must be re-marshaled — see Common Mistakes.
7. After `ret`, execution returns to the instruction after the `RETF` in 32-bit mode. CS has been restored to 0x23 by the return path.

### Variant 2: Manual Segment Switch (No Wow64Transition Dependency)

1. Skip the `ntdll!Wow64Transition` thunk entirely. Instead, directly craft a 32-bit FAR RET to jump into 64-bit code.
2. Allocate RWX memory for the 64-bit stub and a 32-bit→64-bit trampoline. The trampoline is 32-bit code that sets up the stack frame and issues `RETF`:
   ```asm
   ; 32-bit trampoline (CS=0x23)
   push 0x33                         ; 6A 33           — push 64-bit CS selector
   push <stub_addr_lo>               ; 68 XX XX XX XX  — push low 32 bits of 64-bit stub address
   retf                              ; CB              — FAR RET into 64-bit mode
   ```
3. The 64-bit stub performs the syscall as in Variant 1, step 3.
4. To return to 32-bit code, the 64-bit stub must perform a reverse FAR RET back to CS=0x23:
   ```asm
   ; 64-bit code (CS=0x33), returning to 32-bit
   ; Stack frame for 64-bit FAR RET (operand size 64):
   ;   [RSP+0]: <32-bit return address, zero-extended to 64 bits>
   ;   [RSP+8]: 0x0000000000000023
   push 0x23                         ; 6A 23           — push 32-bit CS selector (zero-extended to 64 bits on stack)
   ; Push the 32-bit return address as a 64-bit value
   mov rax, <return_addr_32>
   push rax                          ; 50              — push 64-bit RIP (zero-extended 32-bit address)
   retf                              ; 48 CB           — FAR RET (REX.W prefix for 64-bit operand size)
   ```
   `RETF` in 64-bit mode with REX.W prefix (opcode `48 CB`) pops 8 bytes for RIP and 2 bytes for CS (with 6 bytes padding), consuming 16 bytes from the stack. Without the REX.W prefix, `CB` in 64-bit mode defaults to 32-bit operand size, popping only 4+4=8 bytes — a common source of stack corruption (see Common Mistakes #4).

### Variant 3: Heaven's Gate + Hells Gate Hybrid

1. Locate the 64-bit `ntdll.dll` in the WOW64 process's address space. On 64-bit Windows, the 64-bit ntdll is already mapped — it is the process's real ntdll, with the 32-bit ntdll acting as a thunking layer. From 32-bit code, access the 64-bit PEB via `gs:[0x60]` (the `gs` segment register in a WOW64 process points to the 64-bit TEB). Walk `PEB64.Ldr->InLoadOrderModuleList` (offset 0x18 in the 64-bit PEB, 0x10 in the 64-bit LDR_DATA_TABLE_ENTRY for the `InLoadOrderLinks` field) to find `ntdll.dll` by name. Read `DllBase` from the matching `LDR_DATA_TABLE_ENTRY`.
2. Parse the 64-bit ntdll's export table to find the `Nt*`/`Zw*` function. Walk `IMAGE_DOS_HEADER.e_lfanew` (offset 0x3C) → `IMAGE_NT_HEADERS64` (signature `0x00004550` at the offset) → `OptionalHeader.DataDirectory[0]` (Export Directory RVA) → `IMAGE_EXPORT_DIRECTORY.AddressOfNames` to find the function by name via binary search over the names array.
3. Read the first bytes of the function body. In 64-bit ntdll, the syscall stub begins:
   ```
   4C 8B D1            mov r10, rcx           ; offset +0
   B8 XX XX 00 00      mov eax, <SSN>         ; offset +3, SSN immediate at offset +4
   ```
   The SSN is the 32-bit immediate operand of the `mov eax, imm32` instruction at function offset +4. On Windows 10/11 builds, additional bytes may follow:
   ```
   F6 04 25 08 03 FE 7F 01   test byte ptr [0x7FFE0308], 1   ; check KUSER_SHARED_DATA flag
   75 03                     jne +3
   0F 05                     syscall
   C3                        ret
   ```
   The `test` against `KUSER_SHARED_DATA` at linear address 0x7FFE0308 determines whether the `syscall` or `int 2Eh` path is taken. The SSN remains at offset +4 regardless.
4. Use the extracted SSN to build a 64-bit syscall stub (as in Variant 1, step 3).
5. Switch to 64-bit mode via the manual FAR RET (Variant 2) and execute the syscall. The SSN was extracted by reading bytes from the 64-bit ntdll's code section — no function was called, so any inline hooks on the 64-bit ntdll stubs are irrelevant.

## OS Internals Context

### Segment Descriptors and the GDT

On x86-64 Windows, the Global Descriptor Table (GDT) contains segment descriptors for both 32-bit compatibility mode and 64-bit long mode. The critical user-mode segment selectors are:

- **0x23** — 32-bit user-mode code segment. The GDT entry at index `(0x23 >> 3) = 4` describes a code segment with L=0 (not long mode), D=1 (default operand size 32-bit), DPL=3 (ring 3). When CS=0x23, the processor operates in compatibility mode, executing 32-bit instructions with the upper 32 bits of RAX/RIP/RSP ignored (zero-extended on writes, zero-valued on reads).
- **0x33** — 64-bit user-mode code segment. The GDT entry at index `(0x33 >> 3) = 6` describes a code segment with L=1 (long mode), D=0 (ignored in long mode; default operand size is 32-bit unless REX.W prefix extends it to 64-bit), DPL=3. When CS=0x33, the processor operates in 64-bit long mode, executing 64-bit instructions with access to the full 64-bit register file (RAX, R8-R15, RFLAGS with the full 64-bit RFLAGS), and RIP addressing the full canonical address space.

The selector encoding is: bits 0-1 = RPL (Requested Privilege Level), bit 2 = TI (Table Indicator, 0=GDT, 1=LDT), bits 3-15 = index. So 0x23 = index 4, RPL=3, GDT; 0x33 = index 6, RPL=3, GDT. Both selectors request ring 3 — the transition between them changes execution mode (compatibility ↔ long) but does not change privilege level. No `sysenter`/`sysexit`, no kernel transition, no privilege escalation occurs. The processor validates that the target DPL matches the RPL, but since both segments are DPL=3 and the RPL is 3 in both cases, the check passes unconditionally.

Switching CS from 0x23 to 0x33 (or vice versa) via a FAR control transfer (FAR CALL, FAR JMP, FAR RET, or IRET) causes the processor to switch between compatibility mode and long mode within the same process and the same privilege level. This is the architectural foundation of Heaven's Gate and the same mechanism the WOW64 thunking layer uses internally.

### WOW64 Thunking Architecture

The WOW64 subsystem exists because 32-bit applications cannot directly use the 64-bit `syscall` instruction to enter the kernel — the 32-bit ntdll.dll does not contain `syscall` stubs. Instead, the thunking chain operates as follows:

1. A 32-bit application calls `ntdll32.dll!NtCreateFile` (or any `Nt*`/`Zw*` function).
2. The 32-bit stub marshals arguments into the WOW64 information fields of the 32-bit TEB (accessible via `fs` segment in 32-bit mode). The TEB32 contains WOW64-specific fields that `TurboDispatch` reads to determine the target syscall number and argument layout.
3. The stub calls `ntdll32.dll!Wow64Transition`, which is a FAR CALL to CS=0x33. This enters `wow64cpu.dll!TurboDispatch` in 64-bit mode.
4. `TurboDispatch` reads the syscall number from the WOW64 TIB fields, translates 32-bit argument pointers (which reside in the low 4GB) to 64-bit equivalents by zero-extension, and calls the real 64-bit `ntdll.dll!Nt*` function.
5. The 64-bit ntdll issues the actual `syscall` instruction, which enters the kernel via `KiSystemCall64` (the entry point stored in the IA32_LSTAR MSR at 0xC0000082).
6. The return path unwinds back through `TurboDispatch` to 32-bit mode, with output parameters translated back to 32-bit widths.

Heaven's Gate short-circuits steps 2-5. Instead of letting `TurboDispatch` issue the 64-bit syscall through the 64-bit ntdll (which may itself be hooked), the attacker's code directly executes the `syscall` instruction in 64-bit mode, using an SSN extracted from the 64-bit ntdll's export stubs. This bypasses both the 32-bit ntdll hooks (the 32-bit stub is never called) and the 64-bit ntdll hooks (the 64-bit ntdll function is never called — only its bytes were read to extract the SSN).

### KUSER_SHARED_DATA and the Syscall Path

`KUSER_SHARED_DATA` is a read-only page shared between user mode and kernel mode at fixed virtual address `0x7FFE0000`. It contains system information that the kernel populates at boot and updates periodically. Relevant fields include `SystemCall` (at offset 0x300, containing the address of `KiSystemCall64` on AMD64 systems) and `SystemCallPad` fields used for syscall entry state.

The `syscall` instruction (opcode `0F 05`) uses two MSRs: IA32_LSTAR (MSR address `0xC0000082`, contains the target RIP for `KiSystemCall64`) and IA32_FMASK (MSR `0xC0000084`, contains the RFLAGS mask applied during the syscall transition). The `syscall` instruction saves the user-mode RIP to RCX and the user-mode RFLAGS to R11, then loads RIP from IA32_LSTAR and applies the RFLAGS mask. The kernel reads the SSN from EAX and uses it as an index into `KiServiceTable` (the System Service Descriptor Table, or SSDT), with `KiServiceLimit` bounding the valid range.

In 64-bit long mode (CS=0x33), the `syscall` instruction is available and functions identically to a native 64-bit process calling it. The kernel has no awareness that the caller is a WOW64 process — the syscall is processed as if it came from a native 64-bit process. The `KTRAP_FRAME` pushed on the kernel stack records the user-mode CS as 0x33, which the kernel treats as a normal 64-bit user-mode call. The kernel does not check whether the calling process image is 32-bit or 64-bit — it only inspects the CS value in the trap frame, which is 0x33, a valid 64-bit user-mode segment.

### PEB and Ldr Structures in WOW64

A WOW64 process maintains two parallel PEB/TEB structures:

- **32-bit PEB** (referenced via `fs:[0x30]` in 32-bit mode) and **32-bit TEB** (referenced via `fs:[0x18]`). The 32-bit `Ldr` (at PEB32 offset 0x64) points to the 32-bit loader data, where `ntdll32.dll` is the first entry in `InLoadOrderModuleList`. This is the ntdll that EDR hooks target for 32-bit processes.
- **64-bit PEB** (referenced via `gs:[0x60]` in 64-bit mode, but also accessible from 32-bit code using `gs` segment override with appropriate instruction encoding) and **64-bit TEB** (referenced via `gs:[0x30]` or `gs:[0x18]` self-pointer). The 64-bit `Ldr` (at PEB64 offset 0x18) points to the 64-bit loader data, where the real `ntdll.dll` is the first entry in `InLoadOrderModuleList`. This is the ntdll whose syscall stubs contain the real 64-bit SSNs.

The `gs` segment register in a WOW64 process points to the 64-bit TEB, even when the processor is in 32-bit compatibility mode. This is because the `gs` base is set by the kernel to the 64-bit TEB address via the GSPR MSR on thread creation, and the WOW64 layer does not change it when switching between 32-bit and 64-bit modes. This means a 32-bit instruction like `mov eax, gs:[0x60]` reads the 64-bit PEB pointer from the 64-bit TEB, giving 32-bit code direct access to the 64-bit loader structures.

## Key Implementation Details

**Argument marshaling is the hardest part.** The 32-bit Windows calling convention (cdecl/stdcall) passes arguments on the stack in reverse order. The 64-bit Windows calling convention (Microsoft x64 ABI) passes the first four integer/pointer arguments in RCX, RDX, R8, R9, with remaining arguments on the stack at 16-byte aligned offsets. When transitioning from 32-bit to 64-bit mode, the 32-bit stack layout does not match the 64-bit calling convention. The 64-bit stub must manually load arguments into the correct registers before issuing `syscall`. For example, `NtAllocateVirtualMemory` takes 6 arguments: `ProcessHandle` (HANDLE), `BaseAddress**` (PVOID*), `ZeroBits` (ULONG_PTR), `RegionSize*` (PSIZE_T), `AllocationType` (ULONG), `Protection` (ULONG). The stub must move the first four into RCX/RDX/R8/R9 and place the remaining two on the stack at `[RSP+0x28]` and `[RSP+0x30]` (accounting for the 32 bytes of shadow space required by the x64 ABI). Output pointers (`BaseAddress**`, `RegionSize*`) must point to 64-bit-sized buffers — a 32-bit `PVOID*` is 4 bytes, but the kernel writes an 8-byte pointer, corrupting adjacent stack data if the buffer is only 4 bytes wide.

**Stack pointer width changes.** When transitioning to 64-bit mode, RSP is the zero-extension of ESP from the 32-bit context. But 64-bit `push`/`pop` operations move 8 bytes, while 32-bit operations move 4 bytes. If the 64-bit stub uses `push`/`pop`, it must account for the stack pointer having been set up by 32-bit code (which used 4-byte pushes and 4-byte alignment). The stub should explicitly align RSP to a 16-byte boundary (required by the x64 ABI and by the kernel's `KTRAP_FRAME` expectations) using `and rsp, -16` or `sub rsp, X` before `syscall`. Misaligned stacks cause `#GP` (General Protection Fault) or silent corruption of the kernel trap frame.

**SSN extraction from 64-bit ntdll.** The 64-bit ntdll.dll's syscall stubs follow a consistent pattern across Windows 10 and 11 builds. The first three bytes are always `4C 8B D1` (`mov r10, rcx`), followed by `B8 XX XX 00 00` (`mov eax, <SSN>`), where the 32-bit immediate at offset +4 is the service number. SSNs are typically in the range 0x0000-0x0FFF (system call numbers below 4096). The stub may be followed by the `test byte ptr [0x7FFE0308], 1` check and branch, but the SSN offset does not change. When extracting SSNs, parse the export directory of the 64-bit ntdll (not the 32-bit one), resolve the function by name, read the `mov eax` immediate at function_base+4, and store it for use in the 64-bit syscall stub. Note that on newer builds, SSNs are ordered by function address (not alphabetically), so they may appear shuffled — this does not affect the extraction technique, only the expected numeric sequence.

**WOW64 thread context duality.** Each WOW64 thread maintains two contexts: a 32-bit `CONTEXT` (accessible via `GetThreadContext` with `CONTEXT_WOW64` flag, or `WOW64_CONTEXT` structure) and a 64-bit `CONTEXT` (accessible via `NtGetContextThread` with the full `CONTEXT` structure). When the thread executes 64-bit code via Heaven's Gate, the 64-bit `CONTEXT.SegCs` is 0x33 and the 64-bit `Rip` points to the 64-bit stub. But if an EDR or debugger queries the 32-bit context (`WOW64_CONTEXT`), it sees the last 32-bit instruction pointer — the code after the FAR RET — and `SegCs = 0x23`. This context duality can be exploited for detection evasion (the 32-bit context looks normal) but also for detection (the mismatch between 32-bit and 64-bit instruction pointers during execution is anomalous).

## Why It Matters

Heaven's Gate matters because it demonstrates that WOW64 processes are not confined to the 32-bit syscall path. EDR vendors who deploy hooks only on the 32-bit `ntdll.dll` — a common deployment choice because WOW64 processes were historically considered lower-risk and because 32-bit hook stubs are simpler to inject — are completely blind to syscalls issued through the 0x33 segment. The technique enables a 32-bit payload (which may have been chosen for file-size efficiency, compatibility with older shellcode generators, or evasion of 64-bit static-analysis pipelines) to access the full native syscall surface with no kernel involvement and no privilege requirements.

The technique composes powerfully with Hells Gate-style SSN extraction (T-001): extract SSNs from the 64-bit ntdll's export stubs, build 64-bit syscall stubs, and issue all syscalls through Heaven's Gate. The result is a 32-bit payload that is invisible to 32-bit ntdll hooks and can optionally bypass 64-bit ntdll hooks by not calling the hooked 64-bit functions at all — only reading their bytes. Combined with NTDLL unhooking (T-002), this forms a layered syscall evasion strategy where each layer covers the gaps of the others.

On modern Windows 10/11, the technique has been partially superseded by SysWhispers3's WoW64 stub generation, which embeds 64-bit syscall stubs directly in compiled .NET or C/C++ payloads. However, the manual Heaven's Gate transition remains relevant for position-independent shellcode, beacon object files (BOFs), and scenarios where compiling with SysWhispers3 is not feasible (e.g., hand-crafted shellcode in exploit payloads).

## Detection Considerations

- **Telemetry sources**: ETW-TI (Microsoft-Windows-Threat-Intelligence, provider GUID `{F4E1897C-B5BF-40C2-A0A6-30A6F0F4D027}`) hooks at the kernel syscall layer and observes all syscalls regardless of caller bitness. The kernel `KTRAP_FRAME` records `SegCs = 0x33`, which is normal for native 64-bit processes but anomalous for a process whose image is 32-bit (PE32 `OptionalHeader.Magic = 0x10B`). Cross-referencing the process image type (via `NtQueryInformationProcess(ProcessWow64Information)`, which returns non-zero for WOW64) with the `KTRAP_FRAME.SegCs` value reveals a 32-bit process issuing syscalls from 64-bit mode — a strong heuristic. The `Microsoft-Windows-Wow64` ETW provider logs WOW64 transitions and can flag non-standard crossings that do not originate from `Wow64Transition`/`TurboDispatch`. Memory scanning for 64-bit code patterns (`4C 89 CA B8` followed by `0F 05`) within a 32-bit PE image's address space is a reliable static indicator. Thread context inspection via `NtGetContextThread` showing `SegCs = 0x33` in a WOW64 process during execution is anomalous outside of legitimate WOW64 thunking.

- **Bypass options**: Avoid `Wow64Transition` entirely (use manual FAR RET, Variant 2) to evade hooks on `wow64cpu.dll!TurboDispatch`. Pre-extract SSNs at payload generation time to avoid runtime ntdll parsing (eliminates read-access patterns on ntdll export pages). Use indirect syscalls — jump to a `syscall` instruction located inside a legitimate 64-bit module like `ntdll.dll` or `win32u.dll` — so the return address on the kernel stack points to a known-good module, defeating return-address-based detection. Spawn a native 64-bit thread inside the WOW64 process via `NtCreateThreadEx` with the start address pointing to 64-bit code and the initial thread context set to `SegCs = 0x33` — the thread starts in 64-bit mode natively and never performs a manual FAR RET. Encrypt the 64-bit stub in memory and decrypt it only during the brief execution window to reduce memory-scanning exposure.

- **Residual artifacts**: The RWX memory region containing the 64-bit syscall stub persists as long as the process is alive. The region's first bytes — `4C 89 CA B8 XX 00 00 00 0F 05 C3` — are a distinctive byte signature. If the SSN was extracted at runtime, the 64-bit ntdll export table was traversed, leaving a read-access pattern on the export directory and code-section pages of `ntdll.dll` that page-fault-based detection can observe. Thread context dumps during the 64-bit execution window show `SegCs = 0x33` with `Rip` pointing outside `ntdll.dll` and `wow64cpu.dll`. If `Wow64Transition` was used (Variant 1), the 64-bit call stack shows a frame originating from an address outside the normal WOW64 thunk path, which stack-trace-based EDRs can flag.

## Variant Comparison Table

| Variant | Transition Method | SSN Source | Avoids 32-bit Hooks | Avoids 64-bit Hooks | Complexity |
|---------|-------------------|------------|---------------------|---------------------|------------|
| 1: Classic Wow64Transition | `ntdll!Wow64Transition` FAR call | 64-bit ntdll exports | Yes | No (calls hooked 64-bit ntdll) | Low |
| 2: Manual FAR RET | Crafted stack frame + `RETF` (0xCB) | 64-bit ntdll exports | Yes | Yes (direct `syscall`) | Medium |
| 3: Hells Gate Hybrid | Manual FAR RET + runtime SSN extraction | Parsed from `ntdll.dll` stub bytes | Yes | Yes (direct `syscall`) | High |

## Historical Context

The technique was first publicly described by the researcher "george42" circa 2009, with proof-of-concept code demonstrating the FAR RET transition from 32-bit to 64-bit mode in a WOW64 process. The name "Heaven's Gate" evokes the idea of ascending from the 32-bit "lower" world to the 64-bit "higher" plane. The technique gained operational prominence in the mid-2010s as EDR products increasingly relied on user-mode ntdll hooks for syscall interception, creating a detection gap that 32-bit payloads could exploit.

Microsoft has never "fixed" Heaven's Gate because it is not a bug — it is the intended CPU architecture behavior that the WOW64 subsystem itself depends on. The `Wow64Transition` FAR call uses the exact same segment selector switch (0x23 ↔ 0x33) that Heaven's Gate repurposes. Patching the ability to switch CS between 0x23 and 0x33 from user mode would break the WOW64 thunking layer entirely, rendering all 32-bit applications inoperable on 64-bit Windows.

In 2020, the SysWhispers3 project by @klezVirus incorporated WoW64-aware syscall stub generation, making the technique accessible to compiled .NET assemblies and C# tooling. The Hells Gate technique (2020, @smashz) formalized runtime SSN extraction from ntdll export stubs, which composes naturally with Heaven's Gate for a complete "extract-then-cross" workflow. Modern EDR vendors have responded by hooking `wow64cpu.dll!TurboDispatch`, deploying kernel-level callbacks (`PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks`) that are bitness-agnostic, and using ETW-TI for kernel-level syscall visibility.

## Common Mistakes

1. **Forgetting to zero-extend pointers.** A 32-bit pointer passed to a 64-bit syscall is only 4 bytes wide. The 64-bit stub must zero-extend it to 8 bytes before loading it into RCX/RDX/R8/R9. A 32-bit `mov` instruction (`89` or `8B` without REX.W prefix) writes only the low 32 bits of the destination register and zero-extends the result — but if the register previously held a 64-bit value with non-zero high bits (e.g., from a previous `mov` to a different 64-bit register), the zero-extension handles this correctly. The real danger is output pointers: a `PVOID*` that receives a kernel-written 64-bit pointer must point to an 8-byte buffer. If the 32-bit caller allocated only 4 bytes for the output, the kernel writes 8 bytes and corrupts adjacent stack or heap data.

2. **Stack alignment violations.** The x64 ABI requires RSP to be 16-byte aligned before `syscall` (the kernel expects a specific alignment for the `KTRAP_FRAME` pushed onto the kernel stack). A 32-bit FAR RET leaves RSP at whatever alignment the 32-bit stack had — typically 4-byte or 8-byte aligned, but not necessarily 16-byte. The 64-bit stub must insert `and rsp, -16` or `sub rsp, N` (where N aligns RSP to a 16-byte boundary) before `syscall`. Without this, the kernel raises `#GP` or the `KTRAP_FRAME` is misaligned, causing unpredictable crashes that are difficult to debug because they manifest inside the kernel, not in user-mode code.

3. **Using the wrong SSN source.** The 32-bit ntdll's syscall stubs contain SSNs for the 32-bit WOW64 dispatch path, which maps to the same `KiServiceTable` but may use different indices due to the WOW64 translation layer. The 64-bit ntdll's stubs contain SSNs that directly index `KiServiceTable` without translation. These are the correct values for a 64-bit `syscall` instruction. An operator who extracts the SSN from the 32-bit ntdll and uses it in a 64-bit `syscall` will either call the wrong kernel function (if the SSNs differ) or trigger an out-of-range check in `KiServiceLimit`, resulting in `STATUS_INVALID_SYSTEM_SERVICE` (0xC0000017).

4. **Returning to 32-bit mode incorrectly.** The 64-bit FAR RET (opcode `48 CB` with REX.W prefix) pops 8 bytes for RIP and then 8 bytes for CS (only low 16 bits used). If the REX.W prefix is omitted (plain `CB` in 64-bit mode), the FAR RET operates with 32-bit operand size: it pops 4 bytes for EIP and 4 bytes for CS, consuming only 8 bytes from the stack instead of 16. If the stack frame was prepared for 16-byte consumption (pushing an 8-byte RIP and an 8-byte CS), the misaligned FAR RET reads garbage for EIP and CS, crashing the process with `#GP`. The correct encoding is `48 CB` — the `48` REX.W prefix is mandatory for 64-bit operand size in long mode.

5. **Not handling WOW64 thread context correctly.** When a thread executes 64-bit code, its WOW64 context (the 32-bit `CONTEXT` saved by the WOW64 layer) is not automatically updated — it still reflects the last 32-bit instruction pointer. If the thread is suspended and inspected by a debugger or EDR during 64-bit execution, the 32-bit context shows stale data. This can cause confusion in debugging (breakpoints set on the 32-bit return address never hit during 64-bit execution) and may trigger heuristics in EDRs that compare the 32-bit and 64-bit thread contexts and find them inconsistent.

6. **Assuming all syscalls work cross-bitness identically.** Some syscalls have WOW64-specific behavior. `NtQueryInformationProcess` with `ProcessWow64Information` returns the 64-bit PEB address of the WOW64 process, but calling it from 64-bit mode vs 32-bit mode via the thunk path may yield different results for other info classes. `NtReadVirtualMemory` on a WOW64 process from 64-bit context reads raw 64-bit pointers from the target process's 64-bit PEB, while from 32-bit context the WOW64 layer may thunk pointer widths. Always verify syscall behavior in 64-bit mode from a WOW64 process — do not assume parity with native 64-bit process behavior.

## Detection Evasion Ladder

1. **Baseline**: Use `Wow64Transition` directly (Variant 1). Easily detected by hooks on `wow64cpu.dll!TurboDispatch` and by the `Microsoft-Windows-Wow64` ETW provider.
2. **Step 1**: Use manual FAR RET (Variant 2). Avoids `Wow64Transition` and `TurboDispatch` hooks entirely. Still detectable by memory scanning for 64-bit code patterns in a 32-bit process address space and by ETW-TI syscall observation with CS=0x33 cross-referenced against WOW64 process type.
3. **Step 2**: Use indirect syscalls — jump to a `syscall` instruction inside `ntdll.dll`'s 64-bit code section. The return address on the kernel stack points to `ntdll.dll`, blending with legitimate WOW64 thunk calls. Defeats return-address-based detection that flags `syscall` returns from unknown memory regions.
4. **Step 3**: Spawn a native 64-bit thread inside the WOW64 process via `NtCreateThreadEx` with the start address in 64-bit code and initial `CONTEXT.SegCs = 0x33`. The thread starts in 64-bit mode natively and never performs a manual FAR RET. The `SegCs` value is 0x33 from creation, appearing as a legitimate 64-bit thread to casual inspection.
5. **Step 4**: Combine with SSN extraction from a freshly mapped clean copy of ntdll (via `NtCreateSection` + `MapViewOfFile` with `SEC_IMAGE = 0x01000000`, bypassing any hooks on the in-memory ntdll) and ROP-based indirect syscall chains that never execute a contiguous `mov eax, SSN; syscall` pattern. The 64-bit stub is constructed from gadgets in legitimate modules, defeating static memory scanning for syscall stub byte signatures.

## Related Techniques

- **T-001 Direct Syscalls** — Heaven's Gate is the cross-bitness extension of T-001's native 64-bit direct syscall technique. T-001 covers the same `mov r10, rcx; mov eax, SSN; syscall` stub pattern from a native 64-bit process; this card extends it to WOW64 processes that must cross the 0x23→0x33 segment boundary first.
- **T-002 NTDLL Unhooking** — Composes with Heaven's Gate by providing a clean 64-bit ntdll for SSN extraction. After unhooking the 64-bit ntdll (T-002), extract SSNs from the now-clean stubs and issue syscalls via Heaven's Gate for layered evasion.
- **T-095 NTDLL Unhook Typology** — Documents the variants of ntdll unhooking that can supply clean SSNs for Heaven's Gate syscall stubs. The "fresh mapping" variant (mapping a clean copy via `NtCreateSection` + `MapViewOfFile` with `SEC_IMAGE`) provides an SSN source resilient to inline hooks.