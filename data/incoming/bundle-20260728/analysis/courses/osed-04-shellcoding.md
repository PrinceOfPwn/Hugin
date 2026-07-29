---
id: RTO-osed-04-shellcoding-dep-bypass
name: OSED 04 — Protocol Reverse Engineering, Stack Overflows & DEP Bypass via ROP
source: Red Team Ops / Offensive Security Exploit Development (OSED)
category: exploit-development
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-005, T-016, T-020, T-021, T-023]
tags: [exploit-development, rop, dep-bypass, win32, windbg, ida-pro, reverse-engineering, stack-overflow, seh-overwrite, virtualalloc, gadget-discovery, pykd, rp++, tivoli-fastback, protocol-re, x86]
---

# OSED 04 — Protocol Reverse Engineering, Stack Overflows & DEP Bypass via ROP — Training Reference

## TL;DR
This module walks through end-to-end binary exploit development against IBM Tivoli Storage Manager FastBack Server — from black-box protocol reverse engineering (using IDA Pro + WinDbg) through to a working DEP bypass with a hand-built ROP chain invoking `VirtualAlloc`. While the target (FastBack Server) and mitigations (DEP-only, no ASLR) are dated, the methodology — combined static/dynamic analysis, opcode tree walking, `sscanf` overflow hunting, IAT-based API resolution, and incremental ROP chain construction — remains the canonical foundation for modern exploit development. The vault's offensive tradecraft (T-005 Ekko ROP Sleep, T-016 EDR Evasion) presupposes the ROP and Win32 API mastery taught here.

## Key Concepts

1. **Combined Static + Dynamic Analysis Loop**
   - IDA Pro provides the structural map (basic blocks, call graph, jump tables); WinDbg provides ground truth (register state, memory contents, stack arguments at the moment of execution). Switching between them and keeping their positions synchronized is the core RE workflow. The `bc *` / `bp <addr>` / `g` / `p` / `pt` cycle is the loop primitive.
   - Vault parallel: T-020 Anti-Analysis Suite's diagnostic test harness uses the same marker-based dynamic verification pattern.

2. **Hardware Breakpoint on Input Buffer**
   - `ba r1 <addr>` (byte access read, size 1) is the canonical technique for finding the first instruction that touches attacker-controlled input. Used repeatedly to locate `memcpy` destinations, `sscanf` source buffers, and opcode comparisons.
   - This pattern is foundational to all the vault's syscall hook research (T-001 RecycledGate, T-003 VEH Gate both rely on similar memory access tracing for SSN discovery).

3. **Protocol Reverse Engineering via Call Stack Unwinding**
   - The methodology: trigger `memcpy` hit on input → `k` (call stack) → identify caller → `u <caller_offset> - 5 L1` to find the `call` instruction → re-run with `bp` set just before the call → dump `dd esp L3` to read arguments.
   - Each layer of the protocol is uncovered by returning up the call stack and re-deriving the caller's preconditions.

4. **Big-Endian / Little-Endian Conversion in Parsers**
   - Network protocols often ship DWORDs big-endian and convert in-line (manual byte shifting via `and 0xFF`, `shl 0x18`, etc.). The `struct.pack(">i", value)` Python idiom produces the correct wire format. Skipping this step is the #1 reason initial PoCs fail to advance past header validation.

5. **Opcode Dispatch via Jump Tables**
   - `mov al, byte ptr [table1 + ecx]` → `mul 4` → `jmp dword ptr [table2 + eax*4]` is the canonical switch/jump-table pattern. The first comparison is the upper bound (e.g., subtract `0x518`, compare to `0x3B`); the byte at `[0x575F6E + ecx]` indexes the case-pointer table at `0x575F06`. Recognizing this pattern in WinDbg (`u eip L10`) accelerates dispatch-tree walking.

6. **Stack Buffer Overflow Mechanics — Two Preconditions**
   - (a) Destination buffer must be at a stack address **lower** than the target return address (verify via `!teb` StackBase/StackLimit and `dds <saved_ebp> L2`).
   - (b) Copy size must exceed the distance `? <ret_addr_storage> - <dest_buffer>` (calculated via `?` evaluate command). Both checks are mandatory before pursuing an overflow primitive.

7. **SEH Chain Overwrite as an EIP-Control Strategy**
   - When direct return-address overwrite requires too large a copy (corrupting intervening pointers used before `ret`), an alternative is to overwrite the SEH chain (`!exchain`) and trigger an exception by writing past the end of the stack. The SEH handler is invoked with attacker-controlled EIP.
   - This is x86-only tradecraft; x64 uses `__C_specific_handler` and SEH table verification. Vault techniques (T-016 KiUserException StepOver) operate in the same exception-dispatch space but for evasion rather than exploitation.

8. **DEP (Data Execution Prevention) Theory**
   - Hardware NX bit; `/NoExecute` boot.ini (XP) or `bcdedit.exe` (Vista+) sets global policy: OptIn / OptOut / AlwaysOn / AlwaysOff. Per-process policy via `LdrpCheckNXCompatibility` → `NtSetInformationProcess` (ProcessExecuteFlags, 0x22). Permanent DEP (Vista SP1+/XP SP3+) for `/NXCOMPAT`-linked binaries cannot be re-disabled via `NtSetInformationProcess`.
   - `!vprot <addr>` shows page protection; `PAGE_EXECUTE_READ` (0x20) is executable, `PAGE_READWRITE` (0x4) is not.
   - The Narly WinDbg extension (`!nmod`) parses PE headers for SafeSEH/ASLR/DEP flags — useful for triage.

9. **Windows Defender Exploit Guard (WDEG)**
   - Successor to EMET (deprecated Windows 10 Fall Creators Update). Accessed via *Windows Defender Security Center → App & browser control → Exploit protection settings → Program settings*. Allows per-process enforcement of DEP (and other mitigations) on binaries not compiled with `/NXCOMPAT`.
   - WDEG is the modern vehicle for forcing mitigations on legacy targets during red team engagement hardening.

10. **Return Oriented Programming (ROP) — Core Theory**
    - Compose short instruction sequences ending in `RET` ("gadgets") to perform arbitrary computation without executing attacker data. On x86, the variable instruction length enables gadget harvesting inside other opcodes (e.g., `0x5D` at offset N is `POP EBP`; `0x04 0x5D` at offset N-1 is `ADD AL, 0x5D`).
    - Two strategic goals: (a) 100% ROP shellcode (rarely practical); (b) ROP stage that calls `VirtualAlloc`/`VirtualProtect`/`WriteProcessMemory` to enable subsequent traditional shellcode execution.

11. **Gadget Discovery Automation**
    - **Pykd** (WinDbg Python extension): enumerate module pages → filter to executable (`getVaProtect` ∈ {0x10, 0x20, 0x40, 0x80}) → scan for `0xC3`/`0xC2` opcodes → walk backward N bytes disassembling → filter privileged instructions (`clts`, `hlt`, `mov cr/dr/tr`, `cli`, `sti`, etc.) and flow-control instructions (`call`, `jmp`, conditional jumps). ~30k gadgets from FastBackServer.exe in 13s.
    - **RP++** (`rp-win-x86.exe -f <binary> -r 5`): file-system PE parser, faster than pykd, multi-arch, outputs `0xADDR: instr1 ; instr2 ; ... ; ret` format ideal for `findstr` searches.

12. **VirtualAlloc Skeleton + Runtime Patching via ROP**
    - The exploit places a *skeleton* on the stack via the buffer overflow: `[VirtualAlloc_addr][ret_to_shellcode][lpAddress][dwSize][flAllocationType][flProtect]`. Placeholders are dummy values (e.g., `0x45454545`) that are dynamically patched by the ROP chain at runtime to avoid NULL bytes and unknown runtime addresses.
    - `MEM_COMMIT = 0x1000`, `PAGE_EXECUTE_READWRITE = 0x40`. ROP must compute the runtime stack address (via ESP leak into EAX), resolve the API address (via IAT dereference), and write each patch using `MOV DWORD [ESI], EAX ; RET` gadgets.

13. **IAT-Based Runtime API Resolution**
    - Import Address Table entries are at fixed offsets within their host module (e.g., `VirtualAlloc` IAT entry at `0x5054A220` in CSFTPAV6.dll). The IAT entry contains the runtime-resolved address of the API (`MOV EAX, DWORD [EAX]` dereferences it). To avoid bad-char addresses, store `IAT+1` and subtract 1 via ROP.
    - This is the same principle used by the vault's PEB walker (T-004) and DJB2 hash-based API resolution, but operating via a host DLL's IAT rather than walking the loader's module list.

14. **Negative-Offset Arithmetic for NULL-Byte Avoidance**
    - When a small positive constant is needed (e.g., `0x1C`, `0x200`), encode it as a negative two's-complement value (`0xFFFFFFE4`, `0xFFFFFDF0`). Add via `ADD EAX, ECX ; RET`. The CPU represents `-0x1C` as `0xFFFFFFE4`, which has no NULL bytes.
    - This trick is universally needed in `sscanf`-based overflows because the source is a null-terminated string.

15. **Stack Distance Calculation for Offset Patching**
    - The dummy `VirtualAlloc` skeleton lives at a fixed negative offset from ESP at the moment of EIP control (e.g., `ESP - 0x1C`). Capture ESP via a `push esp ; push eax ; pop edi ; pop esi ; ret` gadget into a non-ESP register, then add the (negative) offset via arithmetic gadgets.

## Operational Techniques

### Static + Dynamic Analysis Loop for Protocol RE
- **What**: Iteratively walk a binary's call tree from `recv`/`read` upward, using IDA Pro for structure and WinDbg for verification.
- **When to use**: Black-box network protocol analysis where no source or documentation is available.
- **How**:
  1. In IDA Pro, locate `recv`/`WSARecv` xrefs; in WinDbg `bp <recv>` and trigger network input.
  2. On hit, `ba r1 <input_buffer_addr>` (hardware read breakpoint, size 1 byte).
  3. `g` until breakpoint fires; `k` for call stack; `dd esp L<N>` for arguments.
  4. `u <caller_offset> - 5 L1` to find the `call <callee>` instruction.
  5. `bc *; bp <caller_offset>; g` to re-run and trace forward.
  6. In IDA, follow the same addresses in graph view; rename variables (`var_C370` → `psAgentCommand`) as their meaning is discovered.
  7. Repeat until the protocol structure is fully mapped.
- **Vault link**: T-020 Anti-Analysis uses marker-based dynamic verification in its diagnostic test harness; same dual static/dynamic discipline, applied to self-validation rather than third-party RE.
- **Tool/code**: IDA Pro, WinDbg, `ba r1`, `bc *`, `bp`, `g`, `p`, `pt`, `k`, `dds`, `dd`, `?`, `.formats`, `u`.
- **OPSEC**: Lab-only methodology; engagement use implies that target binary is already accessible for instrumentation. On real targets, sandbox-style dynamic RE may trigger EDR telemetry — pair with T-020's anti-VM checks if validating reach.

### Hardware-Breakpoint Input-Buffer Tracing
- **What**: Use `ba r1 <addr>` to find the first instruction that reads attacker-controlled input, revealing the parsing entry point.
- **When to use**: Any time you can identify the address of attacker-controlled data (e.g., immediately post-`recv`) but don't know what code processes it.
- **How**: After `recv` returns, read the buffer address from `dd esp L1` (first arg) or from `[socket_struct+offset]`. Issue `ba r1 <buffer_addr>` then `g`. The first hit is the parser's first byte access. Stack-trace from there.
- **Vault link**: T-001 RecycledGate, T-003 VEH Gate both rely on memory access tracing for SSN discovery; the `ba` hardware breakpoint is the same primitive.
- **Tool/code**: `ba r1 <addr>` (read access), `ba w1 <addr>` (write access), `ba e1 <addr>` (execute access — equivalent to a software bp on code).
- **OPSEC**: Hardware breakpoints are limited to 4 simultaneous; `bc *` to clear before setting a new one.

### Endian-Aware PoC Construction
- **What**: Build the binary packet with correct endianness for each field, accounting for in-line byte-reversal in the parser.
- **When to use**: Always, when crafting network protocol PoCs. Inspecting the parser's endianness-handling instructions (`and 0xFF` / `shl 0x18` sequences) reveals wire format.
- **How**: Use Python's `struct.pack(format, value)`: `">i"` for big-endian 32-bit, `"<i"` for little-endian 32-bit, `">Q"` / `"<Q"` for 64-bit. The format string in the PoC must match the parser's expected wire byte order, *not* the in-memory representation after conversion.
- **Vault link**: T-021 Crypto & Obfuscation's shellcode encoders (IPv4, IPv6, MAC, UUID, words) use the same byte-ordering discipline; the encode/decode round trip must preserve byte semantics.
- **Tool/code**: `from struct import pack`; `pack(">i", 0x1234)`; `pack("<i", 0x534)`.
- **OPSEC**: None — pure PoC correctness.

### Stack Distance Calculation for Overflow Viability
- **What**: Verify that the destination buffer is on the stack at a lower address than the target return address, and that the maximum copy size exceeds the distance.
- **When to use**: Before pursuing any `memcpy`/`sscanf`/`strcpy` overflow as a return-address overwrite candidate.
- **How**:
  1. Break on the copy call; `dd esp L3` to read args (dst, src, size).
  2. `!teb` to confirm dst ∈ [StackLimit, StackBase].
  3. `k` to find the call stack frame whose return address you want to overwrite.
  4. `dds <saved_ebp> L2` to find the storage address of the return address (it's the second DWORD).
  5. `? <ret_addr_storage> - <dest_buffer>` to compute the minimum required overflow length.
  6. Compare against the maximum copy size allowed by the parser.
- **Vault link**: No direct vault equivalent — the vault focuses on injection via legitimate APIs, not corruption-based exploits. However, T-005 Ekko ROP Sleep's ROP frame construction requires analogous stack layout reasoning.
- **Tool/code**: `!teb`, `k`, `dds`, `?`, `dd`.
- **OPSEC**: Lab-only diagnostic.

### SEH Chain Overwrite for EIP Control
- **What**: When direct return-address overwrite requires too large a copy (corrupting intervening pointers used before `ret`), instead overwrite the SEH chain and trigger an exception by writing past the end of the stack.
- **When to use**: x86 targets with no SafeSEH (or where the SEH list is in a non-SafeSEH-protected module). Particularly useful when the maximum copy size is large but the destination-to-ret-addr distance is small *to SEH* but the function uses many stack pointers before returning.
- **How**:
  1. Identify the destination buffer's offset relative to the SEH chain (use `!exchain` to dump the current chain).
  2. Calculate the size needed to reach the SEH record.
  3. Craft the overflow with that size.
  4. Trigger an exception (e.g., copy past the end of the stack page — `rep movs` will fault on the inaccessible page).
  5. The dispatcher invokes the overwritten handler → EIP control.
- **Vault link**: T-016's KiUserExceptionDispatcher StepOver operates in the same exception-dispatch space, but to *bypass* EDR rather than *hijack* execution. The two techniques are conceptually opposite uses of the same kernel-user exception transition.
- **Tool/code**: `!exchain`, `bp <memcpy_call>`, `p`, `g`.
- **OPSEC**: x86 only; x64 SEH is table-based and verified. SafeSEH blocks this if the handler module is enrolled.

### Negative-Offset Source for memcpy Wrap-Around
- **What**: When a parser does `memcpy(dst, src + offset, size)` and doesn't validate `offset`, supply a large negative offset to make the effective source point to memory preceding `psCommandBuffer`.
- **When to use**: When the maximum packet size (e.g., `0x4400`) is smaller than the required overflow distance to the return address or SEH chain. The attacker can use a negative offset to read from earlier in the heap, achieving an arbitrarily large effective source buffer.
- **How**: Set the offset field to a negative value (e.g., `-0x11000`). The `memcpy` then reads `0x11000` bytes of preceding memory followed by the first part of `psCommandBuffer`. This works as long as the preceding memory is allocated and readable.
- **Vault link**: No direct vault equivalent.
- **Tool/code**: `buf += pack("<i", -0x11000)` for the offset field.
- **OPSEC**: Requires the heap layout to have allocated, readable memory at the negative offset — usually true for long-running services with multiple allocations.

### DEP Triage via Narly WinDbg Extension
- **What**: Parse the PE header of a target module to enumerate its declared mitigations (SafeSEH, ASLR, DEP).
- **When to use**: Initial triage of an exploit target.
- **How**: `.load narly` then `!nmod` lists all loaded modules and their flags. `*DEP` (asterisk) means DEP is *not* enabled; presence of `DEP` without asterisk means it is enabled.
- **Vault link**: T-020 Anti-Analysis Suite's recon module covers similar binary triage from the defensive perspective (detecting which mitigations an EDR has applied).
- **Tool/code**: `.load narly`, `!nmod`, `!vprot <addr>`.
- **OPSEC**: Attaching WinDbg to a process is itself detectable; on red team engagements, prefer static PE parsing (the same data is in the DLL Characteristic field of `IMAGE_OPTIONAL_HEADER`).

### Enforcing DEP via WDEG
- **What**: Use Windows Defender Exploit Guard to force DEP (and other mitigations) on a target binary that wasn't compiled with `/NXCOMPAT`.
- **When to use**: When the engagement requires demonstrating the full bypass chain, even if the production target isn't DEP-protected.
- **How**: *Windows Defender Security Center → App & browser control → Exploit protection settings → Program settings → Add program to customize → Choose exact file path → Navigate to FastBackServer.exe → Enable "Data Execution Prevention (DEP)" with "Override system settings"*. Restart the target service. Verify by writing `0x90909090` to the stack and setting `eip = esp`; if DEP is enforced, `p` triggers access violation `c0000005`.
- **Vault link**: T-016 EDR Evasion Suite covers BYOVD (Bring Your Own Vulnerable Driver) for kernel mitigation disabling; WDEG is the user-mode counterpart that an operator may need to disable for offensive tooling rather than for the target.
- **Tool/code**: WDEG UI; `ed esp 90909090; r eip = esp; p` to verify.
- **OPSEC**: WDEG settings are registry-backed and may be detected by EDR. The registry path is `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<binary>\MitigationOptions`.

### Pykd Gadget Discovery Script
- **What**: Automate ROP gadget enumeration by scanning executable memory pages of a loaded module.
- **When to use**: When offline analysis (rp++) isn't possible (e.g., module only exists in memory, JIT-compiled, or unpacked at runtime) or for educational understanding.
- **How**:
  1. `.load pykd` in WinDbg.
  2. Write a Python script: `from pykd import *`; `mod = module("<modname>")`; `pn = int((mod.end() - mod.begin()) / 0x1000)`.
  3. For each page, `getVaProtect(addr)` ∈ `{0x10, 0x20, 0x40, 0x80}` means executable.
  4. For each executable page, scan bytes via `loadSignBytes(ptr, 1)[0] & 0xff`; if ∈ `{0xc3, 0xc2}` it's a `RET`/`RETN N` opcode.
  5. For each RET address, walk backward 1..N bytes, `disasm(addr).instruction()` to get the mnemonic.
  6. Filter privileged instructions (`clts`, `hlt`, `lmsw`, `ltr`, `lgdt`, `lidt`, `lldt`, `mov cr`, `mov dr`, `mov tr`, `in`, `ins`, `invlpg`, `invd`, `out`, `outs`, `cli`, `sti`, `popf`, `pushf`, `int`, `iret`, `iretd`, `swapgs`, `wbinvd`) and flow-control (`call`, `jmp`, `leave`, conditional jumps, `lock`, `enter`, `wait`).
  7. Use Python `any(bad in instr for bad in BAD)` to detect and skip.
  8. Write gadgets to a text file for offline search.
- **Vault link**: The vault's `dark_crystal/crowd/src/resolve.rs` (T-002 Hell's/Halo's/Tartarus Gate) walks ntdll's `.text` section in a similar pattern — scanning for syscall stub signatures rather than RET opcodes.
- **Tool/code**: Pykd 0.3.0+; sample script in `C:\Tools\pykd\findropfull.py`.
- **OPSEC**: Loading a Python interpreter into WinDbg is heavy and detectable. Use only in lab/analysis environments.

### RP++ for Fast Gadget Discovery
- **What**: Pre-built CLI tool that parses PE files directly from disk (no debugger needed) and outputs gadgets.
- **When to use**: Default choice for offline gadget enumeration — much faster than pykd and produces searchable output.
- **How**: `rp-win-x86.exe -f <target.exe> -r 5 > rop.txt` where `-r 5` is the maximum gadget length in instructions. Output format: `0xADDR: instr1 ; instr2 ; ... ; ret`. Search with `findstr ": pop eax ; ret" rop.txt` to find specific gadgets.
- **Vault link**: T-002 — same pattern of binary analysis for code discovery, different objective (syscalls vs gadgets).
- **Tool/code**: `rp-win-x86.exe` (32-bit) or `rp-win-x64.exe`; available at `C:\Tools\dep\` on the OSED VM. Supports PE, ELF, Mach-O.
- **OPSEC**: File-system scan, no debugger footprint. Safe for sensitive engagements.

### VirtualAlloc Skeleton + Runtime Patching via ROP
- **What**: Place a `VirtualAlloc` call skeleton on the stack via the buffer overflow, then use ROP gadgets to dynamically patch placeholder values before transferring control.
- **When to use**: Primary DEP bypass technique on x86 targets where the destination buffer is on a non-executable stack.
- **How** (per training material, in order):
  1. **Layout skeleton** at `psCommandBuffer` start: `VirtualAlloc_addr | ret_to_shellcode | lpAddress | dwSize | flAllocationType | flProtect`. Use dummy values like `0x45454545`, `0x46464646`, etc. Calculate the offset between the skeleton start and the EIP overwrite location, and pad with `b"A" * (offset - skeleton_len)`.
  2. **Capture ESP into a callee-saved register** via `push esp ; push eax ; pop edi ; pop esi ; ret` (the push/pop dance moves ESP through EAX-junk into ESI without consuming ESI itself).
  3. **Compute VirtualAlloc placeholder address**: `MOV EAX, ESI ; POP ESI ; RETN` (junk for POP ESI) → `POP ECX ; RETN` with `0xFFFFFFE4` (-0x1C) on stack → `ADD EAX, ECX ; RETN`. Now EAX points to the placeholder. `PUSH EAX ; POP ESI ; RETN` moves it back to ESI.
  4. **Resolve VirtualAlloc via IAT**: `POP EAX ; RETN` with `IAT_address + 1` on stack → `POP ECX ; RETN` with `0xFFFFFFFF` (-1) on stack → `ADD EAX, ECX ; RETN` (restores original IAT address, avoiding bad chars in the literal) → `MOV EAX, DWORD [EAX] ; RETN` (dereferences IAT entry → real API address).
  5. **Patch VirtualAlloc address**: `MOV DWORD [ESI], EAX ; RETN` writes the API address over the dummy `0x45454545`.
  6. **Advance ESI to next placeholder**: `INC ESI ; ADD AL, 0x2B ; RETN` × 4 (or similar INC gadget chain) moves ESI to the return-address placeholder.
  7. **Compute shellcode address**: copy ESI to EAX (`MOV EAX, ESI ; POP ESI ; RETN`, then restore via `PUSH EAX ; POP ESI ; RETN`), add a fixed positive offset via negative arithmetic (`POP ECX 0xFFFFFDF0` then `SUB EAX, ECX ; RETN`). The fixed offset equals the distance from the return-address placeholder to the shellcode location, computed after the full ROP chain is finalized.
  8. **Patch return address**: `MOV DWORD [ESI], EAX ; RETN`.
  9. **Repeat for `lpAddress`, `dwSize`, `flAllocationType`, `flProtect`** using the same INC+add+mov pattern. `dwSize = 0x1000` (page size, avoids NULL-byte issue if encoded as negative-of-positive-small-value), `flAllocationType = 0x1000` (`MEM_COMMIT`), `flProtect = 0x40` (`PAGE_EXECUTE_READWRITE`).
  10. **Jump to VirtualAlloc**: After all patches, the ROP chain ends with a `RET` to a `XCHG EAX, ESP ; RETN` gadget (or equivalent) that pivots the stack to the skeleton, which the CPU then treats as a `call` frame: the `RET` at the end of the last gadget pops `VirtualAlloc`'s address into EIP.
  11. **Shellcode execution**: When `VirtualAlloc` returns, it pops the patched return address (shellcode address) into EIP, executing on the now-RWX page.
- **Vault link**: T-005 Ekko ROP Sleep uses a 6-frame ROP chain for *legitimate* (defensive) PE encryption during sleep obfuscation — same ROP construction discipline, different goal. T-016's stack spoofing also relies on similar gadget-chain construction to fabricate legitimate-looking call stacks.
- **Tool/code**: rp++ output, `0x50501110: push esp ; push eax ; pop edi ; pop esi ; ret`, `0x5050118e: mov eax,esi ; pop esi ; retn`, `0x505115a3: pop ecx ; ret`, `0x5051579a: add eax, ecx ; ret`, `0x50537d5b: push eax ; pop esi ; ret`, `0x5053a0f5: pop eax ; ret`, `0x5051f278: mov eax, dword [eax] ; ret`, `0x5051cbb6: mov dword [esi], eax ; ret`, `0x50522fa7: inc esi ; add al, 0x2B ; ret`.
- **OPSEC**: The ROP chain itself executes from non-executable stack memory *only via RET-driven dispatch* — DEP does not block this. The eventual shellcode is on a RWX page allocated by the legitimate `VirtualAlloc` call. No DEP violation occurs. This is the canonical DEP bypass and remains viable on modern Windows for non-`/NXCOMPAT` targets or processes where WDEG hasn't been applied.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `ba r1 <addr>` | Hardware read breakpoint on input buffer | 4-breakpoint max; `bc *` to clear |
| `bc *` | Clear all breakpoints | Required between PoC iterations |
| `bp <addr>` | Set software breakpoint | Page-protection-aware |
| `g`, `p`, `pt`, `t` | Continue / step-over / step-to-return / trace-into | `pt` to advance to next `ret` |
| `k`, `dds`, `dd`, `da` | Call stack / symbolized dump / DWORD dump / ASCII dump | `dds` interprets DWORDs as symbols |
| `?` | Evaluate expression | `? 0xABC - 0xDEF`, `? -0x1C` |
| `.formats <value>` | Binary/decimal/octal/hex/float disassembly of a value | Useful for sign-bit analysis |
| `u <addr> L<N>` | Unassemble (disassemble) N instructions | `u eip L10` |
| `ed <addr> <val>` | Enter DWORD | Live-patches memory for analysis bypass |
| `r <reg> = <val>` | Set register | Live-redirect EIP for testing |
| `!vprot <addr>` | Dump memory page protection | `PAGE_EXECUTE_READ` = 0x20, `PAGE_READWRITE` = 0x4 |
| `!teb` | Dump TEB (stack bounds, exception list) | StackBase / StackLimit for bounds check |
| `!exchain` | Dump current SEH chain | Before/after overwrite comparison |
| `lm m <module>` | List loaded modules matching name | Base/end address for module selection |
| Narly (`!nmod`) | PE header mitigation triage (SafeSEH/ASLR/DEP) | Detectable by EDR; use static parsing on engagements |
| Pykd (`!py <script>`) | Python WinDbg automation | Heavy footprint; lab/analysis only |
| RP++ (`rp-win-x86.exe -f <bin> -r 5 > rop.txt`) | Offline gadget discovery | File-system scan, low OPSEC footprint |
| `findstr ": pop eax ; ret" rop.txt` | Grep gadgets in rp++ output | Combine with `; ret` to anchor at RET |
| `msf-pattern_create -l <N>` / `msf-pattern_offset -q <val>` | Cyclic pattern for offset discovery | Standard Metasploit utility |
| `struct.pack(">i", val)` / `pack("<i", val)` | Endian-aware binary packing | `>` = big-endian, `<` = little-endian |
| WDEG UI | Per-process mitigation enforcement | Registry-backed at `HKLM\...\Image File Execution Options\<bin>\MitigationOptions` |
| IDA Pro `Options > General > Graph > Max nodes` | Increase graph view node cap above 1000 | Required for very large functions like `FXCLI_OraBR_Exec_Command` |

## Gaps & Extensions

### What this training covers that the vault does **not**
- **Classic stack buffer overflow exploitation** — the vault's T-007 Pool Party, T-008 Threadless, T-012 Early Cascade, etc. all use *legitimate* API-mediated injection (thread pools, APCs, section mapping). The vault has no coverage of memory-corruption-based exploitation (`memcpy`/`sscanf`/`strcpy` overflows).
- **Protocol reverse engineering methodology** — combined IDA Pro + WinDbg static/dynamic analysis loop, hardware-breakpoint input tracing, opcode-dispatch tree walking, call-stack-unwinding caller discovery. The vault assumes knowledge of target APIs and skips this black-box RE phase entirely.
- **DEP bypass via `VirtualAlloc`/`VirtualProtect` ROP** — the vault's ROP usage (T-005 Ekko Sleep) is for *defensive* sleep obfuscation, not for DEP bypass.
- **Pykd WinDbg scripting** — the vault's diagnostic test harness (T-020) is Rust-based, not Python-based.
- **Bad-character identification methodology** — iterative binary sweep (`0x00..0xFF`) and crash analysis. The vault's shellcode encoders (T-021 IPv4/IPv6/MAC/UUID/words) presuppose knowledge of bad chars; the training teaches the discovery process.
- **Endianness-aware PoC construction with `struct.pack`** — the vault's networking (T-022) handles binary protocol bytes but doesn't explicitly teach endianness conversions.
- **SEH chain overwrite** — x86-only technique; the vault is x64-first and uses different primitives.
- **IAT-based runtime API resolution** — the vault's T-004 PEB Walker resolves APIs by walking `InLoadOrderModuleList` and DJB2-hashing names; this training resolves via host DLL IAT entries. Both are valid; the IAT approach is simpler when an appropriate host DLL is loaded.

### What the vault covers that this training does **not**
- **Indirect syscalls** (T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, T-003 VEH Gate) — the training's ROP runs through Win32 API calls (`VirtualAlloc` via IAT); the vault dispatches through `ntdll` gadgets to avoid EDR hooks entirely.
- **Modern process injection** — Pool Party (T-007), Threadless (T-008), Ghosting (T-009), Herpaderping (T-010), Dirty Vanity (T-011), Early Cascade (T-012) — the training's "injection" is a `VirtualAlloc`+copy+jump model, not the sophisticated thread-pool/APC/section techniques of the vault.
- **Sleep obfuscation** (T-005 Ekko ROP Sleep) — the training's ROP immediately transfers to shellcode; the vault's ROP chain has a *legitimate* purpose (encrypt the implant during sleep) and is reconstructed every wake cycle.
- **EDR evasion** (T-016) — AMSI/ETW patching, stack spoofing, PEB unlink, NTDLL unhook, ACG, Block-DLL, handle blocking, KiUserException StepOver, arg spoofing, proxy DLL. The training's only "evasion" is the WDEG configuration step (which *enables* mitigations rather than bypassing them).
- **Anti-analysis** (T-020) — anti-VM (10 checks), API hammering, IAT camouflage, self-deletion. The training assumes the analyst can attach WinDbg freely.
- **Persistence** (T-017, T-018, T-019) — five-layer persistence, Edo Tensei polymorphic resurrection, Edo Dead Drop autonomous C2.
- **Modern cryptography & encoding** (T-021) — AES-GCM+zstd, Ethereum TX signing, IPv4/IPv6/MAC/UUID shellcode encoders. The training's "encoding" is just the bad-character-aware payload construction.
- **Networking & C2** (T-022) — SOCKS5, HVNC, malleable C2, multi-chain vault, peer relay, HTTP poll, NT sockets, BYOVD.
- **Client capabilities** (T-023) — BOF execution, keylogger, browser hook, screen capture, H.264 encoding, dirty rect, credential harvest, HTML/Win32 overlays. The training's "shellcode" is a placeholder; the vault delivers an actual implant.

### Conceptual divergence
The training and the vault represent **two different eras of offensive security**:
- **Training (OSED)**: Classical exploit development against a vulnerable third-party service. Goal: achieve arbitrary code execution via memory corruption. Target-tailored. Lower-level primitives (x86, ROP, DEP).
- **Vault (modern)**: Implant tradecraft against modern Windows with EDR. Goal: maintain stealthy, evasive persistence in a target environment. Defensive primitives (indirect syscalls, sleep obfuscation, anti-analysis).

A complete operator masters both: the OSED techniques to *gain initial execution* via memory corruption, and the vault techniques to *maintain and operate* the resulting implant. The ROP discipline taught here directly transfers to T-005 (Ekko ROP Sleep frame construction), T-016 (stack spoofing gadget chains), and T-002 (Tartarus Gate walks the same `ntdll` memory the training walks for gadgets).

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| Static + dynamic analysis loop | T-020 Anti-Analysis (diagnostic test harness) | Same dual-analysis discipline; vault applies to self-validation |
| Hardware breakpoint input tracing (`ba r1`) | T-001 RecycledGate, T-003 VEH Gate | Same `ba` primitive; vault uses for SSN discovery, training for input-parse discovery |
| PEB/module walking (implicit in IAT resolution) | T-004 PEB Walker | Both resolve APIs; vault walks `InLoadOrderModuleList` + DJB2 hash; training dereferences IAT directly |
| ROP gadget chain construction | T-005 Ekko ROP Sleep | Same gadget-composition discipline; vault applies to sleep obfuscation (defensive), training to DEP bypass (offensive) |
| `MOV DWORD [ESI], EAX` write primitive | T-016 stack spoofing | Same write-what-where primitive; vault uses for stack fabrication, training for skeleton patching |
| IAT dereference for API address | T-004 PEB Walker, T-002 Hells Gate | All resolve API addresses at runtime; different sources (IAT vs. PEB module walk vs. ntdll `.text` scan) |
| Negative-offset arithmetic for NULL-byte avoidance | T-021 shellcode encoders | Both solve the "avoid NULL bytes in payload" problem; vault via encoding, training via two's-complement arithmetic |
| DEP theory & `!vprot` page inspection | T-016 EDR Evasion (NTDLL unhook, PE stomping) | Both manipulate memory protections; vault changes protections to evade, training bypasses them to execute |
| WDEG mitigation enforcement | T-016 BYOVD (T-022 vault) | Both touch Windows mitigation systems; WDEG is user-mode config, BYOVD is kernel-mode driver abuse |
| Pykd Python WinDbg scripting | T-020 diagnostic test harness | Both automate dynamic analysis; vault via Rust markers, training via Python |
| RP++ gadget discovery | T-002 Hells/Halo's/Tartarus Gate ntdll scan | Both scan executable memory for byte signatures; vault finds syscall stubs, training finds `RET` opcodes |
| Opcode dispatch (jump table) recognition | (No vault equivalent) | Training-only: pattern recognition for reversing application logic |
| Stack distance calculation (`? ret - dst`) | (No vault equivalent) | Training-only: overflow viability check |
| SEH chain overwrite | (No vault equivalent; T-016 KiUserException StepOver is adjacent) | x86-only tradecraft; vault is x64-first and doesn't address SEH for exploitation |
| `VirtualAlloc` skeleton + runtime patching | T-005 Ekko ROP Sleep (analogous skeleton) | Vault's ROP frames are pre-built for sleep obfuscation; training's skeleton is dynamically patched for DEP bypass |
| Bad character identification (`0x00..0xFF` sweep) | T-021 shellcode encoders | Vault encoders presuppose bad chars are known; training teaches the discovery process |
| Endian-aware `struct.pack` PoC construction | T-022 malleable C2 / T-021 protocol bytes | Vault handles binary protocols in Rust; training teaches the manual Python approach |
| Combined `bc *` / `bp` / `g` workflow | (No vault equivalent) | Training-only: WinDbg-driven iterative RE loop |

---

*End of reference document. This document covers OSED Module 04 in its entirety as a foundation for the vault's modern offensive tradecraft. Operators should treat the ROP gadget-construction discipline and the static/dynamic analysis loop as transferable skills that underpin several vault techniques, particularly T-002, T-005, and T-016.*