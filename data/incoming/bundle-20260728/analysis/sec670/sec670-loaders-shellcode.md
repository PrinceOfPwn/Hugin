---
id: RTO-sec670-loaders-shellcode-unhooking
name: SEC670.5 — Custom Loaders, Shellcode & Unhooking
source: SANS SEC670 / Red Team Ops
category: process-injection
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-001, T-002, T-003, T-004, T-005, T-006, T-007, T-008, T-013, T-014, T-016, T-020]
tags: [reflective-dll-injection, srdi, pe-loader, syscalls, hells-gate, halos-gate, heavens-gate, unhooking, iat-hooking, inline-hooking, trampolines, syswhispers, fresh-copy, suspended-copy]
---

# SEC670.5 — Custom Loaders, Shellcode & Unhooking — Training Reference

## TL;DR
SEC670 Section 5 walks operators through foundational implant enhancement: writing custom PE loaders (RDI / sRDI / manual LoadLibrary), understanding syscall mechanics (direct vs indirect, Heaven's/Hell's/Halo's Gates), and three unhooking strategies (byte validation, fresh-copy from disk, suspended-process copy). The material is pedagogically valuable as primer but is **substantially superseded** by vault techniques T-001/T-002 (RecycledGate + 4-stage SSN cascade), T-016 (NTDLL unhook via known-good suspended process), and T-013 (reflective PE loader). Use this as conceptual scaffolding; use the vault for operator-grade implementations.

## Key Concepts

1. **Custom Loader / Manual LoadLibrary**
   Operator implements a PE mapper that handles DOS/NT header parsing, section copy with original permissions (IMAGE_SCN_MEM_DISCARDABLE / NOT_CACHED), base relocation, IAT resolution, and entry-point invocation. This is the foundational technique underlying the vault's `pe_loader.rs` (T-013) and `module_overload.rs`.

2. **Reflective DLL Injection (RDI) — Stephen Fewer**
   The DLL exports a position-independent `ReflectiveLoader` that self-resolves `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc` (via walking PEB → kernel32/ntdll), allocates memory, copies headers/sections, processes relocations/IAT, then calls `DllMain`. Stealth advantage: no disk path written, no LoadLibrary call. Vault reference: T-013 reflective PE loader; training is conceptual ancestor.

3. **Shellcode RDI (sRDI) — Nick Landers / monoxgas**
   Converts any DLL into position-independent shellcode via a PE-loader shellcode blob. Includes `GetProcAddressR` for runtime export resolution. Supports section permissions and TLS callbacks. Useful when injecting DLL via any shellcode-capable injection primitive. Vault reference: T-013 (shellcode execution templates) and T-021 (shellcode encoding pipeline).

4. **Entry-Point Signatures**
   Operator must dispatch the correct entry signature:
   - DLL: `DllMain(HINSTANCE, DWORD, LPVOID)`
   - Console: `main(int argc, char** argv, char** envp[])` / `wmain`
   - GUI: `WinMain(HINSTANCE, HINSTANCE, PSTR, int)` / `wWinMain`
   - Native: `NtProcessStartup(PPEB peb)`
   - Field: `IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint`

5. **Syscall Mechanics (j00ru table, KUSER_SHARED_DATA)**
   Syscalls are indexed kernel routines. Stub signature in ntdll:
   ```
   mov r10, rcx
   mov eax, <SSN>
   test byte ptr [7FFE0308h], 1   ; KUSER_SHARED_DATA->SystemCall
   jne <fallback>
   syscall
   ret
   int 0x2E  ; legacy interrupt path
   ret
   ```
   SSN values vary across Windows versions (XP SP1 → Win11); hardcoding limits portability. GUI syscalls (win32u.dll → win32k.sys) and native syscalls (ntdll → ntoskrnl) split into two table regions.

6. **Direct vs Indirect Syscalls**
   - *Direct*: build syscall stub in implant's own memory; execute `syscall` instruction locally. Bypasses user-mode hooks but call stack shows non-ntdll return address (detectable by kernel-mode EDR).
   - *Indirect*: jump into ntdll's existing `syscall` instruction (`ntdll!Nt*+0x10`), only SSN resolved locally. Call stack looks more legitimate. Vault reference: **T-001 RecycledGate** (S-tier, uses recycled ntdll gadgets) and **T-006 Phantom Stubs** (MEM_IMAGE-backed stubs).

7. **Hell's Gate (am0nsec / RtlMateusz)**
   Dynamically walks PEB → ntdll (`__readgsqword(0x60)`, hardcoded 2nd entry in `InMemoryOrderModuleList`), validates opcodes (`*(PBYTE)TargetFunction + 3 == 0xB8`), extracts SSN. Position-independent. Fails if target syscall is hooked. Vault reference: **T-002 stage 1** of the 4-stage cascade.

8. **Halo's Gate (Reenz0h / Sektor7)**
   Walks neighbor syscall stubs when target is hooked — SSNs are sequential in ntdll. Looks ±N stubs (each stub is 0x20 bytes apart), increments/decrements SSN accordingly. Preserves the EDR's hook so integrity checks pass. Vault reference: **T-002 stage 2** (Halo's Gate).

9. **Heaven's Gate (Wow64 transition)**
   32-bit processes use `jmp 033:wow64cpu+offset` far jump via `ntdll!Wow64Transition` → `wow64cpu.dll` → 64-bit ntdll syscall stub. Hooks on 32-bit ntdll are bypassable by hooking the 64-bit ntdll. Legacy relevance for Wow64; modern x64-native implants can ignore.

10. **Inline & IAT Hooking**
    - *IAT*: parse DataDirectory[1], VirtualProtect to PAGE_READWRITE, overwrite function pointer, restore protections.
    - *Inline*: read 5+ bytes (32-bit: 2-byte `MOV EDI,EDI` hotpatch pad + 5 NOPs; 64-bit: 12+ bytes for `MOV RAX, addr; JMP RAX`), patch with `JMP rel32` or absolute-jump trampoline, restore post-hook to invoke original.

11. **Trampolines**
    Stolen original bytes + jump back to `original+N` (offset past overwritten region). Prevents hook recursion. For 32-bit hooks, jump back +6; for 64-bit +12 minimum.

12. **Unhooking — Three Methods**
    - *Byte validation*: scan first 5+ bytes for unexpected opcodes (e.g., `JMP`); restore from disk copy.
    - *Fresh copy*: `CreateFileA("C:\\Windows\\System32\\ntdll.dll")` → `CreateFileMapping` → `MapViewOfFile` → locate `.text` → `memcpy` over hooked `.text`. Detectable but uncommon.
    - *Suspended copy*: `CreateProcess(..., CREATE_SUSPENDED, ...)` — only ntdll is mapped (no hooks yet). Pattern-scan for syscall stubs, copy clean `.text` into hooked process.
    Vault reference: **T-016** `ntdll_unhook_inject.rs` implements the suspended-process approach at production grade.

13. **SysWhispers3 (KlezVirus)**
    Python generator producing `.h` / `.c` / `.asm` triples for direct syscalls. Modes: `egg_hunter`, WoW64, direct syscall jumps in both WoW64 and x64, random syscall jumps. Requires MASM build dependency. Does not support GUI (win32u) syscalls. Vault note: largely superseded by T-001/T-002/T-003 (no MASM dependency, pure Rust + inline asm).

## Operational Techniques

### Custom PE Loader (ManualLoadLibrary)
- **What**: Manually map a PE image from a buffer into process memory, mimicking the system loader.
- **When to use**: DLL received over socket, no disk drop permitted, beaconing implant pulling stage-2 PE.
- **How**:
  1. `CreateFileA` / socket recv → raw bytes buffer.
  2. Validate `IMAGE_DOS_HEADER.e_magic == "MZ"`.
  3. Validate `IMAGE_FILE_HEADER.Machine == IMAGE_FILE_MACHINE_AMD64`.
  4. `VirtualAlloc(NULL, OptionalHeader.SizeOfImage, ...)`.
  5. Copy headers (SizeOfHeaders), then each section with original `Characteristics` permissions via `VirtualProtect`.
  6. Apply `IMAGE_DIRECTORY_ENTRY_BASERELOC` relocations (delta = real_base − `ImageBase`).
  7. Process `IMAGE_DIRECTORY_ENTRY_IMPORT` → resolve each DLL via `LoadLibraryA`, each function via `GetProcAddress`, patch IAT.
  8. Execute TLS callbacks if present.
  9. Cast `AddressOfEntryPoint` to function pointer matching target signature (DllMain / main / WinMain / NtProcessStartup), invoke.
- **Vault link**: **T-013 Remaining Injection → pe_loader.rs** — vault implementation is the production-grade equivalent; SEC670 is the conceptual walk-through.
- **Tool/code**: C++ with `PIMAGE_DOS_HEADER`, `PIMAGE_NT_HEADERS64`, `VirtualAlloc`, `VirtualProtect`, `LoadLibraryA`, `GetProcAddress`.
- **OPSEC**: No disk artifact. Risk: VirtualAlloc RWX allocation is a flag — use RX+RW split (vault T-013 does). IAT resolution via `LoadLibraryA` is itself hooked by EDRs — vault walks PEB and resolves via exports (T-004).

### Reflective DLL Injection (RDI)
- **What**: Self-loading DLL exports `ReflectiveLoader` (PI code) that maps itself.
- **When to use**: Cross-process injection where you don't control the loader stub in target.
- **How**:
  1. Implant writes RDI DLL bytes into target via `NtMapViewOfSection` / `VirtualAllocEx` + `WriteProcessMemory`.
  2. Create remote thread at `ReflectiveLoader` export RVA.
  3. `ReflectiveLoader` self-locates via call/pop, walks PEB for `kernel32!LoadLibraryA` / `GetProcAddress` / `VirtualAlloc`.
  4. Allocates contiguous `SizeOfImage`, copies headers/sections, processes relocs + IAT.
  5. Computes `AddressOfEntryPoint`, casts to `DllMain`, calls with `DLL_PROCESS_ATTACH`.
- **Vault link**: **T-013** (reflective PE loader) — vault's loader is generic, can load DLL OR EXE, and is composed with injection primitives like T-007 Pool Party / T-008 Threadless.
- **Tool/code**: Stephen Fewer's `ReflectiveDLLInjection` repo, compiled with `ReflectiveLoader` export.
- **OPSEC**: No `LoadLibrary` call on injected DLL → not in PEB module list. Risk: remote thread at non-image-backed address is a flag. Vault mitigates via T-012 Early Cascade (APC-based, image-backed).

### sRDI (Shellcode RDI)
- **What**: PE-loader shellcode blob that converts any DLL into PI shellcode.
- **When to use**: Injecting a DLL when only shellcode-exec primitives are available.
- **How**:
  1. Build DLL normally.
  2. Run `ConvertToShellcode.py` from monoxgas/sRDI against the DLL → produces PI shellcode blob.
  3. Inject via chosen primitive (CreateThread, APC, thread hijack, fiber, callback, etc.).
  4. Blob self-resolves, maps the embedded DLL reflectively, calls `DllMain`.
- **Vault link**: **T-021 Crypto & Obfuscation** (shellcode encoding pipeline) + **T-013** (pe_loader.rs is the in-vault reflective loader). sRDI's `GetProcAddressR` is mirrored by vault's manual export resolution (T-004 PEB walker + DJB2 hashing).
- **Tool/code**: `monoxgas/sRDI` repo, `ConvertToShellcode.py`.
- **OPSEC**: Blob in RWX memory is a flag. Combine with T-013 module overloading or T-008 Threadless for image-backed execution.

### Direct Syscalls
- **What**: Build a syscall stub in implant memory; execute `syscall` instruction locally with resolved SSN.
- **When to use**: Quick bypass of user-mode-hooked EDRs with no kernel component.
- **How**:
  1. Resolve SSN (Hell's Gate / Halo's Gate / static table / SysWhispers3).
  2. Construct stub: `mov r10, rcx; mov eax, <SSN>; syscall; ret`.
  3. Invoke with conventional calling convention.
- **Vault link**: **T-001 RecycledGate** (S-tier) is the vault's indirect evolution — jumps into ntdll gadget for the `syscall` instruction itself, eliminating the direct-syscall call-stack smoking gun.
- **Tool/code**: SysWhispers3 (`py syswhispers.py --preset common -o syscalls_common -m egg_hunter`), requires MASM build dep.
- **OPSEC**: Call stack return address is not in ntdll → kernel EDR flags. Superseded by indirect syscalls.

### Indirect Syscalls
- **What**: Resolve SSN locally but jump into ntdll's `syscall` instruction (`ntdll!Nt*+0x10`).
- **When to use**: Default operator mode against user-mode-hooked EDRs with kernel-mode call-stack inspection.
- **How**:
  1. Resolve SSN via Hell's/Halo's Gate.
  2. Locate clean `syscall` instruction in ntdll (post-hook bytes).
  3. Construct stub: `mov r10, rcx; mov eax, <SSN>; jmp <ntdll_syscall_addr>`.
  4. Call as a normal function.
- **Vault link**: **T-001 RecycledGate** (canonical implementation) — additionally recycles ntdll gadgets to chain syscall + ret without leaving the implant's own return address on the stack. **T-006 Phantom Stubs** provides MEM_IMAGE-backed stubs for full image-backed dispatch.
- **Tool/code**: Custom asm stub; vault provides `sys_recycled.rs` and `sys_indirect.rs`.
- **OPSEC**: Call stack shows ntdll return address. Better than direct; still single-frame — vault's advanced stack spoofing (T-016) builds multi-frame legitimate-looking stacks.

### IAT Hooking
- **What**: Overwrite imported function pointer in target's IAT.
- **When to use**: API introspection / redirection in your own or injected process.
- **How**:
  1. Get own base address.
  2. Walk PE → `DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]`.
  3. Loop import descriptors to find target module (e.g., `kernel32.dll`).
  4. Loop `FirstThunk` entries to find target function (e.g., `VirtualAlloc`).
  5. `VirtualProtect` IAT page → `PAGE_READWRITE`, save old.
  6. Overwrite thunk with hook function address.
  7. Restore protections.
- **Vault link**: Not directly implemented — vault's evasion suite (T-016) focuses on the inverse (unhooking). The principle is mirrored in **T-013 Vectored Overloading** which uses EAT hook redirection.
- **Tool/code**: `VirtualProtect`, manual PE parsing.
- **OPSEC**: Detectable via IAT integrity checkers. Useful for testing/research more than ops.

### Inline Hooking (64-bit)
- **What**: Patch function's first bytes with a jump to a hook function; use trampoline for original invocation.
- **When to use**: API introspection when IAT hooking isn't viable (delay-load, dynamic resolution).
- **How**:
  1. `GetProcAddress(hModule, "NtQuerySystemInformation")`.
  2. Save 12+ bytes (need full instruction boundaries for 64-bit; use length disasm).
  3. `VirtualProtect` → `PAGE_EXECUTE_READWRITE`.
  4. Patch: `mov rax, <hook_addr>; jmp rax` (10 + 1 = 11 bytes, pad to 12+).
  5. Trampoline: saved bytes + `jmp <original+N>`.
  6. From hook, call trampoline to invoke original.
- **Vault link**: Vault does not implement inline hooking as an offensive technique (focus is on *unhooking*). T-016's `ntdll_unhook` reverses this exact pattern.
- **Tool/code**: Microsoft Detours, EasyHook, or manual length-disasm + patching.
- **OPSEC**: Detectable via byte-comparison integrity checks. Hook function address must be in executable region.

### Unhook: Fresh Copy (Disk)
- **What**: Restore ntdll `.text` from `C:\Windows\System32\ntdll.dll`.
- **When to use**: Mass unhook of all ntdll syscalls.
- **How**:
  1. `CreateFileA("C:\\Windows\\System32\\ntdll.dll", ...)`.
  2. `CreateFileMapping(hNtdll, PAGE_READONLY, ...)`.
  3. `MapViewOfFile(hMapping, FILE_MAP_READ, ...)`.
  4. Parse PE → locate `.text` section.
  5. `VirtualProtect` in-memory `.text` → `PAGE_READWRITE`.
  6. `memcpy(in_mem_text, disk_text, text_size)`.
  7. Restore protections to `PAGE_EXECUTE_READ`.
- **Vault link**: **T-016** (`ntdll_unhook_inject.rs`) — vault implements the suspended-process variant as primary (more robust against on-disk tampering). The fresh-copy approach is documented as a fallback.
- **Tool/code**: `CreateFileA` + `CreateFileMapping` + `MapViewOfFile`.
- **OPSEC**: Defenders can monitor file reads of `ntdll.dll`. On-disk tampering by an attacker defeats this. Suspended-copy is strictly better.

### Unhook: Suspended Copy
- **What**: Spawn suspended process; copy its clean ntdll `.text` into hooked process.
- **When to use**: Default operator unhook approach against user-mode hooks.
- **How**:
  1. `CreateProcessA(..., CREATE_SUSPENDED, ...)`.
  2. `EnumProcessModules` → locate ntdll base in suspended process.
  3. Walk ntdll PE in suspended process → locate `.text`.
  4. `NtReadVirtualMemory` from suspended process `.text`.
  5. `VirtualProtect` current process ntdll `.text` → RW.
  6. `memcpy` clean `.text` over hooked `.text`.
  7. Restore protections.
- **Vault link**: **T-016** (`ntdll_unhook.rs` and `ntdll_unhook_inject.rs`) — vault's canonical implementation. Composed with T-015 PPID spoofing for the sacrificial suspended process.
- **Tool/code**: `CreateProcessA` with `CREATE_SUSPENDED`, `NtReadVirtualMemory`.
- **OPSEC**: Process creation event is logged. Mitigated by T-015 (PPID spoofing) and sacrificial-process selection (e.g., `notepad.exe`, `conhost.exe`).

### Hell's Gate
- **What**: Dynamically resolve SSN from ntdll stub opcodes.
- **When to use**: When targeting non-hooked syscalls on unknown Windows versions.
- **How**:
  1. `__readgsqword(0x60)` → PEB.
  2. Walk `PEB->LoaderData->InMemoryOrderModuleList` — 2nd entry is ntdll.
  3. Walk EAT for target `Nt*` function.
  4. Validate `*(PBYTE)TargetFunction + 3 == 0xB8` (mov eax, imm32).
  5. Extract SSN: `*(PDWORD)(TargetFunction + 4)`.
  6. Build local syscall stub, invoke.
- **Vault link**: **T-002 stage 1** (Hell's Gate) — vault composes Hell's + Halo's + Tartarus + FreshyCalls into a 4-stage cascade with fallback logic.
- **Tool/code**: `am0nsec/HellsGate` repo.
- **OPSEC**: Fails on hooked functions (opcode check fails). Use Halo's Gate fallback.

### Halo's Gate
- **What**: Resolve SSN by walking neighbor syscall stubs when target is hooked.
- **When to use**: Target syscall is hooked but neighbors are clean.
- **How**:
  1. Compute target stub address (Hell's Gate logic).
  2. If opcode check fails (hooked), walk ±N stubs (each stub is 0x20 bytes apart in modern ntdll).
  3. For each neighbor: validate `0xB8` opcode.
  4. SSN(target) = SSN(neighbor) ± distance.
  5. Invoke locally with resolved SSN.
- **Vault link**: **T-002 stage 2** (Halo's Gate) — vault additionally has Tartarus Gate (RVA sort) and FreshyCalls as fallbacks when neighbors are also hooked.
- **Tool/code**: Sektor7 blog reference (`blog.sektor7.net/#!res/2021/halosgate.md`).
- **OPSEC**: Preserves the EDR's hook → integrity checks pass. Vulnerable to randomized SSN ordering (Tartarus Gate handles this).

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `CreateFileA("C:\\Windows\\System32\\ntdll.dll")` | Open on-disk ntdll for fresh-copy unhook | Defenders monitor ntdll file reads |
| `CreateFileMapping` + `MapViewOfFile` | Map on-disk ntdll into process memory | Mapping of ntdll.dll is itself a behavioral indicator |
| `CreateProcess(..., CREATE_SUSPENDED, ...)` | Spawn clean ntdll carrier for unhook | Sacrificial process creation logged; compose with T-015 PPID spoof |
| `__readgsqword(0x60)` | PEB access for module walking | Direct PEB access is itself a flag for some EDRs (T-004 mitigates) |
| `*(PBYTE)TargetFunction + 3 == 0xB8` | Opcode check for SSN extraction (Hell's Gate) | Fails on hooked stubs → use Halo's fallback |
| `VirtualProtect` (IAT/inline) | Make read-only pages writable | Heavy use of VirtualProtect is a behavioral flag |
| `py syswhispers.py --preset common -o syscalls_common -m egg_hunter` | Generate syscall stubs (SysWhispers3) | Adds MASM build dep; no GUI syscall support |
| Stephen Fewer `ReflectiveDLLInjection` | Reference RDI implementation | Old; modern EDRs flag the `ReflectiveLoader` export name |
| `monoxgas/sRDI` `ConvertToShellcode.py` | Convert DLL to PI shellcode | Produces recognizable blob signature |
| j00ru syscall table (`github.com/j00ru/windows-syscalls`) | SSN reference by Windows version | Static; use for verification, not runtime resolution |
| `MOV EDI, EDI` (hotpatch pad) | 2-byte NOP for 32-bit inline hook anchor | 64-bit has no equivalent — need 12+ bytes for `MOV RAX; JMP RAX` |

## Gaps & Extensions

**Vault covers (training does not):**
- **RecycledGate (T-001)** — indirect syscall dispatch via recycled ntdll gadgets, eliminating the local return-address problem entirely. SEC670 only shows naive direct/indirect.
- **VEH Gate (T-003)** — HW breakpoint-mediated syscall dispatch via VEH, no stubs at all. Training has no equivalent.
- **Phantom Stubs (T-006)** — MEM_IMAGE-backed syscall stubs for full image-backed dispatch. Training's direct syscalls are RWX heap.
- **Tartarus Gate + FreshyCalls (T-002 stages 3-4)** — RVA-sort SSN resolution when neighbors are also hooked. SEC670 stops at Halo's Gate.
- **Advanced multi-frame stack spoofing (T-016)** — SEC670 only mentions stack spoofing exists in passing.
- **Sleep obfuscation (T-005 Ekko ROP)** — SEC670 has no module on sleep obfuscation.
- **Modern injection primitives** — Pool Party (T-007), Threadless (T-008), Ghosting (T-009), Herpaderping (T-010), Dirty Vanity (T-011), Early Cascade (T-012), NtCreateUserProcess (T-014), PPID spoofing (T-015). SEC670 only covers classic + reflective.
- **AMSI/ETW patching (T-016)** — SEC670 has a separate lab (5.4) but the analyzed chunk does not include it; vault covers comprehensively.
- **BYOVD (T-018)** — Bring-Your-Own-Vulnerable-Driver. Not in this SEC670 chunk (mentioned as SEC770 follow-on).
- **Persistence suite (T-017)** — SEC670 persistence is in a different section.
- **Anti-analysis suite (T-020)** — anti-VM, API hammering, IAT camouflage. Not in this chunk.
- **Crypto & obfuscation (T-021)** — IPv4/IPv6/MAC/UUID/words shellcode encoding. Not in this chunk.

**Training covers (vault does not, or covers differently):**
- **Inline hook implementation** as an offensive technique — vault focuses on unhooking, not hooking.
- **IAT hooking** — same; vault doesn't expose IAT hooking as an operator technique.
- **Trampoline construction** — foundational knowledge assumed by vault's unhook logic but not explicitly taught.
- **Heaven's Gate (Wow64 transition)** — legacy 32→64 bit transition mechanics. Vault assumes x64-native; no Wow64 handling.
- **Entry-point signature dispatch table** (DllMain/WinMain/main/NtProcessStartup) — vault's pe_loader handles this internally but doesn't expose it as a teaching artifact.
- **Hook integrity monitoring concept** — SEC670 mentions EDRs may re-hook after detecting unhook. Vault doesn't explicitly model this adversarial loop.

**Where training is outdated / superseded:**
- Direct syscalls (SEC670 slide 34) — **explicitly superseded** by T-001 RecycledGate.
- Halo's Gate only (SEC670 slide 43) — **superseded** by T-002 4-stage cascade.
- Fresh-copy unhook from disk (SEC670 slide 50-51) — **superseded** by T-016 suspended-process unhook (robust against on-disk tampering).
- SysWhispers3 with MASM dependency — **superseded** by vault's pure-Rust inline-asm syscall stubs (T-001/T-006).
- Reflective DLL Injection with named `ReflectiveLoader` export — **superseded** by T-013 generic reflective PE loader (no signatured export name).

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| Custom PE Loader (ManualLoadLibrary) | T-013 (pe_loader.rs) | Vault implements production-grade; SEC670 is conceptual walk-through |
| Reflective DLL Injection (RDI) | T-013 (pe_loader.rs, ReflectivePELoader) | Vault's generic loader subsumes RDI; composes with modern injection primitives |
| sRDI (Shellcode RDI) | T-013 + T-021 | Vault's encoding pipeline (IPv4/IPv6/MAC/UUID/words) wraps the shellcode; pe_loader does the mapping |
| Entry-point signature dispatch | T-013 (internal) | Vault handles internally; SEC670 exposes as teaching artifact |
| Direct syscalls | T-001 (RecycledGate) | Vault supersedes with indirect + gadget chaining |
| Indirect syscalls | T-001 (RecycledGate), T-006 (Phantom Stubs) | Vault implementations are strictly more advanced |
| PEB walking (gs:[0x60]) | T-004 (PEB Walker) | Vault has production implementation with DJB2 hashing |
| Hell's Gate | T-002 stage 1 | Vault uses as first stage of 4-stage cascade |
| Halo's Gate | T-002 stage 2 | Vault uses as second stage; adds Tartarus + FreshyCalls fallbacks |
| Heaven's Gate (Wow64) | (none in vault) | Vault is x64-native; SEC670 covers legacy |
| IAT hooking | (none in vault) | Vault doesn't implement IAT hooking as offensive technique |
| Inline hooking | (none in vault as offensive) | Vault implements the inverse (unhooking); T-013 Vectored Overloading uses EAT redirection conceptually similar |
| Trampolines | (assumed in T-016) | Foundational concept; vault assumes understanding |
| Fresh-copy unhook (from disk) | T-016 (ntdll_unhook_inject.rs) | Vault implements suspended-process variant as primary; fresh-copy as documented fallback |
| Suspended-copy unhook | T-016 (ntdll_unhook.rs, ntdll_unhook_inject.rs) | Vault's canonical implementation; composes with T-015 PPID spoofing |
| SysWhispers3 | T-001/T-002/T-003 (inline asm, no MASM dep) | Vault supersedes — pure Rust + inline asm |
| Process hollowing (mentioned in passing) | T-013 (process_hollow.rs) | Vault has full implementation |
| j00ru syscall table | T-002 (runtime resolution) | Vault resolves at runtime, no static table dependency |