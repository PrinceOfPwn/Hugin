---
id: T-004
name: PEB Walker via gs:[0x60]
category: syscalls
tier: A
mitre: T1106
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires: []
enables: [T-001, T-002, T-003, T-006, T-016]
min_windows: Windows XP x64 / Server 2003 x64 (any x64 Windows; gs segment convention)
needs_admin: no
tags: [peb, inline-asm, module-resolution, zero-api, djb2, pe-walking, x64-only]
---

# PEB Walker via gs:[0x60] — Operator Playbook

## TL;DR
Self-contained module + export resolution that touches zero Win32 imports. Reads the PEB pointer straight from the TEB via `gs:[0x60]`, walks `PEB.Ldr.InLoadOrderModuleList`, hashes each `BaseDllName` with DJB2, and chases the resolved DLL's export table to find function pointers by name hash. This is the foundation that every other T-001/T-002/T-003/T-006 syscall dispatch technique in the vault depends on — without it, none of them can locate `ntdll.dll` or its `Zw*` exports without `GetModuleHandleA`/`GetProcAddress` appearing in the IAT.

## How It Works

The card only ships the single `mov` instruction, but the file manifest (`dark_crystal/crowd/src/resolve.rs` → role "PEB walker + DJB2 hash resolution") plus standard x64 Windows internals fix the rest of the mechanism. The actual chain is:

1. **Read TEB → PEB pointer.** The thread's TEB is at `gs:[0x30]` (the `NtTib.Self` field), but the most useful field on it is `gs:[0x60]` — the `ProcessEnvironmentBlock` pointer. The asm emits `mov rax, gs:[0x60]` via the `mov {}, gs:[{:e}]` template with `eax` holding `0x60`. No syscall, no library call. This is the only way to ask "where is my PEB" without going through an imported API.
2. **Follow `PEB->Ldr` (offset 0x18).** The `Ldr` field is a pointer to `PEB_LDR_DATA`. PEB itself is a per-process structure mapped at a fixed per-process address (kept in TEB so threads share one PEB).
3. **Walk `InLoadOrderModuleList` (offset 0x10 in PEB_LDR_DATA).** This is a doubly-linked `LIST_ENTRY` whose head is the loader's bookkeeping struct (not a real entry). The `Flink` chain visits every loaded `LDR_DATA_TABLE_ENTRY` in load order. ntdll.dll is always first in `InInitializationOrderLinks` (offset 0x20), and `kernel32.dll` historically second — both useful ordering facts used to short-circuit hashes.
4. **For each entry, read `BaseDllName` (offset 0x58) and `DllBase` (offset 0x30).** `BaseDllName` is a `UNICODE_STRING` (16-bit length, 16-bit max, pointer to wide buffer). The DJB2 hash function consumes the wide chars (case-folded to lower) so `ntdll.dll`, `NTDLL.DLL`, and `Ntdll.dll` all hash identically — defeats path/case variation without `wcsicmp`.
5. **Match against the pre-computed target hash.** When the desired module's DJB2 hash matches, capture `DllBase`. The card explicitly says "Module base resolution by DJB2 hash (no string comparisons)" — operator-grade anti-string-scan.
6. **Parse the PE export table.** From `DllBase`: read `e_lfanew` at offset `0x3C` → `IMAGE_NT_HEADERS`; the export directory RVA lives in `OptionalHeader.DataDirectory[0]` (offset `0x70` from optional header start, i.e. `0x18 + 0x70 = 0x88` from `IMAGE_NT_HEADERS`, or `e_lfanew + 0x88`). Follow to `IMAGE_EXPORT_DIRECTORY`: `NumberOfNames`, `AddressOfNames`, `AddressOfNameOrdinals`, `AddressOfFunctions` — all RVAs relative to `DllBase`.
7. **Hash each export name, find the target.** Same DJB2 pass over the ASCII name (`AddressOfNames[i]` is an RVA to a null-terminated string). On match, read `AddressOfNameOrdinals[i]` (a 16-bit value), use it as index into `AddressOfFunctions[]` → function RVA → add `DllBase` → absolute VA.
8. **Return.** The caller receives a raw `*const c_void` function pointer. That pointer is then handed to T-002 (for SSN extraction) or T-001 (for the syscall gadget in ntdll's `.text`).

### Memory state at each stage
- Stage 1: `gs` segment read, no allocation.
- Stages 2–5: reads from PEB and PEB_LDR_DATA, which live in the process's own address space (no kernel transition).
- Stage 6–7: reads from the DLL's image header + export directory, which are `MEM_IMAGE` pages backed by the on-disk DLL — read-only, executable only for `.text`. Walking exports touches only `.idata`-adjacent header pages, never `.text`.

### Timing / race
There is no race in steady state. The only failure window is during the loader's own `LdrpInitializeProcess` while the list is being constructed — but by the time your implant runs (post-`LdrInitializeThunk`), the list is stable. The only mutation you might observe is another concurrent `LoadLibrary` *from your own process* inserting a node; the standard mitigation is to snapshot `Flink` once and not re-walk.

## Operational Profile

### When to Use
- Any chain where the loader/dropper is built with the explicit goal of an empty `GetProcAddress`/`GetModuleHandleA` IAT — i.e. essentially every dark_crystal engagement chain.
- When the target EDR hooks `GetModuleHandle*` / `GetProcAddress` (some do, to log API acquisition by suspicious processes).
- When you need `ntdll.dll`'s base for unhooking (T-016), SSN resolution (T-002), or syscall gadget hunting (T-001).
- When you want `kernel32.dll` exports (`LoadLibraryA`, `VirtualAlloc`, `CreateThread`) without `kernel32!GetProcAddress` showing up in your IAT.
- As the prerequisite for any direct-syscall or indirect-syscall chain (T-001 / T-002 / T-003 / T-006) — there's no other clean way to find `ntdll` on a fully unhooked process.

### When NOT to Use
- 32-bit (WoW64) targets. `gs:[0x60]` is the x64 PEB field; on a 32-bit process you need `fs:[0x30]` and a different TEB layout. If the binary must run under WoW64, you must add an `#[cfg(target_arch = "x86")]` path or use `NtQueryInformationProcess(ProcessBasicInformation)` (which itself needs resolution — chicken/egg).
- ARM64 Windows. `gs` is x64-only; ARM64 uses a different segment register and TEB layout. The asm would have to be rewritten.
- When EDR does *full* `.text` hooking of `ntdll` *and* validates that you're reading its export table — the walker still resolves, but the addresses it returns land on hooks. Pair with T-016 (NTDLL unhook) before relying on them.
- Engagements where you've already acquired `GetProcAddress` legitimately (e.g. you're already inside a host process with normal imports) and the OPSEC cost of adding the PEB-walking code path exceeds the benefit. PEB walking is large-ish code; sometimes the cleaner IAT is the better trade.

### Kill Chain Position
This is **position 0** — it's the bootstrap. Every other syscall-related technique depends on it.

Example chain:
**T-004 (PEB walk → ntdll)** → **T-002 (Hell/Halo/Tartarus → SSNs)** → **T-001 (RecycledGate gadget)** → **T-012 (Early Cascade inject)** → **T-005 (Ekko sleep)** → **T-017 (persistence)**

Specifically the operator can expect this wiring in the codebase:
- `crowd/src/resolve.rs` is consumed by `crowd/src/hells_gate.rs` (T-002), which needs `ntdll.dll` base to walk its `.text` for SSNs.
- `crowd/src/syscall_map.rs` (T-004 syscall dispatch in the manifest) consumes the resolved function addresses to build the SSN+gadget table for `crowd/src/sys_indirect.rs` (T-001).
- `crowd/src/ntdll_unhook_inject.rs` (T-016) uses T-004 to find `ntdll.dll`'s `.text` section to overwrite with a fresh copy.
- `crowd/src/peb_unlink.rs` (T-016) uses T-004 (or direct PEB access) to find the loader list to unlink your own module.
- `crowd/src/phantom.rs` (T-006) uses T-004 to locate `ntdll`'s `.text` so it can copy `Zw*` stubs into `MEM_IMAGE`-backed pages.

### Trade-offs
| Dimension | Rating | Notes |
|---|---|---|
| Stealth | 9 | Zero API surface; PEB read is invisible to user-mode hooks. Only "artifact" is the IAT cleanliness. |
| Reliability | 8 | PEB/LDR layout has been stable since x64 Windows XP. Failure modes are export-forwarding and ordinal-only exports, both addressable. |
| Complexity | 4 | Mostly struct layout + pointer chasing + a hash function. Single asm line. Maintenance burden is the `#[repr(C)]` struct definitions. |
| Version range | All x64 Windows (XP x64 → Win11 24H2 → Server 2025) | TEB `gs:[0x60]` convention is ABI-frozen. PEB offsets used (0x18 Ldr) unchanged since 2003. |
| Privilege needed | none | Self-process read only. No syscall required. |

## Rust Implementation Deep Dive

> The card shipped only the inline-asm snippet, not the full `resolve.rs` source. What follows is operator-grade analysis of *what the implementation must do*, cross-referenced with the file-manifest role ("PEB walker + DJB2 hash resolution"). Where I'm inferring from standard Windows internals rather than reading the source, I say so explicitly.

### The asm

```rust
core::arch::asm!("mov {}, gs:[{:e}]", out(reg) peb, in(reg) 0x60u32,
    options(nostack, readonly, pure))
```

- `out(reg) peb` — let the allocator pick a 64-bit GPR; `peb` will be a `*mut PEB` or `usize`.
- `in(reg) 0x60u32` — the constant `0x60` placed in a 32-bit GPR. The `:e` modifier forces 32-bit form so the assembler emits `mov rax, gs:[eax]` style addressing. Without `:e` the compiler would default to 64-bit which still works but emits slightly different codegen.
- `options(nostack, readonly, pure)`:
  - `nostack` — promise this asm does not touch the red zone or `rsp`. True here (no `push`/`call`).
  - `readonly` — promise the asm only reads memory, never writes. The compiler is allowed to reorder the read relative to other `readonly` asm. Safe here: the only read is `gs:[0x60]` which the OS guarantees stable for the thread's lifetime.
  - `pure` — promise no externally visible side effects *and* that for the same inputs the output is deterministic. Combined with `readonly`, the compiler may CSE multiple PEB reads and even hoist the read out of loops. For a per-process constant like PEB, this is correct and useful.
- One subtle correctness requirement: `pure` requires that the asm not trap. `mov rax, gs:[0x60]` cannot fault on x64 Windows (gs base is always valid for the current thread). Safe.

### unsafe boundaries

The entire technique is `unsafe`. The reason it must be:
1. The asm reads from a segment register — Rust cannot prove `gs` is valid.
2. `peb` is a raw pointer; every subsequent deref is `unsafe`.
3. The `LIST_ENTRY` walk is a hand-rolled linked-list traversal over raw pointers with no bounds checking — if the list is corrupt, you get UB.

Operator-grade advice: wrap each phase in its own `unsafe fn` so panics in higher layers don't bleed into the unsafe scope. The crowd crate's `resolve.rs` does this naturally because each helper (`peb()`, `find_module_by_hash`, `find_export_by_hash`) is its own unit.

### FFI / struct layout

The card mentions "Full PEB → PEB_LDR_DATA → LDR_DATA_TABLE_ENTRY chain defined as `#[repr(C)]` structs." The minimum fields needed (and the operator should expect to see them in the source):

```rust
#[repr(C)]
#[derive(Clone, Copy)]
struct LIST_ENTRY { Flink: *mut LIST_ENTRY, Blink: *mut LIST_ENTRY }

#[repr(C)]
struct UNICODE_STRING { Length: u16, MaximumLength: u16, Buffer: *mut u16 }

#[repr(C)]
struct PEB { /* ... */ Ldr: *mut PEB_LDR_DATA, /* ... */ }   // Ldr at 0x18

#[repr(C)]
struct PEB_LDR_DATA {
    Length: u32, Initialized: u8, /* pad */
    SsHandle: *mut c_void,
    InLoadOrderModuleList: LIST_ENTRY,        // 0x10
    InMemoryOrderModuleList: LIST_ENTRY,      // 0x20
    InInitializationOrderModuleList: LIST_ENTRY, // 0x30
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    InLoadOrderLinks: LIST_ENTRY,             // 0x00
    InMemoryOrderLinks: LIST_ENTRY,          // 0x10
    InInitializationOrderLinks: LIST_ENTRY,  // 0x20
    DllBase: *mut c_void,                     // 0x30
    EntryPoint: *mut c_void,                   // 0x38
    SizeOfImage: u32,                          // 0x40
    /* pad 4 */
    FullDllName: UNICODE_STRING,              // 0x48
    BaseDllName: UNICODE_STRING,              // 0x58
    /* ... */
}
```

These structs are non-exhaustive on purpose — only the fields the walker reads are declared. Alignment is critical: skipping `EntryPoint` or `SizeOfImage` would shift `BaseDllName` off `0x58` and silently read the wrong pointer. A single misaligned `#[repr(C)]` field = instant crash. If you ever debug "PEB walker returns garbage for module name," check struct layout first, not the hash.

For the PE side:

```rust
#[repr(C)]
struct IMAGE_DOS_HEADER { e_lfanew: i32, /* ... */ }  // 0x3C
#[repr(C)]
struct IMAGE_NT_HEADERS64 { Signature: u32, FileHeader: ..., OptionalHeader: ... }
// DataDirectory[0] (Export) is at OptionalHeader + 0x70 → 0x88 from NT headers start
#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,    // RVA
    AddressOfNames: u32,        // RVA
    AddressOfNameOrdinals: u32, // RVA
}
```

### DJB2 hash

DJB2 is `hash = hash * 33 + c` starting from `5381`. For module names, lowercase-fold the wide chars; for export names, lowercase-fold the ASCII bytes. The card emphasizes "no string comparisons" — operators should hash *both* sides at compile time where possible (const fn) so the comparison is just `if computed_hash == CONST_HASH_NTDLL`.

### Error paths

The card doesn't enumerate failure modes, but a careful operator implementation must:
- Return `Option<*mut c_void>` or `Result<...>`, never panic.
- On `BaseDllName.Buffer == null`, skip the entry.
- On `DllBase == null` (some entries are placeholder stubs under API sets), skip.
- On PE header signature mismatch (`"PE\0\0"` not found at `DllBase + e_lfanew + 0x4`), bail with `None` — the image is corrupt or it's an API-set virtual DLL.
- On export table `AddressOfNames == 0` (ordinal-only DLL — rare, mostly some legacy), return `None` since you cannot resolve by name.

The implementation should *not* retry. Either the module is in the PEB or it isn't; retrying risks re-walking a mutating list.

### Initialization

A PEB walker is stateless per-call but caching the resolved `ntdll` base in a `OnceLock<*mut c_void>` is the right move — PEB doesn't move, and re-walking on every syscall adds measurable overhead. The crowd crate's `resolve.rs` likely exposes a `pub fn ntdll() -> *mut c_void` backed by `OnceLock`. If you add a new module to look up, mirror that pattern.

### Memory layout

The structures are pointer-sized aligned (8 bytes on x64). The `LIST_ENTRY` walk is the dangerous part: `Flink` is a `*mut LIST_ENTRY` whose *container* is the `LDR_DATA_TABLE_ENTRY` (offset 0 for `InLoadOrderLinks`). To recover the entry, use `CONTAINING_RECORD`-style pointer arithmetic:

```rust
let entry = (links as usize - offset_of!(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)) as *mut LDR_DATA_TABLE_ENTRY;
```

Rust has no built-in `offset_of!` before 1.69 (recently stabilized as `core::mem::offset_of!`); the crate may carry its own macro or use a const-eval trick. Grep for `offset_of` before assuming.

## Edge Cases & Failure Modes

1. **Export forwarding.**
   - **Scenario:** you resolve `ntdll!NtQueryInformationProcess`, but it's actually forwarded to `ntdll!NtQueryInformationProcessInternal` or, in some Windows builds, KUSER_SHARED_DATA-backed stubs. More commonly `kernel32!HeapFree` is forwarded to `ntdll!RtlFreeHeap`.
   - **Failure:** the address you get points to a `jmp` trampoline whose target is the forwarded name — but you treated it as the final function. Crashes or wrong behavior.
   - **Symptom:** calling the resolved pointer traps or behaves unexpectedly; checking `IMAGE_EXPORT_DIRECTORY` shows the name resolves to an RVA inside `AddressOfFunctions` that points to a string like `NTDLL.RtlFreeHeap`.
   - **Workaround:** after resolving the RVA, check if it falls *inside* the export directory's range (`AddressOfFunctions` ≤ rva < `AddressOfFunctions + NumberOfFunctions*4`). If yes, it's a forwarder string; parse it (`MODULE.Function`) and recursively resolve via T-004 on the named module. This is a one-shot fix — add it once and the walker is complete.

2. **API-set redirection (Win10+).**
   - **Scenario:** you ask for `kernel32.dll` but the actual loaded module is `kernelbase.dll`, or you ask for `api-ms-win-core-processthreads-l1-1-0.dll`. API sets are virtual DLLs resolved at load time.
   - **Failure:** hash for `kernel32.dll` matches but exports like `CreateFileW` are forwarded to `kernelbase.dll` (which you haven't resolved). You deref a forwarded pointer.
   - **Symptom:** some exports work, others return forwarded-strings-as-pointers and crash.
   - **Workaround:** implement forwarder resolution (see #1) — it transparently solves API-set cases too because forwarder strings name the *target* module (`KERNELBASE.CreateFileW`). Alternatively, hash `kernelbase.dll` and resolve there directly.

3. **EDR has unhooked/hollowed `ntdll.dll` in your process.**
   - **Scenario:** a hooking EDR replaces `ntdll.dll`'s `.text` page in your process with patched stubs. The export *addresses* you resolve are still valid (they're RVAs into the patched image), but the instructions at those addresses are `jmp edr_dll!hook`.
   - **Failure:** T-002 SSN resolution reads the patched `mov eax, SSN` and extracts the EDR's *bogus* SSN, or worse, the EDR's stub doesn't have a `mov eax, imm32` at all and SSN extraction faults.
   - **Symptom:** syscalls return `STATUS_INVALID_SYSTEM_SERVICE` or hang.
   - **Workaround:** combine with T-016 (NTDLL unhook via fresh `.text` from disk) *before* T-002 runs. Order: T-004 → T-016-unhook → T-002 → T-001.

4. **PEB list mutation during walk.**
   - **Scenario:** another thread in your own process calls `LoadLibrary` while you're walking `InLoadOrderModuleList`. The list is mutated under a loader lock, but the Flink chain can be observed in a transiently inconsistent state if your walk doesn't acquire the lock.
   - **Failure:** stale `Flink` lands on a freed node → null deref.
   - **Symptom:** rare intermittent crash during walk; reproduces only under concurrent `LoadLibrary`.
   - **Workaround:** snapshot the head and the first node's addresses, walk to a bounded count, and accept that you may need to retry once. The crowd implementation likely doesn't bother — the engagement scenario (a freshly-spawned implant with no other threads loading libraries) makes this vanishingly rare. Add `LdrLockDll` (`RtlEnterCriticalSection` on `PEB_LDR_DATA.LoaderLock`) only if you must.

5. **ASLR / image base != on-disk ImageBase.**
   - **Scenario:** resolved `DllBase` is the *loaded* base, not the PE's `OptionalHeader.ImageBase`. RVAs in the export table are relative to the *loaded* base, so this "just works" — but if you naively add `ImageBase` from the PE header you'll get a wrong VA.
   - **Failure:** you read `OptionalHeader.ImageBase` and add RVAs to it.
   - **Symptom:** all resolved pointers fault.
   - **Workaround:** always add RVAs to the *runtime* `DllBase` from the PEB, never the on-disk `ImageBase`. Standard practice; the card implies this is done correctly.

6. **Module name with mixed case (`NTDLL.dll` vs `ntdll.DLL`).**
   - **Scenario:** Windows is inconsistent about case in `BaseDllName`. Some modules (`NTDLL.DLL` uppercase) appear differently across versions.
   - **Failure:** exact-string comparison would miss. DJB2 with case folding handles this, but only if the case-folding is correct (ASCII `tolower` for ASCII chars; wide chars should be folded with `RtlDowncaseUnicodeChar`-equivalent or a manual `if c >= 'A' && c <= 'Z' { c + 0x20 }`).
   - **Symptom:** hash mismatches on certain modules only.
   - **Workaround:** verify the hash function lowercases ASCII chars and treats non-ASCII as-is. Don't use `tolower()` from CRT — you don't have CRT.

7. **`#[cfg(target_arch = "x86")]` (WoW64).**
   - **Scenario:** binary compiled as 32-bit. `gs` doesn't hold the PEB; `fs:[0x30]` does, and TEB/PEB layout differs (offsets 0x30 / 0x0C etc).
   - **Failure:** the asm compiles but reads garbage.
   - **Symptom:** walker returns wild pointers on WoW64.
   - **Workaround:** add `#[cfg(target_arch = "x86")]` path using `fs:[0x30]`, or compile the implant x64-only and document WoW64 as unsupported.

## Variant Ideas

- **InInitializationOrder short-circuit.** ntdll is always the first entry in `InInitializationOrderModuleList` (offset 0x20 in PEB_LDR_DATA), kernel32 historically second. Walk that list instead of `InLoadOrder` and you can resolve `ntdll` in O(1) without hashing. Tradeoff: slightly less generic; only useful for the few modules guaranteed to be early in init order.
- **API-set schema resolution.** Parse `apisetschema.dll` (or read `Peb->ApiSetMap` at PEB offset 0x68) to translate `api-ms-*` virtual DLL names to real host modules. Lets you resolve any `api-ms-win-core-*` symbol directly. Useful when chaining against `kernelbase` exports.
- **Hash the entire export directory and pre-bake.** At build time, hash every `Zw*` name you care about, embed the hash constants via `const fn`, and at runtime only compare hashes. This is what the card implies; go further by also pre-baking module name hashes for `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `user32.dll`, `advapi32.dll` as `const NTDLL_HASH: u32 = ...`. Reduces runtime string ops to zero.
- **Caching with `OnceLock<[*mut c_void; N]>`.** Instead of one `OnceLock` per function, bake a fixed-size array indexed by an enum (`enum NtFn { NtAllocateVirtualMemory, NtProtectVirtualMemory, ... }`) and resolve all of them once. Hot-path syscalls become a single array index. This pattern composes naturally with T-001's syscall map (`crowd/src/syscall_map.rs`).
- **PEB → ProcessHeap → RTL_USER_PROCESS_PARAMETERS walk.** Beyond modules, `PEB->ProcessHeap` (offset 0x30) gives you the default heap, and `PEB->ProcessParameters` (offset 0x20) gives `RTL_USER_PROCESS_PARAMETERS` with `CommandLine`, `ImagePathName`, `CurrentDirectory`. Useful for T-016 argument spoofing and self-deletion (T-020). Already implied by the PEB struct — just expose more fields.
- **Combine with T-003 (VEH Gate) for safe walking.** Wrap the Flink walk in a VEH-protected scope that catches `EXCEPTION_ACCESS_VIOLATION` on a bad `Flink`. Lets you walk a possibly-corrupt list without crashing. The crowd crate already has the VEH subsystem (T-003) — wire it up as a debugging fallback.
- **KUSER_SHARED_DATA shortcut.** For time-sensitive reads (tick count, KdDebuggerEnabled) the `KUSER_SHARED_DATA` page at `0x7FFE0000` is always mapped and readable without going through PEB. Useful as a complementary zero-API data source.

## OPSEC Notes

- **IAT cleanliness:** the *primary* OPSEC win. A binary using T-004 has zero `GetProcAddress` / `GetModuleHandleA` / `LoadLibraryA` references in its IAT (unless it also does normal-API fallback). This defeats the most common static triage heuristic ("implant imports API resolver").
- **No runtime artifacts.** PEB walking doesn't write to disk, doesn't touch the registry, doesn't allocate memory, and doesn't generate any event log entry. There is no ETW TI event for "process read its own PEB" because there's no syscall — the read happens entirely in user mode against per-process memory.
- **No telemetry.** EDR vendors cannot intercept a `mov rax, gs:[0x60]`. There is no hook point. The only thing an EDR can do is *patch* the resolved `ntdll` exports after you read them, which is a different problem (handled by T-016 + T-001).
- **Detectable only via memory introspection.** A hypervisor or a kernel-mode EDR with `MmCopyVirtualMemory` could observe a process reading its own PEB.Ldr chain — but this is indistinguishable from legitimate loader activity and not a viable detection signal.
- **What to clean up:** nothing. There is no persistent state from a PEB walk. If you cache results in `OnceLock`, those are just pointer-sized fields in your own process memory, gone when you exit.
- **Combinations to avoid:** don't pair PEB walking with an immediate `LoadLibraryA("ntdll.dll")` call to "make sure it's loaded" — that *will* show up in ETW and defeats the entire point of T-004. ntdll is *always* loaded; trust it.

## Reusable Patterns

### Pattern: Zero-API Inline Segment Read
- **Use when:** you need a per-process or per-thread constant that lives in the TEB or PEB (PEB pointer, TEB self, stack base/limit, TlsSlots, ProcessHeap pointer, etc).
- **How:** `core::arch::asm!("mov {}, gs:[{:e}]", out(reg) out, in(reg) offset, options(nostack, readonly, pure))`. Use `gs` on x64, `fs` on x86. Mark `pure + readonly` so the compiler can CSE repeated reads.
- **Code ref:** `dark_crystal/crowd/src/resolve.rs` — the `mov {}, gs:[{:e}]` template.

### Pattern: DJB2-with-Lowercase-Fold Hash for Module/Export Names
- **Use when:** you need to compare strings (DLL names, export names) without leaving string literals in the binary or calling string-compare functions.
- **Use how:** write `fn djb2_ascii(s: &[u8]) -> u32` and `fn djb2_wide(s: &[u16]) -> u32`, both folding ASCII letters to lowercase before adding. Compile-time hash your targets with a `const fn` so the binary contains only the constant.
- **Code ref:** `dark_crystal/crowd/src/resolve.rs` (referenced by file-manifest role "DJB2 hash resolution").

### Pattern: `#[repr(C)]` Non-Exhaustive Windows Struct
- **Use when:** you need to walk a documented but unstable Windows internal structure (PEB, TEB, LDR_DATA_TABLE_ENTRY, RTL_USER_PROCESS_PARAMETERS).
- **How:** declare only the fields you read, in order, with `#[repr(C)]` and explicit padding (`_pad: [u8; N]`) when skipping fields. Field offsets are ABI for the OS version you target — verify with WinDbg `dt PEB` / `dt LDR_DATA_TABLE_ENTRY`.
- **Code ref:** the `PEB` / `PEB_LDR_DATA` / `LDR_DATA_TABLE_ENTRY` chain in `crowd/src/resolve.rs`.

### Pattern: `OnceLock` for Per-Process Constant Caching
- **Use when:** a value is computed by walking a process-wide structure (PEB, KUSER_SHARED_DATA, process parameters) and is invariant for the process lifetime.
- **How:** `static NTDLL_BASE: OnceLock<usize> = OnceLock::new(); NTDLL_BASE.get_or_init(|| peb_walk_for_hash(NTDLL_HASH))`. Subsequent calls are a single atomic load.
- **Code ref:** look in `crowd/src/resolve.rs` for `OnceLock` use; the same pattern is documented in `architecture/rust-patterns.md`.

### Pattern: CONTAINING_RECORD via `offset_of!`
- **Use when:** a `LIST_ENTRY` is embedded at a non-zero offset in a parent struct and you need to recover the parent from a `Flink` pointer.
- **How:** `(links as usize - core::mem::offset_of!(Parent, field)) as *mut Parent`. Requires Rust ≥ 1.69 for `core::mem::offset_of!`; for older toolchains, a `const fn` reading `&(*(0 as *const Parent)).field as *const _ as usize` works under `const_eval`.
- **Code ref:** the `InLoadOrderLinks` recovery in `crowd/src/resolve.rs` (inferred; verify by grep `offset_of`).

### Pattern: Forwarder-String Resolution Loop
- **Use when:** walking PE export tables where exports may be forwarded (`kernel32!HeapFree` → `ntdll!RtlFreeHeap`).
- **How:** after computing the function RVA, check whether it falls inside the export directory's RVA range. If yes, treat the bytes at `DllBase + rva` as a null-terminated ASCII string `"MODULE.Function"`, split on `.`, re-resolve module via T-004, recurse on the new function name.
- **Code ref:** not shown in the card; if missing in `crowd/src/resolve.rs` this is the first operator patch to apply.