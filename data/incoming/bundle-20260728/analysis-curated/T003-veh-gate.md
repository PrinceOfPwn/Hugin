---
id: T-003
name: VEH Syscall Gate
category: syscalls
tier: S
mitre: T1106
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires: [T-004]
enables: [T-005, T-007, T-009, T-012, T-014, T-015, T-017]
vault_references:
  - dark_crystal/crowd/src/veh_gate.rs
  - dark_crystal/crates/core/src/experimental/evasion/veh/hooks.rs
  - dark_crystal/crates/core/src/experimental/evasion/veh/syscall.rs
  - dark_crystal/crates/core/src/experimental/evasion/veh/def.rs
implements:
  - file: dark_crystal/crowd/src/veh_gate.rs
    key_functions: [initialize, destroy, set_hw_bp, take_last_rax, get_ssn_by_name, find_peb, ldr_module_info, hash_unicode_djb2, djb2_hash, cstr_len, AddHwBp, HandlerHwBp, syscall_trampoline]
    key_structs: [SyscallState, DllInfo, ListEntry, UnicodeString, SectionPointer, HashLinksOrSectionPointer, TimeDateStampOrLoadedImports, LoaderDataTableEntry, PebLoaderData, PEB, ImageDosHeader, ImageFileHeader, ImageDataDirectory, ImageOptionalHeader64, ImageNtHeaders, ImageExportDirectory, ImageRuntimeFunctionEntry]
    key_constants: [CALL_FIRST, EXCEPTION_ACCESS_VIOLATION, EXCEPTION_SINGLE_STEP, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, TRACE_FLAG, OPCODE_CALL, OPCODE_RET, OPCODE_RET_CC, OPCODE_SUB_RSP, OPCODE_SZ_ACC_VIO, FIFTH_ARGUMENT, NTDLL_HASH, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, IMAGE_DIRECTORY_ENTRY_EXCEPTION]
    lines_of_interest:
      - "L160-L180: find_peb() inline asm reading gs:[0x60]"
      - "L260-L340: get_ssn_by_name() PEB walk + Exception Directory SSN resolution"
      - "L390-L430: AddHwBp() ACCESS_VIOLATION handler, scans 25 bytes for 0F 05"
      - "L440-L590: HandlerHwBp() three-case state machine (DR0 hit / single-step / DR1 hit)"
      - "L640-L700: initialize() handler registration + ntdll resolution with cleanup"
      - "L730-L745: set_hw_bp() inline asm triggering null-deref AV"
      - "L780-L820: veh_syscall! macro with param_count extended-args detection"
  - file: dark_crystal/crates/core/src/experimental/evasion/veh/hooks.rs
    key_functions: [initialize_hooks, destroy_hooks, set_hw_bp, take_last_rax, initialize_dll_info, AddHwBp, HandlerHwBp, syscall_trampoline]
    key_structs: [SyscallState]
    key_constants: []
    lines_of_interest:
      - "L20-L40: imports from def.rs and utils, debug_println! macro"
      - "L75-L130: AddHwBp with verbose debug logging"
      - "L132-L260: HandlerHwBp mirror of crowd version"
      - "L265-L295: initialize_hooks() — silent failure path (no Result)"
  - file: dark_crystal/crates/core/src/experimental/evasion/veh/syscall.rs
    key_functions: [get_ssn_by_name]
    key_structs: [ImageRuntimeFunctionEntry, IMAGE_RUNTIME_FUNCTION_ENTRY_u]
    key_constants: []
    lines_of_interest:
      - "L1-L60: syscall! macro using crate::get_ssn_by_name and crate::set_hw_bp"
      - "L75-L180: get_ssn_by_name with MDsec Exception Directory technique"
      - "L185-L210: ImageRuntimeFunctionEntry struct + PimageRuntimeFunctionEntry type alias"
  - file: dark_crystal/crates/core/src/experimental/evasion/veh/def.rs
    key_functions: []
    key_structs: [DllInfo, ListEntry, UnicodeString, SectionPointer, HashLinksOrSectionPointer, TimeDateStampOrLoadedImports, LoaderDataTableEntry, PebLoaderData, PEB, RtlUserProcessParameters, ImageDosHeader, ImageFileHeader, ImageDataDirectory, ImageExportDirectory, ImageNtHeaders, ImageOptionalHeader64]
    key_constants: [OPCODE_SUB_RSP, OPCODE_RET_CC, OPCODE_RET, OPCODE_CALL, CALL_FIRST, TRACE_FLAG, OPCODE_SZ_ACC_VIO, FIFTH_ARGUMENT, SIXTH_ARGUMENT, SEVENTH_ARGUMENT, EIGHTH_ARGUMENT, NINTH_ARGUMENT, TENTH_ARGUMENT, ELEVENTH_ARGUMENT, TWELFETH_ARGUMENT, EXCEPTION_ACCESS_VIOLATION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_SINGLE_STEP, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE]
    lines_of_interest:
      - "L1-L30: opcode constants + arg offset table"
      - "L60-L120: PEB / PebLoaderData / LoaderDataTableEntry repr(C) definitions"
      - "L120-L170: full PEB struct (complete, vs crowd's trimmed version)"
      - "L210-L260: ImageOptionalHeader64 with data_directory[16]"
min_windows: "7 x64 (technique); 10 1607+ (purpose: ETW-TI evasion)"
needs_admin: "no"
tags: [syscalls, veh, hardware-breakpoints, exception-handling, etw-ti-evasion, indirect-syscalls, ssn-resolution, peb-walk]
---

# VEH Syscall Gate — Operator Playbook

## TL;DR
The VEH Syscall Gate hijacks ntdll's syscall stubs by arming DR0/DR1 hardware breakpoints through a self-induced ACCESS_VIOLATION, then single-steps the CPU through ntdll's prologue until the `syscall` instruction. The kernel sees a `KiSystemCall64` transition originating from inside `ntdll.dll`'s `.text` section, defeating stack-based ETW-TI telemetry and unbacked-memory detections. It is the cleanest user-mode syscall primitive in the dark_crystal crate, at the cost of ~3-5k cycles of exception overhead per call and global VEH handler state.

## Source File Map

| File | Role | Key Exports | Size |
|---|---|---|---|
| `dark_crystal/crowd/src/veh_gate.rs` | Consolidated single-file port of the 5-file experimental module; uses anyhow::Result for clean init; production builder pipeline | `initialize()`, `destroy()`, `set_hw_bp()`, `take_last_rax()`, `get_ssn_by_name()`, `veh_syscall!` | ~920 lines |
| `dark_crystal/crates/core/src/experimental/evasion/veh/hooks.rs` | Original module: VEH handler registration, SyscallState machine, debug-gated logging | `initialize_hooks()`, `destroy_hooks()`, `set_hw_bp()`, `take_last_rax()`, `AddHwBp`, `HandlerHwBp`, `syscall_trampoline` | ~340 lines |
| `dark_crystal/crates/core/src/experimental/evasion/veh/syscall.rs` | SSN resolution via MDsec Exception Directory technique + `syscall!` macro; **typo bug**: calls `dbj2_hash` instead of `djb2_hash` | `get_ssn_by_name()`, `syscall!`, `ImageRuntimeFunctionEntry`, `PimageRuntimeFunctionEntry` | ~210 lines |
| `dark_crystal/crates/core/src/experimental/evasion/veh/def.rs` | All repr(C) struct definitions + opcode/argument-offset constants; complete PEB layout | `DllInfo`, `PEB`, `LoaderDataTableEntry`, all OPCODE_* / *_ARGUMENT constants | ~260 lines |

## How It Works

The technique is a five-phase state machine driven entirely by hardware exception delivery. Trace it function by function:

1. **Initialization (`veh_gate::initialize()`)** — registers two VEH handlers via `AddVectoredExceptionHandler(CALL_FIRST, Some(AddHwBp))` and `AddVectoredExceptionHandler(CALL_FIRST, Some(HandlerHwBp))`. Both use `CALL_FIRST = 1` so they execute before any application-installed VEH. If H2 registration fails, H1 is rolled back via `RemoveVectoredExceptionHandler(H1)`. After handler registration, `ldr_module_info(NTDLL_HASH)` walks the PEB to capture ntdll's `base_address` and `end_address` into `NTDLL_INFO`. `NTDLL_HASH = 0x1edab0ed` is the DJB2 hash of `"ntdll.dll"` (case-insensitive). The end_address is computed as `base.add(size_of_image)`, used later to bound the single-step window.

2. **SSN + stub address resolution (`get_ssn_by_name()`)** — walks PEB InMemoryOrderModuleList, for each LDR entry parses `ImageDosHeader.e_lfanew` to find `ImageNtHeaders`, reads `data_directory[0]` (Export Directory). Filters modules by DJB2 hash of the export directory's `name` field against `NTDLL_HASH`. When ntdll is found, reads `data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]` (= 3) — the runtime function table, which is **sorted by `begin_address` RVA**. For each runtime function entry, scans the Export Address Table for a function whose RVA matches `begin_address`. When found, if the name matches the requested syscall, returns the current SSN counter and writes the stub address into `addr`. SSN is incremented only when the matched export name starts with `"Zw"` — because the runtime function table is sorted by address and Zw* stubs are emitted in SSN order, this correlation yields the exact SSN. Returns `-1` on failure.

3. **Triggering the AV (`set_hw_bp(addr, extended, ssn)`)** — stores `extended_args` (bool) and `syscall_no` into the global `STATE` Mutex. Then executes:
   ```asm
   xor rax, rax
   mov edx, dword ptr [rax]
   ```
   with `addr` passed in `rcx`. The `mov edx, [0]` dereferences null, raising `EXCEPTION_ACCESS_VIOLATION (0xC0000005)`. The target ntdll stub address is smuggled through RCX because x64 Windows passes the first integer arg in RCX — so the handler reads it back from the saved CONTEXT.

4. **First VEH handler (`AddHwBp`)** — receives the AV. Reads `Rcx` from `ContextRecord` (= target stub address). Scans up to 25 bytes from `entry_address` looking for the byte sequence `0F 05` (SYSCALL). Stores `opcode_syscall_off` (= offset to 0F 05) and `opcode_syscall_ret_off` (= offset + 2, the byte after the RET that follows SYSCALL). Sets `Dr0 = entry_address` (syscall entry breakpoint) and `Dr1 = entry_address + off_ret` (post-SYSCALL breakpoint). Sets `Dr7 |= 1<<0` (local enable DR0) and `Dr7 |= 1<<2` (local enable DR1). Advances `Rip += OPCODE_SZ_ACC_VIO` (= 2) to skip past the faulting `xor rax,rax` instruction. Returns `EXCEPTION_CONTINUE_EXECUTION`.

5. **Second VEH handler (`HandlerHwBp`)** — receives every `EXCEPTION_SINGLE_STEP (0x80000004)`. Three cases:
   - **Case A — DR0 hit (syscall entry)**: `ExceptionAddress == entry_address`. Clears DR0 (sets `Dr0 = 0`, `Dr7 &= !(1<<0)`). Allocates a `Box<CONTEXT>`, `ptr::copy_nonoverlapping`s the current ContextRecord into it, stores into `SAVED_CONTEXT`. Redirects `Rip = syscall_trampoline as u64` (an empty `extern "C" fn` used purely as a benign RIP target). Sets `EFlags |= TRACE_FLAG (0x100)` to keep single-stepping.
   - **Case B — Single-stepping inside ntdll**: `Rip` is within `[ntdll_base, ntdll_end]`. Three sub-phases tracked via `is_sub_rsp`:
     - **Phase 0 (is_sub_rsp == 0)**: Scans up to 80 bytes from current RIP for `ret;int3` (boundary, `0xCCC3` little-endian → break), or `sub rsp, imm8` pattern (`opcode & 0xFFFFFF == 0xEC8348`). If `imm8 >= 0x58` (48 bytes — typical ntdll stub stack frame), sets `is_sub_rsp = 1` and re-arms `TRACE_FLAG`. Otherwise breaks (wrong function).
     - **Phase 1 (is_sub_rsp == 1)**: Reads u16 at RIP. If `0xCCC3` or low byte `0xC3` (RET) → reset to 0. If low byte `0xE8` (CALL) → set `is_sub_rsp = 2`, keep stepping. This is the internal `call` within the ntdll stub (e.g., to `Wo64GetSystemServiceCallNumber` or similar pre-syscall helper).
     - **Phase 2 (is_sub_rsp == 2)**: The internal call returned. Sets `is_sub_rsp = 0`. Snapshots current `Rsp` into `temp_rsp`. `ptr::copy_nonoverlapping`s the **saved** CONTEXT back over the live ContextRecord (restoring caller's registers). Restores `Rsp = temp_rsp` (preserves the deep ntdll stack frame). Sets `R10 = Rcx` (Windows syscall ABI: 1st arg goes to R10 not RCX because RCX is clobbered by `syscall`), `Rax = ssn` (SSN), `Rip = entry_address + sys_off` (points at the `0F 05` byte). If `extended_args`, copies 5th-12th arguments from `saved.Rsp + offset` to `current.Rsp + offset` (8 bytes each, offsets 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60). Clears `TRACE_FLAG`. Returns `EXCEPTION_CONTINUE_EXECUTION` — CPU now executes the `syscall` instruction natively.
   - **Case C — DR1 hit (after SYSCALL;RET)**: `ExceptionAddress == ret_address`. Clears DR1 (`Dr1 = 0`, `Dr7 &= !(1<<2)`). Restores `Rsp` from `SAVED_CONTEXT.Rsp` (caller's original stack pointer). Captures `Rax` into `LAST_RAX` Mutex (the NTSTATUS). Returns `EXCEPTION_CONTINUE_EXECUTION`.

The result: the syscall executes with `Rip` pointing into ntdll's `.text`, RSP inside ntdll's prologue frame, no Win32 API imports, no direct syscall instruction in operator's own image. ETW-TI's stack walk at `EtwTiLogSysCall` sees a return address chain rooted in `ntdll.dll`.

## Code Architecture

### Module Split (experimental vs. consolidated)

The 5-file `crates/core/src/experimental/evasion/veh/` module has been **consolidated** into the single `crowd/src/veh_gate.rs` for the production builder pipeline. Functionally equivalent, with these deltas:

| Aspect | experimental (veh/) | crowd (veh_gate.rs) |
|---|---|---|
| Init return type | `()` (silent failure, debug print) | `anyhow::Result<()>` (propagated) |
| `set_hw_bp` flag type | `flag: i32` | `extended: u8` (cleaner) |
| Debug logging | `debug_println!` gated by `verbose_debug` feature + `selection_config::verbose_debug()` runtime check | removed |
| PEB struct | Full `PEB` with `RtlUserProcessParameters`, `process_parameters`, etc. | Trimmed — only fields through `loader_data` |
| SSN resolver | In `syscall.rs`, uses `super::utils::{dbj2_hash, find_peb, get_cstr_len}` | Inline in same file, uses `djb2_hash`, `find_peb`, `cstr_len` |
| Macro | `syscall!` | `veh_syscall!` |

### Call Graph

```
veh_syscall! macro
  ├─ veh_gate::get_ssn_by_name(name, None, &mut addr)   [SSN + stub addr]
  ├─ veh_gate::set_hw_bp(addr, extended, ssn)            [triggers AV]
  │     └─ asm!("xor rax,rax"; "mov edx,[rax]")          [ACCESS_VIOLATION]
  │           └─ AddHwBp (VEH #1, CALL_FIRST)
  │                 ├─ reads RCX (stub addr)
  │                 ├─ scans 25 bytes for 0F 05
  │                 ├─ sets Dr0 = entry, Dr1 = entry + ret_off
  │                 └─ Rip += 2  [skip faulting instr]
  └─ pt_syscall(params...)                                [call stub]
        └─ (CPU hits Dr0 → SINGLE_STEP)
              └─ HandlerHwBp (VEH #2, CALL_FIRST)
                    ├─ Case A: Dr0 hit → save CONTEXT, Rip = syscall_trampoline, set TRACE_FLAG
                    ├─ Case B: single-step ntdll → find sub_rsp,0x58 + call → restore, set R10/RAX/RIP
                    └─ Case C: Dr1 hit → save RAX, restore RSP, clear DR0/DR1
```

### Data Flow

- **Static state** (all `Mutex<>`-protected globals):
  - `STATE: Mutex<SyscallState>` — current syscall in flight: `syscall_entry_address`, `opcode_syscall_off`, `opcode_syscall_ret_off`, `is_sub_rsp` (phase counter 0→1→2→0), `syscall_no` (SSN), `extended_args`
  - `NTDLL_INFO: Mutex<DllInfo>` — `[base_address, end_address]` bound for single-step window
  - `SAVED_CONTEXT: Mutex<Option<Box<CONTEXT>>>` — full caller CONTEXT captured at DR0 hit, restored at SYSCALL
  - `LAST_RAX: Mutex<Option<u64>>` — NTSTATUS from last syscall (consumed via `take_last_rax()`)
  - `static mut H1/H2: *mut c_void` — VEH registration handles (raw, no RAII; cleaned in `destroy()`)

- **Type hierarchy**: `EXCEPTION_POINTERS → CONTEXT → {Dr0..Dr7, Rip, Rsp, Rax, Rcx, R10, EFlags}` — the handler mutates these fields directly via `*ei.ContextRecord`.

### Feature Gates

- `#[cfg(target_arch = "x86_64")]` gates `find_peb()` (uses `gs:[0x60]`) and `ImageNtHeaders`/`ImageOptionalHeader64`
- `#[cfg(feature = "verbose_debug")]` gates `debug_println!` in experimental module
- `#[allow(static_mut_refs)]` on `initialize`/`destroy` — suppresses `static_mut_refs` lint for H1/H2 mutation
- `#[allow(dead_code, non_snake_case, non_camel_case_types)]` at top of `veh_gate.rs` — required because Win32 convention uses CamelCase structs and snake_case would break FFI

## Operational Profile

### When to Use
- Engagements against EDR with **ETW-TI kernel telemetry** (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne) — these walk the call stack at `KiSystemCall64` and flag transitions originating outside ntdll
- Long-running implants where syscall stealth matters more than per-call latency (3-5k cycle overhead per call due to exception delivery)
- When paired with T-005 Ekko sleep or T-007 Pool Party — both rely on `Nt*` calls that benefit from clean stacks
- When the operator's image must avoid containing a `0F 05` byte sequence anywhere (RIP-based detections)

### When NOT to Use
- High-throughput syscall paths (e.g. file copy loops, screen capture frame pumps) — exception overhead is ~100x direct syscall cost
- Pre-initialization: `initialize()` requires PEB walk to succeed; if called too early in loader (TLS callback before Ldr completes), `NTDLL_INFO` will be empty and Case B of `HandlerHwBp` will fail to bound-check
- Cross-thread concurrent syscalls: `SAVED_CONTEXT` is a single-slot `Option<Box<CONTEXT>>` Mutex — two threads hitting DR0 simultaneously will corrupt each other's saved context
- Targets with custom ntdll (e.g. compatibility shims, custom loaders) where Exception Directory sort order may be broken
- When the operator cannot afford ANY ntdll probing at runtime — `get_ssn_by_name` walks InMemoryOrderModuleList

### Kill Chain Position

`T-004 (PEB walk)` → **`T-003 (VEH Gate)`** → `T-005 (Ekko sleep)` / `T-007 (Pool Party)` / `T-012 (Early Cascade)` → `T-017 (persistence)`

VEH Gate sits AFTER module resolution but BEFORE any NT operation that needs stealth. It's a syscall dispatcher, not a payload — pair it with any technique that performs NT API calls into a hardened target.

### Trade-offs

## Rust Implementation Deep Dive

### `unsafe` blocks — exhaustive list

1. **`find_peb()` (veh_gate.rs)** — single-statement `asm!("mov {}, gs:[0x60]", out(reg) peb)`. Reads PEB pointer from GS segment. `#[inline(always)]` for inlining into callers. Returns `*mut PEB`.

2. **`hash_unicode_djb2(buffer, length_bytes)` (veh_gate.rs)** — constructs `core::slice::from_raw_parts(buffer, wide_len)` from raw `*const u16`. Walks UTF-16LE bytes, casts low byte to ASCII uppercase, hashes with DJB2.

3. **`cstr_len(p)` (veh_gate.rs)** — manual strlen: walks `*const u8` until `*cur == 0`, returns `cur as usize - p as usize`.

4. **`ldr_module_info(module_hash)` (veh_gate.rs)** — walks PEB `InLoadOrderModuleList`. For each `LoaderDataTableEntry`, hashes `base_dll_name.buffer` and compares. On match, parses `ImageDosHeader.e_lfanew` → `ImageNtHeaders.optional_header.size_of_image`. Returns `(dll_base as *const u8, size)`.

5. **`get_ssn_by_name(syscall_name, hash, addr)` (veh_gate.rs / syscall.rs)** — walks `InMemoryOrderModuleList`. For each module, parses DOS/NT headers, reads `data_directory[0]` (Export). Filters by DJB2 hash of export directory's `name` field. Reads `data_directory[3]` (Exception). Nested loop: outer over `rtf` (runtime function table, sorted), inner over export name table. **Mismatch bug** in syscall.rs: calls `dbj2_hash` (typo) vs `djb2_hash` (correct) — would fail to compile unless `dbj2_hash` is aliased somewhere upstream; veh_gate.rs uses the correctly-spelled `djb2_hash` and works.

6. **`AddHwBp(exception_info)` (veh_gate.rs / hooks.rs)** — `extern "system"`. Reads `(*ei.ContextRecord).Rcx`, `ptr::read`s up to 25 bytes from `entry_address` looking for `0F 05`. Writes to `(*ei.ContextRecord).Dr0`, `.Dr1`, `.Dr7`, `.Rip`. Returns `i32` (EXCEPTION_CONTINUE_EXECUTION / SEARCH).

7. **`HandlerHwBp(exception_info)` (veh_gate.rs / hooks.rs)** — `extern "system"`. The big one. Three cases dispatched on `(*ei.ExceptionRecord).ExceptionAddress`. Case B has three sub-phases via `state.is_sub_rsp`. In phase 2, `ptr::copy_nonoverlapping`s `SAVED_CONTEXT` back over live ContextRecord. Uses `copy_stack_arg!` macro (veh_gate.rs) or inline `ptr::copy_nonoverlapping` calls (hooks.rs) to copy 8 extended args.

8. **`syscall_trampoline()` (veh_gate.rs / hooks.rs)** — `unsafe extern "C" fn` with empty body. Used purely as a benign RIP redirect target — single instruction is `ret`. `unsafe` because extern fn body is technically unsafe (no safety contract).

9. **`set_hw_bp(addr, extended, ssn)` (veh_gate.rs / hooks.rs)** — inline `core::arch::asm!` block:
   ```rust
   core::arch::asm!(
       "xor rax, rax",
       "mov edx, dword ptr [rax]",
       in("rcx") addr,
       out("rax") _,
       out("rdx") _,
       clobber_abi("system"),
   );
   ```
   `in("rcx") addr` — passes ntdll stub address to handler via RCX. `out("rax") _`, `out("rdx") _` — discard outputs. `clobber_abi("system")` — declares System V clobbers. The `mov edx, [rax]` is the actual AV trigger (RAX is 0).

10. **`veh_syscall!` macro body** — `core::mem::transmute(syscall_addr)` to cast `*mut u8` to typed fn pointer `pt_syscall: $fn_sig`. Then `set_hw_bp(addr, extended, ssn)`. Then `pt_syscall($($param),*)`. The "extended" flag is computed at macro expansion by counting params: `let mut n = 0u8; $(let _ = &$param; n += 1;)*` — clever but fragile: it counts *macro token* count, not actual stack-passed args. For a function with 5+ args, the 5th+ go on the stack and must be copied in Case B phase 2.

### Initialization patterns

- `static STATE: Mutex<SyscallState> = Mutex::new(SyscallState { ... })` — const-evaluable Mutex init, no `OnceLock`/`Lazy` needed
- `static SAVED_CONTEXT: Mutex<Option<Box<CONTEXT>>> = Mutex::new(None)` — Option<Box<>> allows late allocation on first use
- `static mut H1/H2: *mut c_void = ptr::null_mut()` — raw static muts (avoided in idiomatic Rust but necessary here because VEH handles are `PVOID` and lifetime is process-wide)
- `#[allow(static_mut_refs)]` — silences `static_mut_refs` lint that fires when taking `&mut` of a `static mut`; necessary because `H1 = ...` and `RemoveVectoredExceptionHandler(H1)` both read the static

### FFI patterns

- `AddVectoredExceptionHandler(FirstHandler: u32, Handler: PVECTORED_EXCEPTION_HANDLER) -> *mut c_void` — `PVECTORED_EXCEPTION_HANDLER` is `Option<unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> i32>`. Our handlers use `#[no_mangle]` to prevent Rust name mangling and `extern "system"` for Win64 fastcall.
- `RemoveVectoredExceptionHandler(Handle: *mut c_void) -> i32` — returns 0 on failure, non-zero on success; not checked in `destroy()`.
- `Box::new(core::mem::zeroed::<CONTEXT>())` — allocates a zero-initialized CONTEXT on the heap. `core::mem::zeroed()` is sound here because CONTEXT is a POD struct of integers/pointers.
- `ptr::copy_nonoverlapping(ei.ContextRecord, ctx.as_mut(), 1)` — full 1232-byte CONTEXT copy (Win64 CONTEXT is `sizeof(CONTEXT) = 0x4D0 = 1232` bytes).

### Memory layout

- `CONTEXT` on x64 is 1232 bytes (0x4D0). The handler relies on field offsets: `Dr0` at 0x350, `Dr7` at 0x358, `Rax` at 0x78, `Rcx` at 0x80, `R10` at 0x98, `Rip` at 0xF8, `Rsp` at 0x98... (actual offsets determined by winapi::um::winnt::CONTEXT; we just write fields by name).
- `LoaderDataTableEntry` — full layout including `in_load_order_links`, `in_memory_order_links`, `in_initialization_order_links`, `dll_base`, `entry_point`, `size_of_image`, `full_dll_name`, `base_dll_name`. Critical: the experimental `def.rs` has `InMemoryOrderLinks` first after `InLoadOrderLinks` so the `offset(-(size_of::<ListEntry>()))` trick to get the LDR entry from a list pointer works (veh_gate.rs `get_ssn_by_name` uses this).
- `ImageOptionalHeader64.data_directory: [ImageDataDirectory; 16]` — index 0 = Export, index 3 = Exception. Both used in SSN resolution.

### Error handling

- `initialize()` returns `anyhow::Result<()>`. On H2 failure, removes H1 and returns `Err`. On PEB walk failure, removes both handlers and returns `Err`. **Bug**: if PEB walk fails, `H1` and `H2` are set to `null_mut()` AFTER `RemoveVectoredExceptionHandler(H1)` is called — but the local `H1` variable was assigned by the AddVectored call before PEB walk; the cleanup sequence is correct.
- `destroy()` is silently idempotent — `if !H1.is_null()` guard.
- `get_ssn_by_name()` returns `i32` — `>= 0` on success, `-1` on failure (Rust idiom violation; should be `Option<u32>`).
- `veh_syscall!` macro **panics** on resolution failure (clean abort).
- `syscall!` macro (in syscall.rs) **silently returns** (`return;` from enclosing function) — this is a worse pattern because it aborts the caller unexpectedly.

### Syscall numbers

Not stored as compile-time constants. Resolved at runtime via `get_ssn_by_name()` walking ntdll's Exception Directory (sorted by RVA) and correlating with Export Address Table, counting only `Zw*` exports. This is the MDsec technique (https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/). Result cached nowhere — re-resolved on every `veh_syscall!` invocation. Operators wanting performance should cache `(ssn, addr)` tuples.

## Cross-References Found in Code

- `veh_gate.rs:find_peb()` → T-004 (PEB Walker) — reads `gs:[0x60]` for PEB base, same primitive as `resolve.rs` and `crates/core/src/sys_resolve.rs`
- `veh_gate.rs:ldr_module_info(NTDLL_HASH)` → T-004 (PEB Walker) — walks `InLoadOrderModuleList`, hashes module names with DJB2
- `veh_gate.rs:djb2_hash()` → cross-cutting DJB2 pattern (Rust Patterns) — same algorithm as `resolve.rs` and `crates/core/src/sys_resolve.rs`
- `veh_gate.rs:get_ssn_by_name()` → related to T-002 (Hell's/Halo's/Tartarus Gate) but uses **Exception Directory correlation** instead of stub byte scanning; does NOT depend on T-002
- `veh_gate.rs:AddHwBp/HandlerHwBp` — production handlers used by any code calling `veh_syscall!` macro; enables T-005 (Ekko uses NtSetTimer/etc.), T-007 (Pool Party uses NtQueryInformationWorkerThread), T-009 (Process Ghosting uses NtCreateProcessEx), T-012 (Early Cascade uses NtQueueApcThreadEx), T-014 (NtCreateUserProcess), T-015 (PPID spoofing uses NtAllocateProcess)
- `hooks.rs:debug_println!` → `crate::selection_config::verbose_debug()` — links to T-021 (selection_config runtime config)
- `syscall.rs:ImageRuntimeFunctionEntry` struct defined locally — the crowd `veh_gate.rs` has its own copy; both mirror `_IMAGE_RUNTIME_FUNCTION_ENTRY` from WinNT.h
- `def.rs:PEB` struct is the **complete** PEB layout — used by T-009 (PEB unlink), T-013 (anti-VM checks), T-016 (PEB-based evasion). The trimmed crowd version only retains the first ~7 fields.

## Edge Cases & Failure Modes

1. **EDR hooks ntdll syscall stub prologue** (e.g. inline `jmp` patch at stub entry).
   - Failure path: `AddHwBp` scans 25 bytes for `0F 05`; if hook jumps away before offset 25, the scan fails and `off_sys` remains 0. `Dr1 = entry_address + 0` → DR1 fires immediately, Case C runs before any syscall happens, returns garbage RAX.
   - Symptom: All `veh_syscall!` invocations return STATUS_INVALID_PARAMETER or similar garbage. No crash, just wrong behavior.
   - Workaround: Pre-flight with `T-002 (Hells Gate)` to detect patched stubs; fall back to direct `syscall` instruction or use `T-001 (RecycledGate)`'s ntdll gadget scan instead.

2. **Multiple threads issue `veh_syscall!` concurrently**.
   - Failure path: `SAVED_CONTEXT` is `Mutex<Option<Box<CONTEXT>>>` — single-slot. Thread A hits DR0, saves CONTEXT, redirects to trampoline. Thread B hits DR0 before A completes, overwrites `SAVED_CONTEXT` with B's context. A's syscall then runs with B's saved RSP → stack corruption, NTSTATUS returned to wrong thread.
   - Symptom: Random NTSTATUS mismatches, eventual AV in unrelated code.
   - Workaround: Serialize all VEH syscalls behind an outer `Mutex` (only one `set_hw_bp` in flight across all threads). For multi-thread implants, prefer `T-001 (RecycledGate)` which is stateless per call.

3. **`sub rsp, imm8` imm8 < 0x58**.
   - Failure path: `HandlerHwBp` Case B phase 0 scans up to 80 bytes; finds the `sub rsp` pattern but imm8 is e.g. 0x28 → `else { break; }` branch taken, phase 0 aborts. Default case at bottom re-arms TRACE_FLAG, so single-stepping continues forever (or until 80-byte scan window exhausted repeatedly).
   - Symptom: Infinite single-step loop, CPU spins in ntdll, process appears hung.
   - Workaround: Tune the threshold (`>= 0x58`) per Windows build, or use a different stub-detection heuristic (look for `mov eax, imm32` which is the SSN-load instruction immediately before `syscall`).

4. **VEH handler itself triggers an exception** (e.g. ntdll base address invalid → `ptr::read` of bogus RIP).
   - Failure path: Recursing into VEH handler. Windows does deliver recursive exceptions but stack overflow eventually kills the process.
   - Symptom: Process dies with stack overflow (`0xC00000FD`).
   - Workaround: Validate `NTDLL_INFO.base_address != 0` at top of `HandlerHwBp` Case B and return `EXCEPTION_CONTINUE_SEARCH` if invalid.

5. **`initialize()` called before Ldr completes** (e.g. from a TLS callback during process init).
   - Failure path: `ldr_module_info(NTDLL_HASH)` walks `InLoadOrderModuleList` but ntdll may not yet be fully initialized; `size_of_image` could be 0 → `NTDLL_INFO.end_address = base_address`. `HandlerHwBp` Case B bounds check `Rip <= ntdll_end` fails immediately → falls through to default (re-arm TRACE_FLAG, single-step forever outside ntdll).
   - Symptom: As edge case 3.
   - Workaround: Defer `initialize()` to a point after `LdrpProcessRelocationBlock` completes; or use `T-004 (PEB Walker)` to verify ntdll's `load_count > 0` first.

6. **Extended args (>4 syscall params) with caller's saved RSP not page-aligned**.
   - Failure path: `copy_stack_arg!(FIFTH_ARGUMENT)` reads from `saved.Rsp + 0x28`. If saved RSP was near a page boundary and 0x28 spills into the next page which is uncommitted, `ptr::copy_nonoverlapping` AVs.
   - Symptom: ACCESS_VIOLATION inside VEH handler → recursive exception → process death.
   - Workaround: Caller must ensure 256 bytes of valid stack below the deepest stack arg. Standard Win64 ABI guarantees 32-byte shadow + 4 stack args = 64 bytes; 5th-12th args need 64 + 64 = 128 bytes guaranteed. Win64 reserves 4KB, so safe in practice.

7. **`syscall.rs` typo bug**: `dbj2_hash` vs `djb2_hash`.
   - Failure path: `syscall.rs`'s `get_ssn_by_name` calls `dbj2_hash(dll_name_str.as_bytes())` which is misspelled. If `dbj2_hash` is not aliased elsewhere in the crate (it isn't, per the file content), this module fails to compile.
   - Workaround: Use the consolidated `veh_gate.rs` (production), not the experimental `syscall.rs`. The crowd version is the canonical impl.

8. **Debug logging overhead in experimental module**.
   - Failure path: `debug_println!` in `hooks.rs` calls `println!` which acquires stdout lock. If `verbose_debug` feature is enabled AND another thread is holding stdout (e.g. legitimate program logging), VEH handler blocks on stdout lock → deadlock during exception dispatch.
   - Workaround: Never ship `verbose_debug` feature flag in production.

## OPSEC Notes

**Artifacts left:**
- Two registered VEH handlers in the process's `LdrpVectorListHead` (visible via `GetModuleHandle` +0x18 walk). `ntdll!RtlpGetExceptionList` reveals registered handlers. EDRs that enumerate VEH chains will see `AddHwBp` and `HandlerHwBp` as non-Microsoft handlers.
- DR0 and DR1 are set during every syscall window. A EDR sensor calling `GetThreadContext(GetCurrentThread())` at the right moment can observe non-zero DR0/DR1 and the local-enable bits in DR7. EDRs that monitor DR7 changes (`NtSetContextThread` hook) might miss this since we modify CONTEXT directly, not via `SetThreadContext`.
- `SAVED_CONTEXT` Box allocation — a 1232-byte heap alloc per syscall in flight. Heuristic-detectable as anomalous alloc pattern correlated with syscall exceptions.
- `LAST_RAX` Mutex — a `Mutex<Option<u64>>` global. If the operator's process is dumped, this Mutex's name (`LAST_RAX::__static_mutex_acquire` in symbol-stripped builds still leaks via RTTI in some toolchains) is suspicious.
- The `veh_syscall!` macro panics on failure — Rust panic allocates a `Box<str>` for the message; this leaves a heap footprint before process death.

**Cleanup performed:**
- `destroy()` calls `RemoveVectoredExceptionHandler(H1)` and `RemoveVectoredExceptionHandler(H2)`, sets both to null. Should be called before unloading the operator's image.
- DR0/DR1 are explicitly cleared at DR1-hit time (`Dr0 = 0`, `Dr7 &= !(1<<0)` in Case A; `Dr1 = 0`, `Dr7 &= !(1<<2)` in Case C). After each syscall completes, no DR registers remain set.
- `SAVED_CONTEXT` is NOT cleared after each syscall — the `Box<CONTEXT>` persists until the next DR0 hit replaces it. Forensic memory dump captures the last caller's full register state including RCX (ntdll stub address) and RSP (caller stack pointer). 

**Telemetry surfaces:**
- `EXCEPTION_ACCESS_VIOLATION` and `EXCEPTION_SINGLE_STEP` are loud events. ETW's `Microsoft-Windows-Kernel-Process` provider emits ExceptionEvent (event ID 5) for each first-chance exception. A process making thousands of AV+SS exceptions stands out. EDRs correlating exception spikes with syscall activity will flag.
- `RtlDispatchException` walks the SEH table; our handlers run via VEH (separate from SEH) so SEH-based detectors miss them. But `AddVectoredExceptionHandler` itself can be hooked by EDRs (T-016 stack-spoofed calls to it recommended).

## Reusable Patterns

### Pattern: Mutex-protected global syscall state with optional Box
- **Use when**: A subsystem needs process-global mutable state that must survive across function calls but doesn't fit OO encapsulation
- **Code ref**: `veh_gate.rs:STATE`, `SAVED_CONTEXT`, `LAST_RAX`
- **How**: `static SAVED_CONTEXT: Mutex<Option<Box<CONTEXT>>> = Mutex::new(None);`. The Option allows late allocation on first use without `OnceLock`. The Box avoids stack-allocating 1232-byte CONTEXT. Acquire-lock-mutate-drop pattern in each handler case.

### Pattern: Self-induced exception as cross-context signal
- **Use when**: Need to transfer control to an exception handler with arbitrary data, without explicit function call (defeats stack-walk detection)
- **Code ref**: `veh_gate.rs:set_hw_bp()` — `asm!("xor rax,rax"; "mov edx,[rax]"; in("rcx") addr; ...)`
- **How**: Pass data in a non-clobbered register (RCX for x64 SysV), trigger a deterministic exception (null deref), read data back from saved CONTEXT in handler. Cheap, no Win32 API call needed, but generates ETW exception events.

### Pattern: Macro variadic param counting
- **Use when**: Need to know how many arguments a macro was invoked with at expansion time
- **Code ref**: `veh_gate.rs:veh_syscall!` macro
- **How**: `let mut n = 0u8; $(let _ = &$param; n += 1;)*` — the `$(...)*` repeats once per param, each iteration binds a throwaway `let _ = &$param` and increments. Result is a compile-time-known count usable for runtime flag computation (here: `extended_flag = if param_count > 4 { 1 } else { 0 }`).

### Pattern: Memory-image-benign RIP redirect
- **Use when**: VEH handler needs to redirect RIP to a "safe" location to continue single-stepping without executing dangerous code
- **Code ref**: `veh_gate.rs:syscall_trampoline` — `pub unsafe extern "C" fn syscall_trampoline() {}`
- **How**: Empty extern fn compiles to a single `ret` instruction. Its address is inside the operator's own image (or a benign DLL). RIP set here, TRACE_FLAG set in EFLAGS — CPU executes `ret`, raises SINGLE_STEP, handler regains control. Lets the state machine "idle" between real ntdll instruction steps without hitting arbitrary memory.

### Pattern: Win32 repr(C) struct chain with type-safe traversal
- **Use when**: Manual PE/PEB parsing without depending on windows-sys or windows crate
- **Code ref**: `veh_gate.rs:get_ssn_by_name()` + `def.rs` structs
- **How**: Define `ImageDosHeader`, `ImageNtHeaders`, `ImageOptionalHeader64`, `ImageExportDirectory`, `ImageRuntimeFunctionEntry` as `#[repr(C)]` with exact field order. Use `dll_base.offset((*dos_header).e_lfanew as isize) as *const ImageNtHeaders` for RVA-to-pointer. Note: experimental `def.rs` has the **complete** `PEB` struct (with `RtlUserProcessParameters`); crowd's `veh_gate.rs` has a **trimmed** `PEB` with only first 7 fields — useful when only `loader_data` is needed and struct size discipline matters.

### Pattern: Three-state exception-driven state machine
- **Use when**: Need to chain multiple exceptions to walk through code you don't control (e.g. ntdll syscall stub internals)
- **Code ref**: `veh_gate.rs:HandlerHwBp` Case B phases 0/1/2 via `is_sub_rsp: i32`
- **How**: Use a small integer state counter in a Mutex. Each exception handler invocation reads + mutates the state. Phase 0 = scanning for pattern A; Phase 1 = waiting for pattern B; Phase 2 = execute real action + reset. The `TRACE_FLAG` (EFlags bit 8) drives the single-step exception pump — set it to keep stepping, clear it to halt.
