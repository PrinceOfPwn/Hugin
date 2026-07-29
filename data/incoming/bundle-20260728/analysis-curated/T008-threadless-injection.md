---
id: T-008
name: Threadless Injection (Export Hijacking)
category: process-injection
tier: A
mitre: T1055
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires:
  - T-001
  - T-004
enables:
  - T-005
  - T-013
  - T-016
  - T-017
vault_references:
  - dark_crystal/crowd/src/threadless.rs
  - dark_crystal/crates/core/src/experimental/injection/threadless.rs
implements:
  - file: dark_crystal/crowd/src/threadless.rs
    key_functions:
      - try_threadless_inject
      - remote_module_base
      - find_memory_hole
      - install_trampoline
      - resolve_suspend_resume
      - free_hole_syscall
      - install_clean_stub
      - utf16z_to_string
    key_structs:
      - ModuleEntry32W
      - CreateToolhelp32SnapshotFn
      - Module32FirstWFn
      - Module32NextWFn
      - NtSuspendProcessFn
      - NtResumeProcessFn
    key_constants:
      - PATCH_SHELLCODE (121 bytes)
      - TH32CS_SNAPMODULE (0x0000_0008)
      - TH32CS_SNAPMODULE32 (0x0000_0010)
      - PAGE_EXECUTE_READ (0x20)
      - PAGE_READWRITE (0x04)
      - MEM_COMMIT|MEM_RESERVE (0x00003000)
      - MEM_RELEASE (0x00008000)
      - CLEAN_STUB ([0x31, 0xC0, 0xC3])
    lines_of_interest:
      - "L33-L77: PATCH_SHELLCODE 121-byte trampoline with XMM0-XMM5 MOVAPS save/restore"
      - "L153-L211: try_threadless_inject — full injection flow with RecycledGate syscalls"
      - "L153-L168: target export RVA resolution + suspended-process fallback for system DLLs"
      - "L184-L200: nt_read_virtual_memory capture of original 8 bytes"
      - "L218-L244: hole allocation + patch + shellcode + flip to PAGE_EXECUTE_READ"
      - "L311-L363: install_trampoline — NtSuspend/Resume bracketing the 5-byte CALL write"
      - "L288-L307: resolve_suspend_resume — dynamic NtSuspendProcess / NtResumeProcess resolution"
  - file: dark_crystal/crates/core/src/experimental/injection/threadless.rs
    key_functions:
      - try_threadless_inject
      - remote_module_base
      - find_memory_hole
      - install_trampoline
      - install_clean_stub
      - utf16z_to_string
    key_structs:
      - ModuleEntry32W
      - CreateToolhelp32SnapshotFn
      - Module32FirstWFn
      - Module32NextWFn
    key_constants:
      - PATCH_SHELLCODE (121 bytes)
      - TH32CS_SNAPMODULE (0x0000_0008)
      - TH32CS_SNAPMODULE32 (0x0000_0010)
      - CLEAN_STUB ([0x31, 0xC0, 0xC3])
    lines_of_interest:
      - "L10-L17: Win32 API imports (VirtualAllocEx, VirtualProtectEx, ReadProcessMemory, WriteProcessMemory) — legacy non-syscall path"
      - "L19-L66: PATCH_SHELLCODE — identical 121-byte template"
      - "L116-L168: remote_module_base — identical toolhelp snapshot enumeration"
      - "L170-L233: try_threadless_inject — uses Win32 memory APIs, no thread suspension"
      - "L235-L253: find_memory_hole — VirtualAllocEx probing loop"
      - "L255-L292: install_trampoline — no NtSuspendProcess bracketing (race-prone)"
min_windows: Windows 7 x64
needs_admin: conditional
tags:
  - injection
  - export-hijack
  - self-restoring
  - xmm-preservation
  - recycled-gate
  - rva-call-trampoline
  - threadless
  - memory-hole
---

# Threadless Injection (Export Hijacking) — Operator Playbook

## TL;DR
Hijacks a single exported function in a live process with a 5-byte `CALL` trampoline, diverting it into a 121-byte `PATCH_SHELLCODE` stub that saves XMM0–XMM5, restores the original 8 bytes of the export, executes your payload, then `JMP RAX` back into the original (now-healed) function. The crowd variant routes every memory primitive through RecycledGate (`T-001`) and brackets the trampoline write with `NtSuspendProcess`/`NtResumeProcess` to defeat cross-cache-line torn reads — making it the deployment-grade path over the legacy Win32 core variant.

## Source File Map

| File | Role | Key Exports | Size |
|---|---|---|---|
| `dark_crystal/crowd/src/threadless.rs` | Production variant — RecycledGate syscalls, thread suspension, system-DLL fallback for suspended targets | `try_threadless_inject()`, `install_trampoline()`, `install_clean_stub()`, `find_memory_hole()` | ~390 LOC |
| `dark_crystal/crates/core/src/experimental/injection/threadless.rs` | Reference variant — vanilla Win32 (`VirtualAllocEx`/`VirtualProtectEx`/`WriteProcessMemory`), no thread sync, no fallback | Same public surface | ~270 LOC |

Both files share the **identical 121-byte `PATCH_SHELLCODE`** and `ModuleEntry32W` toolhelp enumeration. The crowd file is a hardened superset.

## How It Works

The technique has six logical phases. All citations are to `crowd/src/threadless.rs` unless noted.

### 1. Resolve the export's address in the *remote* process
`try_threadless_inject(h_process, target_dll, target_export, shellcode)` first does a *local* `LoadLibraryA(target_dll)` + `GetProcAddress(target_export)` to compute the function's RVA inside the DLL image (`func_rva = address - h_module.0`, L153–L168). It then converts that RVA back into the *remote* process's address space:

- Self-target fast-path: `h_process == GetCurrentProcess()` → just `(h_module.0 + func_rva)`.
- Remote target: `remote_module_base(h_process, target_dll)` walks a `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)` (L88–L144), enumerating `Module32FirstW`/`Module32NextW`, matching `sz_module` or `sz_exe_path` basename case-insensitively. Returns `mod_base_addr` of the loaded image.
- **Suspended-process fallback** (crowd only, L161–L168): if the toolhelp snapshot is empty (PEB not yet populated — typical of `T-012` Early Cascade targets that haven't run `LdrInitializeThunk`), the code falls back to the *local* base for `ntdll.dll` / `kernel32.dll` / `kernelbase.dll`, exploiting the fact that these are system-wide ASLR images mapped at the same VA in every process.

### 2. Capture the original 8 bytes
`original_bytes = [0u8; 8]` is read from `func_address` (L184–L198):

- Remote target → `crate::recycled::nt_read_virtual_memory(h_proc_raw, func_address, original_bytes.as_mut_ptr(), 8, &mut bytes_read)`. Status < 0 or short read → abort.
- Self → `std::ptr::copy_nonoverlapping` (in-process memcpy).

These 8 bytes are spliced into `PATCH_SHELLCODE[18..26]` as an *immediate* in `MOV RCX, imm64` (L201). On first execution the stub will `MOV [RAX], RCX` to *heal* the trampoline byte-for-byte.

### 3. Carve a near memory hole
`find_memory_hole(h_process, func_address, total_size)` (L247–L273):

- Starts at `(func_address & 0xFFFFFFFFFFF70000) - 0x70000000` — page-align downward, then drop ±~1.75 GB below the export.
- Probes upward in 0x10000 (64 KiB) strides while `address < func_address + 0x70000000`.
- Each probe calls `crate::recycled::nt_allocate_virtual_memory(h_proc_raw, &mut base, 0, &mut region_size, 0x00003000 /* MEM_COMMIT|MEM_RESERVE */, 0x04 /* PAGE_READWRITE */)`.
- First success → returns the base pointer. The 0x70000000 window keeps the eventual `CALL rel32` RVA within `i32` range.

### 4. Write patch trampoline + payload, flip RX
Sequenced writes into the hole (L209–L243):

1. `nt_write_virtual_memory(h_proc_raw, hole, &patch, 121, &mut written)` — the 121-byte `PATCH_SHELLCODE` with embedded original 8 bytes.
2. `nt_write_virtual_memory(h_proc_raw, hole + 121, shellcode, shellcode.len(), &mut written)` — operator payload, immediately after the patch.
3. `nt_protect_virtual_memory(h_proc_raw, &mut base, &mut region_size, 0x20 /* PAGE_EXECUTE_READ */, &mut old)` — flip the whole region RX in one shot.

Note: never `PAGE_EXECUTE_READWRITE`. RW write, then RX protect — this matches `T-016` ACG-friendly allocation discipline. Any failure along the way calls `free_hole_syscall(h_proc_raw, hole)` → `nt_free_virtual_memory(... 0x00008000 /* MEM_RELEASE */)` (L209, L219, L228, L233) so no zombie allocation survives.

### 5. Install the 5-byte CALL trampoline
`install_trampoline(h_process, hole, func_address)` (L311–L363) is the only step that touches the *export* itself:

1. Build `trampoline = [0xE8, rva[0..4]]` — a `CALL rel32`.
2. Compute `rva = hole.wrapping_sub(function_address + 5)` and bounds-check `i32::MIN..=i32::MAX` (L317–L320). Out-of-range → fail.
3. `nt_protect_virtual_memory(function_address, 5, 0x04 /* PAGE_READWRITE */, &mut old)` — flips the export's first 5 bytes writable.
4. **Critical crowd-only step:** call `resolve_suspend_resume()` → dynamically `LoadLibraryA("ntdll.dll")` + `GetProcAddress("NtSuspendProcess")`/`GetProcAddress("NtResumeProcess")` (L288–L307), then `nt_suspend(h_proc_raw)` *before* the write (L344). This freezes every thread in the target so no thread can read the half-written `CALL` mid-patch.
5. `nt_write_virtual_memory(function_address, trampoline, 5, &mut written)` — atomic cross-thread write.
6. `nt_resume(h_proc_raw)` (L357) — unfreeze.
7. `nt_protect_virtual_memory(function_address, 5, old_protect, &mut old)` — restore original protection (return value ignored via `let _ =`).

The legacy `core/src/experimental/injection/threadless.rs` variant skips steps 4/6 — it just calls `VirtualProtectEx` → `WriteProcessMemory` → `VirtualProtectEx` with no suspension. This is a real race window if another thread hits the export exactly as the 5-byte patch is being laid down.

### 6. Self-restoration on first call
When the export is next invoked by the target process, control flows `CALL rel32 → hole → PATCH_SHELLCODE`:

```
0x58                    POP RAX                ; return addr from the CALL we just executed
48 83 E8 05             SUB RAX, 5             ; → address of the trampolined export entry
50                      PUSH RAX               ; save return-to-original path
51 52 41 50 41 51 41 52 41 53   PUSH RCX,RDX,R8,R9,R10,R11
48 B9 <8 orig bytes>    MOV RCX, imm64        ; payload of original 8 bytes
48 89 08                MOV [RAX], RCX         ; *** heal the trampoline ***
48 81 EC A8 00 00 00    SUB RSP, 0xA8          ; 16-byte align for MOVAPS
0F 29 44 24 40          MOVAPS [RSP+0x40], XMM0
0F 29 4C 24 50          MOVAPS [RSP+0x50], XMM1
0F 29 54 24 60          MOVAPS [RSP+0x60], XMM2
0F 29 5C 24 70          MOVAPS [RSP+0x70], XMM3
0F 29 64 24 80          MOVAPS [RSP+0x80], XMM4
0F 29 6C 24 90          MOVAPS [RSP+0x90], XMM5
E8 11 00 00 00          CALL +0x11             ; jump into operator shellcode
0F 28 6C 24 90          MOVAPS XMM5, [RSP+0x90]
0F 28 64 24 80          MOVAPS XMM4, [RSP+0x80]
... (restore XMM3..XMM0)
48 81 C4 A8 00 00 00    ADD RSP, 0xA8
41 5B 41 5A 41 59 41 58 5A 59 58   POP R11,R10,R9,R8,RDX,RCX,RAX
FF E0                   JMP RAX                ; → back to original export (now healed)
```

The `MOV [RAX], RCX` at offset 0x15 is the lynchpin: it overwrites the 5-byte `CALL` with the original 8 bytes, so every *subsequent* call into the export executes the unmodified original code. This is what makes it "threadless" — no hijacked thread, no second-stage cleanup thread, just a one-shot side-effect on first invocation.

The `SUB RSP, 0xA8` is non-negotiable: `MOVAPS` requires 16-byte stack alignment. After the `CALL` that brought us here (pushed 8 bytes) + the seven `PUSH` ops (7 × 8 = 56 bytes), RSP is misaligned by 8. The 0xA8 subtraction realigns *and* carves room for the six 16-byte XMM saves. `T-016`'s stack-spoof modules reuse the same pattern.

## Code Architecture

### Call graph
```
install_clean_stub()
  └─ try_threadless_inject(h_process, target_dll, target_export, [0x31,0xC0,0xC3])

try_threadless_inject()
  ├─ LoadLibraryA / GetProcAddress              [local RVA probe]
  ├─ remote_module_base(h_process, target_dll)   [remote address]
  │     ├─ LoadLibraryA("kernel32.dll")
  │     ├─ GetProcAddress("CreateToolhelp32Snapshot" / "Module32FirstW" / "Module32NextW")
  │     ├─ create_snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
  │     └─ CloseHandle(snapshot)
  ├─ crate::recycled::nt_read_virtual_memory     [T-001 RecycledGate]
  ├─ find_memory_hole(h_process, func_address, total_size)
  │     └─ crate::recycled::nt_allocate_virtual_memory  [T-001]
  ├─ crate::recycled::nt_write_virtual_memory × 2       [T-001]
  ├─ crate::recycled::nt_protect_virtual_memory (RX)    [T-001]
  └─ install_trampoline(h_process, hole, func_address)
        ├─ resolve_suspend_resume()
        │     ├─ LoadLibraryA("ntdll.dll")
        │     └─ GetProcAddress("NtSuspendProcess" / "NtResumeProcess")
        ├─ crate::recycled::nt_protect_virtual_memory (RW)   [T-001]
        ├─ nt_suspend(h_proc_raw)
        ├─ crate::recycled::nt_write_virtual_memory (5 bytes)
        ├─ nt_resume(h_proc_raw)
        └─ crate::recycled::nt_protect_virtual_memory (restore) [T-001]

[on failure →] free_hole_syscall(h_proc_raw, hole) → crate::recycled::nt_free_virtual_memory(MEM_RELEASE)
```

### Data flow
1. **Operator inputs**: `h_process: HANDLE`, `target_dll: &str` (e.g. `"ntdll.dll"`), `target_export: &str` (e.g. `"NtTraceControl"`), `shellcode: &[u8]`.
2. **Local probe** produces `func_rva` (offset within the DLL image).
3. **Remote probe** (`remote_module_base`) produces `func_address` in target VA space.
4. **Read primitive** produces `original_bytes: [u8; 8]` (the heal payload).
5. **Patch template** (`PATCH_SHELLCODE`) is cloned to `let mut patch` and mutated at offset `18..26` to embed the heal bytes.
6. **Hole finder** produces a near-by `*mut c_void`.
7. **Writes + protect** produce a contiguous RX region `[hole .. hole + 121 + shellcode.len()]`.
8. **Trampoline** writes a 5-byte `CALL rel32` at `func_address` pointing to `hole`.
9. **First execution** at runtime heals `func_address` back to its original bytes and `JMP RAX`s into the original code path.

### Type hierarchy
- `ModuleEntry32W` — `#[repr(C)]` mirror of `MODULEENTRY32W` for the toolhelp API.
- Function pointer typedefs (`CreateToolhelp32SnapshotFn`, `Module32FirstWFn`, `Module32NextWFn`, `NtSuspendProcessFn`, `NtResumeProcessFn`) — runtime-resolved via `GetProcAddress` + `transmute`.
- `PATCH_SHELLCODE: [u8; 121]` — `static mut`, treated as a template; copied locally before mutation.

### Feature gates
- Both files are `#![allow(dead_code)]` — compiled as opt-in.
- The crowd variant hard-depends on `crate::recycled::*` (RecycledGate, T-001). The core variant hard-depends on the `windows` crate's `Win32::System::Memory` / `Diagnostics::Debug` bindings. Switching crates requires swapping every `crate::recycled::nt_*` call for its Win32 equivalent.

## Operational Profile

### When to Use
- **Long-dwell payload in a long-running host process** (`explorer.exe`, `svchost.exe`, `runtimebroker.exe`) — the self-healing property leaves zero residual patch after first execution.
- **EDR-saturated environments** where you must avoid CreateRemoteThread, QueueUserAPC, NtCreateThreadEx — anything that emits a thread-creation telemetry event.
- **Target exports that are called rarely** (so first-call heal isn't racing the EDR's memory scanner) but reliably (so the payload does eventually fire).
- **Cross-bitness targets**: works on x64 only (RAX/XMM/`MOVAPS` x64 idioms).
- **Suspended-process injection chains** (crowd variant only) — the system-DLL fallback at L161–L168 explicitly handles `T-012` Early Cascade targets whose PEB hasn't populated yet.

### When NOT to Use
- **x86 targets** — the 121-byte `PATCH_SHELLCODE` is unconditionally x64.
- **Targets where the chosen export is on a hot code path** — the suspended write only protects the *write* of the trampoline, not the *read* by another thread that may have already cached the original bytes speculatively. If the export is hammered concurrently you risk a torn read that bypasses the heal.
- **Targets without a known resident DLL with a callable export** — `remote_module_base` returns None and (for non-system DLLs) you fail.
- **Targets where you can't get `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE`** — the technique is DOA without these access mask bits on the handle.
- **Stealth-critical one-shot implants** — the 5-byte `CALL` patch is briefly visible to a scanner running exactly between the protect-to-RW and the resume.

### Kill Chain Position
```
T-004 (PEB walk for module resolution, inside recycled::)
  → T-001 (RecycledGate syscall primitives)
    → T-002 (SSN resolution, transitively used by RecycledGate)
      → T-008 (this — Threadless export hijack)
        → T-005 (Ekko ROP sleep, in injected payload)
          → T-017 (Persistence layer via clean-stub export hook)
```

The injected shellcode payload can be anything: an `Ekko` sleep-obfuscated implant (`T-005`), a beacon loader, or `install_clean_stub` itself for neutralizing a defensive export.

## Rust Implementation Deep Dive

### `unsafe` blocks (crowd variant)
| Location | Purpose | What it does |
|---|---|---|
| `remote_module_base` (L86) | FFI into toolhelp | `LoadLibraryA` + `GetProcAddress` + `transmute` of raw fn pointers + `create_snapshot` invocation |
| `try_threadless_inject` (L153) | Whole body | Every `crate::recycled::*` syscall is unsafe; `PATCH_SHELLCODE` is `static mut` (read via implicit `&mut`) |
| `free_hole_syscall` (L247) | Cleanup FFI | `nt_free_virtual_memory` call |
| `find_memory_hole` (L251) | Allocation FFI | `nt_allocate_virtual_memory` in a loop |
| `resolve_suspend_resume` (L288) | FFI resolution | `LoadLibraryA`/`GetProcAddress`/`transmute` |
| `install_trampoline` (L311) | Patch write | All five syscall calls + suspend/resume bracketing |

### Inline assembly
**No `core::arch::asm!` blocks** in either file. The "assembly" is pre-assembled opcode bytes in `PATCH_SHELLCODE`. This is the right call — `asm!` would require `unsafe(asm)` and nightly in some configurations; raw byte arrays are link-time stable. The trade-off is that offset invariants (e.g. `patch[18..26]` = the immediate slot of `MOV RCX, imm64`) are not compiler-checked.

Key opcode offsets to memorize if you modify the stub:
- `[0]` — `POP RAX`
- `[1..5]` — `SUB RAX, 5`
- `[5]` — `PUSH RAX` (save return-to-original path)
- `[6..16]` — 7 volatile register pushes (RCX,RDX,R8,R9,R10,R11)
- `[16..18]` — `MOV RCX, imm64` opcode prefix
- `[18..26]` — **the only mutable slot**, gets `original_bytes`
- `[26..29]` — `MOV [RAX], RCX` (the heal)
- `[29..36]` — `SUB RSP, 0xA8`
- `[36..76]` — 6× `MOVAPS [RSP+offset], XMMn` saves (XMM0..XMM5)
- `[41..46]` — `CALL +0x11` (relative, points into the operator shellcode right after the patch)
- `[76..96]` — 6× `MOVAPS XMMn, [RSP+offset]` restores (reverse order: XMM5..XMM0)
- `[96..103]` — `ADD RSP, 0xA8`
- `[103..114]` — 11 pops (R11..RAX)
- `[114..116]` — `JMP RAX` (back to healed original)

If you extend the patch by N bytes you must:
1. Update `PATCH_SHELLCODE: [u8; 121]` size.
2. Re-verify the `CALL +0x11` displacement (currently `0x11` because the next instruction is at offset 0x2B and the call's continuation is at offset 0x30, so the displacement is `0x30 - 0x2B + (any bytes added before the CALL)`).
3. Keep `SUB RSP`/`ADD RSP` matched (currently 0xA8 — sized for 6×16-byte XMM + 8-byte align slack = 0x98 + 0x10 = 0xA8).
4. Update `patch[18..26]` slot position if you shift bytes.

### FFI patterns
- **`windows::core::PCSTR`** with `c"string".as_ptr() as *const u8` — the canonical Rust-on-Windows inline-CSTR idiom (cstr literals stabilize the pointer lifetime).
- **`std::mem::transmute::<_, FnType>`** to coerce `GetProcAddress` raw pointers into typed `extern "system" fn` aliases. This is UB-adjacent if the resolved symbol's signature mismatches the typedef; both files assume the SDK-documented signature.
- **`HANDLE` to `usize`**: crowd variant strips `HANDLE` to `h_proc_raw: usize` (`h_process.0 as usize`) because `crate::recycled::*` RecycledGate stubs take a raw handle value, not a typed `HANDLE`. This is a deliberate choice so the syscall layer can be reused for kernel-handle spoofing contexts.
- **CString lifetime**: `let dll_cstr = CString::new(target_dll).unwrap();` kept alive across the `LoadLibraryA` call — without this the `as_ptr()` would dangle.

### Initialization patterns
- `PATCH_SHELLCODE` is `static mut` and used as a *template*. `let mut patch = PATCH_SHELLCODE;` makes a stack copy, then `patch[18..26].copy_from_slice(&original_bytes)` mutates the copy. The static is never written to in production, but technically the read of a `static mut` is unsafe under strict aliasing — `#![allow(dead_code)]` doesn't suppress that. In practice MSVC/LLVM layout the array as POD and the implicit `&mut` is fine, but a future Rust edition may force `addr_of_mut!` access.
- No `OnceLock`/`Lazy` in this file — resolution is per-call. `resolve_suspend_resume()` is called inside `install_trampoline` and re-resolves ntdll every invocation. This is wasteful for batch installs; an operator refactoring for volume use should hoist it to a `OnceLock<(NtSuspendProcessFn, NtResumeProcessFn)>`.

### Error handling
| Failure site | Behavior |
|---|---|
| `LoadLibraryA` (target DLL) | `return false` from `try_threadless_inject` |
| `GetProcAddress` (target export) | `return false` |
| `remote_module_base` returns None + non-system DLL | `return false` |
| `remote_module_base` returns None + system DLL (ntdll/kernel32/kernelbase) | **fallback to local base** (crowd only) |
| `nt_read_virtual_memory` status < 0 OR short read | `return false` |
| `find_memory_hole` exhausts range | `return false` |
| `nt_write_virtual_memory` (patch or shellcode) status < 0 | `free_hole_syscall(hole); return false` |
| `nt_protect_virtual_memory` (RX flip) status < 0 | `free_hole_syscall(hole); return false` |
| `install_trampoline` `nt_protect` (RW) status < 0 | `return false` (hole already RX; not freed — **leak**) |
| `install_trampoline` `nt_write` status ignored (`let _ =`) | Silent success regardless of write outcome |
| `install_trampoline` `nt_protect` (restore) status ignored (`let _ =`) | Silent success even if old protect isn't restored → target left RW |

**Notable hole**: if `install_trampoline`'s first `nt_protect_virtual_memory` (RW flip of the export) succeeds but the trampoline write fails for some reason (it can't really fail since the thread is suspended and the page is RW), the function still returns `true` — the calling `try_threadless_inject` then sees success and never frees the hole. In practice this is unreachable but it's a logic gap.

### Memory layout
- `ModuleEntry32W` is `#[repr(C)]` matching `MODULEENTRY32W`. Field order is load-bearing — the SDK uses `dw_size` as a version discriminator, set via `size_of::<ModuleEntry32W>() as u32` (L132).
- `PATCH_SHELLCODE` is 121 bytes — not page-aligned, not padded. Written at the start of the hole; the operator shellcode follows at offset 121.
- The hole's total size is `shellcode.len() + 121`. Allocated with `MEM_COMMIT|MEM_RESERVE` and a *zero* zero-bits arg → `nt_allocate_virtual_memory(h_proc_raw, &mut base, 0, &mut region_size, ...)` lets the kernel pick the alignment within the probed address (RtlAllocateHeap semantics).

### Syscall numbers
None resolved in this file. The actual SSN lookup is delegated to `crate::recycled` (which in turn calls into `crate::resolve` and `crate::hells_gate` per `T-002`/`T-004`). Operators modifying this code only need to know that `crate::recycled::nt_*` accepts a `usize` handle and returns an `i32` NTSTATUS.

## Cross-References Found in Code

| Reference | Location | Target Technique | Why |
|---|---|---|---|
| `crate::recycled::nt_read_virtual_memory` | `try_threadless_inject` L186 | **T-001 (RecycledGate)** | Cross-process read primitive; the indirection gadget in ntdll's `.text` is what makes this EDR-invisible vs `ReadProcessMemory` (which carries ETW TI telemetry). |
| `crate::recycled::nt_write_virtual_memory` ×3 | L213, L221, L348 | **T-001** | Same reasoning — no `WriteProcessMemory` in the import list of the crowd variant. |
| `crate::recycled::nt_protect_virtual_memory` ×3 | L228, L336, L356 | **T-001** | Replaces `VirtualProtectEx`. |
| `crate::recycled::nt_allocate_virtual_memory` | `find_memory_hole` L257 | **T-001** | Replaces `VirtualAllocEx`. |
| `crate::recycled::nt_free_virtual_memory` | `free_hole_syscall` L248 | **T-001** | Replaces `VirtualFreeEx`. |
| `crate::resolve` (transitive, behind `crate::recycled`) | — | **T-004 (PEB Walker)** + **T-002 (Hells Gate)** | The recycled module resolves ntdll via `gs:[0x60]` PEB walk and SSNs via the Hells/Halo/Tartarus cascade. |
| `NtSuspendProcess`/`NtResumeProcess` | `resolve_suspend_resume` L288 | **T-016 (EDR Evasion — KiUserException StepOver family)** | Suspend/resume bracketing to serialize the trampoline write. Same conceptual class as thread-freeze techniques. |
| `CreateToolhelp32Snapshot` + `Module32FirstW`/`NextW` | `remote_module_base` L88 | (none directly, but conceptually adjacent to **T-004**) | Toolhelp is the user-mode mirror of the PEB module list — useful when the PEB walk fails or for cross-bitness enumeration (`TH32CS_SNAPMODULE32`). |
| `install_clean_stub` 3-byte `xor eax, eax; ret` | L378 | **T-016** (export neutralization) | Routes the threadless mechanism to neutralize a defensive export (e.g., `AMSI.ScanBuffer` or `EtwNotificationRegister`). |
| `core/src/experimental/injection/threadless.rs` Win32 imports | L10–L17 | **T-013** (Remaining Methods family) | Reference variant sits next to other classic injection methods in the experimental tree (process hollowing, callback exec, fiber exec, etc.). |
| `PAGE_EXECUTE_READ`/`PAGE_READWRITE` protect flips, never `RWX` | L224, L336 | **T-016 (ACG compliance)** | Avoids `PAGE_EXECUTE_READWRITE` which is the textbook ACG/WX guard trigger. |

## Edge Cases & Failure Modes

1. **Suspended target with empty PEB** (e.g., post-`NtCreateProcessEx`, pre-`LdrInitializeThunk`)
   - **What goes wrong**: `remote_module_base` walks `Module32FirstW` against `CreateToolhelp32Snapshot(pid)` and gets zero modules because the loader hasn't run yet.
   - **Symptom**: returns `None`; `try_threadless_inject` falls back to local base *only* for `ntdll.dll`/`kernel32.dll`/`kernelbase.dll` (crowd L161–L168). For any other DLL it returns false.
   - **Workaround**: this is the intended hand-off to `T-012 Early Cascade`, which runs *before* the loader and uses a different mechanism entirely. For post-bootstrap but pre-loader injection of arbitrary DLLs, you'd need to extend the fallback to consult the section-object mapping list via `NtQueryInformationProcess(ProcessMappedInformation)`.

2. **Trampoline write races (legacy core variant only)**
   - **What goes wrong**: between `VirtualProtectEx(RW)` and `VirtualProtectEx(restore)` in `install_trampoline`, a concurrent thread in the target may execute the export and read a half-written `CALL` (torn fetch across a cache-line boundary).
   - **Symptom**: target crashes with `STATUS_ACCESS_VIOLATION` at a garbage RIP; the patch never heals; EDR sees the export corrupted.
   - **Workaround**: use the crowd variant — its `NtSuspendProcess`/`NtResumeProcess` bracketing at L344/L357 freezes every thread for the duration of the 5-byte write.

3. **Memory hole search fails on fragmented VA space**
   - **What goes wrong**: `find_memory_hole` probes 0x10000 (64 KiB) strides over a ±0x70000000 (~1.75 GB) window. On heavily ASLR-randomized or address-space-pressured processes (e.g., a browser with many content processes), the window may have no contiguous free region of the requested size at the requested alignment.
   - **Symptom**: returns None; injection fails silently.
   - **Workaround**: increase stride to page-size (0x1000) granularity, or fall back to `NtAllocateVirtualMemory` with `BaseAddress=NULL` (let kernel choose) and use an indirect `CALL` via a 64-bit absolute displacement (`FF 15 02 00 00 00` + 8-byte absolute address) — but this changes the trampoline from 5 to 14 bytes, which exceeds the 8-byte heal window.

4. **`PATCH_SHELLCODE` static-mut race**
   - **What goes wrong**: if `try_threadless_inject` is called concurrently from two threads, both read `PATCH_SHELLCODE` and one mutates `patch[18..26]` — but since `let mut patch = PATCH_SHELLCODE` makes a stack copy, the mutation is local. The *read* of `static mut` is still UB-adjacent under strict Stacked Borrows.
   - **Symptom**: in practice none on current LLVM; under future strict aliasing checks this could miscompile.
   - **Workaround**: change to `static PATCH_SHELLCODE: [u8; 121] = ...` (drop `mut`) — it's never written through.

5. **RVA out of i32 range**
   - **What goes wrong**: `install_trampoline` computes `rva = hole - (func_address + 5)` and bounds-checks `i32::MIN..=i32::MAX`. If the hole finder chose a hole > 2 GB away (impossible per `find_memory_hole`'s 0x70000000 window, but defensive).
   - **Symptom**: returns false; hole leaks (no `free_hole_syscall` call in that branch — bug).
   - **Workaround**: add `free_hole_syscall(h_proc_raw, hole); return false;` to the out-of-range branch. Currently the function just `return false`s.

6. **`NtSuspendProcess` resolution fails (ntdll stripped/hooked)**
   - **What goes wrong**: `resolve_suspend_resume` returns None.
   - **Symptom**: crowd variant skips the suspend/resume and writes the trampoline unsynchronized (degraded to the legacy core variant's race profile).
   - **Workaround**: fall back to thread-by-thread suspension via `NtGetNextThread` + `NtSuspendThread` if you can still get those — or migrate to `T-003 VEH Syscall Gate` to intercept the EDR's hook on `NtSuspendProcess`.

7. **First-call heal races concurrent scanner**
   - **What goes wrong**: an EDR memory scanner samples `func_address` in the window between the trampoline write and the first invocation. It sees the 5-byte `CALL rel32` and may flag/quarantine.
   - **Symptom**: detection; possibly the target is killed.
   - **Workaround**: pre-warm the export. After `install_trampoline` returns true, call the export yourself via `NtCreateThreadEx` (defeats the "threadless" property but ensures the heal runs before any scanner tick). Or pick an export that is invoked within milliseconds by the target's own startup (e.g., `LdrLockLoaderLock` in `ntdll.dll`).

## OPSEC Notes

### Artifacts left
- **5-byte `CALL rel32` at `func_address`** — visible from `func_address` to `func_address + 5` between `install_trampoline` write and the first invocation of the export by any thread in the target. After first invocation, *healed* (zero residual).
- **121-byte RX hole near `func_address`** — persists for the lifetime of the payload. The hole is within ±1.75 GB of the export, finds via `NtAllocateVirtualMemory` with explicit base address (not `NULL`) — this is itself unusual: legitimate allocations usually pass `BaseAddress=NULL`. An EDR hook on `NtAllocateVirtualMemory` that flags explicit-base allocations will catch it.
- **Two-stage protect sequence** RW → RX (no `RWX` ever) — good baseline but the protect count itself is observable via `T-016` ETW TI hooks on `NtProtectVirtualMemory`.
- **`NtSuspendProcess`/`NtResumeProcess` bracket** — if the target is a service hosting many threads, this freezes *all* of them, which is observable as a sub-ms stall in any telemetry correlated across the suspended window.
- **Toolhelp snapshot** in `remote_module_base` — `CreateToolhelp32Snapshot` with `TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32` is a documented detection signal (it's how Process Explorer enumerates modules; some EDRs flag it in low-priv contexts).

### Telemetry surface (crowd variant)
- All memory primitives go through `T-001 RecycledGate` → no Win32 `*Ex` calls in the import table; no `kernel32!VirtualAllocEx` / `kernel32!WriteProcessMemory` ETW TI events.
- `LoadLibraryA` + `GetProcAddress` *do* hit the standard loader path — these are visible in `T-016` ETW TI as image-load events for `kernel32.dll` and `ntdll.dll` (though both are already loaded, so it's a no-op refcount bump).
- `NtSuspendProcess`/`NtResumeProcess` are NT-direct; EDRs that hook `ntdll!NtSuspendProcess` will see them. `T-003 VEH Gate` is the upgrade path.

### Cleanup
- `free_hole_syscall` on every failure path before the trampoline write — no leak.
- After successful trampoline install and first-call heal, the *only* residual is the 121-byte RX hole. To clean it: queue an APC into the target that calls `NtFreeVirtualMemory` on the hole after a delay, or include a self-free tail in the operator shellcode (`NtFreeVirtualMemory(GetCurrentProcess(), &hole, 0, MEM_RELEASE)` as the last action before `JMP RAX`).
- `CloseHandle(snapshot)` in `remote_module_base` — toolhelp handle is released; no handle leak.

## Reusable Patterns

### Pattern: Static-Byte-Array Shellcode Template with Single Mutable Slot
- **Use when**: you need a hand-assembled shellcode stub with one operator-supplied variable baked in.
- **Code ref**: `crowd/src/threadless.rs:PATCH_SHELLCODE` + `try_threadless_inject` L201 (`patch[18..26].copy_from_slice(&original_bytes)`).
- **How**: declare `pub static mut TEMPLATE: [u8; N] = [...];`. At call time, `let mut patch = TEMPLATE;` copies to stack, then `patch[OFFSET..OFFSET+LEN].copy_from_slice(&dynamic_data)`. Document the offsets as comments so modifiers know which slots are mutable.

### Pattern: ±2GB Memory-Hole Probe for Relative-Branch Trampolines
- **Use when**: building a 5-byte `CALL rel32` / `JMP rel32` patch that must reach a remote allocation.
- **Code ref**: `find_memory_hole` L247–L273.
- **How**: start at `func_address & !0xFFFF` minus `0x70000000` (the 32-bit signed displacement ceiling), step by `0x10000` (64 KiB, a typical allocation granularity), `nt_allocate_virtual_memory` at each probe, first success wins. Bounds-check the resulting displacement to `i32` before encoding.

### Pattern: Suspend-Write-Resume Bracket for Non-Atomic Cross-Process Patches
- **Use when**: writing a multi-byte patch into a live process where a concurrent thread could read mid-write.
- **Code ref**: `install_trampoline` L344–L357 (`nt_suspend` → `nt_write_virtual_memory` → `nt_resume`).
- **How**: resolve `NtSuspendProcess`/`NtResumeProcess` at runtime from `ntdll.dll` (avoids import-table leakage); suspend, write, resume. *Don't* leave the target suspended across I/O or long-running ops — the suspend window is itself a detection signal if it exceeds ~10 ms.

### Pattern: System-DLL Address Fallback for Suspended Targets
- **Use when**: injecting into a process that hasn't run its loader yet (post-`NtCreateProcessEx`, pre-`LdrInitializeThunk`) — i.e., `T-012 Early Cascade` targets.
- **Code ref**: `try_threadless_inject` L161–L168.
- **How**: if `remote_module_base` returns None and `target_dll` ∈ {`ntdll.dll`, `kernel32.dll`, `kernelbase.dll`}, reuse the *local* base address because these images are mapped at the same VA in every process via system-wide ASLR. **Caveat**: this breaks under per-process image-randomization mitigations (currently not shipped by Microsoft, but watch for it).

### Pattern: XMM Register Preservation Around Operator Shellcode
- **Use when**: injecting a CALL into an arbitrary code path in a process you don't control — the target may use SSE/SSE2 floating point, and your shellcode will corrupt XMM0–XMM5 (the Win64 volatile set) unless you save them.
- **Code ref**: `PATCH_SHELLCODE[36..96]` (six `MOVAPS` saves + six `MOVAPS` restores).
- **How**: before calling the operator payload, `SUB RSP, 0xA8` (must be a multiple of 16 plus 8 to fix the post-CALL misalignment), then `MOVAPS [RSP+offset], XMMn` for each XMM0–XMM5. After the CALL, restore in reverse order, then `ADD RSP, 0xA8`. The `0xA8` size = `6×16 + 0x10` (slack for alignment). Without this, target-side FPU state silently corrupts and the host crashes hours later with a NaN in an unexpected place — extremely difficult to triage.
