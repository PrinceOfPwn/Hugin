---
id: T-016
name: EDR Evasion Suite (12 techniques — 6 files analyzed)
category: edr-evasion
tier: mixed
mitre:
  - T1562.001  # Disable or Modify Tools — block_handle, policy, ki_step_over, peb_unlink
  - T1562.002  # Disable Windows Event Logging — ki_step_over (silent hook bypass)
  - T1564       # Hide Artifacts — peb_unlink, stack_spoof
  - T1564.004   # Hidden APIs — arg_spoof, peb_unlink
  - T1055       # Process Injection — arg_spoof supports injection chains
  - T1106       # Native API — all files use NT direct
  - T1574       # Hijack Execution Flow — ki_step_over exception dispatcher hook
  - T1620       # Reflective Code Loading — peb unlink after reflective load
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires:
  - T-001  # RecycledGate — used by arg_spoof, peb_unlink, policy, block_handle via crate::recycled::invoke
  - T-004  # PEB Walker — used via crate::resolve::compute_hash and ntdll_base_and_name_hashes
  - T-002  # Hells/Halos/Tartarus Gate — used by ki_step_over::register_step_over → resolve_ssn_by_hash
  - T-003  # VEH Gate — same SSN resolution path (T-002/T-003 share resolver)
enables:
  - T-007  # Process Injection — arg_spoof is part of the ppid.rs→NtCreateUserProcess chain; policy hardens pre-injection
  - T-013  # Module Overloading — policy.rs comment: "ACG applied AFTER module loading so the overloaded DLL can still execute"
  - T-015  # PPID Spoofing — arg_spoof is invoked from ppid.rs to swap benign→real args
  - T-008  # Persistence — block_handle + policy = resilient persistent process
  - T-014  # NtCreateUserProcess — arg_spoof operates on suspended NtCreateUserProcess output
  - T-016  # Self: ki_step_over installs HW BP bypass that other T-016 techniques (AMSI-HBP) must coordinate with
vault_references:
  - techniques/T016-edr-evasion.md
  - src/dark_crystal/crowd/src/stack_spoof.rs
  - src/dark_crystal/crowd/src/arg_spoof.rs
  - src/dark_crystal/crowd/src/ki_step_over.rs
  - src/dark_crystal/crowd/src/peb_unlink.rs
  - src/dark_crystal/crowd/src/policy.rs
  - src/dark_crystal/crowd/src/block_handle.rs
implements:
  - file: src/dark_crystal/crowd/src/stack_spoof.rs
    key_functions: [spoof_caller, find_frame_in_kernelbase, calc_frame_size_inner, get_pdata, get_own_base, get_own_image_size, null_guard]
    key_structs: [SpoofGuard, RuntimeFunction, UnwindInfo]
    key_constants: [UWOP_ALLOC_SMALL, UWOP_ALLOC_LARGE, UWOP_PUSH_NONVOL, UWOP_SET_FPREG, UNW_FLAG_CHAININFO, MAX_CHAIN_DEPTH]
    lines_of_interest:
      - "L42-L58: SpoofGuard #[must_use] RAII + Drop that restores the original return address"
      - "L62-L66: get_rsp() core::arch::asm! reading rsp register"
      - "L73-L139: calc_frame_size_inner — recursive .pdata unwinder with CHAININFO depth cap"
      - "L142-L163: get_pdata — manual PE header walk to locate IMAGE_DIRECTORY_ENTRY_EXCEPTION (DataDirectory[3])"
      - "L168-L207: find_frame_in_kernelbase — randomized scan for matching frame-size gadget in kernelbase.dll"
      - "L222-L258: spoof_caller — stack walk to locate own-module return slot and substitute"
      - "L261-L273: get_own_base via gs:[0x60] PEB.ImageBaseAddress (offset 0x10)"
  - file: src/dark_crystal/crowd/src/arg_spoof.rs
    key_functions: [spoof_args_in_peb, inner_spoof]
    key_structs: [ProcessBasicInfo]
    key_constants: [CMDLINE_LENGTH_OFFSET, CMDLINE_BUFFER_OFFSET, CMDLINE_MAXLENGTH_OFFSET, BENIGN_ARGS]
    lines_of_interest:
      - "L36-L78: inner_spoof — full NtQueryInformationProcess → PEB.ProcessParameters → CommandLine.Buffer rewrite"
      - "L83-L96: NtReadVirtualMemory on PEB.ProcessParameters RVA 0x20"
      - "L112-L130: bounds-check against remote MaximumLength before write"
      - "L134-L160: NtWriteVirtualMemory on Buffer + Length + MaxLength fields"
      - "L172: BENIGN_ARGS='RuntimeBroker.exe -Embedding' decoy string"
  - file: src/dark_crystal/crowd/src/ki_step_over.rs
    key_functions: [exception_handler, install_step_over, register_step_over, set_hardware_breakpoint_dr, hook_exception_dispatcher, unhook_exception_dispatcher, find_wow64_callback_pointer, get_nt_continue, lookup_ssn, find_syscall_instruction]
    key_structs: [CONTEXT_AMD64, ExceptionRecord, FunctionEntry]
    key_constants: [STATUS_SINGLE_STEP, CONTEXT_DEBUG_REGISTERS, FUNC_TABLE, SSN_TABLE, MAX_CHAIN_DEPTH]
    lines_of_interest:
      - "L42-L61: FUNC_TABLE (8 FunctionEntry slots) + SSN_TABLE + TABLE_COUNT static muts"
      - "L66-L100: CONTEXT_AMD64 minimal layout — _p1[6] = 0x30 padding to ContextFlags"
      - "L113-L130: get_nt_continue — AtomicPtr-cached GetProcAddress"
      - "L141-L196: exception_handler — DR-arity check, RAX=SSN, RIP=syscall, NtContinue"
      - "L236-L263: set_hardware_breakpoint_dr — RtlCaptureContext + DR7 local-enable bit set + NtContinue"
      - "L274-L308: hook_exception_dispatcher — VirtualProtect + .rdata callback pointer overwrite"
      - "L378-L435: find_wow64_callback_pointer — fragile ANSI_STRING heuristic in ntdll .rdata"
      - "L441-L470: install_step_over — registers up to 4 functions distributed across DR0-DR3"
  - file: src/dark_crystal/crowd/src/peb_unlink.rs
    key_functions: [unlink_module, unlink_self, inner_unlink, unlink_list_entry, ldr_lock_loader_lock, ldr_unlock_loader_lock]
    key_structs: []
    key_constants: [DLLBASE_OFFSET, INLOAD_OFFSET, INMEMORY_OFFSET, ININIT_OFFSET]
    lines_of_interest:
      - "L38-L44: LDR_DATA_TABLE_ENTRY x64 offsets (DllBase=+0x30)"
      - "L48-L62: ldr_lock_loader_lock — calls ntdll export via RecycledGate::invoke (NOT a syscall)"
      - "L77-L86: unlink_module wraps with loader-lock acquire/release"
      - "L88-L139: inner_unlink — InLoadOrderModuleList walk + 3-list unlink"
      - "L142-L155: unlink_list_entry — Flink/Blink patching + self-referential zeroing"
      - "L158-L171: unlink_self — reads PEB.ImageBaseAddress (+0x10) via gs:[0x60]"
  - file: src/dark_crystal/crowd/src/policy.rs
    key_functions: [apply_block_dll_policy, apply_acg_policy, harden_process, set_process_info]
    key_structs: [ProcessSignaturePolicyInfo, ProcessDynamicCodePolicyInfo]
    key_constants: [PROCESS_MITIGATION_POLICY_CLASS, MITIGATION_POLICY_SIGNATURE, MITIGATION_POLICY_DYNAMIC_CODE]
    lines_of_interest:
      - "L22: PROCESS_MITIGATION_POLICY_CLASS = 52 (ProcessInformationClass)"
      - "L26-L27: sub-policy discriminants 8=Signature, 2=DynamicCode"
      - "L36-L44: two-policy struct layout (u32 discriminant + u32 flags)"
      - "L47-L52: set_process_info — NtSetInformationProcess via RecycledGate with 4 args"
      - "L57-L66: apply_block_dll_policy — MicrosoftSignedOnly bit 0x1"
      - "L71-L80: apply_acg_policy — ProhibitDynamicCode bit 0x1"
      - "L87-L91: harden_process — BlockDLL only; ACG must be applied post-load manually"
  - file: src/dark_crystal/crowd/src/block_handle.rs
    key_functions: [block_external_handles, inner_block]
    key_structs: []
    key_constants: [DACL_SECURITY_INFORMATION, PROCESS_ALL_ACCESS, ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACE_INHERIT_ALL]
    lines_of_interest:
      - "L17-L21: SD/ACL/ACE type constants"
      - "L42-L167: inner_block — hand-rolled SECURITY_DESCRIPTOR + ACL + 2 ACEs in 256-byte buffer"
      - "L107-L130: DENY Everyone (S-1-1-0) ACE construction"
      - "L133-L154: ALLOW SYSTEM (S-1-5-18) ACE construction"
      - "L156-L167: ACL header write (AclRevision=2, AceCount=2)"
      - "L168-L180: NtSetSecurityObject call — may require SeSecurityPrivilege"
min_windows: "Windows 10 1607 (ACG requires RS1; other techniques work on Win7+)"
needs_admin: conditional
tags: [amsi, etw, stack-spoofing, peb-unlink, ntdll-unhook, block-dll, acg, block-handle, advanced-stack, arg-spoofing, hardware-breakpoint, ki-step-over, dr-registers, exception-handler-hook, sddl, dacl, mitigation-policy]
---

# EDR Evasion Suite — Operator Playbook

## TL;DR

This card's six analyzed files form the **ring-3 hardening and stealth layer** of `dark_crystal/crowd`. They share one architectural invariant: every privileged NT call goes through `crate::recycled::invoke` (T-001 RecycledGate) with DJB2-hashed function names from `crate::resolve::compute_hash` (T-004 PEB walker), so no Win32 import table entry ever names `NtSetInformationProcess`, `NtSetSecurityObject`, `NtReadVirtualMemory`, or `LdrLockLoaderLock`. The suite covers three evasion pillars: (1) **post-facto stealth** — `peb_unlink`, `stack_spoof`, `block_handle`; (2) **pre-facto policy hardening** — `policy` (BlockDLL + ACG); (3) **silent hook bypass** — `ki_step_over` DR0/VEH mechanism; and (4) **deception at process-creation time** — `arg_spoof`. Use `policy` + `block_handle` + `ki_step_over` together as a hardened carrier for any T-007 injection chain.

## Source File Map

| File | Role | Key Exports | Approx Size |
|---|---|---|---|
| `crowd/src/stack_spoof.rs` | Single-frame return-address substitution with RAII restore | `spoof_caller()`, `SpoofGuard`, `null_guard()` | ~325 lines |
| `crowd/src/arg_spoof.rs` | PEB ProcessParameters→CommandLine.Buffer overwrite on suspended child | `spoof_args_in_peb()`, `BENIGN_ARGS` | ~175 lines |
| `crowd/src/ki_step_over.rs` | DR0-DR3 HW BP on hooked ntdll instructions + Wow64PrepareForException callback hijack | `install_step_over()`, `register_step_over()`, `set_hardware_breakpoint_dr()`, `hook_exception_dispatcher()`, `exception_handler` | ~470 lines |
| `crowd/src/peb_unlink.rs` | 3-list PEB.Ldr unlink under loader lock | `unlink_module()`, `unlink_self()` | ~190 lines |
| `crowd/src/policy.rs` | ProcessSignaturePolicy + ProcessDynamicCodePolicy via NtSetInformationProcess class 52 | `apply_block_dll_policy()`, `apply_acg_policy()`, `harden_process()` | ~95 lines |
| `crowd/src/block_handle.rs` | Hand-rolled SECURITY_DESCRIPTOR + DACL + 2 ACEs written via NtSetSecurityObject | `block_external_handles()` | ~180 lines |

## How It Works

### 1. PEB Module Unlinking (`peb_unlink.rs::unlink_module`)
1. Thread acquires the NT loader lock by hashing `"LdrLockLoaderLock"` via `crate::resolve::compute_hash` and invoking it through `crate::recycled::invoke` with `Flags=0` (blocking) + `&mut disposition` + `&mut cookie`. The cookie is captured for later release.
2. PEB is fetched via `core::arch::asm!("mov {}, gs:[0x60]")` — same pattern T-004 PEB walker uses.
3. `PEB.Ldr` is read from `peb+0x18`; the `InLoadOrderModuleList` head is at `Ldr+0x10`.
4. The walker dereferences `*(head_load) = Flink` and follows it. For each entry, `DllBase` is at `entry+0x30` (`DLLBASE_OFFSET`). When `dll_base == target_base`, the entry is unlinked from all three lists.
5. `unlink_list_entry` performs classic doubly-linked-list removal: `blink.Flink := flink`, `flink.Blink := blink`. It then writes `entry.Flink = entry.Blink = entry` (self-referential) to make forensics reconstruction harder.
6. The `InInitializationOrderLinks` (offset 0x20) is only unlinked if its Flink/Blink are non-null and non-self-referential — `ntdll` and the process image often aren't in this list.
7. Loader lock is released via `LdrUnlockLoaderLock(0, cookie)` through RecycledGate.
8. After unlink, the module is invisible to `EnumProcessModules`, `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`, and any PEB-walking EDR enumerator. The DLL's `DllMain` had to have already run.

### 2. Stack Spoofing (`stack_spoof.rs::spoof_caller`)
1. `get_rsp()` issues `core::arch::asm!("mov {}, rsp")` with `options(nostack, readonly, pure)` to read the current stack pointer without allocating.
2. `get_own_base()` reads `PEB.ImageBaseAddress` from `gs:[0x60] + 0x10` — exact T-004 pattern.
3. `find_frame_in_kernelbase(0x28)` is called with the **canonical 0x28 frame size** (most common wrapper-frame size in kernelbase). It loads `kernelbase.dll` via `GetModuleHandleA`, walks `.pdata` via `get_pdata` (manual PE parsing — `e_lfanew` at 0x3C, NT sig at 0x4550, `DataDirectory[3]` at `opt+0x60`), and scans every `RUNTIME_FUNCTION` entry for one whose `calc_frame_size` returns `0x28`.
4. `calc_frame_size` recurses up to `MAX_CHAIN_DEPTH=32` through `UNW_FLAG_CHAININFO` chains (chain entry is at `unwind_addr + 4 + (count_of_codes+1)/2*4`). It sums stack adjustments: `UWOP_PUSH_NONVOL` adds 8, `UWOP_ALLOC_SMALL` adds `(info+1)*8`, `UWOP_ALLOC_LARGE` adds either `next_u16*8` (info==0) or `(hi<<16)|lo` (info!=0). Adds 8 for the return-address slot at the end.
5. The chosen kernelbase function gets a randomized interior offset: `seed * 6364136223846793005 + 1442695040888963407` mod `(fn_size/2)` — these constants are the PCG/LCG multiplier and increment, used to perturb the pointer without being identical across runs.
6. `spoof_caller` walks 12 stack slots from `[RSP+8]` to `[RSP+96]` looking for a value in `[own_base, own_base + SizeOfImage)`. The first match is the caller's return address — it gets overwritten in place with the kernelbase interior pointer.
7. `SpoofGuard` captures `stack_slot` + `original_ret`. When the guard drops, it writes `original_ret` back to `stack_slot`, restoring the stack before the kernelbase pointer is actually called (which would crash by jumping into the middle of an unrelated kernelbase function).

### 3. KiUserExceptionDispatcher StepOver (`ki_step_over.rs::install_step_over`)
1. `hook_exception_dispatcher()` calls `crate::resolve::ntdll_base_and_name_hashes()` (T-004) to find ntdll's base, then `find_wow64_callback_pointer` scans ntdll's `.rdata` section for an `ANSI_STRING` whose `Buffer` points to the bytes `"Wow64PrepareForException"`. The qword immediately after that `ANSI_STRING` is treated as the function-pointer slot and overwritten with `exception_handler as usize` (after `VirtualProtect` → `PAGE_READWRITE`).
2. For each NT function in the supplied list, `register_step_over` resolves its SSN via `crate::resolve::resolve_ssn_by_hash(hash)` (T-002/T-003 SSN cascade). It gets the function address via `GetProcAddress(ntdll, name)`, checks the byte at `func_addr+3` — if it's `0xE9` (JMP rel32), the EDR has hooked the function.
3. The address+SSN pair is appended to `FUNC_TABLE` / `SSN_TABLE` (up to 8 entries).
4. `set_hardware_breakpoint_dr(func_addr+3, dr_index)` distributes targets across DR0-DR3. It captures context via `RtlCaptureContext`, sets the breakpoint address in the requested DR register, sets the local-enable bit in DR7 (`1u64 << (dr_index * 2)`), then `NtContinue`s back.
5. When the thread hits the JMP instruction, `STATUS_SINGLE_STEP` (0x80000004) fires. The replaced callback dispatches to `exception_handler`. The handler matches RIP against `[Dr0, Dr1, Dr2, Dr3]`, computes `base_addr = rip - 3`, looks up the SSN in `FUNC_TABLE`, scans forward up to 25 bytes for the `0F 05` syscall pattern via `find_syscall_instruction`, sets `RAX := SSN`, `RIP := syscall_addr`, clears `Dr6` (acknowledges), and `NtContinue`s. The DR register is **not** cleared, so the BP re-arms for the next call.
6. `unhook_exception_dispatcher(slot)` writes `null` back into the callback slot (the original `Wow64PrepareForException` pointer isn't saved/restored — see Edge Cases).

### 4. Process Argument Spoofing (`arg_spoof.rs::spoof_args_in_peb`)
1. Caller (e.g., `ppid.rs`) creates a suspended process via `NtCreateUserProcess` with `BENIGN_ARGS = "RuntimeBroker.exe -Embedding"`. The PEB of the child has a `ProcessParameters` whose `CommandLine.Buffer` contains the benign string.
2. `arg_spoof::spoof_args_in_peb(h_process, real_args)` calls `crate::recycled::nt_query_information_process` with `ProcessBasicInformation` (class 0) to fetch `PEB.ProcessParameters` of the child via `ProcessBasicInfo.peb_base_address`.
3. It reads the `RTL_USER_PROCESS_PARAMETERS` pointer from `peb_base + 0x20` via `NtReadVirtualMemory` (resolved by `compute_hash("NtReadVirtualMemory")` and invoked through `crate::recycled::invoke` with 5 args).
4. It reads `MaximumLength` at `proc_params+0x72` and `Buffer` at `proc_params+0x78`. Bounds-checks: `byte_len(new_args) > remote_max_length` → returns Err to prevent overflow.
5. UTF-16-encodes `real_args`, writes via `NtWriteVirtualMemory` to `cmd_buffer_ptr`. Then patches `Length` (+0x70) and `MaximumLength` (+0x72) to `byte_len` and `byte_len+2`.
6. The child process is then resumed (by the caller). The eventlog/sysmon creation event captured the benign CommandLine; the running process sees the real one.

### 5. Mitigation Policies (`policy.rs::apply_block_dll_policy` / `apply_acg_policy`)
1. `set_process_info(info_class, data, data_len)` constructs `[GetCurrentProcess(), info_class, data, data_len]` and invokes `compute_hash("NtSetInformationProcess")` with arg count 4 through RecycledGate.
2. **BlockDLL**: builds `ProcessSignaturePolicyInfo { policy: 8, flags: 0x1 }` (MicrosoftSignedOnly) and calls `set_process_info(52, &policy, 8)`. After this, only Microsoft-signed DLLs can be mapped into the process — EDR DLL injection fails at the loader.
3. **ACG**: builds `ProcessDynamicCodePolicyInfo { policy: 2, flags: 0x1 }` (ProhibitDynamicCode) and calls the same NtSetInformationProcess path. Subsequent `VirtualAlloc(PAGE_EXECUTE_*)` and `VirtualProtect(PAGE_EXECUTE_*)` calls fail with `STATUS_DYNAMIC_CODE_BLOCKED`.
4. `harden_process()` applies **only** BlockDLL. The ACG call is intentionally skipped because any RX allocation done *after* ACG (e.g., shellcode buffers, trampolines) will fail. The comment directs the operator to call `apply_acg_policy()` manually after module mapping is complete — critical sequencing hint for T-013 Module Overloading.

### 6. Handle Blocking (`block_handle.rs::block_external_handles`)
1. `inner_block(h_process)` builds a complete self-relative `SECURITY_DESCRIPTOR` in a 256-byte stack/heap buffer.
2. SD header: `Revision=1`, `Control = SE_DACL_PRESENT(0x0004) | SE_SELF_RELATIVE(0x8000)`, `Dacl offset = 20`.
3. ACL header at offset 20: `AclRevision=2`, `AclSize = 8+40 = 48`, `AceCount=2`.
4. ACE 1 (offset 28): `ACCESS_DENIED_ACE_TYPE` for Everyone (`S-1-1-0`) — SID has `Revision=1`, `SubAuthorityCount=1`, `IdentifierAuthority[6]=[0,0,0,0,0,1]`, `SubAuthority[0]=0`. Mask = `PROCESS_ALL_ACCESS (0x1FFFFF)`. Size = 20 bytes.
5. ACE 2 (offset 48): `ACCESS_ALLOWED_ACE_TYPE` for SYSTEM (`S-1-5-18`) — same shape, `IdentifierAuthority[7]=5`, `SubAuthority[0]=18`. Mask = `PROCESS_ALL_ACCESS`. Size = 20 bytes.
6. `NtSetSecurityObject(h_process, DACL_SECURITY_INFORMATION=0x4, buf.as_mut_ptr())` via RecycledGate. After this, `OpenProcess(pid, PROCESS_ALL_ACCESS)` from any non-SYSTEM non-owner caller returns `STATUS_ACCESS_DENIED`.

## Code Architecture

### Module Dependency Graph (verified by reading actual `use` statements)

```
                        ┌─ crate::recycled (T-001 RecycledGate) ───┐
                        │                                            │
arg_spoof.rs ───────────┤                                            │
peb_unlink.rs ──────────┤──► crate::recycled::invoke                 │
policy.rs ──────────────┤    crate::recycled::nt_query_information_process
block_handle.rs ────────┤                                            │
                        │                                            │
                        └─ crate::resolve (T-004 PEB Walker + DJB2)──┘
                           crate::resolve::compute_hash
                           crate::resolve::resolve_ssn_by_hash  ◄─── ki_step_over.rs
                           crate::resolve::ntdll_base_and_name_hashes ◄─ ki_step_over.rs

ki_step_over.rs ──► winapi::um::libloaderapi (GetModuleHandleA / GetProcAddress)
                ──► winapi::um::memoryapi (VirtualProtect)
                ──► winapi::um::winnt (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER)
                ──► crate::mega_dbg! macro

stack_spoof.rs ────► windows::Win32::System::LibraryLoader::GetModuleHandleA (windows-rs crate, NOT winapi)
                ──► core::arch::asm!
```

**Inconsistency worth flagging**: `ki_step_over.rs` uses the older `winapi` crate (`winapi::um::*`), while `stack_spoof.rs` uses `windows-rs` (`windows::Win32::*`). The rest of the suite (`arg_spoof`, `peb_unlink`, `policy`, `block_handle`) goes through `crate::recycled` exclusively — making them effectively crate-internal. This means `ki_step_over.rs` and `stack_spoof.rs` import their own Win32 bindings, which can cause symbol duplication in the final binary and increases IAT surface (each `winapi::um::libloaderapi::GetProcAddress` reference is a real IAT entry, not a hashed dynamic resolution).

### Data Flow

- **Static state**: `ki_step_over.rs` holds three mutable statics — `FUNC_TABLE` (8 × `FunctionEntry` with `AtomicU64` addresses), `SSN_TABLE` (8 × u32), `TABLE_COUNT`. `NT_CONTINUE_PTR` is `AtomicPtr<c_void>` cached once.
- **Per-call state**: `stack_spoof::SpoofGuard` lives on the calling function's stack — Drop restores the return address. `peb_unlink::unlink_module` returns `Result<()>` and holds the loader lock cookie in a local.
- **No global state in**: `arg_spoof`, `policy`, `block_handle`, `peb_unlink` other than the cached `NT_CONTINUE_PTR`.

### Type Hierarchy

```
stack_spoof:
  SpoofGuard { stack_slot: *mut usize, original_ret: usize }   // #[must_use], Drop restores
  RuntimeFunction { begin_rva, end_rva, unwind_rva: u32 }       // 12 bytes, .pdata entry
  UnwindInfo { version_flags, size_of_prolog, count_of_codes, frame_register_offset: u8 }

ki_step_over:
  CONTEXT_AMD64 { ... Dr0..Dr7, Rax..R15, Rip, _rest[1024] }  // align(16), ~1232 bytes
  ExceptionRecord { ExceptionCode, ...ExceptionInformation[15] }
  FunctionEntry { address: AtomicU64, ssn: u32 }

policy:
  ProcessSignaturePolicyInfo { policy: u32, flags: u32 }       // 8 bytes
  ProcessDynamicCodePolicyInfo { policy: u32, flags: u32 }     // 8 bytes

arg_spoof:
  ProcessBasicInfo { exit_status, peb_base_address, affinity_mask, base_priority, unique_process_id, inherited_from_unique_pid: usize }

peb_unlink, block_handle: no structs of their own
```

### Feature Gates

None of these six files have `#[cfg(...)]` conditionals except `stack_spoof::get_own_base` which has `#[cfg(target_arch = "x86_64")]` and returns 0 on non-x86_64 (functionally dead code on other targets — file is x86_64-only). `ki_step_over.rs::find_wow64_callback_pointer` uses `if cfg!(target_arch = "x86_64")` for the `ANSI_STRING.Buffer` offset (8 vs 4).

## Operational Profile

### When to Use

- **`policy::harden_process`** — apply **before** any T-007 injection into the current process. BlockDLL stops the EDR's userland DLL from getting mapped (the standard EDR injection vector). Use on the spawning parent process before it goes persistent.
- **`policy::apply_acg_policy`** — call **after** all RX regions you need are mapped. Pairs well with T-013 Module Overloading where the overloaded DLL is the only RX page you ever need.
- **`block_handle::block_external_handles`** — apply to the spawned child process *immediately after* injection and *before* the child's first beacon. Stops pe-sieve, Process Hacker, EDR DLL re-injection at ring 3.
- **`ki_step_over::install_step_over`** — use when you suspect EDR has inline hooks in ntdll (you can detect via the `0xE9` byte check at `func_addr+3` baked into `register_step_over`). Pre-populate the function list with the same NT functions the rest of your chain uses (e.g., `["NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx"]`).
- **`peb_unlink::unlink_module`** — after reflective DLL load (T-013 PE Loader) to drop the module from `EnumProcessModules` results. The module's `DllMain` must have already run.
- **`peb_unlink::unlink_self`** — dropper self-unlink before `self_delete.rs` runs, so the dying process doesn't appear in module snapshots.
- **`stack_spoof::spoof_caller`** — wraps any single call to a Win32 API that an EDR stack-traces. Must be the *first statement* of an `#[inline(never)]` function; the `SpoofGuard` must live through the entire call scope.
- **`arg_spoof::spoof_args_in_peb`** — between `NtCreateUserProcess` (suspended) and `NtResumeThread`. Pairs with T-015 PPID Spoofing and T-014 NtCreateUserProcess.

### When NOT to Use

- **BlockDLL on the EDR's own host process** — MicrosoftSignedOnly blocks EDR DLLs but also blocks **your** non-Microsoft-signed beacon DLL. Only apply to processes that load only Microsoft-signed post-policy.
- **ACG before shellcode execution** — ACG prevents `VirtualProtect(PAGE_EXECUTE_READWRITE)`. If your chain relies on RWX trampolines (T-007 Callback Exec, T-007 Fiber Exec), apply ACG last or skip entirely.
- **`ki_step_over` when the process is pure 64-bit** — see Edge Case #1: the `Wow64PrepareForException` hook is WOW64-only. On 64-bit faulting code the hook may not fire.
- **`peb_unlink` on a module that's still referenced by name through `LdrGetProcedureAddress`** — the loader will fault. Unlink only after you've cached every export pointer you need.
- **`stack_spoof::spoof_caller` in async or stack-switching code** — the guard assumes a contiguous stack frame. Across `await` points or fiber switches the SpoofGuard is dropped prematurely and the spoof vanishes (or worse, the kernelbase pointer gets called and crashes).
- **`arg_spoof` when `real_args` is longer than `BENIGN_ARGS`** — the `MaximumLength` bounds check returns Err. Pad the decoy with whitespace.

### Kill Chain Position

```
T-004 (PEB Walk) ─► T-002 (Hell's Gate SSN) ─► T-001 (RecycledGate)
                                                │
                                                ▼
                                  ┌─── T-016 (this suite) ────┐
                                  │                            │
                  policy::harden_process (pre-spawn)            arg_spoof::spoof_args_in_peb (suspended child)
                                  │                            │
                                  ▼                            ▼
                  T-015 (PPID Spoof) ──► T-014 (NtCreateUserProcess) ──► T-012 (Early Cascade) or T-013 (Module Overload)
                                                │
                                                ▼
                                block_handle + ki_step_over (post-injection)
                                                │
                                                ▼
                                T-005 (Ekko Sleep) + stack_spoof (per-API)
                                                │
                                                ▼
                                  T-008 (Persistence) + peb_unlink (forensics)
```

### Trade-offs

## Rust Implementation Deep Dive

### `unsafe` Blocks (every one, by file)

**stack_spoof.rs**
- `unsafe fn get_rsp()` (L62-L66) — single `asm!("mov {}, rsp")`. Pure/readonly/nostack.
- `unsafe fn calc_frame_size_inner(...)` (L73-L139) — dereferences raw `*const UnwindInfo` and `*const u16` codes; recursive on `UNW_FLAG_CHAININFO`.
- `unsafe fn get_pdata(module_base)` (L142-L163) — PE header pointer arithmetic: `*(base as *const u16) == 0x5A4D`, `e_lfanew` at `0x3C`, NT sig `0x4550`, `DataDirectory[3]` at `opt+0x60`.
- `unsafe fn find_frame_in_kernelbase(...)` (L168-L207) — `GetModuleHandleA` then walks pdata with raw `*const RuntimeFunction`. The RNG `(seed * 6364136223846793005 + 1442695040888963407) % (fn_size/2)` is a 64-bit LCG with the PCG-style constants.
- `pub unsafe fn spoof_caller()` (L222-L258) — walks 12 stack slots from RSP, looks for own-module pointers, overwrites in place.
- `unsafe fn get_own_base()` (L261-L273) — `asm!("mov {}, gs:[0x60]")` then `*(peb as *const usize).add(2)` for `PEB.ImageBaseAddress`.
- `unsafe fn get_own_image_size(base)` (L276-L287) — reads `OptionalHeader + 0x38`.
- `impl Drop for SpoofGuard::drop` (L51-L57) — `*self.stack_slot = self.original_ret`.

**arg_spoof.rs**
- `unsafe fn inner_spoof(h_process, real_args)` (L36-L170) — five `crate::recycled::invoke` calls: NtQueryInformationProcess, NtReadVirtualMemory ×3, NtWriteVirtualMemory ×3. Each passes 5 args in a `&[usize]`.

**ki_step_over.rs**
- `pub extern "system" fn exception_handler(...)` (L141-L196) — raw `*mut ExceptionRecord` + `*mut CONTEXT_AMD64`. Calls `nt_continue(ctx, 0)` which doesn't return. Note: the function is `extern "system"` so it's safe to install as a callback, but `mega_dbg!` inside it may allocate —_dbg-in-exception-handler is risky.
- `fn get_nt_continue()` unsafe block (L113-L130) — `GetModuleHandleA("ntdll.dll")` + `GetProcAddress("NtContinue")` + `transmute`.
- `pub fn set_hardware_breakpoint_dr(...)` unsafe block (L236-L263) — `RtlCaptureContext(&mut ctx)` then patch DRx + DR7 + `NtContinue(&mut ctx, 0)`.
- `pub fn hook_exception_dispatcher()` unsafe block (L274-L308) — `VirtualProtect(PAGE_READWRITE)` on the callback slot, `*(slot as *mut usize) = exception_handler as usize`, then `VirtualProtect(PAGE_READONLY)`.
- `pub fn unhook_exception_dispatcher(...)` unsafe block (L311-L335) — VirtualProtect + null-out + VirtualProtect.
- `pub fn register_step_over(...)` unsafe block (L338-L373) — `*(hook_addr as *const u8) == 0xE9` hook check + writes to `FUNC_TABLE`/`SSN_TABLE` (mutable statics — UB if called concurrently).
- `fn find_wow64_callback_pointer(...)` unsafe block (L378-L435) — `IMAGE_DOS_HEADER` / `IMAGE_NT_HEADERS64` / `IMAGE_SECTION_HEADER` walk, then 8-byte stride .rdata scan comparing `ANSI_STRING` Length/MaxLength/Buffer.
- `fn lookup_ssn(...)` unsafe block — reads `TABLE_COUNT` and `FUNC_TABLE` mutable statics.
- `fn find_syscall_instruction(from)` — reads `*ptr == 0x0F && *(ptr.add(1)) == 0x05`.

**peb_unlink.rs**
- `unsafe fn ldr_lock_loader_lock()` (L48-L62) — RecycledGate::invoke with `&mut disposition`, `&mut cookie`.
- `unsafe fn ldr_unlock_loader_lock(cookie)` (L65-L74) — invokes `"LdrUnlockLoaderLock"` with 2 args.
- `unsafe fn inner_unlink(target_base)` (L88-L139) — `asm!("mov {}, gs:[0x60]")` + `*((peb+0x18) as *const usize)` for Ldr, walks `*(head_load)`.
- `unsafe fn unlink_list_entry(entry)` (L142-L155) — Flink/Blink patching + self-referential zeroing.
- `pub fn unlink_self()` unsafe block (L158-L171) — reads `*((peb+0x10) as *const usize)` for own ImageBase.

**policy.rs**
- `unsafe fn set_process_info(...)` (L47-L52) — RecycledGate::invoke with 4 args including `GetCurrentProcess().0`.
- `pub unsafe fn apply_block_dll_policy()` (L57-L66) — builds `ProcessSignaturePolicyInfo` and calls `set_process_info(52, ...)`.
- `pub unsafe fn apply_acg_policy()` (L71-L80) — same with `ProcessDynamicCodePolicyInfo`.
- `pub unsafe fn harden_process()` (L87-L91) — calls BlockDLL only.

**block_handle.rs**
- `unsafe fn inner_block(h_process)` (L42-L180) — 256-byte buffer manipulation + `crate::recycled::invoke("NtSetSecurityObject", 3, args)`.

### `core::arch::asm!` Inventory

| File | Function | Instruction | Constraints | Clobbers |
|---|---|---|---|---|
| stack_spoof.rs | `get_rsp` | `mov {}, rsp` | `out(reg) rsp`, `options(nostack, readonly, pure)` | none |
| stack_spoof.rs | `get_own_base` | `mov {}, gs:[0x60]` | `out(reg) peb`, `options(nostack, readonly, pure)` | none |
| peb_unlink.rs | `inner_unlink` | `mov {}, gs:[0x60]` | `out(reg) peb`, `options(nostack, readonly, pure)` | none |
| peb_unlink.rs | `unlink_self` | `mov {}, gs:[0x60]` | `out(reg) peb`, `options(nostack, readonly, pure)` | none |

All asm is x86_64-specific. `options(pure)` lets the optimizer reorder — combined with `readonly` this means the compiler is told the asm doesn't mutate memory. For `gs:[0x60]` this is correct (PEB is thread-local via the TEB segment). For `rsp` it's correct (RSP doesn't change between the asm and the use of its output).

### FFI Patterns

- **Winapi (ki_step_over.rs)**: uses `winapi::um::libloaderapi::GetModuleHandleA/GetProcAddress`, `winapi::um::memoryapi::VirtualProtect`, `winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, PAGE_READWRITE, PAGE_READONLY}`. These are static imports — they appear in the import table.
- **Windows-rs (stack_spoof.rs, policy.rs)**: `windows::Win32::System::LibraryLoader::GetModuleHandleA`, `windows::Win32::System::Threading::GetCurrentProcess`. Also static imports.
- **RecycledGate dynamic (arg_spoof.rs, peb_unlink.rs, policy.rs, block_handle.rs)**: `crate::recycled::invoke(compute_hash(name), argc, &args)`. No static IAT entries for the named NT functions. **This is the core evasion property of the suite.**
- **Cached pointer (ki_step_over.rs)**: `NT_CONTINUE_PTR: AtomicPtr<c_void>` cached via `transmute`. Once-only GetProcAddress — note this is a static import of `GetProcAddress`.

### Initialization Patterns

- **OnceLock/LazyCell**: none in these six files. The closest is `NT_CONTINUE_PTR: AtomicPtr<c_void>` in `ki_step_over.rs` (manually cached, Relaxed ordering).
- **`include_str!`**: not used in these files (used elsewhere for config).
- **`#[must_use]`**: `SpoofGuard` carries `#[must_use = "..."]` with operator-facing message.
- **Static mutables**: `ki_step_over.rs` has `static mut SSN_TABLE: [u32; 8]`, `static mut TABLE_COUNT: usize`. These are unsafe to access concurrently — no `AtomicUsize` is used for `TABLE_COUNT` despite `FUNC_TABLE` using `AtomicU64`. **Concurrency bug**: `install_step_over` is not reentrant; calling it from multiple threads simultaneously would race on `TABLE_COUNT`.

### Error Handling

- **`anyhow::Result`** in `arg_spoof`, `peb_unlink`, `block_handle` — failures are bubbled up with context.
- **Boolean returns** in `policy` — `apply_block_dll_policy` returns `bool` (true = success). No error context. Status code is lost.
- **Silent failures**: `ki_step_over::register_step_over` returns `false` if not hooked or if SSN resolution fails — caller may interpret "not hooked" (which is fine) the same as "failed to resolve" (which is a problem).
- **Panic-free** in all hot paths. `find_frame_in_kernelbase` uses `unwrap_or_default()` on `SystemTime::now().duration_since(UNIX_EPOCH)` to avoid panicking if the clock is before epoch (impossible but defensive).

### Memory Layout

- `CONTEXT_AMD64` (ki_step_over.rs): `align(16)`, `_p1: [u64; 6]` (48 bytes for P1Home..P6Home), `ContextFlags: u32` at offset 0x30, `_mxcsr: u32` at 0x34, `_seg: [u16; 6]` at 0x38 (12 bytes), `_eflags: u32` at 0x44, then Dr0..Dr7 at 0x48..0x78, Rax..R15 at 0x78..0xF8, Rip at 0xF8, `_rest: [u8; 1024]` for the remaining ~1024 bytes (Xmm, Vector, etc.). Total ~1232 bytes — matches Windows `CONTEXT` (1232 bytes on x64).
- `RuntimeFunction` (stack_spoof.rs): 12 bytes — `begin_rva, end_rva, unwind_rva: u32`. Matches x64 `RUNTIME_FUNCTION`.
- `UnwindInfo`: 4 bytes header (version_flags, size_of_prolog, count_of_codes, frame_register_offset) — unwind codes follow as `u16` array.
- `ProcessSignaturePolicyInfo` / `ProcessDynamicCodePolicyInfo`: 8 bytes each — `policy: u32` discriminant + `flags: u32`. Matches the kernel's `PROCESS_MITIGATION_POLICY_INFORMATION` union.

### Syscall / SSN Resolution

- `arg_spoof`, `peb_unlink`, `policy`, `block_handle`: all NT syscalls are dispatched through `crate::recycled::invoke(hash, argc, args)`. The SSN resolution happens inside `crate::recycled` which presumably uses the SSN map (T-004 sysindirect_map.rs). The caller doesn't see SSNs.
- `ki_step_over::register_step_over`: explicitly calls `crate::resolve::resolve_ssn_by_hash(hash)` to get the `(ssn, _gadget)` pair — this is the T-002/T-003 Hells Gate cascade. The SSN is stored in `SSN_TABLE[i]` and written to `RAX` in the exception handler.

## Cross-References Found in Code

- `arg_spoof.rs:inner_spoof()` → calls `crate::recycled::nt_query_information_process` and `crate::recycled::invoke(compute_hash("NtReadVirtualMemory"), ...)` / `NtWriteVirtualMemory` → **T-001 (RecycledGate)**, **T-004 (PEB Walker/DJB2)**
- `arg_spoof.rs:1` comment → "NtCreateUserProcess with args benignos (en ppid.rs)" → **T-015 (PPID Spoofing)**, **T-014 (NtCreateUserProcess)**
- `ki_step_over.rs:18` comment → "crowd's AMSI-HBP (amsi_hbp.rs) also uses DR0. Call ki_step_over functions after AMSI-HBP has been installed and triggered" → **T-016 (AMSI HBP — same card, conflict noted in code)**
- `ki_step_over.rs:register_step_over()` → calls `crate::resolve::resolve_ssn_by_hash(hash)` → **T-002 (Hells Gate) / T-003 (VEH Gate)** — same SSN resolution path
- `ki_step_over.rs:hook_exception_dispatcher()` → calls `crate::resolve::ntdll_base_and_name_hashes()` → **T-004 (PEB Walker)**
- `peb_unlink.rs:ldr_lock_loader_lock()` → `crate::recycled::invoke(compute_hash("LdrLockLoaderLock"), 3, ...)` → **T-001 (RecycledGate)** — note: LdrLockLoaderLock is a regular ntdll export, NOT a syscall. This implies RecycledGate::invoke has a fallback path for non-syscall ntdll exports, OR this code path silently fails.
- `policy.rs` comment → "caller must call apply_acg_policy() manually post-load if desired" → **T-013 (Module Overloading)** — sequencing dependency
- `policy.rs:set_process_info()` → `crate::recycled::invoke(compute_hash("NtSetInformationProcess"), 4, ...)` → **T-001**, **T-004**
- `block_handle.rs:inner_block()` → `crate::recycled::invoke(compute_hash("NtSetSecurityObject"), 3, ...)` → **T-001**, **T-004**
- `stack_spoof.rs:get_own_base()` → `mov {}, gs:[0x60]` → **T-004 (PEB Walker — same TEB→PEB access pattern)**
- `ki_step_over.rs` `STATUS_SINGLE_STEP` semantics, DR registers, KiUserExceptionDispatcher → **T-002 (VEH Gate)** — conceptually related exception-mediated syscall dispatch
- `stack_spoof.rs:1` comment → "Portado del proyecto Unwinder (legacy)" → references the legacy `Unwinder` project (not in vault)
- `ki_step_over.rs:33` comment → "Type aliases (adapted from Tsukuyomi — no dinvk dep)" → external project reference

## Edge Cases & Failure Modes

1. **`ki_step_over` may not fire on pure 64-bit code**
   - **Scenario**: Process is pure x64 (no WOW64 involved). EDR hooks ntdll's `NtAllocateVirtualMemory` with `0xE9` at +3. DR0 is set on the hook instruction.
   - **What goes wrong**: The `Wow64PrepareForException` callback is only invoked by `KiUserExceptionDispatcher` when the faulting code is in 32-bit (WOW64) context. For native 64-bit exceptions, `KiUserExceptionDispatcher` → `RtlDispatchException` walks the SEH/VEH table directly; `Wow64PrepareForException` is bypassed.
   - **Symptom**: STATUS_SINGLE_STEP fires; the original Wow64PrepareForException handler (which the code has overwritten with null on unhook, or replaced with `exception_handler`) is never invoked; the process crashes with an unhandled single-step exception.
   - **Workaround**: Install a proper VEH via `AddVectoredExceptionHandler` (T-003 VEH Gate path) instead of hijacking the Wow64 callback. The code's comment "Bypasses EDR inline hooks silently" overstates the mechanism's reach.

2. **`ki_step_over::unhook_exception_dispatcher` writes `null` into the callback slot**
   - **Scenario**: Operator calls `unhook_exception_dispatcher(slot)` to clean up.
   - **What goes wrong**: The original `Wow64PrepareForException` pointer is never saved. The unhook code does `*(slot as *mut *mut c_void) = ptr::null_mut()` — it nulls the slot rather than restoring the original.
   - **Symptom**: After unhook, any WOW64 exception will dereference null and crash.
   - **Workaround**: Modify the unhook to save the original pointer at install time and restore it. This is a real bug.

3. **`find_wow64_callback_pointer` is a brittle heuristic**
   - **Scenario**: ntdll's `.rdata` contains an `ANSI_STRING` for `"Wow64PrepareForException"` followed by a function pointer in a global table. The code scans for the ANSI_STRING and assumes the *next qword* is the function pointer.
   - **What goes wrong**: Across Windows builds, the layout of `Wow64Info` / `LdrpWow64Info` may shift. If the ANSI_STRING and the function pointer aren't adjacent in some build, the code writes `exception_handler as usize` into an unrelated qword in `.rdata`.
   - **Symptom**: Either the hook never fires (because the real callback is untouched) or ntdll's globals are corrupted.
   - **Workaround**: Use a known offset from the `LdrpWow64Info` global rather than scanning. Or pin the technique to specific Windows builds.

4. **`ki_step_over` has no synchronization on `TABLE_COUNT` / `SSN_TABLE`**
   - **Scenario**: Two threads call `install_step_over` concurrently.
   - **What goes wrong**: `TABLE_COUNT` is `static mut usize` — non-atomic. Both threads read the same index, both write `FUNC_TABLE[idx]` and `SSN_TABLE[idx]`, then both `TABLE_COUNT += 1` — lost update.
   - **Symptom**: One of the registered functions is overwritten; its DR0 breakpoint fires but the SSN table returns 0 → handler returns null → process crashes.
   - **Workaround**: Wrap `install_step_over` in a `Mutex` or make `TABLE_COUNT` an `AtomicUsize` with fetch_add.

5. **`stack_spoof::spoof_caller` uses a hardcoded 0x28 frame size**
   - **Scenario**: The caller's actual frame size is not 0x28 (e.g., a function with large locals).
   - **What goes wrong**: The code looks up a kernelbase function with frame size 0x28 and substitutes its interior pointer. The actual return slot is at `[RSP + caller_frame_size]`, not `[RSP + 8..96]`.
   - **Symptom**: The 12-slot scan finds the wrong return address (or no return address) and either no-ops (returns `SpoofGuard{null,0}`) or overwrites the wrong stack slot.
   - **Workaround**: Use the advanced version (`crates/core/src/experimental/evasion/advanced_stack.rs`) which uses `BitReader` for full unwind parsing and constructs multi-frame fake chains via `global_asm!` trampoline.

6. **`stack_spoof::spoof_caller` writes a kernelbase interior pointer that may be called**
   - **Scenario**: The `SpoofGuard` drops *after* the spoofed function returns (correct usage), but if the spoofed function itself calls something that walks the stack (e.g., a stack-tracing EDR), the EDR sees a kernelbase pointer as the return address.
   - **What goes wrong**: If the EDR walks into that kernelbase function, it sees a nonsensical call sequence (the kernelbase function expects its own caller to be in kernel32/ntdll).
   - **Symptom**: EDR may flag the suspicious stack.
   - **Workaround**: Use `stack_spoof::spoof_caller` only for very short scopes (one syscall), not across long functions.

7. **`arg_spoof` MaximumLength check fails for longer real args**
   - **Scenario**: Real command line is `"powershell.exe -encodedcommand <base64>"` (~1000 chars). Benign decoy is `"RuntimeBroker.exe -Embedding"` (~30 chars).
   - **What goes wrong**: `byte_len > remote_max_length` → `Err("...would overflow")`.
   - **Symptom**: Function returns Err, no spoof happens, caller proceeds with benign args visible in logs but the real payload never runs.
   - **Workaround**: Pass a benign decoy at least as long as the real args (pad with whitespace). Modify `BENIGN_ARGS` accordingly.

8. **`block_handle::inner_block` may need `SeSecurityPrivilege`**
   - **Scenario**: Applying SDDL to another user's process.
   - **What goes wrong**: `NtSetSecurityObject` returns `STATUS_PRIVILEGE_NOT_HELD` (0xC0000061) or `STATUS_ACCESS_DENIED`.
   - **Symptom**: The error path returns `Err("NtSetSecurityObject failed: 0x{:x} (may require SeSecurityPrivilege)")`. Process remains unprotected.
   - **Workaround**: Enable `SeSecurityPrivilege` via `RtlAdjustPrivilege` (currently not done by the code) before the call.

9. **`peb_unlink::ldr_lock_loader_lock` calls a non-syscall via RecycledGate**
   - **Scenario**: RecycledGate::invoke expects an SSN-bearing syscall. `LdrLockLoaderLock` is a regular ntdll export.
   - **What goes wrong**: If `crate::recycled::invoke` only supports syscalls (SSN+gadget dispatch), it cannot resolve `LdrLockLoaderLock` — the call would return an error status. If the error path is taken, `unlink_module` returns Err without unlinking.
   - **Symptom**: Module remains linked in PEB. No crash, but no stealth either.
   - **Workaround**: Verify that `crate::recycled::invoke` has a non-syscall ntdll export path. If not, call `LdrLockLoaderLock` via a direct `GetProcAddress`-resolved function pointer instead.

## OPSEC Notes

### Artifacts Left

- **`ki_step_over.rs::hook_exception_dispatcher`** — `VirtualProtect` on ntdll `.rdata` from `PAGE_READONLY` → `PAGE_READWRITE` → `PAGE_READONLY`. This generates a `PAGE_WRITECOPY`/`PAGE_EXECUTE_WRITECOPY` event in ETW-Wow64 if the page was shared. psnotify/ETW-TI sees it.
- **`ki_step_over.rs` DR registers** — DR0-DR3 set on the EDR hook addresses. `GetThreadContext(thread, &ctx)` from another process will see non-zero Dr0..Dr3. EDR that periodically snapshots thread context will flag this.
- **`ki_step_over.rs` `Wow64PrepareForException` slot overwrite** — `*(ntdll!LdrpWow64Info+X)` is now a non-ntdll pointer. Integrity scanners that hash ntdll .rdata will detect this.
- **`policy.rs` NtSetInformationProcess class 52** — process object now has `ProcessSignaturePolicy.MicrosoftSignedOnly` and (optionally) `ProcessDynamicCodePolicy.ProhibitDynamicCode` set in the kernel's `EPROCESS.MitigationFlags`. Visible via `GetProcessMitigationPolicy` API — EDR can query this and immediately flag the process as hardened (strong indicator of malware).
- **`block_handle.rs` DACL change** — `NtSetSecurityObject` modifies the process's security descriptor. The SDDL with a Deny-All for Everyone is highly suspicious — EDR/SOC playbooks flag this exact pattern. Also visible via `GetSecurityObject` / Process Hacker.
- **`peb_unlink.rs` self-referential Flink/Blink** — `*((entry) as *mut usize) = entry` is a telltale of unlinking. Some forensic tools check for self-referential LIST_ENTRY nodes as "module hidden" indicator.
- **`stack_spoof.rs` kernelbase interior return address** — when the EDR walks the stack, the return address points to a non-prologue, non-epilogue location inside kernelbase. This is itself an anomaly — legitimate return addresses are typically at function boundaries or known call sites.

### Cleanup Performed

- **`ki_step_over::unhook_exception_dispatcher(slot)`** — restores the .rdata slot (but nulls it — see Edge Case #2, this is a bug). Restores DR registers? **No** — DR0-DR3 remain set after the unhook. Operator must manually clear them.
- **`SpoofGuard::drop`** — restores the original return address on the stack. Clean.
- **No cleanup** for: `policy` (irreversible for the process's lifetime), `block_handle` (DACL stays), `peb_unlink` (no restoration path implemented — `unlink_module` has no `relink_module` counterpart).
- **`arg_spoof`** — no cleanup, but the spoofed PEB is only in the child process's address space. Once the child exits, the artifact is gone.

### Telemetry Surface

- `ntdll!LdrLockLoaderLock` call from `peb_unlink` is a non-syscall ntdll export — visible in ETW `Module/Load` events as a `LdrLockLoaderLock` symbol resolution (if RecycledGate resolves it dynamically; otherwise it's invisible).
- `ntdll!NtSetInformationProcess(52, ...)` is a syscall — visible to ETW-TI/sysmon as a process-mitigation change.
- `kernel32!VirtualProtect(ntdll!LdrpWow64Info+X, ...)` from `ki_step_over` is a Win32 call (not a syscall) — visible in IAT-driven ETW module-level tracing.
- The `winapi::um::libloaderapi::GetProcAddress(ntdll, "NtContinue")` call in `ki_step_over::get_nt_continue` is a static import — appears in the binary's IAT as `GetProcAddress`, which EDRs consider suspicious in non-trivial processes.

## Reusable Patterns

### Pattern: `#[must_use]` RAII Guard for In-Memory Mutations
- **Use when**: You must temporarily mutate a memory location (stack slot, function pointer, page protection) and guarantee restoration even on `panic`/early-return.
- **Code ref**: `crowd/src/stack_spoof.rs:SpoofGuard` (L42-L58)
- **How**: `#[must_use = "..."] pub struct SpoofGuard { slot: *mut usize, original: usize }` with `impl Drop for SpoofGuard { fn drop(&mut self) { unsafe { *self.slot = self.original; } } }`. Caller binds the guard to a local that lives through the spoofed call scope. Dropping the guard restores the original. Use this pattern for any temporary in-place memory mutation.

### Pattern: `AtomicPtr<c_void>` Cached Function Pointer
- **Use when**: A Win32/NT function pointer must be resolved once and reused many times across threads without per-call `GetProcAddress` overhead.
- **Code ref**: `crowd/src/ki_step_over.rs:NT_CONTINUE_PTR` (L40, L113-L130)
- **How**: `static NT_CONTINUE_PTR: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut())`. `fn get_nt_continue() -> Option<NtContinueFn>` reads `Relaxed`, returns the cached value if non-null, else does `GetModuleHandleA + GetProcAddress`, `transmute`s the result, stores it `Relaxed`, returns it. Trade-off: `Relaxed` ordering means another thread might do the same resolution in parallel — wasted work but no UB since the value is idempotent.

### Pattern: Manual PE Header Walk for `.pdata`/`.rdata`
- **Use when**: You need a section pointer from a loaded module without depending on `windows::Win32` PE types (which differ across `windows` crate versions).
- **Code ref**: `crowd/src/stack_spoof.rs:get_pdata` (L142-L163), `crowd/src/ki_step_over.rs:find_wow64_callback_pointer` (L378-L435)
- **How**: Cast `base as *const u8`, check `*(base) == 0x5A4D` (DOS magic), read `e_lfanew` at `0x3C`, check `*(nt) == 0x4550` (PE magic), read `OptionalHeader` at `nt+24`, locate the relevant `IMAGE_DIRECTORY_ENTRY_*` (`DataDirectory[3]` for Exception/.pdata). Walk `IMAGE_SECTION_HEADER` array starting at `nt + sizeof(IMAGE_NT_HEADERS64)`.

### Pattern: Syscall Dispatch via DJB2 Hash + RecycledGate
- **Use when**: You need to invoke an NT function without an IAT entry naming it.
- **Code ref**: `crowd/src/arg_spoof.rs:inner_spoof` (L83-L96), `crowd/src/policy.rs:set_process_info`, `crowd/src/block_handle.rs:inner_block`
- **How**: `crate::recycled::invoke(crate::resolve::compute_hash("NtWriteVirtualMemory"), 5, &[h_process, addr, src, len, &mut written as *mut usize as usize])`. The hash function is DJB2 (likely — `compute_hash` in T-004 PEB walker), the SSN is resolved via T-002/T-003 Hells Gate cascade, the syscall instruction gadget is found in ntdll's `.text` (T-001 RecycledGate). Caller doesn't see SSNs or gadgets.

### Pattern: Hand-Rolled Security Descriptor in a Stack Buffer
- **Use when**: You need a `SECURITY_DESCRIPTOR` + DACL + ACEs and want zero heap allocation.
- **Code ref**: `crowd/src/block_handle.rs:inner_block` (L42-L167)
- **How**: `let mut buf = vec![0u8; 256]; let base = buf.as_mut_ptr();` then write `Revision=1`, `Control=0x8004`, `Dacl offset=20` at offsets 0, 2, 16. ACL header at offset 20: `AclRevision=2`, `AclSize=8+total_ace_size`, `AceCount=2`. Each ACE: `Type(1) + Flags(1) + Size(2) + Mask(4) + SID(...)`. Use well-known SIDs (`S-1-1-0` Everyone, `S-1-5-18` SYSTEM) — these are 12 bytes each (1+1+6+4).

### Pattern: Loader-Lock-Acquired PEB Mutation
- **Use when**: Modifying `PEB.Ldr` lists could race with concurrent module load/unload on other threads.
- **Code ref**: `crowd/src/peb_unlink.rs:unlink_module` (L77-L86)
- **How**: `let cookie = ldr_lock_loader_lock()?; let result = inner_unlink(target_base); ldr_unlock_loader_lock(cookie); result`. The lock is acquired via `crate::recycled::invoke(compute_hash("LdrLockLoaderLock"), 3, ...)` with `Flags=0` (blocking), `&mut disposition`, `&mut cookie`. Always release with the cookie — even on the error path. The `?` operator on `ldr_lock_loader_lock` returns Err early — but the lock is held only inside the `unsafe` block scope, so the release is conditional on the lock succeeding. Matches the canonical NT loader-lock pattern.
