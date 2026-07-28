---
id: T-006
name: Phantom Stubs (MEM_IMAGE Syscall Stubs)
category: syscalls
tier: A
crate: dark_crystal
mitre: T1055
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: medium
requires: [T-002, T-004]
enables: [T-007, T-009, T-012, T-015, T-016]
min_windows: "Windows 10 1709 (RS3)"
needs_admin: "no"
tags: [syscalls, mem-image, sec-image, signed-dll, cow, version-dll, indirect-syscall, evasion]
---

# Phantom Stubs — Operator Playbook

## TL;DR
Build your own `mov eax, SSN; syscall; ret` stubs but host them inside a `SEC_IMAGE` section backed by `C:\Windows\System32\version.dll`, so memory scanners walking `VirtualQuery` see `MEM_IMAGE` with a Microsoft-signed backing file rather than private `MEM_PRIVATE` `RX` commit — the classic direct-syscall red flag. The trick lives or dies on using `PAGE_WRITECOPY (0x08)` instead of `PAGE_READWRITE`; on Win10 RS3+ the latter returns `STATUS_INVALID_PAGE_PROTECTION` for `SEC_IMAGE` mappings. Pairs naturally with T-002 SSN resolution and T-001 as an alternative dispatch mode — RecycledGate borrows existing `ntdll` bytes, Phantom Stubs forges new ones but gives them the same backing class.

## How It Works
The card describes the mechanism; the underlying Windows internals are:

1. **Locate the backing DLL.** `C:\Windows\System32\version.dll` is chosen because (a) it is Microsoft-signed, (b) it loads normally on every Windows build since at least Vista, (c) it is small (~30–50 KB), and (d) it is rarely hooked by EDR user-mode sensors. Path resolution uses the standard `gs:[0x60] → PEB → ProcessParameters →ImagePathName/DllPath` walk (T-004) or a hardcoded `%SystemRoot%\System32\version.dll` string. The `OBJECT_ATTRIBUTES` is initialized with `OBJ_CASE_INSENSITIVE` and an `UNICODE_STRING` path like `\??\C:\Windows\System32\version.dll`.

2. **Open the file via `NtOpenFile`.** Desired access `FILE_EXECUTE | FILE_READ_DATA | SYNCHRONIZE` (typically `0x120196`). Share mode `FILE_SHARE_READ | FILE_SHARE_DELETE`. Returns an `HANDLE` to the file object.

3. **Create a section with `NtCreateSection`.**
   - `MaximumSize = 0` (uses file size)
   - `SectionPageProtection = PAGE_WRITECOPY` (this is the critical flag — the section is created writable)
   - `AllocationAttributes = SEC_IMAGE`
   - `FileHandle = <from step 2>`
   - Returns a section `HANDLE`. The kernel constructs a `SEGMENT` and `CONTROL_AREA` that record the file object as the backing store.

4. **Map a view via `NtMapViewOfSection`.**
   - `BaseAddress = NULL` (caller-chosen)
   - `ZeroBits = 0`
   - `CommitSize = 0x1000` minimum (one page; in practice the full image size)
   - `AllocationType = 0` (no `MEM_RESERVE` needed — the section already describes the VA range)
   - `Win32Protect = PAGE_WRITECOPY` ← **must match step 3**
   - The returned `BaseAddress` now points at a `MEM_IMAGE`-classified VA range. `VirtualQuery` on any address inside returns `Type = MEM_IMAGE (0x1000000)`, `AllocationProtect = PAGE_WRITECOPY`, and `GetMappedFileName` returns `version.dll`.

5. **Choose stub slots inside the mapped image.** The stub is 8 bytes:
   - `B8 <SSN:32>` `mov eax, imm32` — 5 bytes
   - `0F 05` `syscall` — 2 bytes
   - `C3` `ret` — 1 byte
   - Total 7 bytes, padded to 8 for alignment. The slots are placed in `.text`-class regions of the version.dll image (the actual `.text` section RVA, or simply the first 0x1000 bytes where the PE header + early code lives — slot placement is implementation-specific). Stubs are 8-byte aligned so `RSP+8` alignment is preserved when called as a function.

6. **Flip page protection for writing.** `NtProtectVirtualMemory(BaseAddress, len=0x1000, PAGE_WRITECOPY, &old)`. On Win10 RS3+, attempting `PAGE_READWRITE` here returns `STATUS_INVALID_PAGE_PROTECTION (0xC000004D)` because the VAD describes a `SEC_IMAGE` section and the MM refuses to widen the protection beyond what the section allows. `PAGE_WRITECOPY` makes the PTE copy-on-write; the first write triggers a private copy of the page, but the **VAD type remains `MEM_IMAGE`** and the section/file mapping relationship is preserved.

7. **Write stubs.** For each `(slot_address, ssn)` pair, write the 8-byte sequence `B8 <SSN_LE> 00 00 0F 05 C3` (the high byte of `mov eax` is the SSN high byte; for SSN ≤ 0xFF, bytes 2 and 3 of the immediate are zero). After the write, the page is COW'd into private storage in the page file but `MiQueryImageFileMapping` and `GetMappedFileName` still report `version.dll` because the VAD still references the original `CONTROL_AREA`.

8. **Restore execution protection.** `NtProtectVirtualMemory(slot, 8, PAGE_EXECUTE_READ, &old)`. This downgrades the page from writable to executable-read. The VAD type stays `MEM_IMAGE`.

9. **Dispatch via function pointer.** Each stub is invoked as `let stub: unsafe extern "C" fn(...) -> NTSTATUS = transmute(slot_addr); stub(arg1, arg2, ...)`. The Win64 calling convention ensures the first 4 args land in `RCX/RDX/R8/R9`, the syscall instruction reads `R10` (the kernel copies `RCX→R10` before syscall) — wait, no: the kernel's `KiSystemCall64` prologue copies `RCX` to `R10` itself. So a standard `extern "C"` call placing the syscall number in `EAX` and args in `RCX, RDX, R8, R9, [stack]` is correct.

**Memory state at each stage:**
- After step 4: shared file-mapped `MEM_IMAGE` pages, `PAGE_WRITECOPY`, backing = `version.dll`
- After step 6: still `MEM_IMAGE`, `PAGE_WRITECOPY`, not yet COW'd
- After step 7: pages COW'd to private pagefile storage, VAD still says `MEM_IMAGE` + `version.dll`
- After step 8: pages `RX`, VAD still `MEM_IMAGE` + `version.dll`

**Race conditions:** None significant. The COW happens synchronously on the write. The only timing concern is if another thread (e.g., a scanner thread inside the same process) queries the page during the brief window between `NtProtectVirtualMemory(PAGE_WRITECOPY)` and `NtProtectVirtualMemory(PAGE_EXECUTE_READ)` — at which point the page is `WC` and contains syscall bytes. Real EDR scanners that walk other-process memory via `NtReadVirtualMemory` will not see this in-process window. In-process scanners (rare in modern EDR) could see it.

## Operational Profile

### When to Use
- Target runs an EDR that flags `MEM_PRIVATE RX` regions containing `0F 05` byte patterns (most modern vendors: Defender for Endpoint, CrowdStrike Falcon, SentinelOne Singularity, Elastic Endpoint).
- Your chain already resolves SSNs via T-002 (Hells/Halo/Tartarus Gate) and you need a host for the dispatch stubs that survives memory enumeration.
- You want a self-contained stub area that you can re-key with new SSNs at runtime without touching `ntdll.dll` (avoids `ntdll` integrity scanners).
- Target build is Win10 1709+ / Server 2019+ — older builds don't enforce the `PAGE_WRITECOPY` restriction and the code path may differ.
- You need to invoke syscalls from contexts where jumping into `ntdll` gadgets (T-001 RecycledGate) is undesirable — e.g., when the gadgets are hooked or watched by ETW-TI.
- Medium-IL is sufficient; no token manipulation needed.

### When NOT to Use
- Target EDR performs `.text`-section integrity checks: it hashes the in-memory `.text` of loaded images and compares to the on-disk file. Because step 7 overwrites image bytes, this scanner will flag the tampered region. Microsoft Defender for Endpoint with certain ASR rules and some EDR configurations do this.
- You only need a handful of syscalls and RecycledGate (T-001) is available — T-001 is simpler, has no allocation, and reuses legitimate `ntdll` bytes. Phantom Stubs is heavier.
- The chain already does `ntdll` unhook restoration (T-016) — that restores `.text` from a known-good copy and would conflict with stubs hosted in `ntdll`. Phantom Stubs sidesteps this by hosting in `version.dll`, but if you also restore `version.dll`, you'll wipe your stubs.
- Pre-Win10 1709 target — the `PAGE_WRITECOPY` requirement is documented for RS3+; on older builds the behavior is implementation-defined. The card explicitly notes the version dependency.
- High pressure of in-process unhooking/scanning where the brief `WC` window matters — though this is rare.

### Kill Chain Position
Phantom Stubs sits in the **syscall dispatch layer**, parallel to T-001 (RecycledGate) and T-003 (VEH Gate). It is consumed by every technique that issues NT syscalls: injection methods (T-007 through T-015), EDR evasion (T-016 — unhooking, handle blocking, arg spoofing), sleep obfuscation (T-005 Ekko), and persistence (T-017).

Typical chain:
```
T-004 (PEB walker) → T-002 (SSN resolve) → T-006 (Phantom Stubs host) → T-012 (Early Cascade inject) → T-005 (Ekko sleep) → T-017 (persistence)
```

Alternative chain swapping dispatch mode:
```
T-002 (SSN) → T-001 (RecycledGate)  [if ntdll gadgets are clean]
T-002 (SSN) → T-003 (VEH Gate)      [if you need HW-BP mediation for ETW-TI]
T-002 (SSN) → T-006 (Phantom Stubs) [if MEM_PRIVATE detection is hot]
```

### Trade-offs
| Dimension | Rating | Notes |
|---|---|---|
| Stealth | 8 | Beats direct syscalls in private memory; still vulnerable to .text integrity scans |
| Reliability | 7 | COW path is stable on supported versions; fails hard on pre-RS3 with WC-restricted builds |
| Complexity | 5 | Four NT calls to set up vs. RecycledGate's zero-allocation gadget reuse |
| Version range | Win10 1709+, Win11, Server 2019+ | `PAGE_WRITECOPY` enforcement documented from RS3; older builds behavior-dependent |
| Privilege needed | none | Medium-IL is fine; no SeDebugPrivilege required for in-process mapping |

## Rust Implementation Deep Dive
> **Source extract was not provided.** The card identifies `dark_crystal/crowd/src/phantom.rs` (~317 lines) as the implementation. The following is reconstructed from the card's stated mechanism, Windows internals, and the patterns used elsewhere in the vault (T-001 `sys_recycled.rs`, T-002 `hells_gate.rs`, T-004 `resolve.rs`). Treat field names as inferred unless confirmed by reading the file.

### Likely FFI surface
Based on `dark_crystal/crates/core/src/wrappers.rs` patterns (`windows_targets::link!`):
```rust
windows_targets::link!("ntdll.dll" "system" fn NtOpenFile(
    FileHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    IoStatusBlock: *mut IO_STATUS_BLOCK,
    ShareAccess: u32,
    OpenOptions: u32,
) -> NTSTATUS);

windows_targets::link!("ntdll.dll" "system" fn NtCreateSection(
    SectionHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    MaximumSize: *mut i64,
    SectionPageProtection: u32,
    AllocationAttributes: u32,
    FileHandle: HANDLE,
) -> NTSTATUS);

windows_targets::link!("ntdll.dll" "system" fn NtMapViewOfSection(
    SectionHandle: HANDLE,
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut c_void,
    ZeroBits: usize,
    CommitSize: usize,
    SectionOffset: *mut i64,
    ViewSize: *mut usize,
    InheritDisposition: SECTION_INHERIT,
    AllocationType: u32,
    Win32Protect: u32,
) -> NTSTATUS);
```
These are standard `extern "system"` (Win64 fastcall) bindings. Handles are `OwnedHandle`-style RAII wrapped elsewhere; in `phantom.rs` they are likely raw `HANDLE` with explicit `NtClose` in drop paths.

### Stub layout
The 8-byte stub is almost certainly:
```rust
#[repr(C, align(8))]
pub struct PhantomStub {
    mov_eax: u32,   // 0xB8 + (SSN << 8) packed as little-endian
    syscall_ret: u16, // 0x050F (syscall little-endian)
    ret: u8,          // 0xC3
    pad: u8,          // 0x90 or 0x00 (NOP / INT3)
}
```
Writing it: `ptr::write(slot.cast::<PhantomStub>(), PhantomStub { mov_eax: 0xB8 | (ssn as u32) << 8, syscall_ret: 0x050F, ret: 0xC3, pad: 0x90 });`

### `unsafe` boundaries
- **Mapping**: `NtMapViewOfSection` returns a raw `*mut c_void`. Holding this across the FFI boundary is unsafe because the kernel may unmap on process exit; the caller must keep the section handle alive for the lifetime of the view. Rust-wise this is `PhantomData<&'a Section>` tying view lifetime to section lifetime.
- **Writing stubs**: dereferencing the COW'd pointer is unsafe; alignment must be guaranteed (`addr_of_mut!` if `&mut` would risk UB on uninitialized memory).
- **Calling the stub**: `mem::transmute::<*mut u8, unsafe extern "C" fn(...) -> NTSTATUS>(slot)` — the function pointer is unsafe to construct because there is no static proof the bytes form a valid function. The caller must ensure `PAGE_EXECUTE_READ` is set before invocation.

### `core::arch::asm!` usage
Phantom Stubs itself is pure memory writes — no inline asm needed for the **setup** path. The **dispatch** path either (a) calls the stub as a function pointer (no asm) or (b) uses a small `core::arch::asm!("call rax", ...)` shim if args need register pinning. The card does not show this; T-001 `sys_recycled.rs` and `sys_indirect.rs` are the dispatch entry points and may share code with Phantom Stubs.

### Initialization
Look for:
```rust
static PHANTOM_BASE: OnceLock<*mut u8> = OnceLock::new();
```
or
```rust
static PHANTOM: LazyCell<PhantomAllocator> = LazyCell::new(PhantomAllocator::init);
```
The `OnceLock`/`LazyCell` pattern is used pervasively in this vault (`byakugan.rs`, `selection_config.rs`, `sysindirect_map.rs`). The first syscall dispatch triggers `init()`, which runs steps 1–4 once and caches the base pointer. Subsequent stub writes reuse the cached region.

### Error paths
- `NtOpenFile` fails (file locked, AV quarantine on `version.dll`) → bail with `NTSTATUS` to the caller. Impl probably uses `Result<*mut u8, NTSTATUS>` or a custom error enum. The chain runner in `runner.rs` would log and degrade to direct syscalls.
- `NtCreateSection` fails with `STATUS_INVALID_IMAGE_NOT_MZ` → `version.dll` is corrupted or replaced; bail.
- `NtMapViewOfSection` fails with `STATUS_INVALID_PAGE_PROTECTION` → wrong protect flag passed; this is the documented footgun, so the impl should hard-code `PAGE_WRITECOPY`.
- `NtProtectVirtualMemory` returning non-zero → caller should check `STATUS_INVALID_PAGE_PROTECTION` specifically and downgrade gracefully.

### Memory layout
- One `0x1000` page can host `0x1000 / 8 = 512` stubs. Windows has ~470 syscalls; a single page suffices for the full syscall table. The impl likely allocates one page and indexes by SSN: `slot = base + (ssn as usize) * 8`.

## Edge Cases & Failure Modes
1. **Target EDR with image integrity scanning (e.g., Defender for Endpoint with image-load integrity features, Carbon Black Integrity).**
   - Failure: Scanner computes the SHA-256 of the in-memory `.text` of `version.dll` and compares to the on-disk copy. The mismatch (your overwritten stub bytes) triggers an alert.
   - Symptom: Implant loses contact shortly after first syscall dispatch; SOC alert fires on "memory modification of Microsoft-signed module."
   - Workaround: Switch to T-001 RecycledGate (uses pristine `ntdll` gadgets, no writes) or host stubs in a less-scanned image (e.g., `msdart.dll`, `ncobjapi.dll`) and verify the EDR's integrity coverage.

2. **Pre-Win10 1709 target (Win10 1607 / Server 2016 GA).**
   - Failure: `PAGE_WRITECOPY` enforcement differs; on older MM builds `PAGE_READWRITE` on `SEC_IMAGE` was sometimes accepted. Code that hardcodes `PAGE_WRITECOPY` will still work but won't trigger the diagnostic that tells you the alternative is unsupported.
   - Symptom: Subtle — actually works fine. The risk is the inverse: code that tries `PAGE_READWRITE` first and falls back to `PAGE_WRITECOPY` would behave inconsistently.
   - Workaround: Hardcode `PAGE_WRITECOPY` always; don't attempt fallback chains.

3. **`version.dll` is subject to AppLocker / WDAC signed-dll-only policy with path rules.**
   - Failure: Path `\??\C:\Windows\System32\version.dll` is fine under default policies, but a custom rule denying `version.dll` access to non-system contexts would fail at `NtOpenFile` with `STATUS_ACCESS_DENIED`.
   - Symptom: `NtOpenFile` returns `0xC0000022`.
   - Workaround: Fall back to `\??\C:\Windows\System32\KernelBase.dll`, `\??\C:\Windows\System32\msvcrt.dll`, or any other always-loaded MS-signed image with a `.text` section wide enough to host stubs.

4. **AV has quarantined or replaced `version.dll`.**
   - Failure: Some "tunneling" malware victims have a modified `version.dll` in `%SystemRoot%`. `NtCreateSection` with `SEC_IMAGE` will reject non-PE files.
   - Symptom: `STATUS_INVALID_IMAGE_NOT_MZ` (0xC000007B) from `NtCreateSection`.
   - Workaround: Verify `MZ` magic at file head before `NtCreateSection`; pick an alternate image.

5. **Concurrent `NtUnmapViewOfSection` from another thread (e.g., during unload).**
   - Failure: Base pointer becomes dangling; subsequent stub calls jump into unmapped VA → access violation → process crash.
   - Symptom: Crash with `EXCEPTION_ACCESS_VIOLATION` at the stub address; `VirtualQuery` on the address returns `MEM_FREE`.
   - Workaround: Tie the view's lifetime to an `Arc<PhantomAllocator>` RAII guard; never let the unloader fire while dispatchers are in flight. Use a `RwLock` or epoch-based reclamation if hot-reload is a requirement.

6. **Stub invoked before `PAGE_EXECUTE_READ` is applied.**
   - Failure: Page is still `WC` (data, not exec); DEP/NX fires.
   - Symptom: `EXCEPTION_ACCESS_VIOLATION` with `cFlags.ExecuteViolation = 1` on first call.
   - Workaround: Assert protection state in debug builds; gate dispatch behind an `AtomicBool ready` set by the protect step.

7. **Mismatched SSN encoding (SSN > 0xFFFF or endianness bug).**
   - Failure: `mov eax, imm32` encodes the SSN in the lower 16 bits; if the impl writes the SSN as `u16` directly into the `mov` immediate without the `0xB8` opcode prefix, the call puts garbage in `EAX` and the syscall traps wrong.
   - Symptom: `STATUS_INVALID_SYSTEM_SERVICE` (0xC000001C) from the kernel.
   - Workaround: Validate the stub bytes via a debug disassembler before the first real invocation; the bytes should be `B8 XX 00 00 00 0F 05 C3` for SSN ≤ 0xFF.

8. **Target running under WoW64 (32-bit process on 64-bit Windows).**
   - Failure: 32-bit syscall stubs have a different format (`mov eax, SSN / mov edx, esp+4 / call dword fs:[0xC0] / ret`). The 64-bit stub bytes won't work.
   - Symptom: WoW64 ntdll transitions fail; process crashes.
   - Workaround: Phantom Stubs must be built for the process bitness; if WoW64 is expected, ship a 32-bit variant with the `wow64` stub format. The vault appears x64-only based on the asm patterns elsewhere.

## Variant Ideas
- **Alternative backing DLLs.** Beyond `version.dll`, viable candidates: `msdart.dll`, `msxml3.dll`, `ncobjapi.dll`, `mscms.dll`, `winmm.dll`. Pick based on (a) always-present, (b) MS-signed, (c) `.text` section ≥ 0x1000 bytes, (d) not normally scanned by the target EDR. Rotate per-build to defeat IOC matching.

- **Host stubs in the `.data` section, not `.text`.** Some scanners specifically hash `.text` of loaded images; `.data` is rarely integrity-checked. Write stubs to a `.data`-RVA-aligned slot inside the mapped `version.dll`. Trade-off: `.data` is normally `RW`, so executing from it requires `PAGE_EXECUTE_READWRITE`, which itself is a scanner flag. Net: not clearly better.

- **Multiple stub pages, one per syscall category.** Spread stubs across multiple mapped images (version.dll + kernelbase.dll + msvcrt.dll) so that a single integrity scan alert doesn't burn the whole dispatch surface. Adds setup cost but improves resilience.

- **Pair with T-003 VEH Gate for hybrid dispatch.** Use Phantom Stubs for routine syscalls (NtAllocate, NtProtect, NtWrite) where speed matters, and VEH Gate for syscalls where ETW-TI specifically hooks the syscall instruction. The dispatcher in `sys_indirect.rs` already supports mode selection — extend it.

- **Self-healing stubs.** Add a watchdog thread that re-writes stub bytes if a scanner modifies them back to the original `version.dll` content (some EDRs "repair" tampered image regions). Watchdog reads the first byte; if not `0xB8`, re-runs step 7. OPSEC-costly but defeats repair-based scanners.

- **SEC_IMAGE_NO_EXECUTE variant.** Windows 10 1803+ added `SEC_IMAGE_NO_EXECUTE` for sections that should not be executable. Useless for syscall stubs (they must execute), but a sibling technique can host non-exec data (encrypted payload) under `MEM_IMAGE` backing without needing execution. Useful for T-005 Ekko sleep payload staging.

- **Fake backing via `NtCreateSection` with `FileHandle = NULL` and `SEC_IMAGE`.** This creates an image section with no file backing — `GetMappedFileName` returns empty. Defeats scanners that require MS-signed backing, but defeats the technique's purpose. Not viable for our threat model.

- **Per-stub SSN obfuscation.** XOR the SSN with a per-build key and add a `xor eax, key` instruction before `syscall`. Changes the stub bytes from the canonical `B8 XX 00 00 00 0F 05 C3` and defeats static byte signatures over stub memory. Trade-off: 3 extra bytes (_xor eax, imm32 = 35 E8 ... or 31 ..._), breaking 8-byte alignment; pad to 12 or 16.

- **Combine with T-006 (this) hosting stubs *inside* the host process's own image.** If the implant is a DLL loaded via module overloading (T-013 `overload.rs`), it already has `MEM_IMAGE` backing from the overload target. Stubs could live in the overload image's `.text` slack space, eliminating the need for a separate `version.dll` section. Reduces setup but couples stub lifetime to the overload.

## OPSEC Notes
**Artifacts left in the target process:**
- A new VAD entry describing a `MEM_IMAGE` mapping of `version.dll`. Process Hacker / VMMap will show this mapping. If the legitimate `version.dll` is not in `PEB->Ldr` (because we mapped manually without `LdrLoadDll`), the missing-listed-but-mapped state is itself a flag for memory audits. Mitigation: after `NtMapViewOfSection`, optionally call `LdrLoadDll` to add it to `PEB->Ldr` — costs nothing and normalizes the module list.
- A modified `.text` (or chosen region) of the mapped `version.dll`. `GetMappedFileName` returns `version.dll` for scanner queries, but on-disk vs in-memory comparison reveals tampering. No mitigation other than switching to T-001 or selecting a less-integrity-scanned host DLL.
- A `HANDLE` to `version.dll` and to the section object. These persist until `NtClose`d; leak them and `handle.exe` shows extra file/section handles to `version.dll`.

**Telemetry it generates:**
- `NtOpenFile` on `\??\C:\Windows\System32\version.dll` from a non-loader context. EDRs that hook `NtOpenFile` (most) will see this. The file is normally opened during DLL load by `LdrpMapDllNtFileName` from `ntdll`; a call from arbitrary code is suspicious.
- `NtCreateSection` with `SEC_IMAGE` and a file handle is the canonical "manual DLL mapping" pattern, commonly used by process-hollowing and reflective loaders. ETW kernel provider `Microsoft-Windows-Kernel-Process` event ID 1 may log the section creation. Most EDRs treat this as suspicious-but-not-blocking.
- `NtProtectVirtualMemory` flipping an image page to `PAGE_EXECUTE_READ`. This is the page-protection change that "memory scanning EDRs" care most about. CrowdStrike Falcon's memory sensor flags `PAGE_EXECUTE_READ` transitions on image regions. SentinelOne's `EICAR`-class signature doesn't, but its behavioral engine logs.
- Syscall stub bytes (`B8 .. 00 00 0F 05 C3`) in a `MEM_IMAGE` region are themselves an IOC once a scanner pulls the bytes. Yara rule `rule phantom_stub { strings: $a = { B8 ?? 00 00 00 0F 05 C3 } condition: $a }` matches. Mitigation: per-stub byte obfuscation (see Variant Ideas).

**Known EDR detections:**
- **Microsoft Defender for Endpoint**: Memory scanner MDI can flag modified `.text` of Microsoft-signed DLLs as "Image Tampering" (alert `TamperingAttempt`). Behavior depends on configured ASR rules.
- **CrowdStrike Falcon**: `ProcessHollowing` and `WriteToModule` sensors. The COW write to `version.dll` matches the latter sensor. Likely raises a medium-severity event.
- **SentinelOne Singularity**: Deep Visibility can show the `NtProtectVirtualMemory` call site. Default policy may not block but logs.
- **Elastic Endpoint**: Memory scanner with `image_integrity_check` feature. Will flag.

**Cleanup procedures:**
- On unload: `NtProtectVirtualMemory(slot, 8, PAGE_WRITECOPY, &old)` to revert to non-exec, then `memset` the slot back to the original `version.dll` bytes (cache them at write time), then `NtUnmapViewOfSection(base)`, then `NtClose(section_handle)`, then `NtClose(file_handle)`. Failure to unmap leaves the VAD entry; failure to close handles leaks `version.dll` file/section handles that show in `handle.exe`.
- If you opted into `LdrLoadDll` to list the module, also `LdrUnloadDll` to remove from `PEB->Ldr`; otherwise the module-listed-but-no-code scenario is itself a flag.
- There is no on-disk artifact — the file is opened read-only and never modified.

## Reusable Patterns

### Pattern: SEC_IMAGE Section Mapping
- **Use when**: Any technique that needs `MEM_IMAGE`-classified VA ranges without going through `LdrLoadDll` (e.g., manual DLL hosting for shellcode staging, reflectively-loaded module backing, phantom stubs, hide-in-DLL memory for T-005 Ekko payload staging).
- **How**: `NtOpenFile` the target DLL → `NtCreateSection(SEC_IMAGE, PAGE_WRITECOPY)` → `NtMapViewOfSection(PAGE_WRITECOPY)`. COW-write your payload, then `NtProtectVirtualMemory` to the final protection. The COW'd pages retain `MEM_IMAGE` classification and the backing filename.
- **Code ref**: `dark_crystal/crowd/src/phantom.rs` (per card); same primitive reused by `dark_crystal/crowd/src/module_overload.rs` (T-013) and `dark_crystal/crowd/src/mapping_inject.rs` (T-007).

### Pattern: OnceLock-Cached Syscall Dispatch Base
- **Use when**: A one-time setup step allocates a region whose pointer is needed on every subsequent syscall. Avoids re-running setup on each dispatch.
- **How**: `static BASE: OnceLock<*mut u8> = OnceLock::new(); let p = *BASE.get_or_init(|| init_phantom());`. Init runs exactly once even under concurrent first-call races; subsequent calls are lock-free reads. The pointer is `Send` by convention (process-local, never crosses threads boundaries in practice) — wrap in a `struct PhantomBase(*mut u8); unsafe impl Send for PhantomBase {}` to satisfy the type system.
- **Code ref**: Pattern appears in `sysindirect_map.rs`, `byakugan.rs` (`OnceLock` cancellation token), `selection_config.rs`. Apply identically in `phantom.rs`.

### Pattern: 8-Byte Aligned Function-Pointer Stubs
- **Use when**: You need many tiny function-pointer-callable stubs packed densely. 8-byte alignment preserves `RSP+8` post-`call` so the stub can be invoked as `extern "C"` without manual stack fixup.
- **How**: Layout stubs as `#[repr(C, align(8))] struct Stub { ... }` and place at `base + i * 8`. The 8-byte stub form `mov eax, imm32 / syscall / ret` is the canonical indirect-syscall pattern across the vault (T-001 RecycledGate uses the same bytes via a found gadget, T-006 writes them fresh).
- **Code ref**: `sys_recycled.rs` (gadget bytes), `phantom.rs` (written bytes), `sys_indirect.rs` (dispatch wrapper). All share the byte form `B8 ?? 00 00 00 0F 05 C3`.

### Pattern: PAGE_WRITECOPY for SEC_IMAGE Writes
- **Use when**: You must write into a `SEC_IMAGE`-mapped page on Win10 RS3+ without breaking the VAD's `MEM_IMAGE` classification.
- **How**: `NtProtectVirtualMemory` with `PAGE_WRITECOPY (0x08)` instead of `PAGE_READWRITE (0x04)`. The first write triggers COW; VAD type and backing filename are preserved. `PAGE_READWRITE` is rejected by MM with `STATUS_INVALID_PAGE_PROTECTION` on `SEC_IMAGE` mappings.
- **Code ref**: `phantom.rs` (per card), and likely `module_overload.rs` / `mapping_inject.rs` for the same reason — any code that mutates `SEC_IMAGE` pages needs this pattern.

---

**Source extract was not provided for this analysis.** Confidence is **medium** because the operational mechanism, Windows internals behavior, and code patterns are reconstructed from the card's stated mechanism, related vault files (`sys_recycled.rs`, `hells_gate.rs`, `resolve.rs`, `wrappers.rs`), and well-documented Windows MM behavior on Win10 RS3+. Field/function names specific to `phantom.rs` (e.g., `PhantomStub`, `PhantomAllocator`) are inferred and should be verified against the source before depending on them in code.