---
id: [T-009, T-010]
name: "Process Ghosting & Process Herpaderping"
category: process-injection
tier: S
mitre: [T1055.012]
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: medium
requires: [T-001, T-004]
enables: [T-015, T-005, T-016, T-017]
min_windows: "Win7+ (ghosting/herpaderping primitives stable through Win11 24H2; behavior of EDR hooks varies)"
needs_admin: conditional
tags: [injection, ghosting, herpaderping, delete-pending, sec-image, race-condition, decoy-pe, ntcreateprocessex, file-disposition, page-backed-section]
---

# Process Ghosting & Process Herpaderping — Operator Playbook

## TL;DR

Two sibling techniques under ATT&CK T1055.012 that both exploit the gap between **file content** and **section object** during NT process creation. **Ghosting** marks a temp file delete-pending so AV/EDR can't open it for scanning, writes the payload, creates a `SEC_IMAGE` section, then closes the handle — the file vanishes but the section persists, and `NtCreateProcessEx` runs from the orphaned section. **Herpaderping** inverts the timing: write the payload → create the section (content captured) → overwrite the file with a decoy PE → call `NtCreateProcessEx` from the section handle while AV scanning the file sees the decoy. Use Ghosting when the target EDR hooks `NtCreateSection`/`NtOpenFile` and actively scans file content; use Herpaderping when the EDR only inspects the file at `NtCreateProcessEx` time. Both produce a self-contained image-backed process with no on-disk payload, which is the whole point — file-less by construction rather than by cleanup.

## How It Works

### Process Ghosting (T-009)

1. **Temp file creation.** Caller invokes `NtCreateFile` with `DELETE` access in the desired directory (typically `%TEMP%` or `C:\Users\<user>\AppData\Local\Temp`). Filename is randomized. Disposition: `FILE_SUPERSEDE` or `FILE_OVERWRITE_IF`.
2. **Mark delete-pending.** Caller issues `NtSetInformationFile` with `FileDispositionInformation` (or `FileDispositionInformationEx` on Vista+, with `FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS`) setting `DeletePending = TRUE`. The file is now in the delete-pending state: still open on this handle, invisible/unopenable to other openers (filesystem returns `STATUS_DELETE_PENDING` or refuses new opens with `STATUS_SHARING_VIOLATION` depending on share flags).
3. **AV/EDR blind window opens.** Anything attempting `NtCreateFile` on this path now fails. Real-time scanners that triggered on the initial create have a handle to a not-yet-pending file, but the kernel-side data stream is empty at that point. Any scanner trying to open the file *after* step 2 cannot.
4. **Write payload.** Caller writes the raw PE payload bytes via `NtWriteFile` to the delete-pending file. Bytes are now in the file's data stream but the file is unscannable from outside.
5. **Create `SEC_IMAGE` section.** `NtCreateSection(SectionHandle, SECTION_ALL_ACCESS, NULL, &MaxSize, PAGE_READONLY, SEC_IMAGE, FileHandle)`. The memory manager parses the PE, builds the segment object, copies/captures the image content into the section's prototype PTEs backed by the file (at this moment). Critical point: the section object now references the file's *content*, not the file object's name.
6. **Close the file handle.** `NtClose(FileHandle)`. Because the disposition was delete-pending, the file is unlinked from the directory immediately (POSIX semantics) or on last close. Either way, the on-disk file is gone. The section object, however, persists — its prototype PTEs are now backed by the **page file** (or the section holds the pages directly because they were modified/cached). The image content survives in the kernel section object with no remaining file path.
7. **Process creation.** `NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(), SECTION_HANDLE, 0, NULL, NULL, NULL)` (or `NtCreateUserProcess` if using the higher-level wrapper — see T-014). The kernel's `Mm` re-uses the section's image base as the new process's image base. `NtCreateProcessEx` builds the raw address space: allocates EPROCESS, clones section, sets up PEB.
8. **PEB parameter setup.** Caller allocates remote memory for `RTL_USER_PROCESS_PARAMETERS` and the environment block, fills `ImagePathName`, `CommandLine`, `DllPath`, `WindowTitle`, `DesktopInfo` via `RtlCreateProcessParametersEx` locally then writes the (relocated) parameters to the new process's address space at `Peb->ProcessParameters`. This step is mandatory — without it, `LdrInitializeThunk` won't bootstrap `ntdll`/`kernel32` and the process will die in early init.
9. **Optional PPID spoofing.** If the parent process specified in step 7 was opened with `PROCESS_CREATE_PROCESS` access (e.g., via `NtOpenProcess` on a chosen parent PID — see T-015), the new process inherits that parent's CID, token, and affinity. This is the place where high-IL might be needed: getting `PROCESS_CREATE_PROCESS` on a process you don't own often needs `SeDebugPrivilege`. For PPID-ing to a sibling medium-IL process you already have a handle to, no elevation needed.
10. **Initial thread.** `NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, Entry, NULL, FALSE, 0, 0, 0, NULL)` where `Entry` is the new process's image entry point (parsed from the section's PE header). The thread starts suspended by default if `CreateSuspended = TRUE`.
11. **Resume execution.** `NtResumeThread(hThread, NULL)`. The thread hits `LdrInitializeThunk` → `ntdll` boots → loader resolves imports → calls image entry point.

### Process Herpaderping (T-010)

1. **Temp file creation.** Same as Ghosting step 1, but opened with `FILE_SHARE_READ` only — *deliberately not* `FILE_SHARE_WRITE`. This is the herpaderping signature: once the section is created, the file handle remains, but no other opener can get write access. Antivirus hooks that try to open the file for read after section creation get a handle; AV that tries to open for write is blocked.
2. **Write the real payload.** Caller writes the actual malicious PE bytes via `NtWriteFile`. File content is now the real payload.
3. **Create `SEC_IMAGE` section.** `NtCreateSection(..., SEC_IMAGE, FileHandle)`. Same as Ghosting step 5 — the section object captures the *real* image content into the segment's prototype PTEs. At this instant, both the section and the file contain the real payload.
4. **The race — overwrite with decoy.** `NtWriteFile(FileHandle, ...)` writes a benign PE (signed Microsoft binary like `notepad.exe` or `sihost.exe`) *over the same file content*. The file's data stream now contains the decoy, but the section object still points at the original captured image. This is the herpaderping invariant: **the file and the section are now decoupled**.
5. **AV/EDR scanning window.** When `NtCreateProcessEx` is called next, any EDR hook on `NtCreateProcessEx` that opens the *file* to inspect its content will see the decoy. EDR that hooks `NtCreateSection` would have caught the real payload at step 3, but most EDRs don't because that hook fires constantly for legitimate image loads.
6. **Process creation.** `NtCreateProcessEx(ProcessHandle, ..., SectionHandle, ...)`. Same as Ghosting step 7. Section-driven image base — the kernel uses the section, not the file.
7. **PEB parameter setup.** Identical to Ghosting step 8. Card explicitly calls out `RtlCreateProcessParametersEx` for PEB parameter construction and "environment block fixup for remote virtual address space" — meaning the env block is built in the *caller's* address space first, then the buffer is `NtAllocateVirtualMemory`'d in the target and `NtWriteVirtualMemory`'d across, with pointer relocations applied to make `ProcessParameters->Environment` point at the target-side copy rather than the caller-side pointer.
8. **Optional PPID spoofing.** Same as Ghosting step 9 (see T-015).
9. **Initial thread + resume.** Same as Ghosting steps 10-11.

### Operational difference at the kernel level

Both techniques end with `NtCreateProcessEx(SectionHandle=...)`. The kernel path is identical post-section-creation: `MmCreatePeb` → `MiMapViewOfImageSection` → EPROCESS init. The difference is purely in how the section got its content and what the file looks like at the moment of process creation:

| Property | Ghosting | Herpaderping |
|---|---|---|
| File state at `NtCreateProcessEx` time | **Does not exist** (deleted) | Exists with **decoy content** |
| Section backing after file close | Page file | File (with decoy content) |
| Requires `NtSetInformationFile` delete flag | Yes | No |
| Race window tightness | None (file is gone) | Tight (overwrite between section create and process create) |
| Defeated by EDR hook on `NtCreateSection` | No (it would catch the create call) | Same |
| Defeated by EDR hook on `NtCreateProcessEx` with file reopen | No (no file to open) | Yes (sees decoy) |
| Survives EDR hook on `NtCreateFile` for temp paths | Yes (file existed pre-mark, but content not yet written) | Yes (content not yet written at create) |

## Operational Profile

### When to Use

**Ghosting:**
- Target EDR hooks `NtCreateProcessEx` and re-opens the image file by path to scan it at process creation — Ghosting gives it nothing to open.
- You need the file gone immediately, not just disguised — useful when post-execution IR/forensics will sweep `%TEMP%`.
- Target EDR does periodic on-disk scans and will catch the real payload if it persists on disk for any non-trivial duration.
- Engagement requires image-backed process specifically (vs. shellcode injection) — e.g., you need the loaded module list of the spawned process to look like a real PE for in-process recon.
- You want to combine with PPID spoofing (T-015) to a parent that wouldn't normally spawn a temp-file executable — ghosting leaves no file artifact for the parent to "have run."

**Herpaderping:**
- Target EDR only scans file content at `NtCreateProcessEx` time (most common hook pattern for file-based execution).
- You specifically want to leave a *misleading* on-disk artifact — IR responders will pull the file and analyze a benign signed PE, wasting their initial triage window.
- Engagement benefits from the file persisting (e.g., a second-stage loader that will be re-invoked via scheduled task or COM — see T-017 — and the decoy on disk will satisfy that future invocation's content check).
- Ghosting's `NtSetInformationFile` call with delete disposition is a known detection signature on the target EDR but `NtCreateSection` + `NtWriteFile` aren't.
- Target is Win10/11 where `FILE_DISPOSITION_INFORMATION_EX` with `POSIX_SEMANTICS` makes ghosting *too clean* (immediate unlink) and the EDR flags POSIX unlinks.

### When NOT to Use

**Both:**
- Target EDR hooks `NtCreateProcessEx` and inspects the *section object's* image content rather than re-opening the file — defeats both. Several modern EDRs do this via `NtQueryVirtualMemory` with `MemoryMappedFilenameInformation` or `MemorySectionName` against the section backing the new process.
- Engagement is low-complexity / quick-strike — both techniques require ~10+ syscalls and PEB parameter setup; if you have a writable remote process and just need code execution, Early Cascade (T-012) or Pool Party (T-007) are simpler.
- Target has WDAC with `OptionId=UMCI` (User-Mode Code Integrity) enforced — both create unsigned image-backed processes that will be blocked at `NtCreateProcessEx` with `STATUS_INVALID_IMAGE_HASH`. (Only relevant if you're loading an unsigned PE; signed-and-attackertouched PEs are a separate game.)
- Payload PE has a manifest requesting `requireAdministrator` or higher — the new process's token is the caller's token, UAC virtualization does not apply to `NtCreateProcessEx`, so an elevated-requesting manifest will fail or yield a token mismatch.

**Ghosting specifically:**
- Target EDR hooks `NtSetInformationFile` with `FileDispositionInformation` and flags delete-pending on a freshly-created temp file as a high-fidelity Process Ghosting indicator (this is the canonical published detection).
- Target monitors section creation where the backing file was just marked delete-pending (correlated telemetry).

**Herpaderping specifically:**
- Target EDR hooks `NtCreateSection` with `SEC_IMAGE` and resolves the backing file's content at section-creation time — the real payload is captured before the overwrite. Several EDR vendors do this on `SEC_IMAGE` sections to defeat Herpaderping specifically.
- Engagement can't tolerate the overwrite race failing — high-load target systems occasionally have AV scanning the file between `NtCreateSection` and the overwrite, but more commonly the issue is the overwrite itself racing with the EDR's section-create hook.

### Kill Chain Position

Both techniques sit at the **execution/lateral-movement** stage of the chain. They produce a fully-formed process with arbitrary image content, so they're typically the *delivery* of stage 2 or 3, not the initial access vector.

**Typical chain (post-compromise):**

T-004 (PEB walk) → T-001 (RecycledGate syscalls) → T-002 (SSN resolution if needed) → **T-009 or T-010** (ghost/herpaderping spawn) → T-015 (PPID spoofing, optional, integrated) → T-012 (Early Cascade into the spawned process for in-process shellcode) → T-016 (AMSI/ETW patch + stack spoof in the new process) → T-005 (Ekko sleep obfuscation) → T-017 (persistence install)

**For herpaderping specifically**, since the file persists on disk, you can chain to NTFS EA persistence (T-017 layer 2) by writing the EA stream to the decoy file before close, or use the file as the source for a scheduled task path that points to a benign-looking binary.

**Anti-pattern chain**: don't combine Ghosting → T-013 Self-Delete — Ghosting already produces no on-disk artifact; the self-delete adds risk without benefit.

### Trade-offs

| Dimension | Ghosting | Herpaderping | Notes |
|---|---|---|---|
| Stealth | 9/10 | 8/10 | Ghosting leaves zero on-disk artifact; Herpaderping leaves a decoy file (forensic misdirection is a plus) |
| Reliability | 8/10 | 6/10 | Ghosting has no race; Herpaderping has the section→overwrite→create race that can fail under EDR contention |
| Complexity | 7/10 | 8/10 | Herpaderping's env-block relocation in remote VA is fiddly; Ghosting has the delete-pending dance |
| Version range | Win7+ | Win7+ | Both rely on stable NT primitives; modern EDR detection improves with Win10+ telemetry |
| Privilege needed | medium-IL (no PPID), conditional (PPID spoof to foreign PID needs SeDebug) | same | Token is inherited from caller; no inherent admin requirement |
| Detection surface | `NtSetInformationFile(Delete=TRUE)` + `NtCreateSection(SEC_IMAGE)` shortly after | `NtCreateSection(SEC_IMAGE)` + `NtWriteFile` + `NtCreateProcessEx` from same section | EDR with kernel callback on `PsSetCreateProcessNotifyRoutine` correlating with `MiMapViewOfSection` catches both |
| Post-exploit footprint | Clean — no file, ghosted image-backed process in `EPROCESS.ImageFileName` (the section-backed image has a path string in PEB but no real file) | Decoy file on disk in `%TEMP%` | Herpaderping file is both evidence and misdirection |
| Token flexibility | Same as caller | Same as caller | For token manipulation, use T-014 (`NtCreateUserProcess` with explicit parent) |

## Rust Implementation Deep Dive

> **Honesty note**: The input provided here is the technique card pair only. The annotated source extract (`ghost.rs`, `herpaderping.rs`) was not provided. The deep dive below is derived from (a) what the cards explicitly state (e.g., "All operations via RecycledGate syscalls" for Herpaderping; "13-step" enumeration for Ghosting; "RtlCreateProcessParametersEx" for PEB setup) plus (b) standard NT API contract behavior. An operator modifying these files should treat the below as a structural map and grep the actual `.rs` source for the cited identifiers — exact field offsets, struct sizes, and error paths must be verified against the file content.

### Common scaffolding (both files)

Both implementations will share the same shape because they share the same syscalls:

- **`windows_targets::link!` bindings** (per `dark_crystal/crates/core/src/wrappers.rs`, see T-021-patterns card) — declares `NtCreateFile`, `NtWriteFile`, `NtSetInformationFile`, `NtCreateSection`, `NtClose`, `NtCreateProcessEx` or `NtCreateUserProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, `NtResumeThread`, and `RtlCreateProcessParametersEx` (the last one is technically not an NT API but `ntdll` export — resolved via PEB walk, T-004, and called via direct invocation since it's not a syscall).
- **Syscall dispatch via RecycledGate** (T-001) — Herpaderping card explicitly states this. Ghosting card doesn't specify, but the chain `requires: [T-001, T-004]` in this analysis reflects that all NT calls in `dark_crystal/crowd/src/` go through `sys_indirect.rs` / `sys_recycled.rs`.
- **`OBJECT_ATTRIBUTES`** struct built on-stack with `ObjectName` pointing at a `UNICODE_STRING` whose buffer is a heap-allocated wide string of the temp file path.
- **`IO_STATUS_BLOCK`** declared as a local `MaybeUninit<IO_STATUS_BLOCK>` — must be `MaybeUninit` because the NT API writes to it and we don't want a stale Drop.
- **Handle ownership** — file handle, section handle, process handle, thread handle all need `NtClose` on every path including early-return errors. Look for a `struct Handle(usize)` RAII guard with `Drop` calling `NtClose`, or explicit `if !handle.is_null() { NtClose(handle) }` cleanup. The `dark_crystal` codebase uses RAII patterns per the Rust patterns card (T-021) — verify.
- **`unsafe` blocks** — every NT call is unsafe (FFI to `extern "system"`). The block boundaries should encompass only the FFI call and the immediate pointer derefs for output params. Anything larger is a code smell.

### Ghosting-specific (`dark_crystal/crowd/src/ghost.rs`)

The card lists 13 steps; mapping to code:

- **Step 2-3 (delete-pending)**: likely a `FILE_DISPOSITION_INFORMATION { DeleteFile: BOOLEAN(1) }` (4 bytes on x64 due to alignment) passed to `NtSetInformationFile` with `FileDispositionInformation` class. On Win10+ the impl may prefer `FILE_DISPOSITION_INFORMATION_EX { Flags: FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS }` with class `FileDispositionInformationEx (59)` for immediate unlink-on-close.
- **Step 5 (write)**: `NtWriteFile` with the payload `&[u8]` slice. Payload is likely passed as `&[u8]` from the caller (e.g., a `Vec<u8>` containing the decrypted PE from the crypto layer, T-020).
- **Step 6 (SEC_IMAGE)**: `NtCreateSection` with `AllocationAttributes = SEC_IMAGE (0x1000000)`, `MaximumSize` ignored for image sections (pass `NULL` or zero — section size comes from the PE's `SizeOfImage`).
- **Step 7 (close)**: `NtClose(file_handle)` — file unlinks.
- **Step 8 (section persists)**: this is a kernel invariant, no code needed.
- **Step 9 (`NtCreateProcessEx`)**: signature is `NtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, InJob)`. Note: `Flags = 0`, `DebugPort = NULL`, `ExceptionPort = NULL`, `InJob = FALSE`. `ParentProcess` is `NtCurrentProcess()` by default, or the PPID-spoofed parent handle from T-015.
- **Step 10 (PEB params)**: `RtlCreateProcessParametersEx(&params, ImagePathName, DllPath, CurrentDirectory, CommandLine, Environment, WindowTitle, DesktopInfo, ShellInfo, RuntimeData, NULL)`. Then write `params` to the new process's `Peb->ProcessParameters` field. The card doesn't mention step 10's exact mechanism; standard implementations allocate the buffer in target with `NtAllocateVirtualMemory` and `NtWriteVirtualMemory` it across.
- **Step 11 (PPID)**: see T-015. The PPID-spoofed handle replaces `ParentProcess` in step 9.
- **Step 12-13 (thread + resume)**: `NtCreateThreadEx` + `NtResumeThread`.

### Herpaderping-specific (`dark_crystal/crowd/src/herpaderping.rs`, ~676 lines)

The card is explicit on three things:
1. **All operations via RecycledGate syscalls** (T-001) — so the `extern "system"` calls are wrapped through `sys_recycled.rs` dispatch.
2. **`NtOpenFile` with `FILE_SHARE_READ` only** — `ShareAccess = FILE_SHARE_READ (0x1)`. This blocks `FILE_SHARE_WRITE` requests from other openers, including EDR that tries to open for write-scan. Combined with the overwrite step, the herpaderping op becomes "only *we* can write the file, and we will overwrite it after the section captures the content."
3. **Full PEB parameter setup via `RtlCreateProcessParametersEx`** — same as Ghosting.
4. **Environment block fixup for remote virtual address space** — this is the key herpaderping-specific deep-dive item.

**Environment block fixup pattern**: `RTL_USER_PROCESS_PARAMETERS` contains a pointer field `Environment` (offset 0x80 on x64) that points at the env block. When you build the struct in the *caller's* address space via `RtlCreateProcessParametersEx`, that pointer is a *caller-side* pointer. The fixup procedure:
1. `RtlCreateProcessParametersEx` allocates `params` (and the env block) in caller's address space.
2. Calculate the offset of `Environment` from the start of `params`.
3. `NtAllocateVirtualMemory(hProcess, &base, 0, &size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)` in the target process — allocate enough for both `params` and the env block contiguously.
4. `NtWriteVirtualMemory(hProcess, base, params, sizeof(params), NULL)` — copy the params struct.
5. `NtWriteVirtualMemory(hProcess, base + sizeof(params), env_block, env_size, NULL)` — copy env block.
6. Manually patch the `Environment` pointer field in the remote copy: `*(base + offsetof(Environment)) = base + sizeof(params)`. This requires another `NtWriteVirtualMemory` with the patched pointer.
7. Patch any other pointer fields (`ImagePathName.Buffer`, `CommandLine.Buffer`, `DllPath.Buffer`, `CurrentDirectory.DosPath.Buffer`, `WindowTitle.Buffer`, `DesktopInfo.Buffer`, `ShellInfo.Buffer`, `RuntimeData.Buffer`) — these are `UNICODE_STRING`s whose `.Buffer` points to caller-side memory. Each must be relocated to the target-side address.
8. Set `Peb->ProcessParameters = base` in the new process's PEB. This requires `NtReadVirtualMemory` of the PEB `ProcessParameters` field (or `NtQueryInformationProcess` with `ProcessBasicInformation` to get the PEB address, then write the pointer).

The ~676-line file size suggests all this is inlined with substantial error handling rather than factored into a `RtlCreateProcessParametersRemote` helper.

### Error paths and failure handling

Both files likely follow the `dark_crystal` convention (T-021-patterns):

- **NTSTATUS checks**: every call returns `NTSTATUS`; the code should use `ntdll::NtError` or compare `status as i32 >= 0` for `STATUS_SUCCESS` (i.e., `>= 0` for success, `< 0` for error). The pattern is:
  ```rust
  let status = NtCreateFile(...);
  if !nt_success(status) {
      // cleanup already-allocated handles
      return Err(/* NTSTATUS mapped to a Rust error variant */);
  }
  ```
- **Cleanup on failure**: every successful handle allocation between step 1 and the failure point must be `NtClose`'d. Look for a `scope_exit`-like guard or explicit drop blocks. If the code uses `?` operator on `Result`, every `?` must be preceded by manual cleanup if it skips `Drop` guards.
- **`RtlCreateProcessParametersEx` failure** returns an NTSTATUS, not a Rust Result — the call site must convert.
- **Failure of `NtCreateSection`** in Ghosting before file close: file is still delete-pending and must be closed to trigger unlink — otherwise the file lingers with the real payload. Verify the file handle is closed on every error path after step 3 (delete-pending set).
- **Failure of `NtCreateProcessEx`** in Herpaderping: section handle and file handle are both still open and must be closed. The file at this point contains the decoy (overwritten) — closing the file leaves the decoy on disk, which is acceptable.

### Initialization patterns

Both files likely don't need `OnceLock`/`LazyCell` — they're per-call invocations. The only state that might be cached is the syscall SSNs (resolved once via T-002 cascade and stored in the `SYSINDIRECT_MAP`, see T-004 card).

### `core::arch::asm!` usage

Probably none in these two files directly — the asm lives in `sys_recycled.rs` (T-001). The ghost/herpaderping code calls into the RecycledGate wrappers, which internally use `asm!` for the `jmp` to the `ntdll` gadget and the `syscall` instruction. If the herpaderping file uses `asm!` directly, it's likely for stack spoofing at the moment of sensitive syscalls (T-016 advanced stack spoof).

## Edge Cases & Failure Modes

1. **AV/EDR with `NtCreateSection(SEC_IMAGE)` kernel callback (e.g., Microsoft Defender ATP with image-load ETW, CrowdStrike Falcon with section-create notification).**
   - *What goes wrong*: The EDR captures the section's backing file content at section-creation time, before Herpaderping's overwrite. For Ghosting, the EDR captures the content of the delete-pending file (which it can do because it has a process-creation-time callback and the section object survives even after the file is gone — the kernel can still read the section's prototype PTEs).
   - *Symptom*: spawned process is killed by EDR within ~100-500ms of resume; or `NtCreateProcessEx` itself returns `STATUS_ACCESS_DENIED`.
   - *Workaround*: switch to T-012 Early Cascade (APC into an existing legitimate process — no new section, no new process). Or use module stomping (T-013) — load a real DLL into an existing process and overwrite its `.text` section.

2. **Target with WDAC UMCI enforced (UI-policy).**
   - *What goes wrong*: `NtCreateProcessEx` returns `STATUS_INVALID_IMAGE_HASH` (0xC0000428). The new image is not pagehash-validated against a signed catalog.
   - *Symptom*: `NtCreateProcessEx` fails; spawned process never starts.
   - *Workaround*: Don't use these techniques on WDAC-enforced hosts. Fall back to shellcode-only execution via T-008 Threadless or T-007 Pool Party.

3. **Herpaderping race: EDR hooks `NtWriteFile` on the temp file path.**
   - *What goes wrong*: EDR captures the real payload bytes during the first `NtWriteFile` (step 2) and/or the decoy bytes during the second `NtWriteFile` (step 4). If it captures both and notices they differ, it flags the file as suspicious.
   - *Symptom*: EDR alert fires after process creation; new process killed.
   - *Workaround*: Use Ghosting (no second write to the same file). Or write the payload via `NtMapViewOfSection` of a private section rather than `NtWriteFile` (avoids the file-write hook on the payload path) — this is closer to mapping injection (T-013).

4. **PPID spoof to a parent you don't own without `SeDebugPrivilege`.**
   - *What goes wrong*: `NtOpenProcess` on the target parent PID returns `STATUS_ACCESS_DENIED` (0xC0000022). `NtCreateProcessEx` falls back to current process as parent (or fails if you passed a null handle).
   - *Symptom*: Spawned process has your dropper as parent, not the spoofed parent — defeats the OPSEC goal.
   - *Workaround*: Open parent with `PROCESS_CREATE_PROCESS | PROCESS_VM_READ` only — this often succeeds on processes in the same session at same IL without SeDebug. For parents in other sessions, you need elevation (T-017 UAC bypass via CMSTP) before the spoof attempt.

5. **`RtlCreateProcessParametersEx` env block relocation bug.**
   - *What goes wrong*: `ProcessParameters->Environment` pointer is not relocated to the target-side address, leaving it pointing at caller memory. After `NtCreateProcessEx`, the new process's `ntdll` reads env block from a random/unmapped address in its own VA → AV in `LdrInitializeThunk`.
   - *Symptom*: New process exits immediately with `STATUS_ACCESS_VIOLATION` (0xC0000005). No EDR involvement.
   - *Workaround*: Verify every pointer field in `RTL_USER_PROCESS_PARAMETERS` is patched to point at target-VA-allocated memory. Add a debug step that `NtReadVirtualMemory`'s the params back from the target and asserts all pointers are within the target's allocation range.

6. **`FILE_DISPOSITION_INFORMATION_EX` with `POSIX_SEMANTICS` on Win7.**
   - *What goes wrong*: `NtSetInformationFile` with class `FileDispositionInformationEx (59)` returns `STATUS_INVALID_INFO_CLASS` (0xC000000E7) on Win7/Server 2008 R2. The class was added in Win8.
   - *Symptom*: Ghosting's step 3 fails; file remains open with content; not delete-pending; subsequent `NtClose` doesn't unlink.
   - *Workaround*: Use `FileDispositionInformation (13)` with `FILE_DISPOSITION_INFORMATION { DeleteFile: BOOLEAN(1) }` on older Windows. Note this leaves the file present until last close, which is less clean than POSIX semantics.

7. **`NtCreateSection(SEC_IMAGE)` fails with `STATUS_INVALID_IMAGE_NOT_MZ` (0xC000020F).**
   - *What goes wrong*: Payload bytes don't start with `MZ`/`PE\0\0` signature, or PE is malformed.
   - *Symptom*: Section creation fails before file close in Ghosting — file remains delete-pending but unreferenced; closes cleanly on `NtClose`. No damage, but the engagement step fails silently.
   - *Workaround*: Validate PE in caller before writing — parse DOS header, NT headers, optional header. The `pe.rs` module in `dark_crystal/crates/core/src/` (T-007 card) should be the source of the validator.

8. **Anti-virus locks the temp file during initial `NtCreateFile` (before delete-pending set).**
   - *What goes wrong*: AV opens the new file with exclusive access (no share) between your `NtCreateFile` and `NtSetInformationFile`. Your `NtSetInformationFile` fails with `STATUS_SHARING_VIOLATION` (0xC0000043).
   - *Symptom*: Step 3 fails; payload never written; file is empty on disk.
   - *Workaround*: Open the file with `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` on the initial create to tolerate AV opens. Or skip temp file and use a path under your own user-profile that AV doesn't aggressively scan. Or pre-create the file in a prior step and let AV scan the empty file, then re-open for delete-pending.

9. **Spawned process is missing `kernel32`-side imports because env block is empty.**
   - *What goes wrong*: If `Environment` passed to `RtlCreateProcessParametersEx` is `NULL`, the new process has no environment variables; `ntdll`'s loader still works but `kernel32`'s `GetEnvironmentVariable` calls return empty. Some payloads crash on init.
   - *Symptom*: Spawned process starts, runs briefly, crashes during init.
   - *Workaround*: Build env block by inheriting from current process — `NtQueryInformationProcess(GetCurrentProcess(), ProcessEnvironment, ...)` or walk `Peb->ProcessParameters->Environment` and copy the buffer.

10. **Herpaderping: EDR hooks `NtCreateProcessEx` and queries the section's name via `NtQueryVirtualMemory(MemorySectionName)`.**
    - *What goes wrong*: The section's name is still the original file path (the kernel stores `\Device\HarddiskVolume3\Users\...\Temp\ghost.exe` as the section's image name even after the file is deleted in Ghosting, or after the decoy is written in Herpaderping). EDR can match the section name against the file's current content and detect a mismatch in Herpaderping.
    - *Symptom*: EDR flag on section/file content mismatch.
    - *Workaround*: In Herpaderping, name the temp file identically to the decoy (e.g., `notepad.exe`) so the section name and the file content agree at first inspection. The decoy still has to be a real signed `notepad.exe`. In Ghosting, there's no workaround — the section name persists with a path that no longer resolves; this is a known signature.

## Variant Ideas

1. **Double-herpaderping (chained decoys).** Write payload → create section → overwrite with decoy #1 → create process #1 → overwrite with decoy #2 → create process #2 from same section. Both processes run the original payload; both decoys appear in disk forensics. Useful for engagement where you want the IR team to chase two different benign binaries across two different spawned processes.

2. **Ghosting with delayed close.** Hold the file handle open after section creation to keep the file present on disk, then close it *after* `NtCreateProcessEx` returns. This defeats EDRs that check "does the file backing the section still exist?" at process-creation time — when they check, the file is present with the real payload; when they re-check after process creation, the file is gone. Adds a small race window but beats the section-name-vs-file-content mismatch detection in edge case #10.

3. **Section-from-section clone.** `NtCreateProcessEx` can also accept a section handle that was created from *another section* via `NtCreateSectionEx` with `SEC_IMAGE | SEC_BASE_VLM` and a parent section. Lets you pre-build the section object in a context where EDR isn't watching, then clone it for the actual spawn. Requires Win10 1709+.

4. **Combine with T-018 Edo Tensei resurrection.** Pre-create ghosted sections of multiple payloads and store section handles in a global table. When a watchdog detects a primary process was killed, immediately `NtCreateProcessEx` from a stored section handle — instant respawn with no file I/O on the resurrection path. The section handles survive the file deletion indefinitely.

5. **Combine with T-005 Ekko sleep obfuscation.** Spawned ghosted process is the one that runs Ekko sleep, so even if the EDR captured the image at spawn time, the in-memory image rotates through encryption during sleep. Defeats memory-scanning EDRs that re-scan the spawned process's image region periodically.

6. **Herpaderping with NTFS EA-stored second payload.** Write payload to `$DATA` stream → create section → overwrite `$DATA` with decoy → write second payload to `:extra` named stream → close. The decoy file on disk has the benign content in main stream and the second payload in an alternate stream. Pair with T-017 NTFS EA persistence — the scheduled task fires `rundll32 <file>:extra` and pulls the secondary payload.

7. **`NtCreateProcessEx` with explicit `DebugPort` and `ExceptionPort`.** Both default to NULL in the card's flow. Setting `DebugPort` to a port you own lets you receive debug events (including `EXCEPTION_BREAKPOINT` from anti-debug code in the payload) without `DEBUG_PROCESS` flag, defeating the spawned process's `IsDebuggerPresent` checks. Edge case but useful when the payload has anti-debug that's hard to patch.

8. **Combine with T-016 Block-DLL policy.** Spawn the ghosted process with `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` set via the new process's mitigation flags — blocks third-party DLLs (including EDR injectables) from loading into the spawned process. This is set in `RTL_USER_PROCESS_PARAMETERS`'s `MitigationPolicy` field or via `NtCreateProcessEx` `Flags` on Win10+. Effectively gives the spawned process an EDR-free bubble.

9. **Swap the order: section first, write second.** Open the file empty → create `SEC_IMAGE` section (fails — empty file) → no, this doesn't work, but the *variant* that does: pre-create the file with placeholder MZ bytes (real `notepad.exe` header + zero-padded body) → create section → write real payload to file → close. The section has the placeholder; you've now got a section whose image base is valid but whose real content lives only on disk briefly. Useful as a herpaderping variant where the race is *file-write-racing-section-load* rather than section-create-then-overwrite.

10. **Spawning with a custom parent token (not just PPID).** PPID spoofing (T-015) gives you the parent process but inherits the *caller's* token. To also inherit the parent's *token* (not just parent PID), open the parent with `PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE`, then use `NtCreateProcessEx` with that parent — the new process gets the parent's token. This is closer to T-014 NtCreateUserProcess semantics.

## OPSEC Notes

### Artifacts left behind

**Ghosting (T-009):**
- **No on-disk file** in `%TEMP%` after the operation completes. Pre-close, the file existed briefly with a name and 0-size or payload-size depending on timing.
- **Section object** in kernel with the image name string `\Device\HarddiskVolume...\Users\...\Temp\<random>.exe` — this string is queryable via `NtQueryVirtualMemory(MemorySectionName)` and persists for the lifetime of the spawned process. This is the single most identifiable artifact.
- **Spawned process** in `EPROCESS` list with `ImageFileName` pointing at the section's image name (which is a now-nonexistent path). Any process listing tool (`tasklist`, `Get-Process`) shows a process whose image path doesn't resolve.
- **Sysmon EID 1 (ProcessCreate)** fires with `Image` = the section's name (nonexistent path) and `ParentImage` = the dropper (or PPID-spoofed parent). This is a high-signal event for SOCs tuned for it.
- **Sysmon EID 7 (ImageLoad)** for `ntdll.dll`, `kernel32.dll`, etc. in the spawned process — the loader runs normally.
- **Prefetch** (`C:\Windows\Prefetch\<NAME>.pf`) is **not** created — prefetch only triggers for files opened with executable flag from disk; section-backed processes don't prefetch.
- **Event log 4663** (object access) if SACL is set on `%TEMP%` (rare in default configs).
- **AMSI** content log if the spawned process runs script-like content post-execution (only relevant if payload is PowerShell/script-engine-host).

**Herpaderping (T-010):**
- **Decoy file on disk** in `%TEMP%` — full content of a benign signed PE (e.g., `notepad.exe` copy with a different filename). Forensic responders will pull this file and analyze a benign binary, wasting triage time. But if they notice the file's hash doesn't match the legitimate notepad.exe's known hash (because it's a *copy* with a different name), that's a signal.
- **Section object** with image name = the decoy file's path. Same as Ghosting.
- **Spawned process** with `ImageFileName` = decoy path. Process listings look legitimate (a copy of notepad.exe in temp).
- **Sysmon EID 1** with `Image` = decoy path, `ParentImage` = dropper (or spoofed). Hash field shows the decoy's hash, not the real payload's.
- **Sysmon EID 7** for `ntdll.dll`, `kernel32.dll`, and crucially the **real payload's imports** — Sysmon's image load event shows `Image` = decoy path but `ImageLoaded` may include DLLs that the real payload imports. If the real payload imports `ws2_32.dll` and notepad.exe doesn't, the import mismatch is a detection signal. Mitigation: choose a decoy whose imports are a superset of the real payload's.
- **Second `NtWriteFile` event** to the same file path — if EDR logs file writes to temp paths, there's a write-then-overwrite pattern in the audit trail.

### Telemetry that SOCs alert on

- **Microsoft Defender for Endpoint** has explicit Process Ghosting detection (EID 1129 in MDI/Defender sensor log) correlating `NtSetInformationFile(Delete=TRUE)` + `NtCreateSection(SEC_IMAGE)` + `NtCreateProcessEx` in sequence within a short time window. Ghosting against MDE is increasingly unreliable.
- **Sysmon with EventID 1 + rule "Image ends with .exe in Temp AND parent is not explorer.exe, cmd.exe, powershell.exe"** — catches both. Standard SOC rule.
- **Sysmon EID 1 + rule "Image path does not exist on disk"** — catches Ghosting specifically. Less common but used by mature SOCs.
- **CrowdStrike Falcon** has `ProcessGhosting` and `ProcessHerpaderping` sensor events as of 2022+ — both are first-class detections.
- **EDR section-name query at `NtCreateProcessEx`** — catches both, defeats the file-vs-section decoupling.

### Cleanup procedures

**Ghosting**:
- No file to clean. After the spawned process exits, the section object is freed by the kernel (refcount drops to 0 when process exits and no other handle holds it).
- If you want to clean the spawned process while it's running, `NtTerminateProcess` and ensure no parent handle is leaked. The section object lingers briefly in kernel but is unreferenced after process exit.

**Herpaderping**:
- Delete the decoy file from `%TEMP%` via `NtDeleteFile` or `DeleteFileW` after the spawned process is confirmed running. The section holds its own reference to the underlying data; deleting the file post-spawn doesn't affect the running process.
- Note: file delete fires another file-delete event in EDR logs — may itself be a signal. Trade off: leave decoy on disk (cleaner telemetry but visible artifact) or delete it (hides artifact but creates a delete-event signal).

### Known detections to avoid

- **Don't write to `%TEMP%`** on hosts with Sysmon EID 11 (FileCreate) + temp-path rules — write to `C:\Users\<user>\AppData\Local\Microsoft\Windows\INetCache` or a custom subdirectory under your own user profile that doesn't match common temp-path rules.
- **Don't use a random filename** — name the file something plausible (`MicrosoftEdgeUpdate.exe`, `OneDriveStandaloneUpdater.exe`) to reduce SOC visual detection.
- **Don't spawn a process that immediately starts network connections** — even if the spawn is clean, the new process making outbound HTTPS to your C2 in the first 5 seconds is the highest-signal event in the entire chain. Use the spawned process for in-process work; have it call back via the parent dropper's already-established channel (T-019 networking via parent).
- **For Herpaderping specifically**: choose a decoy PE whose imports include all the DLLs the real payload imports. Use `dumpbin /imports` or `pe.rs`'s import parser to verify. The standard decoy `notepad.exe` imports `gdi32.dll`, `user32.dll`, `advapi32.dll`, `kernel32.dll`, `msvcrt.dll`, `comdlg32.dll`, `shell32.dll`, `shlwapi.dll` — if your real payload imports `ws2_32.dll`, `iphlpapi.dll`, `crypt32.dll`, you have a Sysmon EID 7 mismatch.

## Reusable Patterns

### Pattern: NT Handle RAII Guard
- **Use when**: any sequence of `NtCreate*`/`NtOpen*` calls where intermediate handles need deterministic cleanup
- **How**: Wrap handle in `struct NtHandle(usize)` with `Drop` calling `NtClose` via RecycledGate. Implement `Deref` for passthrough and an `into_raw()` for transferring ownership (e.g., to a spawned process).
- **Code ref**: `dark_crystal/crates/core/src/wrappers.rs` (per T-021-patterns card) — exact location of the guard struct needs verification in source

### Pattern: `MaybeUninit<IO_STATUS_BLOCK>` for NT I/O Calls
- **Use when**: calling `NtCreateFile`, `NtWriteFile`, `NtSetInformationFile`, `NtOpenFile` — any NT API that takes an `PIO_STATUS_BLOCK` out-param
- **How**: Declare `let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();` Pass `iosb.as_mut_ptr()`. After the call returns success, `iosb.assume_init()` to access `Status` and `Information` fields. Use `MaybeUninit` rather than `Default::default()` because `IO_STATUS_BLOCK` has no meaningful default and the kernel writes both fields.
- **Code ref**: would be present in both `ghost.rs` and `herpaderping.rs` — grep for `MaybeUninit::<IO_STATUS_BLOCK>` or `IO_STATUS_BLOCK::zeroed()`

### Pattern: Remote Pointer Relocation for `RTL_USER_PROCESS_PARAMETERS`
- **Use when**: setting up PEB parameters for any process created via `NtCreateProcessEx` (not just Ghosting/Herpaderping — also Early Cascade, Process Hollowing, etc.)
- **How**: Allocate `sizeof(params) + env_size + sum_of_string_buffer_sizes` as one contiguous allocation in target process. Write `params` struct, env block, and all string buffers. Then patch every `.Buffer` pointer field (8 on x64) to point at target-side offset. Finally `NtWriteVirtualMemory` the relocated `ProcessParameters` pointer into `Peb->ProcessParameters`.
- **Code ref**: `herpaderping.rs` (~676 lines suggests inlined implementation) — factor out into a `setup_remote_process_parameters()` helper for reuse in T-014 (`nt_create_user_process.rs`), T-013 (process_hollowing)

### Pattern: Per-File-Operation `OBJECT_ATTRIBUTES` Builder
- **Use when**: any `NtCreateFile`/`NtOpenFile` call — both ghosting and herpaderping need it, as does self-delete (T-013), NTFS EA persistence (T-017), NTDLL unhook (T-016)
- **How**: Build `UNICODE_STRING` from `HSTRING` or `Vec<u16>`, store in a local that outlives the call, wrap in `OBJECT_ATTRIBUTES { Length, RootDirectory, ObjectName, Attributes, SecurityDescriptor, SecurityQualityOfService }`. Use `OBJ_CASE_INSENSITIVE` for filesystem paths.
- **Code ref**: both `ghost.rs` and `herpaderping.rs` — should be factored into a `fn make_obj_attr(path: &[u16]) -> (Vec<u16>, UNICODE_STRING, OBJECT_ATTRIBUTES)` helper

### Pattern: Conditional `FILE_DISPOSITION_INFORMATION` vs `FILE_DISPOSITION_INFORMATION_EX`
- **Use when**: needing delete-pending semantics, especially cross-version (Win7 vs Win10+)
- **How**: Try `NtSetInformationFile(FileDispositionInformationEx, ...)` first; if it returns `STATUS_INVALID_INFO_CLASS` (0xC000000E7), fall back to `NtSetInformationFile(FileDispositionInformation, ...)`. The `EX` variant gives POSIX semantics (immediate unlink) on Win8+; the plain variant gives last-close unlink on all versions.
- **Code ref**: `ghost.rs` step 3

### Pattern: Engagement-Scoped Decoy Selection
- **Use when**: choosing a decoy PE for herpaderping
- **How**: Build a "decoy manifest" of signed Microsoft PEs with known import sets, categorized by what legitimate-looking imports they have (network: `wsmprovhost.exe`, `svchost.exe`-variants; GUI: `notepad.exe`, `mspaint.exe`; crypto: `lsass.exe` (don't), `rundll32.exe`). Match decoy to payload's import profile to minimize Sysmon EID 7 mismatch. Build once, reuse across engagements.
- **Code ref**: data table that lives in `selection_config.rs` (per T-021-patterns card) — would be a new section there