---
id: T-098
name: Custom Loader Development and Unhook Bypass C2 Arc
category: edr-evasion
tier: A
crate: dark_crystal
source_file: dark_crystal/crowd/src/ghost.rs
mitre: T1620
mitre_secondary: [T1055]
tags: [custom-loader, manual-pe-mapping, unhook-bypass-arc, c2-callback, phase-sequence, dropper, tradecraft-arc, reflective-loading]
origin: atlas-synthesis
member_notes: [lgtm:cross-source-convergence-custom-loader-to-callback-arc, lgtm:custom-loader-development-tradecraft]
---

# Custom Loader Development and Unhook→Bypass→C2 Callback Arc — Integrated Operational Sequence from Execution to C2

## Summary

SEC670 Section 5 sequences custom loader development, NTDLL unhooking, AV/EDR bypass, AMSI patching, and C2 callback establishment as a single training arc that mirrors the operational reality of implant deployment. The loader is the initial execution vehicle — a custom PE that manually maps and executes the implant payload without invoking the standard Windows loader (`LdrLoadDll`). The loader must establish execution (manual PE mapping), defeat runtime monitoring (unhook ntdll, patch `amsi.dll!AmsiScanBuffer`, muffle ETW), and then establish C2 callback registration before the implant can initiate network communication. The vault's `dark_crystal` crate contains loader infrastructure (phase runner, transport, injection modules) but T-016 does not document the full arc from loader development through C2 callback as an integrated discipline. The arc's ordering — loader first, then in-process evasion, then callback — reflects a hard dependency chain: the implant cannot phone home until evasion is in place, and evasion cannot be applied until the implant is executing in memory.

## Mechanism

1. **Loader execution** — The loader is the initial binary that the operator delivers to the target. It may be embedded with the payload (static linking via `include_bytes!`) or acquire it at runtime (remote download via WinHTTP, read from an alternate data stream, or receive via a stager protocol). The loader's first action is to decrypt the payload in memory (AES-256-GCM decryption in the HUGIN implementation) and prepare it for manual mapping.

2. **Manual PE mapping** — The loader maps the payload PE into the current process's address space without calling `LoadLibrary` or `LdrLoadDll`:
   - Parse the PE headers: read `IMAGE_DOS_HEADER` from the payload base, follow `e_lfanew` to `IMAGE_NT_HEADERS`, read `OptionalHeader.SizeOfImage`.
   - Allocate memory: call `NtAllocateVirtualMemory` with `MEM_COMMIT | MEM_RESERVE` and `PAGE_READWRITE` (writable during mapping; protection is changed to `PAGE_EXECUTE_READ` after all fixups).
   - Copy sections: iterate `IMAGE_SECTION_HEADER` entries, copy each section from `PointerToRawData` to `VirtualAddress` relative to the allocated base.
   - Resolve imports: iterate `IMAGE_IMPORT_DESCRIPTOR` entries, for each DLL call `LdrLoadDll` (or manually resolve via PEB walk T-004), for each function resolve via `LdrGetProcedureAddress` (or manual export table walk T-050), write function pointers to the IAT.
   - Fix relocations: iterate `IMAGE_BASE_RELOCATION` blocks, apply `IMAGE_REL_BASED_DIR64` relocations by adding the delta between the allocated base and the PE's preferred `ImageBase`.
   - Execute TLS callbacks: iterate `IMAGE_DIRECTORY_ENTRY_TLS` callbacks if present.
   - Call entry point: invoke `AddressOfEntryPoint` with `DLL_PROCESS_ATTACH`.
   - Change protection: call `NtProtectVirtualMemory` to set the `.text` section to `PAGE_EXECUTE_READ`.

3. **In-process evasion** — After the payload is mapped and executing, the loader applies evasion techniques:
   - NTDLL unhook: restore original `.text` bytes (see T-095 for variant selection).
   - AMSI patch: overwrite `amsi.dll!AmsiScanBuffer` prologue with `ret` or `mov eax, 0; ret`.
   - ETW muffle: overwrite `ntdll!NtTraceEvent` or `ntdll!EtwTraceEvent` prologue with `ret`.
   - Block DLL policy: set `ProcessDynamicCodePolicy` via `NtSetInformationProcess` to prevent non-Microsoft DLL injection.
   - PEB unlink: remove the payload's `LDR_DATA_TABLE_ENTRY` from the PEB loader list (if registered).
   - PE header stomp: zero the payload's PE headers to prevent PE-sieve identification.

4. **C2 callback establishment** — After evasion is in place, the implant establishes its C2 channel:
   - Register a callback timer (e.g., `CreateTimerQueueTimer` or `SetTimer`) that periodically invokes the C2 check-in function.
   - Initialize the transport layer (TCP, HTTP long-poll, or peer relay in the HUGIN implementation).
   - Perform the initial check-in: send a beacon with system information, receive tasking or configuration updates.
   - Enter the command dispatch loop: the callback receives C2 messages and dispatches them to handler functions (keylogger, screen capture, browser hook, etc.).

## OS Internals Context

The manual PE mapping step replaces the functionality of `LdrLoadDll` and the loader-side `LdrpInitializeProcess` routine. The Windows loader (`ntdll!LdrpInitializeProcess`) performs the same sequence — section mapping, import resolution, relocation application, TLS callback execution, and entry point invocation — but it also registers the module in the PEB loader list (`LdrpHashTable`, `LdrpModuleBaseAddressIndex`), applies security checks (CFG, ASLR, SafeSEH), and notifies ETW providers (`Microsoft-Windows-Kernel-Process` for image load events). By performing manual mapping, the loader avoids generating the ETW image-load event (`EventID = 4` in the `Microsoft-Windows-Kernel-Process` provider) and avoids registering the module in the PEB loader list, making the payload invisible to `EnumProcessModules` and `Module32First`/`Module32Next` enumeration APIs.

The ordering of the arc — loader, then evasion, then C2 — reflects hard dependencies. The AMSI and ETW patches must be applied before the payload executes any code that might be scanned (e.g., PowerShell commands, .NET assembly loading) or that emits ETW events (e.g., network connections via WinHTTP). The NTDLL unhook must be applied before the payload makes any `Nt*` calls that would traverse the EDR's inline hook trampolines. The C2 callback must be established after evasion to ensure that the initial beacon does not trigger ETW network events or AMSI content scans.

The `dark_crystal` crate's phase runner structure mirrors this arc. The `payload_cfg.rs` file configures the phases: `ANTI_VM` and `HAMMER_ENABLED` (pre-execution anti-analysis), `AMSI_HBP` and `ETW_PATCH` (in-process evasion), `INJECTION_TYPE` (payload staging), `SLEEP_MS` (sleep obfuscation timing), and persistence configuration (`PERSIST_ENABLED`, `PERSIST_METHODS`). The phase runner executes these in an ordered sequence that matches the SEC670 arc.

## Key Implementation Details

The `dark_crystal/crowd/src/ghost.rs` file implements the loader component of the arc via Process Ghosting. The `spawn_ghosted` function accepts a decrypted PE payload, a masquerade path (e.g., `C:\Windows\System32\svchost.exe`), and an optional PPID for parent spoofing. It creates a delete-pending temp file, writes the payload, creates a `SEC_IMAGE` section, closes the file (removing it from disk), creates a process via `NtCreateProcessEx` with the section handle, reads the ghosted process's PEB via `NtQueryInformationProcess(ProcessBasicInformation)`, constructs `RTL_USER_PROCESS_PARAMETERS` with the masquerade path via `RtlCreateProcessParametersEx`, writes the parameters into the ghosted process, and creates a thread at the payload's `AddressOfEntryPoint` via `NtCreateThreadEx`.

The `dark_crystal/crowd/src/ki_step_over.rs` file implements the bypass component of the arc. The `install_step_over` function accepts a list of NT function names, resolves their SSNs via the `resolve.rs` PEB walker, checks whether each function is hooked (presence of `0xE9` JMP at offset +3 from the function start), registers the function in an internal SSN table, and sets hardware breakpoints (DR0-DR3) on the hooked instructions. The `exception_handler` function intercepts the resulting single-step exceptions via a `Wow64PrepareForException` callback hook, sets `RAX` to the resolved SSN, sets `RIP` to the `syscall` instruction (skipping the EDR's trampoline), and resumes via `NtContinue`.

The `dark_crystal/crowd/src/payload_cfg.rs` file contains the configuration constants that wire the arc together: `INJECTION_TYPE = "module_overload"` (staging strategy), `ANTI_VM = true` (pre-execution check), `HAMMER_ENABLED = true` (sandbox delay), `AMSI_HBP = ON` (AMSI bypass via hardware breakpoint), `ETW_PATCH = true` (ETW muffle), `BLOCK_DLL = true` (process mitigation policy), `PPID_AUTO = true` (parent spoofing), `SLEEP_MS = 3000` (sleep obfuscation timing), and `PERSIST_ENABLED = true` with `PERSIST_METHODS = "com_hijack"` (persistence layer).

## Why It Matters

The vault documents loader infrastructure (T-022 architecture overview), evasion techniques (T-016), and networking (T-022) as separate capability areas. SEC670 material establishes that these are phases of a single operational arc with hard ordering dependencies: the loader must map the payload before evasion can be applied, and evasion must be applied before the C2 callback can beacon safely. Documenting this arc as an integrated discipline surfaces the ordering constraints that determine whether an operator's deployment succeeds or fails. An operator who establishes C2 before patching AMSI will have their beacon content scanned. An operator who patches AMSI before the payload is mapped will have the mapping operation itself scanned. The arc's ordering is not a recommendation — it is a dependency chain enforced by the runtime behavior of Windows security components.

## Detection Considerations

- **Telemetry sources**: The manual PE mapping step generates `NtAllocateVirtualMemory` ETW events. The evasion step generates `VirtualProtect` events on executable pages. The C2 step generates network connection ETW events (`Microsoft-Windows-Kernel-Network` provider) and DNS query events. Kernel callbacks (`PsSetCreateProcessNotifyRoutine`) fire during the `NtCreateProcessEx` call in the Ghosting variant.
- **Bypass options**: The `ki_step_over.rs` approach bypasses EDR hooks without modifying ntdll's `.text`, avoiding the `VirtualProtect` events that unhooking generates. Indirect syscalls (T-001 RecycledGate) avoid the ntdll stub entirely, reducing the ETW surface. Sleep obfuscation (T-005 Ekko ROP Sleep) encrypts the payload during sleep windows, making memory captures during sleep show encrypted bytes.
- **Residual artifacts**: The ghosted process appears in the process list with the masquerade path. The PEB loader list does not contain the payload (it was mapped via `NtCreateProcessEx` from a section, not via `LdrLoadDll`). The VAD tree contains a `SEC_IMAGE`-backed entry for the ghosted process. The C2 network connections produce traffic that network monitoring (IDS, proxy logs) can detect.

## Related Techniques

- **T-016 EDR Evasion Suite** — The unhook, AMSI patch, and ETW patch phases follow the loader phase in the operational arc; this card documents the ordering dependency between loading and evasion
- **T-022 Network Suite** — C2 callback establishment is the terminal phase of the arc; the transport layer (TCP, HTTP long-poll, peer relay) is configured after evasion is in place
- **T-013 Remaining Methods** — The manual PE loader implements the reflective loading component of the arc, mapping the payload without invoking the standard Windows loader

## References

- Atlas material: atlas-methodology-part8, atlas-methodology-part9
- MITRE ATT&CK: T1620 (https://attack.mitre.org/techniques/T1620)
- LGTM notes: lgtm:cross-source-convergence-custom-loader-to-callback-arc, lgtm:custom-loader-development-tradecraft
- Public references: SEC670 Section 5 (Custom Loaders, units 27-29, 32-37)

## Source Reference

`dark_crystal/crowd/src/ghost.rs` (lines 1-340): implements `spawn_ghosted` — the loader component via Process Ghosting, including `NtCreateProcessEx`, PEB reading, process parameter construction, and entry point thread creation. `dark_crystal/crowd/src/ki_step_over.rs` (lines 1-320): implements `install_step_over` — the bypass component via hardware breakpoint interception. `dark_crystal/crowd/src/payload_cfg.rs` (lines 1-120): configuration constants wiring the arc phases.