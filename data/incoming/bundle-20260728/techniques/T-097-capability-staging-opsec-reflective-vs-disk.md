---
id: T-097
name: Capability Staging OPSEC Reflective vs Disk
category: edr-evasion
tier: A
crate: none
source_file: none
mitre: T1620
mitre_secondary: [T1027]
tags: [opsec, reflective-loading, disk-staging, capability-loss, detection-surface, fileless, payload-staging, minifilter, defender-realtime]
origin: atlas-synthesis
member_notes: [lgtm:coverage-gap-payload-staging-opsec, lgtm:capability-staging-opsec-convergence]
---

# Capability Staging OPSEC — Reflective vs Disk — The Dual Failure Model for Payload Placement

## Summary

SEC670 frames dropping a capability to disk as risking two equivalent operational failures: detection by file-system minifilter drivers or Windows Defender real-time protection, and loss of the capability itself because the staged binary becomes a recoverable artifact for defenders to reverse-engineer. The convergence across SEC670, MalDev Academy, and CRTO tradecraft is that capabilities should prefer reflective loading (manual PE mapping via `RtlImageNtHeaders` and in-process section copying) over disk staging on systems with unknown security products. The vault documents fileless execution techniques (T-009 Process Ghosting, T-010 Process Herpaderping, T-013 reflective PE loader) and artifact management (T-016 evasion suite) but does not frame the staging decision as an explicit OPSEC tradeoff with dual failure modes. SEC670's framing — detection and capability loss as equivalent failures — changes the operator's risk calculus: a staged capability that is detected is not merely burned, it is actively counterproductive because it provides the defender with a recoverable sample of the operator's tooling.

## Mechanism

1. Assess the target environment's detection surface for disk writes:
   - File-system minifilter drivers intercept `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, and `IRP_MJ_SET_INFORMATION` operations. EDR products register minifilters that scan files on creation, modification, and rename.
   - Windows Defender real-time protection uses a minifilter (`WdFilter.sys`) that scans files on write (` real-time protection`) and on execution (`behavior monitoring`). The scan triggers when a file with an executable extension (`.exe`, `.dll`, `.sys`) is written to disk.
   - Sysmon Event ID 11 (FileCreate) and Event ID 23 (FileDelete) log file creation and deletion events if Sysmon is configured with file event monitoring.

2. Assess the target environment's detection surface for in-memory execution:
   - ETW-TI (Threat Intelligence) providers emit events for `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`, `NtMapViewOfSection` with executable protection, and `WriteProcessMemory` across process boundaries.
   - Kernel callbacks (`PsSetCreateProcessNotifyRoutine`, `MmProtectExecutableSection`) observe process creation and executable page protection changes.
   - Memory forensics tools (Volatility, PE-sieve, Moneta — see T-093, T-094) scan for unbacked executable regions and module mismatches in post-capture analysis.

3. Select a staging strategy based on the dual failure model:
   - **Reflective loading** (preferred on unknown targets): the payload PE is embedded in the loader's `.data` or `.rsrc` section, decrypted in memory, and manually mapped via `NtAllocateVirtualMemory` + section copying + import resolution + relocation fixing. No file is written to disk. Detection surface: ETW-TI events for `VirtualAlloc` with executable protection, Moneta's unbacked-executable scan. Capability loss: none — the payload exists only in volatile memory and is lost when the process exits or is terminated.
   - **Disk staging** (acceptable on known-permissive targets): the payload PE is written to disk, then loaded via `LoadLibrary` or executed via `CreateProcess`. Detection surface: file-system minifilter scan on write, Windows Defender real-time scan, Sysmon file events. Capability loss: high — the file persists on disk and is recoverable by forensics even after deletion (NTFS journal, Volume Shadow Copy, file carving on unallocated clusters).
   - **Process Ghosting** (T-009): the payload is written to a delete-pending file, mapped as a `SEC_IMAGE` section, then the file is closed (disappears from disk). The section persists in memory as a file-backed executable region. Detection surface: the file exists on disk only during the write-to-close window (milliseconds), reducing minifilter scan exposure. Capability loss: low — the file is marked for deletion before the EDR can scan it, and the section is backed by a file that no longer exists.
   - **Process Herpaderping** (T-010): the payload is written to a file, a process is created from the file, then the file content is overwritten with a legitimate binary. The process executes the original payload, but the on-disk file shows the legitimate binary. Detection surface: file-system minifilter sees the original write and the subsequent overwrite. Capability loss: the overwritten content may be recoverable via NTFS journaling.

4. Execute the selected staging strategy.
5. Verify that no recoverable artifact remains: for reflective loading, confirm that the embedded payload bytes in the loader's `.data` section are overwritten or encrypted after mapping. For disk staging, confirm that the file is deleted and optionally overwritten with random bytes before deletion.

## OS Internals Context

The file-system minifilter model operates at the IRP (I/O Request Packet) layer. When a user-mode application calls `CreateFileW` followed by `WriteFile`, the I/O Manager constructs an `IRP_MJ_CREATE` followed by an `IRP_MJ_WRITE` IRP and sends it down the device stack. Minifilter drivers register callbacks via `FltRegisterFilter` for pre-operation (`FLT_PRE_OPERATION_CALLBACK`) and post-operation (`FLT_POST_OPERATION_CALLBACK`) notification on specific IRP types. EDR minifilters intercept `IRP_MJ_CREATE` to scan files before they are opened and `IRP_MJ_WRITE` to scan content before it is written. The scan occurs synchronously — the minifilter can return `FLT_PREOP_COMPLETE` to deny the operation, preventing the file write from completing.

Windows Defender's real-time protection uses the `MpFilter` (WdFilter.sys) minifilter driver. It registers pre-operation callbacks on `IRP_MJ_CREATE` (to scan files being opened for execution), `IRP_MJ_WRITE` (to scan content being written), and `IRP_MJ_CLEANUP` (to scan files being closed after modification). The scan engine checks file content against signature databases, heuristics, and cloud-delivered definitions. A PE file written to disk triggers the `IRP_MJ_WRITE` callback, which extracts the file content and runs the signature engine against it.

Reflective loading avoids the file-system minifilter entirely because no `IRP_MJ_CREATE` or `IRP_MJ_WRITE` IRPs are generated — the payload exists as an in-memory buffer and is mapped via `NtAllocateVirtualMemory` (which does not involve the file system). The detection surface shifts to ETW-TI (which monitors `VirtualAlloc` with executable protection) and memory forensics (which scans for unbacked executable regions). The `NtAllocateVirtualMemory` call with `PAGE_EXECUTE_READWRITE` generates a `Microsoft-Windows-Kernel-Process` ETW event (event ID 1 for `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`) that ETW-TI consumers can process.

Process Ghosting exploits the file system's delete-pending state. When `NtSetInformationFile` is called with `FileDispositionInformation` and `DeleteFile = TRUE`, the file is marked for deletion when the last handle is closed. The file remains open and writable — `NtWriteFile` succeeds on a delete-pending file — but the file is invisible to new `CreateFile` callers (they receive `STATUS_DELETE_PENDING`). Minifilter drivers that intercept `IRP_MJ_CREATE` cannot open the file for scanning because the create operation fails. The `NtCreateSection` call with `SEC_IMAGE` succeeds because the section references the file object via the existing open handle, not via a new create operation. When the file handle is closed, the file is deleted from the filesystem — but the section object persists, backed by the file data that was written before deletion.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the OPSEC decision framework that governs payload placement across multiple vault techniques.

The HUGIN source implements several staging strategies referenced in this card. The `dark_crystal/crowd/src/ghost.rs` file implements Process Ghosting (T-009), which stages the payload via a delete-pending file and `SEC_IMAGE` section mapping. The `dark_crystal/crowd/src/payload_cfg.rs` file contains the configuration constants that select the staging strategy: `INJECTION_TYPE` (set to `"module_overload"` in the provided configuration), `PAYLOAD` (empty, indicating runtime payload acquisition rather than embedding), `GHOST_MASQUERADE` (the masquerade path for ghosted processes), and `OVERLOAD_DLL` (the target DLL for module overloading). The configuration supports selecting between process ghosting, module overloading, function stomping, and thread hijacking as staging strategies, each with a different detection and capability-loss profile.

## Why It Matters

The vault documents four staging strategies (T-009 Process Ghosting, T-010 Process Herpaderping, T-013 reflective PE loader, T-016 evasion suite) without surfacing the unifying OPSEC rationale that motivates their existence. SEC670's framing of detection and capability loss as equivalent failures changes the operator's risk assessment: a staged binary that triggers a Defender scan is not merely detected — it is seized by the defender, who now possesses a sample of the operator's malware that can be reverse-engineered, signatured, and distributed to other endpoints. This dual failure model means that disk staging is never a neutral choice; it is always a calculated risk that the operator must evaluate against the target's file-system monitoring posture. Documenting this rationale as a cross-cutting OPSEC framework enables operators to select staging strategies by intent (avoid disk write) rather than by mechanism (ghosting versus herpaderping versus reflective loading).

## Detection Considerations

- **Telemetry sources**: File-system minifilter callbacks (`IRP_MJ_CREATE`, `IRP_MJ_WRITE`) detect disk writes. ETW-TI `VirtualAlloc` events detect in-memory allocation with executable protection. Sysmon Event ID 11 detects file creation. Windows Defender real-time protection scans files on write.
- **Bypass options**: Reflective loading avoids file-system minifilter callbacks. Process Ghosting reduces the minifilter exposure window to the write-to-close interval. Module overloading (mapping into a legitimately loaded module's address space) avoids `VirtualAlloc` with executable protection by using the module's existing `PAGE_EXECUTE_READ` region. PE header stomping (T-096) prevents PE-sieve from identifying the in-memory payload.
- **Residual artifacts**: Reflective loading leaves no disk artifact but leaves an unbacked executable VAD entry. Process Ghosting leaves no disk artifact (file is deleted) but leaves a `SEC_IMAGE`-backed VAD entry. Module overloading leaves no unbacked VAD entry but modifies a legitimately loaded module's `.text` bytes (detectable by PE-sieve). Disk staging leaves a recoverable file artifact even after deletion (NTFS journal, Volume Shadow Copy, file carving).

## Related Techniques

- **T-009 Process Ghosting** — Delete-pending file execution avoids persisting a scannable artifact on disk, reducing both detection and capability-loss risk
- **T-010 Process Herpaderping** — File content race avoids leaving a recoverable payload sample on disk by overwriting the file after process creation
- **T-013 Remaining Methods** — Reflective PE loader implements in-memory mapping to avoid disk staging entirely
- **T-016 EDR Evasion Suite** — Evasion techniques assume the payload is already in memory; staging to disk would create a recoverable artifact that defeats the evasion posture
- **T-020 Anti-Analysis Suite** — Anti-VM and API hammering do not address the disk-write avoidance rationale that motivates fileless execution

## References

- Atlas material: atlas-post-exploit-part15, atlas-post-exploit-part17
- MITRE ATT&CK: T1620 (https://attack.mitre.org/techniques/T1620)
- LGTM notes: lgtm:coverage-gap-payload-staging-opsec, lgtm:capability-staging-opsec-convergence
- Public references: SEC670, MalDev Academy, CRTO tradecraft (reflective loading preference on unknown targets)

## Source Reference

No current implementation. See atlas material for the OPSEC decision framework. HUGIN source files `dark_crystal/crowd/src/ghost.rs` (Process Ghosting) and `dark_crystal/crowd/src/payload_cfg.rs` (staging strategy configuration) implement specific staging strategies referenced in this card.