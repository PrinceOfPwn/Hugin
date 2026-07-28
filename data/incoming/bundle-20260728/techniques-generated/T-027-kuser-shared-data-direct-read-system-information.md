---
id: T-027
name: KUSER_SHARED_DATA Direct-Read System Information
category: discovery
tier: A
crate: none
source_file: none
mitre: T1082
mitre_secondary: [T1497.003]
tags: [kuser-shared-data, fixed-va, direct-read, sysinfo-discovery, timing-source, hook-bypass, syscall-free, kernel-mapped-page]
origin: atlas-synthesis
member_notes: [lgtm:kuser-shared-data-info-source, lgtm:kuser-shared-data-sysinfo-primitive]
---

# KUSER_SHARED_DATA Direct-Read System Information — Hook-Free Enumeration From a Fixed Kernel-Mapped Page

## Summary

KUSER_SHARED_DATA is a kernel-maintained read-only page mapped at the fixed virtual address 0x7FFE0000 into every Windows user-mode process, and reading it directly yields OS version, system root path, tick counts, and system time without invoking any API or syscall. SEC670 presents it as an "Undocumented Method" for system information gathering and as a bonus sysinfo target alongside GetProductInfo, GetWindowsDirectory, GetComputerName, and GetNativeSystemInfo. Operators use it to replace the entire API-based enumeration family with plain memory loads against a page the kernel updates continuously. Because no ntdll export, syscall stub, or Win32 import is exercised, the technique produces no surface for userland inline hooks or syscall monitoring. The primary detection surface is static: the 0x7FFE0000 constant embedded in the binary, which the training material does not discuss further.

## Mechanism

1. Reference the page through the architecture constant 0x7FFE0000. The mapping exists before the first user-mode instruction executes and, per the training material, sits at the "same VA in almost every process" on x86, x64, and WOW64. No enumeration, handle, or loader query is required to locate it. ntdll exports the same address as the `SharedUserData` symbol; operator code hardcodes the constant directly.

2. Read the version block using the ntddk.h field layout (stable across Windows 10/11 for all offsets cited here): `NtMajorVersion` at 0x26C, `NtMinorVersion` at 0x270, `NtBuildNumber` at 0x260, `NtProductType` at 0x264, and `ProductTypeIsValid` at 0x268. This substitutes for GetVersionEx, RtlGetVersion, and the workstation-versus-server portion of GetProductInfo.

3. Read `NtSystemRoot` at offset 0x30, a NUL-terminated `WCHAR[260]` buffer holding the absolute Windows directory path. This substitutes for GetWindowsDirectory and GetSystemWindowsDirectory.

4. Read processor and memory fields: `ImageNumberLow`/`ImageNumberHigh` (0x2C/0x2E, native machine type), `NativeProcessorArchitecture` (0x26A), `ProcessorFeatures` (0x274, a 64-byte boolean array indexed by the PF_* constants), `NumberOfPhysicalPages` (0x2E8, RAM sizing), `LargePageMinimum` (0x244), and `SuiteMask` (0x2D0). These cover the processor-architecture and capability data the recon material attributes to GetNativeSystemInfo.

5. Read the timing triples `InterruptTime` (0x8), `SystemTime` (0x14), `TimeZoneBias` (0x20), and `TickCount` (0x320). Each is a volatile `KSYSTEM_TIME` of `LowPart`, `High1Time`, `High2Time`. On x64 an aligned 64-bit load is atomic; portable code applies the documented read protocol — capture High1Time, then LowPart, then High2Time, and retry if High1Time != High2Time — because the kernel rewrites these fields asynchronously from the timer interrupt path.

6. Derive the GetTickCount value locally: `(TickCountLowDeprecated[0x0] * TickCountMultiplier[0x4]) >> 24`. This is the identical arithmetic kernel32!GetTickCount performs against this page, and GetSystemTimeAsFileTime likewise copies `SystemTime` from offset 0x14. Direct reads therefore return the same values as the API family they replace, with the API's own code path removed.

7. Read system-state flags: `KdDebuggerEnabled` (0x2D4), `SafeBootMode` (0x2EC), `ActiveConsoleId` (0x2D8), and `NXSupportPolicy` (0x2D5). `KdDebuggerEnabled` supplies a kernel-debugger check that traverses neither the PEB nor CheckRemoteDebuggerPresent.

8. Consume the values in place — version gating for payload selection, system-root path construction, tick deltas for timing logic. The only machine instructions involved are loads against a read-only mapping; nothing else executes.

## OS Internals Context

The page is a single physical page shared system-wide. The kernel accesses it through a read-write mapping at 0xFFFFF78000000000 (the `KI_USER_SHARED_DATA` constant in the WDK) and every process receives a read-only mapping of the same physical page at 0x7FFE0000 when its address space is constructed. All processes therefore observe identical values. The mapping carries no privilege requirement: it is present in low-integrity and AppContainer processes exactly as in medium-integrity ones.

The kernel's timer interrupt processing updates `InterruptTime`, `SystemTime`, and `TickCount` on each clock tick; the boot-time fields (version, system root, suite mask) are written once during initialization; `KdDebuggerEnabled` tracks the state of the kernel debugger. Because the user-mode page tables mark the page read-only, any user-mode write raises STATUS_ACCESS_VIOLATION — the kernel writes exclusively through its own mapping. Readers must treat time fields as asynchronous snapshots and must not cache them.

The detection-relevant property is where the read sits relative to the kernel/user boundary: nowhere. Userland EDR instrumentation lives inside ntdll and kernelbase code (inline hooks, patched stubs); syscall-based monitoring observes ring transitions via ETW-TI or kernel drivers. A load from 0x7FFE0000 executes neither hooked code nor a syscall instruction — it is a page-table-resolved memory access indistinguishable from reading a constant. This is the same reason Windows itself uses the page to avoid syscalls: GetTickCount and GetSystemTimeAsFileTime read it in user mode, and on Windows 10 and later QueryPerformanceCounter can complete in user mode using `QpcFrequency` (offset 0x300) published in this page. Microsoft ships the full structure definition in ntddk.h, though the SEC670 material presents the technique under the heading "Undocumented Method"; the operationally relevant facts the course emphasizes are the fixed VA and the breadth of fields ("holds large number of elements").

On WOW64 the page sits at the same VA, `ImageNumberLow` reports the native machine type, and `NativeProcessorArchitecture` distinguishes the native architecture, so a 32-bit reader can identify the 32-on-64 condition without calling IsWow64Process. Offsets for every field cited in this card are identical between the x86 and x64 layouts and have not moved between Windows 10 and Windows 11 — the structure is extended by appending new fields at the tail, never by reordering.

The member notes position this page as a distinct info source from the PEB: the PEB exposes loader state (module lists, process parameters), while KUSER_SHARED_DATA exposes kernel-published runtime state (version, time, processor, system root). Neither requires an API call to reach, but the content sets do not overlap.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C. The three grep-matched files were reviewed and do not implement the technique: `crates/core/src/experimental/evasion/veh/def.rs` defines PEB and loader structures for the VEH gate with no reference to 0x7FFE0000; `crowd/src/chain.rs` reads the PEB via `gs:[0x60]` for own-image-base resolution, which is T-004 territory, not the shared page; `crowd/src/persist/ntfs_ea.rs` is NTFS EA persistence and is unrelated.

An implementation would be a small dependency-free module: a `#[repr(C)]` struct mirroring the ntddk.h layout with explicit padding to the cited offsets, a `const SHARED_USER_DATA: *const KUSER_SHARED_DATA = 0x7FFE0000 as _;`, and `core::ptr::read_volatile` for all timing fields. Helper functions would expose `os_version()`, `nt_system_root()`, `tick_count()`, `interrupt_time()`, and `kd_debugger_enabled()`, with the KSYSTEM_TIME tear-check loop around 64-bit time reads. Because the module emits no imports, it adds no IAT entries and no call targets. Natural integration points are `client_rust/src/sysinfo_collect.rs` (the T-023 HELLO-message sysinfo path, replacing the API calls) and the anti-analysis modules documented in T-020, where the page supplies timing and debugger-state inputs.

## Why It Matters

Every alternative enumeration path — Win32 API, NT API, WMI, registry query — traverses code that EDRs instrument; this technique traverses none, which is the gap T-023's API-based System Info Collection leaves open. It also fills a structural gap in the vault: T-004 covers fixed-structure reads for loader data (modules, exports), while KUSER_SHARED_DATA is a fixed-structure read for kernel-published runtime state, a distinct and reusable primitive per the member notes. One 4KB page supplies inputs to recon (version, system root, architecture), anti-analysis (tick deltas, KdDebuggerEnabled, SafeBootMode), and payload gating, with zero additional hook surface per consumer.

## Detection Considerations

- **Telemetry sources**: The training material characterizes the primitive as bypassing userland hooks and syscall monitoring entirely; no ETW provider, Sysmon event ID, or kernel callback is documented as observing it. Consistent with that characterization, a plain memory load generates no ETW event (no provider GUID applies; none is documented in the material), no Sysmon event, and no object/process/thread callback invocation, because those mechanisms observe API calls, object operations, and ring transitions rather than data reads.
- **Bypass options**: The technique is itself the bypass. The operator substitutes direct reads for the four documented APIs in the recon material (GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo) and for the GetVersionEx/GetTickCount call family. No additional hardening is described in the material.
- **Residual artifacts**: The material describes no residual artifacts. The read opens no handles, touches no files or registry keys, and produces no network traffic. Static detection of the embedded 0x7FFE0000 immediate in a binary is not discussed in the material.

## Related Techniques

- **T-023 Client Capabilities Suite** — The System Info Collection module gathers host data through API calls for the HELLO message; this primitive is the zero-API substitute for its OS, architecture, and system-root fields.
- **T-016 EDR Evasion Suite** — T-016 removes visibility from hooked API paths (NTDLL unhooking, KiUserException StepOver, stack spoofing); T-027 removes the path itself for enumeration, so no unhooking or step-over is ever required.
- **T-020 Anti-Analysis Suite** — T-020's anti-VM and timing checks consume system APIs; KdDebuggerEnabled (0x2D4), InterruptTime/TickCount, and SafeBootMode from the page provide equivalent check inputs without API calls that sandboxes instrument.
- **T-004 PEB Walker** — The vault's other fixed-structure, import-free enumeration primitive; T-004 walks loader structures for modules and exports while T-027 reads kernel-published runtime state, which the member notes frame as a distinct info source.

## References

- Atlas material: atlas-binary-analysis-part2.md (units 21–23 for the KUSER_SHARED_DATA slides; units 16–20 for the GetVersionEx/GetNativeSystemInfo API family it replaces), atlas-recon-part3.md (units 15–16, OS Info bootcamp: GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo, BONUS: KUSER_SHARED_DATA)
- MITRE ATT&CK: T1082 System Information Discovery — https://attack.mitre.org/techniques/T1082/
- LGTM notes: lgtm:kuser-shared-data-info-source, lgtm:kuser-shared-data-sysinfo-primitive
- Public references: Microsoft WDK ntddk.h `KUSER_SHARED_DATA` structure definition; Windows Internals, 7th edition (shared data page coverage). The atlas material names no tool authors or blogs for this primitive.

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.