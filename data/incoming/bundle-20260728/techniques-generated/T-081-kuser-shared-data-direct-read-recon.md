---
id: T-081
name: KUSER_SHARED_DATA Direct Read Recon
category: discovery
tier: A
crate: none
source_file: none
mitre: T1082
mitre_secondary: []
tags: [kuser-shared-data, direct-read, telemetry-evasion, sysinfo, os-fingerprinting, shared-user-data, no-syscall, fixed-address]
origin: atlas-synthesis
member_notes: ['lgtm:kuser-shared-data-recon', 'lgtm:coverage-kuser-shared-data-access']
---

# KUSER_SHARED_DATA Direct Read Recon — Telemetry-Free System Information via Fixed User-Mode Page

## Summary

KUSER_SHARED_DATA is a read-only page mapped at the fixed virtual address 0x7FFE0000 in every user-mode process, containing system time, tick count, OS version, time zone bias, product type, and suite mask fields that the kernel maintains and updates directly. Direct memory reads from this page obtain system information without invoking NtQuerySystemInformation, GetSystemTime, GetVersionEx, or any other documented sysinfo API, generating no syscall, no ETW event, and no userland hook contact. SEC670 presents this as the undocumented alternative path for OS fingerprinting and timestamp retrieval, framing it as critical for evasive reconnaissance. The technique exploits the Windows kernel's design decision to share a read-only data page with user mode for performance — originally intended to allow ntdll.dll's time functions to read system time without the syscall overhead of NtQuerySystemTime. The detection surface is minimal: direct memory reads from a fixed address produce no side effects observable by any standard telemetry channel.

## Mechanism

1. The KUSER_SHARED_DATA structure (also known as SharedUserData or USER_SHARED_DATA) is a single page (4096 bytes) that the memory manager maps into every user-mode process at the fixed virtual address 0x7FFE0000 during process creation. The mapping is established by the memory manager during `MmInitializeProcessAddressSpace` and exposed to user mode via a VAD (Virtual Address Descriptor) entry with PAGE_READONLY protection. The physical page backing this virtual address is a single canonical copy shared across all processes — the kernel maintains the master copy and maps it read-only into each process address space.

2. To read a field, an implant computes the field's address as `0x7FFE0000 + offset` and performs a direct pointer dereference. For example, reading SystemTime at offset 0x14 involves treating address `0x7FFE0014` as a pointer to a `KSYSTEM_TIME` structure and reading the 8-byte LARGE_INTEGER value. No API call, no `syscall` instruction, and no library function invocation occurs. The CPU executes a single MOV instruction.

3. High-value fields and their documented offsets on x64 Windows 10/11:
   - **SystemTime** (offset 0x14, KSYSTEM_TIME containing LARGE_INTEGER) — current system time in FILETIME format (100-nanosecond intervals since January 1, 1601). Updated by the kernel on each clock interrupt. Alternative to GetSystemTimeAsFileTime or NtQuerySystemTime.
   - **TickCount** (offset 0x320, KSYSTEM_TIME) — tick count since boot, derived from the kernel's tick counter. Alternative to GetTickCount or GetTickCount64.
   - **TimeZoneBias** (offset 0x20, KSYSTEM_TIME) — UTC offset in 100-nanosecond intervals. Combined with SystemTime to compute local time without calling GetTimeZoneInformation.
   - **NtMajorVersion** (offset 0x260, ULONG) — major version number (10 for Windows 10/11). Alternative to GetVersionEx or RtlGetVersion.
   - **NtMinorVersion** (offset 0x264, ULONG) — minor version number (0 for Windows 10/11).
   - **ProductType** (ULONG) — VER_NT_WORKSTATION (1), VER_NT_DOMAIN_CONTROLLER (2), or VER_NT_SERVER (3). Alternative to GetVersionEx's wProductType field. Offset varies by Windows version.
   - **SuiteMask** (USHORT) — bitfield indicating installed product suites (VER_SUITE_ENTERPRISE, VER_SUITE_DATACENTER, VER_SUITE_PERSONAL). Offset varies by Windows version.
   - **NumberOfPhysicalPages** (offset 0x60, ULONG) — total physical memory in pages. Alternative to GlobalMemoryStatusEx.
   - **Cookie** (offset 0x330 on x64 Windows 10 builds) — stack cookie value used by /GS compiled code. Reading this field provides the security cookie value, relevant for stack-based exploit development.

4. The read operation is a simple memory access that the CPU executes as a single MOV instruction. The TLB entry for 0x7FFE0000 is populated at process creation and remains valid for the process lifetime, so the access does not fault. The page's PAGE_READONLY protection allows reads but prevents writes from user mode — attempted writes cause STATUS_ACCESS_VIOLATION (0xC0000005), which is the same exception used by the VEH syscall gate (T-003) for other purposes.

5. SEC670 frames the direct-read approach as a BONUS undocumented method that avoids the documented sysinfo syscall path entirely. The technique is useful when EDR products hook NtQuerySystemInformation in ntdll.dll, when the implant's syscall stub has been modified to avoid specific SSNs, or when the operator wants to minimize the syscall surface area to reduce kernel callback exposure.

## OS Internals Context

KUSER_SHARED_DATA has its roots in the Windows NT design philosophy of sharing certain kernel-maintained data with user mode to avoid syscall overhead for frequently accessed values. The structure is defined in ntddk.h as `KUSER_SHARED_DATA` (kernel-side) and is exposed to user mode at the fixed address `MM_SHARED_USER_DATA_VA` (0x7FFE0000 on both x86 and x64). The kernel maintains a separate writable copy at a kernel address and maps the user-mode copy as read-only via a prototype PTE.

The kernel updates KUSER_SHARED_DATA fields at specific intervals:
- **SystemTime** is updated on every clock interrupt (approximately every 15.6ms on standard x64 systems with the periodic timer, or more frequently with dynamic tick / HPET). The update writes the 64-bit value atomically using an interlocked operation, ensuring that user-mode reads of the 8-byte value do not observe a torn update.
- **TickCount** is updated on each clock interrupt by incrementing the tick count fields and adjusting the corresponding KSYSTEM_TIME structure.

The page mapping is established during process creation in `MmInitializeProcessAddressSpace`. The PTE for 0x7FFE0000 is set up as a prototype PTE pointing to the physical page containing the shared data. This means the physical page is shared across all processes with copy-on-write disabled — there is one canonical copy of the data that every process reads. The VAD entry for this region is marked as committed, read-only, and cannot be unmapped or remapped by user-mode code.

The structure layout has evolved across Windows versions. On Windows XP, the structure was 4096 bytes with fewer fields. Windows 7 added fields for extended tick count support and improved timekeeping. Windows 10 added fields related to system call interception and CET (Control-flow Enforcement Technology) shadow stack support. An implant reading specific offsets must account for layout differences across versions, though the offsets for SystemTime (0x14), TimeZoneBias (0x20), NtMajorVersion (0x260), and NtMinorVersion (0x264) have remained stable since Windows NT 4.0 because they are referenced by compiled user-mode binaries that depend on specific offsets.

The PEB structure (used by T-004 PEB Walker) is related but distinct: the PEB contains per-process data (image base, loader data, process parameters) at a process-specific address obtained from the TEB (gs:[0x60] on x64). KUSER_SHARED_DATA is at a fixed address in every process and contains system-wide data. Some PEB fields — OsMajorVersion, OsMinorVersion, OsBuildNumber, NumberOfProcessors — are populated from KUSER_SHARED_DATA during process creation by the kernel's `MmCreatePeb` function. Reading the PEB provides the same version information but through a different access path with different detection characteristics: PEB access requires walking the TEB segment register, while KUSER_SHARED_DATA access is a direct dereference of a known constant address.

The `def.rs` source file in the HUGIN codebase (`dark_crystal/crates/core/src/experimental/evasion/veh/def.rs`) defines a `PEB` structure with `os_major_version`, `os_minor_version`, `os_build_number`, and `number_of_processors` fields. These PEB fields mirror KUSER_SHARED_DATA values but are accessed via the PEB pointer obtained from the TEB, not via direct read from 0x7FFE0000. The file defines PE structures (ImageDosHeader, ImageNtHeaders, ImageExportDirectory) and PEB/LDR structures for the VEH syscall gate module. It does not define a KUSER_SHARED_DATA structure or implement direct reads from the shared page.

## Key Implementation Details

**No current implementation in the HUGIN source.** The `def.rs` file in the VEH module defines PEB and related structures but does not define KUSER_SHARED_DATA or implement direct reads from 0x7FFE0000. The PEB fields for OS version (os_major_version, os_minor_version, os_build_number) provide similar information through a different access path. An implementation would define a `#[repr(C)]` struct matching the KUSER_SHARED_DATA layout with fields at their documented offsets, create a raw pointer to 0x7FFE0000, and perform volatile reads of the required fields. In Rust, this would use `core::ptr::read_volatile` on a pointer constructed as `0x7FFE0000 as *const KUSER_SHARED_DATA`, wrapped in an `unsafe` block. The `read_volatile` is necessary to prevent the compiler from optimizing away the memory access or reordering it relative to other operations. The implementation would provide accessor functions for SystemTime, OS version, tick count, and processor count, returning values without any function call into ntdll.dll or kernel32.dll.

## Why It Matters

KUSER_SHARED_DATA direct reads represent a class of reconnaissance primitive that is structurally invisible to conventional detection mechanisms. The page exists in every process, is mapped by the kernel during process creation, and reading it is a normal memory access that produces no side effects. No documented Windows telemetry channel — ETW providers, kernel callbacks (ObRegisterCallbacks, PsSetCreateProcessNotifyRoutine), userland hooks on ntdll.dll, or Sysmon — captures direct memory reads from this address. The technique fills a gap in the vault's recon coverage by documenting a primitive that bypasses the entire API-layer detection stack, including both documented syscalls and their Win32 wrappers. For implants that need OS version information for conditional technique selection or system time for beacon interval timing, KUSER_SHARED_DATA provides these values with zero syscall surface.

## Detection Considerations

- **Telemetry sources**: No standard telemetry channel captures direct memory reads from 0x7FFE0000. ETW providers do not instrument memory reads at the page level. Sysmon does not monitor memory access patterns. Kernel callbacks do not fire on memory reads. The page is PAGE_READONLY and mapped by the kernel, so access violations do not occur on valid reads within the page.
- **Bypass options**: The technique is inherently a bypass — it avoids all API-layer telemetry by design. An EDR could theoretically implement a page-guard trap on the 0x7FFE0000 page to detect access via STATUS_GUARD_PAGE exceptions, but this would break legitimate code: ntdll.dll's own time functions (NtQuerySystemTime, GetSystemTimeAsFileTime) read this page directly, and the kernel's clock interrupt handler does not coordinate with page-guard traps. Memory scanning could detect code patterns that compute the constant 0x7FFE0000, but this produces false positives on any binary that legitimately reads system time through the shared page.
- **Residual artifacts**: No files, registry keys, handles, or network connections are produced. The only artifact is the MOV instruction in the implant's code section referencing the address 0x7FFE0000, which is indistinguishable from any other memory read without instruction-level tracing or code analysis.

## Related Techniques

- **T-004 PEB Walker** — uses the same family of fixed user-mode structures (TEB/PEB) accessed via segment registers; KUSER_SHARED_DATA extends the pattern to system-wide data at a fixed virtual address known at compile time
- **T-027 KUSER_SHARED_DATA Direct-Read System Information** — existing vault card covering the same primitive; this card adds the offset table, OS internals context, and SEC670's deeper tradecraft framing
- **T-023 Client Capabilities** — reconnaissance module; KUSER_SHARED_DATA reads are a primitive within the broader recon surface catalog
- **T-016 EDR Evasion Suite** — KUSER_SHARED_DATA bypasses userland hooks on sysinfo APIs, complementing the hook-bypass techniques in the evasion suite

## References

- Atlas material: atlas-recon-part1.md, atlas-recon-part4.md
- MITRE ATT&CK: T1082 — https://attack.mitre.org/techniques/T1082/
- LGTM notes: lgtm:kuser-shared-data-recon, lgtm:coverage-kuser-shared-data-access

## Source Reference

No current implementation. The `def.rs` file in the VEH module (`dark_crystal/crates/core/src/experimental/evasion/veh/def.rs`) defines PEB structures with version fields but does not define or read KUSER_SHARED_DATA. See atlas material and Windows Internals 7ed for the structure layout.