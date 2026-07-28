---
id: T-117
name: Windows Privilege Escalation Primitives Admin to SYSTEM
category: privesc
tier: A
crate: none
source_file: none
mitre: T1134
tags: [privesc, admin-to-system, se-debug, se-load-driver, se-take-ownership, se-create-token, token-manipulation, privilege-abuse]
origin: atlas-synthesis
member_notes: [lgtm:cross-source-convergence-admin-to-system-privilege-set, lgtm:coverage-gap-windows-privesc-primitives]
---

# Windows Privilege Escalation Primitives (Admin to SYSTEM) — Canonical Five-Privilege Escalation Set

## Summary

Windows privilege escalation from local administrator to SYSTEM leverages five canonical privilege primitives documented across SEC670, MalDev Academy, and CRTO. Each privilege — SeTakeOwnership, SeTcb, SeCreateToken, SeLoadDriver, and SeDebug — provides a distinct escalation path from administrator to SYSTEM or kernel context. The prerequisite for several paths is programmatic enablement of these privileges via the standard token adjustment API sequence (LookupPrivilegeValue, OpenProcessToken, AdjustTokenPrivileges). The primary detection surface is process handle acquisition on SYSTEM processes (OpenProcess with PROCESS_ALL_ACCESS) and token duplication operations (DuplicateTokenEx).

## Mechanism

1. Enable the target privilege programmatically. Call `OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)` to obtain the current process token. Call `LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)` to resolve the LUID for the privilege. Construct a `TOKEN_PRIVILEGES` structure with `PrivilegeCount=1`, `Luid=luid`, `Attributes=SE_PRIVILEGE_ENABLED`. Call `AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL)` to enable it. This sequence works for SeDebug, SeTakeOwnership, SeLoadDriver, and other privileges present in the admin token.

2. SeDebugPrivilege path: Call `OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)` on a SYSTEM process (`winlogon.exe`, `lsass.exe`, or a SYSTEM-service-hosted process). With SeDebug enabled, the access check succeeds regardless of the caller's integrity relative to the target. Call `OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hSystemToken)`. Call `DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)`. Call `CreateProcessWithTokenW(hDupToken, 0, NULL, cmdline, ..., &si, &pi)` to spawn a process at SYSTEM integrity.

3. SeTakeOwnershipPrivilege path: Identify a SYSTEM-owned service binary or service configuration path. Call `SetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &admin_sid, NULL, NULL, NULL)` to take ownership of the target file or registry key. Then write a DACL granting full control, replace the binary with a payload, and restart the service via SCM (`StartService` or `ControlService` with `SERVICE_CONTROL_CONTINUE`). The service starts the payload as SYSTEM.

4. SeTcbPrivilege path: Open a SYSTEM process via `ZwOpenProcess`. Call `NtCreateThreadEx(threadHandle, ..., hSystemProcess, startRoutine, arg, ...)` to create a thread inside the SYSTEM process address space. The thread executes the payload code in the context of the SYSTEM process. SeTcb grants the ability to operate on any process's address space — historically named for "Terminal Server Base" but functionally representing trusted computing base privileges.

5. SeCreateTokenPrivilege path: Call `NtCreateToken(...)` with a `TOKEN_USER` structure specifying the SYSTEM SID (`S-1-5-18`) in the `User` field. This produces a primary token that claims SYSTEM identity. Use `CreateProcessWithTokenW` or `ImpersonateLoggedOnUser` with the fabricated token. This is the most direct path — no target process handle is required.

6. SeLoadDriverPrivilege path: Write the driver's image path to `HKLM\SYSTEM\CurrentControlSet\Services\<name>\ImagePath` (REG_EXPAND_SZ). Call `NtLoadDriver` to load the driver. The driver runs in kernel context and can call `PsSetCreateProcessNotifyRoutineEx` to register process creation callbacks, or directly manipulate `EPROCESS` structures for token theft. This is the BYOVD (Bring Your Own Vulnerable Driver) escalation path.

## OS Internals Context

Windows privileges are stored in the token's `PRIVILEGE_SET` structure, which is an array of `LUID_AND_ATTRIBUTES` entries. The LUID (Locally Unique Identifier) maps to a specific privilege, and the `Attributes` field contains `SE_PRIVILEGE_ENABLED` (0x2) or `SE_PRIVILEGE_DISABLED` (0x0). The kernel's `SeAccessCheck` function consults these during access validation.

SeDebugPrivilege bypasses the standard security descriptor check: when the caller's token has SeDebug enabled, `SeAccessCheck` grants `PROCESS_ALL_ACCESS` regardless of the DACL on the target process. This is implemented in `SepAccessCheck` via a special case for `SeDebugPrivilege`. The privilege is present in administrator tokens by default but disabled — `AdjustTokenPrivileges` must enable it before use.

SeTakeOwnershipPrivilege grants `WRITE_OWNER` access to any securable object, bypassing the DACL. `SetSecurityInfo` with `OWNER_SECURITY_INFORMATION` changes the owner SID in the object's security descriptor. Once owner, the caller can write a new DACL granting full control.

SeCreateTokenPrivilege grants the broadest capability set of any Windows privilege. `NtCreateToken` is an undocumented NT API (not in ntdll.dll export table) that constructs a token object from caller-supplied data. The `TOKEN_USER` structure's `User.Sid` field specifies the identity the token claims. By supplying the SYSTEM SID (`S-1-5-18`), the resulting token authenticates as SYSTEM. The kernel does not validate that the caller is actually SYSTEM — it trusts the `SeCreateTokenPrivilege` as sufficient authorization for token creation.

SeTcbPrivilege is present only in SYSTEM tokens. It grants the ability to create threads in other processes (`NtCreateThreadEx`), attach to other process address spaces (`NtMapViewOfSection` cross-process), and perform other operations requiring the trusted computing base attribute. On modern Windows, SeTcb is only present in SYSTEM tokens, making it available only after escalation to SYSTEM via another path — it functions more as a SYSTEM-to-SYSTEM persistence mechanism than an admin-to-SYSTEM escalation primitive.

The standard privilege adjustment sequence (`LookupPrivilegeValue` → `OpenProcessToken` → `AdjustTokenPrivileges`) operates entirely in user mode. `AdjustTokenPrivileges` calls `NtAdjustPrivilegesToken`, which updates the token's privilege flags in kernel space. The change is per-token and persists until the token is closed or the privileges are adjusted again.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the privilege escalation primitives as foundational knowledge. The HUGIN source tree contains related implementations: BYOVD (`dark_crystal/crowd/src/byovd.rs`, `dark_crystal/crates/core/src/experimental/evasion/byovd/`) for the SeLoadDriver path, and process injection techniques (`dark_crystal/crowd/src/early_bird.rs`, `process_hollow.rs`) that use SeDebug to open SYSTEM processes. An implementation of the SeDebug → `DuplicateTokenEx` → `CreateProcessWithTokenW` chain would use the `windows-sys` or `winapi` crate bindings for `OpenProcess`, `OpenProcessToken`, `DuplicateTokenEx`, and `CreateProcessWithTokenW`, with the privilege adjustment sequence in a helper function.

## Why It Matters

The vault documents LSASS credential harvest (T-023) and BYOVD (T-022) as standalone capabilities, but neither card documents the prerequisite privilege enablement. An operator attempting T-023's LSASS dump via `MiniDumpWriteDump` cannot open the `lsass.exe` handle without first enabling SeDebugPrivilege. T-022's BYOVD path requires SeLoadDriverPrivilege to call `NtLoadDriver`. This card surfaces the five canonical escalation paths as cross-cutting prerequisites that connect the vault's higher-level techniques to the foundational privilege manipulation that makes them operationally viable. The convergence of SEC670, MalDev Academy, and CRTO on the same five-privilege set indicates strong tradecraft consensus that this is the canonical answer to admin-to-SYSTEM escalation.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 4656 (A handle to an object was requested) captures `OpenProcess` calls on SYSTEM processes when object access auditing is enabled. Sysmon Event ID 4608 (Special Privileges) logs when SeDebug, SeTcb, or SeCreateToken are enabled. EDR products monitor `AdjustTokenPrivileges` calls that enable SeDebug or SeTakeOwnership. Kernel callbacks (`ObRegisterCallbacks` for process handle pre-operation) intercept `OpenProcess` on protected processes.
- **Bypass options**: Direct NT API calls (`NtOpenProcess`, `NtOpenProcessToken`, `NtDuplicateToken`, `NtCreateProcessEx`) bypass user-mode hooks on the Win32 API equivalents. Indirect syscalls (T-001 RecycledGate) bypass ntdll hooks on the NT APIs. Token duplication from a process that already holds the SYSTEM token (e.g., a service host) avoids the `OpenProcess` + `OpenProcessToken` sequence.
- **Residual artifacts**: The spawned SYSTEM process appears in the process list with a SYSTEM security context. The parent process is the escalator (`CreateProcessWithTokenW` caller), creating an anomalous parent-child relationship. The privilege adjustment on the caller's token is visible via `NtQueryInformationToken(TokenPrivileges)`. Registry writes for SeLoadDriver path create entries under `HKLM\SYSTEM\CurrentControlSet\Services\`.

## Related Techniques

- **T-013 Remaining Methods** — Documents process hollowing and injection techniques that require SeDebugPrivilege for handle acquisition on SYSTEM processes.
- **T-022 Network Suite** — Contains the BYOVD module that relies on SeLoadDriverPrivilege for driver loading.
- **T-016 EDR Evasion Suite** — Documents argument spoofing and stack spoofing techniques applicable to the privilege adjustment API sequence.
- **T-023 Client Capabilities** — LSASS dump capability requires SeDebugPrivilege enablement as a prerequisite.
- **T-021 Crypto & Obfuscation** — UAC bypass achieves admin-to-High; this card covers the subsequent High-to-SYSTEM escalation.

## References

- Atlas material: atlas-privesc-part1.md, atlas-privesc-part2.md
- MITRE ATT&CK: T1134 (https://attack.mitre.org/techniques/T1134)
- LGTM notes: lgtm:cross-source-convergence-admin-to-system-privilege-set, lgtm:coverage-gap-windows-privesc-primitives
- Public references: SEC670 privilege escalation module, MalDev Academy, CRTO

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. Related implementations exist in the HUGIN source tree (dark_crystal/crowd/src/byovd.rs for SeLoadDriver, dark_crystal/crowd/src/early_bird.rs for SeDebug-based process access).