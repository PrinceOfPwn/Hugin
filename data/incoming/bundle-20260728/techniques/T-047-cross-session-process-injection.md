---
id: T-047
name: Cross-Session Process Injection via WTS Enumeration
category: process-injection
tier: A
crate: none
source_file: none
mitre: T1055
tags: [cross-session, wts-enumeration, terminal-services, session-targeting, process-injection, session-0, token-access, target-selection]
origin: atlas-synthesis
member_notes: ['lgtm:cross-session-injection-primitive', 'lgtm:cross-session-injection-as-distinct-primitive', 'lgtm:cross-session-injection-variant']
---

# Cross-Session Process Injection via WTS Enumeration — Session-Aware Target Selection Across Logon Sessions

## Summary

Cross-session process injection selects an injection target that runs in a different Terminal Services (WTS) session than the calling process, using session-aware process enumeration to locate it. The technique is built on `WTSEnumerateProcessesExW`, exported by `wtsapi32.dll`, which returns the session ID alongside every process on the system and thereby exposes targets that session-blind enumeration (Toolhelp32, EnumProcesses) does not distinguish: session-0 services, and processes owned by other logged-on users. The injection stage itself reuses the standard primitives catalogued in T-007 and T-013 — what this technique contributes is the targeting stage, which expands the set of reachable processes from a single foothold. The operative constraint is access control rather than the session boundary: opening a process owned by another account requires the target's DACL to permit it or SeDebugPrivilege enabled on the caller's token. The primary detection surface is the cross-session `OpenProcess`/`NtOpenProcess` handle acquisition and whatever injection primitive follows.

## Mechanism

1. Establish the caller's own session baseline by resolving the current session ID — either `GetTokenInformation` with `TokenSessionId` on the process token, or `ProcessIdToSessionId` on `GetCurrentProcessId`.
2. Optionally enumerate logon sessions with `WTSEnumerateSessionsExW` and resolve each session to a user via `WTSQuerySessionInformationW` (`WTSUserName`), so targets can later be selected by owning account rather than by name alone.
3. Call `WTSEnumerateProcessesExW` with `hServer` set to `WTS_CURRENT_SERVER_HANDLE` (or a handle from `WTSOpenServer` for a remote host), `pLevel` set to 1, and `SessionId` set to `WTS_ANY_SESSION`. Level 1 returns an array of `WTS_PROCESS_INFO_EX` structures; the API also returns the process count directly, which the SEC670 material contrasts with EnumProcesses, where the count must be derived from bytes returned.
4. Iterate the returned array. Each entry carries `SessionId`, `ProcessId`, `pProcessName`, `pUserSid`, thread and handle counts, working-set and pagefile figures, and user/kernel CPU times. Filter on `SessionId != caller session`, then match `pProcessName` or `pUserSid` against the desired target — for example a service process in session 0, or a specific user's process in another interactive session.
5. Confirm architecture compatibility between injector and target before opening a handle. The CRTO material's injection OPSEC guidance warns against cross-platform injection and shows target-selection output carrying Arch and User columns for exactly this check.
6. Enable `SeDebugPrivilege` (`SE_DEBUG_NAME`) on the current token via `AdjustTokenPrivileges` when the target is owned by a different account or by SYSTEM. One member note additionally cites SeChangeNotifyPrivilege in the context of session-boundary traversal.
7. Open the target with `NtOpenProcess`/`OpenProcess`, requesting the minimum access mask the chosen injection primitive requires. The SEC670 handle material warns against `PROCESS_ALL_ACCESS`, since over-privileged and leaked handles are observable.
8. Execute the injection primitive (T-007 or any T-013 method). The chain shown in the SEC670 handle unit is the classic `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` sequence, but any vault injection method applies once a suitable handle exists; the session of the target does not change the mechanics of the primitive.
9. Release the enumeration buffer with `WTSFreeMemoryExW` and close all acquired process handles to avoid the handle-leak condition the material describes.

## OS Internals Context

Since Windows Vista, Windows isolates services in session 0 and assigns interactive logons to sessions 1 and higher. Each session gets its own `csrss.exe` instance, its own win32k subsystem instance, and its own set of window stations and desktops. The kernel tracks per-session memory state in `_MM_SESSION_SPACE`, referenced from the `Session` field of `EPROCESS`, and each access token records a session ID retrievable through `GetTokenInformation(TokenSessionId)`. `WTSEnumerateProcessesExW` surfaces exactly this per-process session attribution into user mode.

The session boundary is primarily a windowing and object-namespace boundary, not an address-space or handle-table boundary. Process injection operates on process objects through the kernel's Object Manager and Process Manager, so the gate that matters for cross-session operation is the standard access check performed at `NtOpenProcess`: the caller's token is evaluated against the target process's security descriptor, and if the token holds SeDebugPrivilege in an enabled state, the kernel grants the requested process access regardless of that DACL — the documented behavior of the "Debug programs" user right. This is why the member notes state that token and handle requirements for cross-session operation differ from in-session injection: an in-session same-user target typically opens with default DACL grants, whereas a session-0 service or another user's interactive process generally forces the privilege path. Session-0 targets additionally concentrate the highest-value processes on the host (services, security products, credential-bearing processes), which is the operational reason to traverse the boundary at all.

The WTS API itself is documented Win32: `WTSEnumerateProcessesExW` takes `pLevel` (1 for `WTS_PROCESS_INFO_EX`, 0 for the legacy `WTS_PROCESS_INFOW`), a `SessionId` filter (`WTS_ANY_SESSION` for all sessions), and out-parameters for the structure array and count. The SEC670 material demonstrates it as a purely local query and notes the returned count simplifies iteration. The same course section covers `NtQuerySystemInformation` with the `SystemProcessInformation` class, which returns linked `SYSTEM_PROCESS_INFORMATION` records (`NextEntryOffset`, `NumberOfThreads`, `CreateTime`, `UserTime`, `KernelTime`, `ImageName`, `UniqueProcessId`, `InheritedFromUniqueProcessId`, `Threads[]`). The structure layout documented in the material carries no session field, which is what makes the WTS API the session-aware option: an operator who needs the session attribution either uses WTS or must call `ProcessIdToSessionId` per PID obtained through the native path.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C.

Two matched source files were verified and excluded. `client_rust/src/commands.rs` implements `GET_PROCESS_LIST` through the `sysinfo` crate, returning pid, name, cpu, mem_mb, user, and status — it carries no session ID and makes no WTS calls, so it is session-blind enumeration rather than this technique. `dark_crystal/crowd/src/iat_camo.rs` matched the keyword grep but performs only benign API calls for IAT camouflage; it contains no process enumeration or injection logic.

An implementation would consist of: `extern "system"` bindings to `wtsapi32.dll` for `WTSEnumerateProcessesExW`, `WTSFreeMemoryExW`, `WTSEnumerateSessionsExW`, and `WTSQuerySessionInformationW`; a `#[repr(C)]` definition of `WTS_PROCESS_INFO_EX` matching the documented field order; a caller-supplied predicate applied during iteration (session ID different from own, name or SID match, architecture match); and output of a `(pid, session_id, user_sid)` tuple consumed by the existing crowd injection dispatcher. Buffer ownership follows the WTS contract — the API allocates the array and the caller releases it with `WTSFreeMemoryExW`. Handle acquisition would route through the existing RecycledGate `NtOpenProcess` wrapper rather than Win32 `OpenProcess` to stay consistent with the vault's syscall posture.

## Why It Matters

T-007 and T-013 catalogue how to inject; this card documents where to aim. Without session-aware enumeration, target selection silently defaults to the caller's own session, which on a multi-user host, RDS server, or any machine with active service logons excludes session-0 services and other users' processes — frequently the targets that hold SYSTEM tokens, credential material, or security-product contexts. The three member notes, extracted from three separate atlas batches, each record that SEC670 frames cross-session injection as a distinct operational capability with token and handle requirements that differ from in-session injection, not as a footnote on an existing method. Surfacing it as its own card separates the targeting decision from the mechanism decision, which is how the vault's other injection cards are structured.

## Detection Considerations

Training material does not discuss detection for this technique.

Adjacent material provides operational guidance that bears on observability without constituting detection coverage. The SEC670 handle unit (atlas-post-exploit-part9, unit 24) states that leaked handles are visible through Process Explorer and Sysinternals handle.exe, and cautions developers against requesting `PROCESS_ALL_ACCESS`; both points apply directly to the cross-session `OpenProcess` stage, where the temptation to request maximal rights is strongest because the access check is least predictable. The CRTO process-injection unit (unit 17) warns against cross-platform injection — an injector writing into a target of the other architecture — which produces crashes and obvious artifacts; target selection through the WTS path must therefore record architecture alongside session. No ETW providers, Sysmon event IDs, kernel callbacks, memory-scan heuristics, or residual artifacts specific to this technique are documented in the material.

## Related Techniques

- **T-007 Pool Party** — Pool Party is one of the injection mechanisms a cross-session-selected PID feeds into; this card supplies the target, T-007 supplies the execution.
- **T-013 Additional Injection Methods** — the primitive catalogue executed after target selection; the `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` chain the SEC670 material pairs with handle acquisition corresponds to this card set.
- **T-015 PPID Spoofing** — both techniques acquire handles across a security boundary using NT APIs (parent handle for PPID spoofing, target handle for cross-session injection), and the member notes tie cross-session operation to the differing token and handle requirements that also underlie PPID spoofing's `NtOpenProcess` on the spoofed parent.
- **T-023 Client Capabilities** — the client's existing `GET_PROCESS_LIST` is the non-session-aware enumeration this technique would extend into a targeting-capable process survey.

## References

- Atlas material: atlas-binary-analysis-part2.md (units 30-31), atlas-exploit-dev-part7.md (unit 36), atlas-post-exploit-part9.md (unit 35; adjacent units 17, 24, 34)
- MITRE ATT&CK: T1055 — Process Injection: https://attack.mitre.org/techniques/T1055/
- LGTM notes: lgtm:cross-session-injection-primitive, lgtm:cross-session-injection-as-distinct-primitive, lgtm:cross-session-injection-variant
- Public references: SANS SEC670, "Red Teaming Tools: Developing Custom Tools for Windows" (source named in the atlas material); CRTO Book (source named in the atlas material)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.