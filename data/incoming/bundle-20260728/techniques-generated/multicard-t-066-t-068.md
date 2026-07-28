<!-- BEGIN CARD T-066 -->
---
id: T-066
name: Winsock Reverse Shell via Handle Redirection
category: networking
tier: B
crate: none
source_file: none
mitre: T1059.003
mitre_secondary: [T1095]
tags: [reverse-shell, winsock, wsastartup, startupinfo, std-handle-redirection, createprocess, initial-access, interactive-shell]
origin: atlas-synthesis
member_notes: [lgtm:winsock-reverse-shell-primitive]
---

# Winsock Reverse Shell via Handle Redirection — Socket-Bound cmd.exe Spawn

## Summary

A Winsock reverse shell binds the standard input, output, and error handles of a newly spawned command interpreter to a connected TCP socket, producing a fully interactive text session over a raw network stream. The technique initializes the Winsock 2.2 stack with `WSAStartup(MAKEWORD(2,2))`, opens a stream socket to an operator-controlled listener, then populates `STARTUPINFOA` with `hStdInput`, `hStdOutput`, and `hStdError` all set to the socket handle and `dwFlags` set to `STARTF_USESTDHANDLES` before calling `CreateProcessA` with `bInheritHandles = TRUE`. Operators use it as a minimal initial-access foothold: a few dozen lines of code yield an interactive `cmd.exe` session capable of staging heavier tooling. The primary detection surface is the correlation of process creation telemetry (a `cmd.exe` child inheriting handles from a network-connected parent) against outbound connection telemetry, plus the presence of socket objects in the child's standard handle table.

## Mechanism

1. `WSAStartup(MAKEWORD(2,2), &wsaData)` negotiates Winsock version 2.2, loads `ws2_32.dll` into the stager process, and populates a `WSADATA` structure describing the negotiated implementation. Return code is validated before continuing.
2. `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)` (or `WSASocketA` with equivalent parameters) creates a stream socket. On Windows the returned `SOCKET` is a kernel handle backed by the Ancillary Function Driver and is inheritable by default.
3. A `sockaddr_in` structure is populated: `sin_family = AF_INET`, `sin_port = htons(port)`, `sin_addr.s_addr = inet_addr(ip)` of the operator listener.
4. `connect()` performs the TCP three-way handshake to the listener (ncat, Metasploit `multi/handler`, or an equivalent operator endpoint).
5. `STARTUPINFOA` is zeroed, then configured: `si.cb = sizeof(STARTUPINFOA)`, `si.dwFlags = STARTF_USESTDHANDLES`, and `si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock`. All three standard handles point at the single connected socket.
6. `CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)` spawns the interpreter. `bInheritHandles = TRUE` is mandatory; without it the child receives default console handles and the redirection silently fails.
7. The child `cmd.exe` starts with its standard handle table entries referencing the socket. It detects that the handles are not console handles and falls back to `ReadFile`/`WriteFile`-driven I/O rather than console APIs.
8. A bidirectional stream is established: bytes typed at the listener arrive on the child's stdin via AFD-dispatched reads, and the child's stdout/stderr writes stream back over the same socket.
9. The stager either waits on `pi.hProcess` or exits. The TCP endpoint object persists while any process holds a handle reference, so the session survives stager termination through the inherited handle inside `cmd.exe`.

## OS Internals Context

Standard handle propagation is the mechanism that makes the technique function. When `STARTF_USESTDHANDLES` is set, `CreateProcess` copies the three handle values from `STARTUPINFOA` into the new process's `RTL_USER_PROCESS_PARAMETERS` block (`StandardInput`, `StandardOutput`, `StandardError` fields), which hangs off the PEB. `GetStdHandle(STD_INPUT_HANDLE)` in the child returns whatever value was placed there — there is no kernel-enforced requirement that these be console handles.

Handle inheritance requires two conditions simultaneously: the parent must pass `bInheritHandles = TRUE`, and the specific handle must carry `HANDLE_FLAG_INHERIT`. Sockets returned by `socket()` and by `WSASocket` without `WSA_FLAG_NO_HANDLE_INHERIT` are inheritable, which is why no `DuplicateHandle` or `SetHandleInformation` call is needed in the canonical pattern.

The reason a socket can serve as a standard handle at all is the Windows socket architecture. Unlike POSIX, where sockets are first-class file descriptors for every syscall, Windows sockets are HANDLEs referencing file objects created by the Ancillary Function Driver (`\Device\Afd`, `afd.sys`). `ReadFile` and `WriteFile` on a socket handle dispatch IRPs to AFD, which translates them into transport operations over TCP. This ReadFile/WriteFile overlap is sufficient for redirected shell I/O. Console-specific APIs such as `WriteConsoleA` fail on non-console handles, so `cmd.exe` probes its handles and selects the file-API code path — the same path used when output is piped to a file.

Endpoint ownership has operational consequences. The TCP endpoint is attributed (via `GetExtendedTcpTable`) to the PID that created the socket — the stager. The endpoint object itself persists while any handle references it, so the connection outlives the stager if `cmd.exe` holds the inherited copy. Handle enumeration with `NtQuerySystemInformation(SystemHandleInformation)` shows `\Device\Afd` handles in both processes for the duration.

The channel is plaintext TCP. Every keystroke and every output buffer is visible to network inspection, which is why this pattern appears in exploit-development material as a teaching scaffold and a short-lived foothold rather than a long-term channel.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would be a small `client_rust` module using `windows-sys::Win32::Networking::WinSock` (`WSAStartup`, `socket`, `connect`, `htons`, `inet_addr`) and `windows-sys::Win32::System::Threading` (`STARTUPINFOA`, `CreateProcessA`, `STARTF_USESTDHANDLES`). It could reuse the existing `tcp_transport.rs` connection establishment (T-022) but diverges at the final step: instead of framing protocol messages over the socket, it casts the socket to a `HANDLE`, populates `STARTUPINFOA`, and spawns the interpreter. The module would sit as a minimal fallback channel beneath the full client feature set documented in T-023.

## Why It Matters

The vault documents a full TCP transport, a hidden VNC desktop, and a 40-message binary protocol, but lacks the minimal primitive those capabilities replace. The handle-redirected reverse shell is the canonical first foothold in the exploit-development material: it compiles to a tiny stager, requires no protocol design, and delivers interactivity sufficient to stage the full client. Documenting it establishes the reference baseline against which T-022 and T-023 are the engineered successors, and gives operators a fallback when only a small payload fits the initial-access vector.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 1 (process creation) captures `cmd.exe` spawning with its parent and command line; Sysmon Event ID 3 (network connection) captures the stager's outbound TCP connection; correlating the two by timestamp and host is the standard analytic. ETW providers `Microsoft-Windows-Kernel-Process` and `Microsoft-Windows-Kernel-Network`/TCPIP expose the same events. Handle-table inspection reveals `\Device\Afd` objects held by a `cmd.exe` process, and an interactive `cmd.exe` running without an associated `conhost.exe` console is anomalous on desktop sessions.
- **Bypass options**: wrapping the stream in TLS removes plaintext visibility; substituting a less-signatured interpreter for `cmd.exe` weakens command-line analytics; spoofing the parent (T-015) or spawning the shell from a long-lived, normally-networked process breaks the parent-connection correlation; exiting the stager immediately after spawn removes the attributed socket owner from the TCP table.
- **Residual artifacts**: none on disk if the stager runs in-memory; `ws2_32.dll` loaded into a process whose IAT would not normally import Winsock is a static and memory-scan heuristic; Prefetch and Amcache record the stager binary if executed from disk.

The atlas material for this technique does not discuss detection; the sources above reflect standard Windows and Sysmon telemetry.

## Related Techniques

- **T-022 Network Suite** — provides the engineered TCP transport and protocol layer that supersedes this raw-stream primitive; connection-establishment code is shared.
- **T-023 Client Capabilities** — the full client feature set (screen capture, recon, exfiltration) that a reverse-shell foothold is typically used to stage.

## References

- Atlas material: atlas-exploit-dev-part1.md (units 14, 15)
- MITRE ATT&CK: [T1059.003 — Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- LGTM notes: lgtm:winsock-reverse-shell-primitive

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.

<!-- END CARD T-066 -->

<!-- BEGIN CARD T-067 -->
---
id: T-067
name: AppCert DLL Injection Persistence
category: persistence
tier: B
crate: none
source_file: none
mitre: T1546.009
tags: [persistence, appcertdlls, registry-persistence, dll-injection, csrss, session-manager, host-activity-triggered, createprocess-hook]
origin: atlas-synthesis
member_notes: [lgtm:appcert-dll-persistence]
---

# AppCert DLL Injection Persistence — csrss-Mediated DLL Loading at Process Creation

## Summary

AppCertDlls is a Session Manager registry mechanism that forces a designated DLL into the address space of every process created through the Win32 process-creation APIs. An operator writes a `REG_SZ` value naming an arbitrary value and pointing at a DLL path under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`; thereafter the Client/Server Runtime Subsystem (`csrss.exe`) maps that DLL into each new process during its subsystem registration handshake. Unlike scheduled-task or boot-time persistence, the trigger is host activity: any user, service, or installer calling `CreateProcess`, `CreateProcessAsUser`, `CreateProcessWithLogonW`, `CreateProcessWithTokenW`, or `WinExec` loads the operator's code. Installation requires administrative rights and, per the training material, a reboot for reliable activation. The detection surface is a cataloged autostart registry location plus a single non-Microsoft DLL image loading into an abnormally large population of processes.

## Mechanism

1. With administrative privileges, the operator opens or creates the key `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls` via `RegCreateKeyExW`.
2. `RegSetValueExW` writes a value whose name is arbitrary (for example, a plausible certificate-related name) with type `REG_SZ` and data set to the absolute path of the payload DLL on disk.
3. The system is rebooted. Per the training material this is required for reliable installation: `csrss.exe` reads the AppCertDlls list during subsystem initialization, so additions to a running system are not honored until restart.
4. On each subsequent process creation through the Win32 APIs, the newly created process connects to the Win32 subsystem server during early initialization. The BaseSrv component of `csrss.exe` processes the new-process registration and maps each DLL listed under AppCertDlls into the new process's address space.
5. The DLL must export a function named `CreateProcessNotify`. `csrss` invokes this export with the new process's image information and a reason code during the creation handshake. The export's return value can veto the process creation — the mechanism's legitimate purpose is enterprise application certification, where uncertified binaries are blocked from launching.
6. Operator code executes either in `DllMain` on `DLL_PROCESS_ATTACH` or inside `CreateProcessNotify`, running in the context, token, and integrity level of whatever process triggered the load.
7. Because the load recurs for every created process, the payload gates re-entry — a named mutex, process-name allowlist, or parent-chain check — to avoid uncontrolled propagation into hundreds of short-lived processes.

## OS Internals Context

The AppCertDlls key lives under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`, the same branch that holds `BootExecute`, `KnownDLLs`, and `PendingFileRenameOperations`. Keys in this branch are consumed by `smss.exe` and `csrss.exe` during boot and subsystem startup, which is why a reboot is the reliable activation path: the list is not reparsed on each process creation from a live registry read.

The loading path runs through subsystem registration. On modern Windows, `CreateProcessW` resolves to `NtCreateUserProcess` in `ntdll.dll`, which performs the kernel-side process object creation. The new process must still register with the Win32 subsystem: it connects to the `csrss` SbApiPort (an ALPC port) and the BaseSrv server-side component completes the client initialization. AppCert DLL mapping occurs inside this handshake, before the new process's entry point executes. The timing is significant — the payload runs during the same initialization window as other subsystem setup, ahead of any user code in the target.

The `CreateProcessNotify` export contract is the distinguishing feature. `csrss` requires this named export and invokes it during creation; the return value gates whether creation proceeds. This gives the mechanism a dual nature: a persistence vector (code executes in every new process) and a process-creation gatekeeper (the DLL can abort launches it disapproves of). Operators abusing it for persistence return success unconditionally to avoid breaking host behavior.

Contrast with AppInit_DLLs (T-038) clarifies the loader paths. AppInit DLLs load from `user32.dll` initialization (gated by the `LoadAppInit_DLLs` value), so only processes that load `user32.dll` receive them — console services and non-GUI processes are excluded. AppCert DLLs load via `csrss` for every process created through the Win32 creation APIs regardless of which subsystem DLLs the process imports. Both are HKLM registry-driven mass-injection mechanisms; they differ in the consuming component and coverage profile.

Coverage has defined edges. Processes created without Win32 subsystem registration — minimal processes, Pico processes, or direct `NtCreateUserProcess` invocations that skip the `csrss` handshake — bypass the mechanism. Architecture mismatch also excludes targets: a 64-bit DLL cannot map into a 32-bit Wow64 process, so mixed-environment coverage requires shipping both DLL architectures or accepting partial propagation. Because `csrss` runs as SYSTEM and maps the DLL into processes at every integrity level, the payload executes inside low-integrity sandboxes and SYSTEM services alike.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would add a `persist/appcert.rs` module alongside the existing `persist/com_hijack.rs`, `persist/schtask.rs`, and sibling layers. The registry write path can reuse the `winapi::um::winreg` call pattern already present in the codebase — `edo_tensei.rs` performs `RegCreateKeyExW`/`RegSetValueExW` against HKCU for soul storage, and the AppCert variant differs only in hive (HKLM), key path, and value payload. The companion DLL requires a `CreateProcessNotify` export and a re-entry gate; its on-disk placement inherits the same operational considerations as any persistence binary (signature, path plausibility, timestamp hygiene).

## Why It Matters

The five layers in T-017 trigger on boot, logon, schedule, or binary execution of a specific target; AppCertDlls triggers on ambient host activity — any process creation by any principal. That trigger profile complements rather than duplicates the existing stack: a host that reboots rarely but spawns processes constantly exercises this layer continuously. It is also one registry write away from the process-veto gatekeeper behavior, a capability no other vault persistence layer offers. The mechanism earns its own card because its loader path (`csrss` subsystem registration) and export contract are distinct from every documented layer.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 13 (registry value set) captures writes under the AppCertDlls path, which is a monitored autostart location in standard Sysmon configurations and in Autoruns. Sysmon Event ID 7 (image loaded) exposes the behavioral signature: the same non-Microsoft DLL loading into dozens of unrelated processes is a strong correlation analytic.
- **Bypass options**: naming the value and DLL to blend with legitimate certificate software reduces triage priority; code-signing the DLL lowers image-load heuristic scores; gating propagation to a narrow process allowlist shrinks the image-load fan-out that correlation rules detect.
- **Residual artifacts**: the registry value, the on-disk DLL, and Prefetch/Amcache entries recording the DLL's load across many host processes. The reboot requirement creates a detection window between installation and activation.

The atlas material for this technique does not discuss detection; the sources above reflect standard Windows and Sysmon telemetry.

## Related Techniques

- **T-017 Five-Layer Persistence** — AppCertDlls functions as a sixth, host-activity-triggered layer alongside COM hijack, NTFS EA, scheduled task, TLS callback, and PhantomPersist.
- **T-038 AppInit_DLLs Registry Persistence** — the parallel registry-driven mass DLL injection mechanism; differs in loader path (`user32.dll` initialization versus `csrss` subsystem registration) and process coverage.

## References

- Atlas material: atlas-edr-evasion-part2.md (unit 2)
- MITRE ATT&CK: [T1546.009 — Event Triggered Execution: AppCert DLLs](https://attack.mitre.org/techniques/T1546/009/)
- LGTM notes: lgtm:appcert-dll-persistence

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.

<!-- END CARD T-067 -->

<!-- BEGIN CARD T-068 -->
---
id: T-068
name: SDDL/ACL Hardening for Persistence Resilience
category: persistence
tier: B
crate: none
source_file: none
mitre: T1222.001
mitre_secondary: [T1543.003]
tags: [sddl, acl-hardening, security-descriptor, dacl, deny-ace, persistence-resilience, anti-remediation, setnamedsecurityinfo]
origin: atlas-synthesis
member_notes: [lgtm:sddl-acl-manipulation-proposed, lgtm:security-descriptor-acl-hardening]
---

# SDDL/ACL Hardening for Persistence Resilience — Deny ACEs Against Remediation

## Summary

SDDL/ACL hardening modifies the discretionary access control lists on objects that host persistence — services, registry keys, NTFS files — so that defender accounts cannot stop, delete, or reconfigure them. The operator retrieves the object's current security descriptor with `GetNamedSecurityInfoA`, composes a replacement DACL containing deny ACEs built from `EXPLICIT_ACCESS_A` structures, and writes it back with `SetNamedSecurityInfoA`. The result is a persistence entry whose removal demands ownership takeover and DACL rewriting rather than a simple `sc stop` / `sc delete` or `RegDeleteKey`. The technique hardens existing persistence rather than creating new persistence, and its detection surface is object-access auditing plus the anomalous end state itself — a service that returns access denied to a SYSTEM stop request is inherently suspicious.

## Mechanism

1. A persistence object is installed through any primary method — service creation (T-036), a registry autostart value, or a dropped binary. The hardening pass runs afterward against that object.
2. `GetNamedSecurityInfoA(objectName, objectType, DACL_SECURITY_INFORMATION, ...)` retrieves the object's current DACL. The `objectType` parameter (`SE_OBJECT_TYPE`) selects the object class: `SE_SERVICE` for Service Control Manager objects, `SE_REGISTRY_KEY` for hive keys, `SE_FILE_OBJECT` for NTFS paths; the training material notes the same API pair reaches shares and file-mapping objects.
3. The descriptor is optionally rendered to SDDL with `ConvertSecurityDescriptorToStringSecurityDescriptorA` for inspection. The SDDL ACE field decomposition — ace type, ace flags, rights, object GUID, inherited-object GUID, account SID — provides the manipulation vocabulary.
4. Replacement ACEs are built as `EXPLICIT_ACCESS_A` entries: `grfAccessMode = DENY_ACCESS`; `grfAccessPermissions` set to the remediation-critical rights — `SERVICE_STOP | SERVICE_CHANGE_CONFIG | DELETE | WRITE_DAC` for a service, `DELETE | WRITE_DAC` with key-specific rights for a registry key; the `Trustee` bound to well-known SIDs (`WinBuiltinAdministratorsSid`, `WinLocalSystemSid`) via `BuildTrusteeWithSidA`.
5. `SetEntriesInAclA` merges the new entries with the retained allow ACEs into a new ACL, applying canonical ordering with deny ACEs ahead of allow ACEs.
6. `SetNamedSecurityInfoA` with `DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION` writes the DACL and severs inheritance, preventing parent-container ACEs from re-granting the denied rights.
7. Verification round-trips the descriptor: `sc.exe sdshow <service>` for services, or a second `ConvertSecurityDescriptorToStringSecurityDescriptorA` call, confirms the deny ACEs are in place.

## OS Internals Context

A Windows `SECURITY_DESCRIPTOR` consists of a header, an owner SID, a group SID, a SACL, and a DACL. The DACL is an ordered list of access control entries; the two entry types relevant here are `ACCESS_ALLOWED_ACE` (type 0x0) and `ACCESS_DENIED_ACE` (type 0x1). During an access check, `SeAccessCheck` in the kernel (mirrored by user-mode `AccessCheck`) walks the DACL and evaluates entries in order: a matching deny ACE that intersects the requested access mask terminates evaluation immediately with `STATUS_ACCESS_DENIED`. This short-circuit is why canonical ordering — deny before allow — is the load-bearing property, and why the high-level `SetEntriesInAclA`/`SetNamedSecurityInfoA` path, which normalizes order, is preferred over hand-assembled ACL writes.

Service objects expose their DACLs through the SCM with a service-specific SDDL rights vocabulary used by `sc sdshow` and `sc sdset`: `CC` (SERVICE_QUERY_CONFIG), `DC` (SERVICE_CHANGE_CONFIG), `LC` (SERVICE_QUERY_STATUS), `SW` (SERVICE_ENUMERATE_DEPENDENTS), `RP` (SERVICE_START), `WP` (SERVICE_STOP), `DT` (SERVICE_PAUSE_CONTINUE), `LO` (SERVICE_INTERROGATE), `CR` (SERVICE_USER_DEFINED_CONTROL), alongside the standard rights `SD` (DELETE), `RC` (READ_CONTROL), `WD` (WRITE_DAC), and `WO` (WRITE_OWNER). A deny ACE blocking stop, delete, reconfigure, and DACL-write for SYSTEM and Administrators takes the representative form `D:(D;;WPSDDCWD;;;SY)(D;;WPSDDCWD;;;BA)` prepended ahead of the allow ACEs. After such a write, `sc stop` and `sc delete` fail with `ERROR_ACCESS_DENIED` even from an elevated SYSTEM shell.

The lock is not absolute, and the reason is documented Windows behavior: an object's owner implicitly retains `READ_CONTROL` and `WRITE_DAC` regardless of DACL contents. Deny ACEs cannot strip the owner's ability to rewrite the DACL. A defender holding `SeTakeOwnershipPrivilege` — granted to administrators by default — can call `SetNamedSecurityInfoA` with `OWNER_SECURITY_INFORMATION` to seize ownership, then replace the DACL outright. Hardening therefore raises remediation cost, forces additional attacker-visible steps, and generates extra telemetry, rather than producing an unremovable object.

The abstraction that makes one technique cover many persistence types is `SE_OBJECT_TYPE`. The same `GetNamedSecurityInfoA`/`SetNamedSecurityInfoA` pair, with a different enumeration constant, reaches service objects in the SCM database (`services.exe`), registry keys in the hives, NTFS files and directories, network shares, and named kernel objects such as file mappings. One code path hardens every persistence layer the vault documents.

`EXPLICIT_ACCESS_A` is the composition structure throughout: `grfAccessPermissions` carries the mask, `grfAccessMode` selects `GRANT_ACCESS`, `DENY_ACCESS`, `SET_ACCESS`, or `REVOKE_ACCESS`, `grfInheritance` controls propagation to child objects (relevant for registry keys and directories), and the embedded `TRUSTEE_A` identifies the SID or name the ACE governs.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

The codebase contains one SDDL-adjacent capability that must not be confused with this technique: `block_handle.rs` (manifest role: "Block external handle access"; the `payload_cfg.rs` comment describes "BlockHandle SDDL — restrict handle access via security descriptor") applies a restrictive security descriptor to the operator's own process to block external handle access — an EDR-evasion mechanism in the T-016 suite, not persistence hardening. A T-068 implementation would be a `persist/acl_harden.rs` module using `windows-sys::Win32::Security` (`GetNamedSecurityInfoA`, `SetEntriesInAclA`, `SetNamedSecurityInfoA`, `EXPLICIT_ACCESS_A`, `BuildTrusteeWithSidA`), invoked as a post-install step after each persistence layer, parameterized by object name and `SE_OBJECT_TYPE`.

## Why It Matters

Every persistence layer in the vault is removable by a one-line defender command; this technique converts disposable entries into resilient ones by moving the cost of removal from a delete operation to an ownership-takeover-plus-DACL-rewrite sequence. It is method-agnostic — the same call sequence hardens a service, a run key, or a dropped DLL — so it composes with any T-017 layer without coupling to that layer's install logic. The SDDL parsing literacy it requires also feeds directly into reconnaissance of defender-side hardening (T-029).

## Detection Considerations

- **Telemetry sources**: Windows does not log DACL changes by default; visibility requires SACL-based auditing. Security Event ID 4670 ("Permissions on an object were changed") fires when a SACL is present on the hardened object, and Event ID 4663 records the denied access attempts that follow. Denied service-control operations surface in SCM error events. Sysmon does not natively capture DACL modification; its Event ID 13 covers the persistence install's registry writes but not the ACL pass.
- **Bypass options**: restricting deny ACEs to specific remediation tooling SIDs rather than SYSTEM and Administrators broadly produces a subtler descriptor; leaving `WP` (stop) allowed while denying `SD`/`DC` (delete/reconfigure) lets the service appear stoppable while resisting removal.
- **Residual artifacts**: the DACL itself is durable — it survives payload deletion and reboot, and a service or key whose SDDL shows deny ACEs against SY/BA (visible via `sc sdshow` or `Get-Acl`) is a standing indicator. The anomalous state is self-incriminating: a service that returns access denied to a SYSTEM stop request draws analyst attention.

The atlas material for this technique does not discuss detection; the sources above reflect standard Windows auditing behavior.

## Related Techniques

- **T-017 Five-Layer Persistence** — the hardening pass applies as a post-install step to any of the five layers, converting them from removable to remediation-resistant.
- **T-036 Service-Based Persistence** — services are the primary hardening target documented in the material, with deny ACEs against `SERVICE_STOP`, `SERVICE_CHANGE_CONFIG`, and `DELETE`.
- **T-029 Security Descriptor and SDDL Reconnaissance** — the inspection counterpart: SDDL parsing and descriptor retrieval used defensively-offensively to audit objects rather than harden them.

## References

- Atlas material: atlas-exploit-dev-part10.md (units 19, 20), atlas-exploit-dev-part19.md (units 20, 21, 22)
- MITRE ATT&CK: [T1222.001 — File and Directory Permissions Modification: Windows File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/001/)
- LGTM notes: lgtm:sddl-acl-manipulation-proposed, lgtm:security-descriptor-acl-hardening

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.

<!-- END CARD T-068 -->