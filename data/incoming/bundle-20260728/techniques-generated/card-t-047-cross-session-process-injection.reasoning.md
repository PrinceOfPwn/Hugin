Let me analyze the inputs carefully.

The task: produce T-047 technique card for "Cross-Session Process Injection via WTS Enumeration".

Key facts from the material:

1. Cluster spec: T-047, category process-injection, tier A, crate would be... need to decide. No matching Rust source implements this technique. Let me check the provided source files:
   - `src/client_rust/src/commands.rs` — command dispatch, process list via sysinfo crate, kill process, start process. No WTSEnumerateProcessesEx. No cross-session injection.
   - `src/client_rust/src/main.rs` — main client loop. No WTS.
   - `src/dark_crystal/crowd/src/iat_camo.rs` — IAT camouflage. Unrelated (keyword grep hit on "injection" probably).
   
   So: no current implementation in source. crate: none, source_file: none.

2. Atlas material facts:
   - atlas-binary-analysis-part2 units 30-31: WTS_EnumerateProcessesAx API, Windows Terminal Services, BOOL return type; C code demonstrating WTS_EnumProcessSessions API for identifying cross-session process injection.
   - atlas-exploit-dev-part7 unit 36: WTSEnumerateProcessesEx example — "The example here shows how to use the API to make a local query. The amazing part about this API is that it provides detailed information about each process. We can even query the session to see what session is tied to a certain process. This can lead down a path of injecting into processes that are in a different session. This method is called cross-session process injection. Unlike the EnumProceses API, this one can return the count to you, which is a nice touch. Just like the other API, once the count is known, we can iterate over the..."
   - atlas-post-exploit-part9 unit 35: same WTSEnumerateProcessesEx text (duplicate of unit 36 in part 7).
   - atlas-post-exploit-part9 unit 17 (CRTO): Process Injection, OPSEC warning "Don't perform cross-platform injection", process listing fields PID, Name, Arch, Version, User.
   - atlas-post-exploit-part9 unit 24: Windows Handles — leaked handles, VirtualAllocEx/WriteProcessMemory/CreateRemoteThread classic injection chain, PROCESS_ALL_ACCESS warning.
   - atlas-post-exploit-part9 unit 34: Why Enumerate Processes — finding targets for shellcode injection, detecting security products.

3. Member notes mention: SeChangeNotifyPrivilege / session-boundary traversal (note 1); session-0 service injection and terminal-service session targeting (note 2); token/handle requirements for cross-session operation differ (note 3); would_relate_to includes T-015 (token-related).

MITRE: The best fit is T1055 (Process Injection). There's no specific sub-technique for cross-session. Cross-session injection sometimes maps to T1055 generically. MITRE ATT&CK T1055 Process Injection. I'll use T1055 as primary. Secondary could include T1055.002 (Portable Executable Injection)? Actually not needed. Maybe secondary: T1134 (Access Token Manipulation)? The notes mention token requirements. Note 3 relates to T-015 (PPID spoofing) and mentions "token". Hmm, but PPID spoofing is T1134.004. The cross-session injection notes mention token/handle requirements differ. I could add mitre_secondary: [T1134] — but rule says don't fabricate; pick IDs I'm confident about. T1134 Access Token Manipulation is a real ID. The notes do discuss token requirements (session-boundary traversal requiring SeChangeNotifyPrivilege — actually SeChangeNotifyPrivilege is "Bypass traverse checking" privilege... hmm, the note says "requiring SeChangeNotifyPrivilege / session-boundary traversal". I'll reflect the note's claim but carefully — the material (note) says that. Actually let me think: SeChangeNotifyPrivilege is bypass traverse checking; SeDebugPrivilege is the more standard one for opening processes of other users. The note says "requiring SeChangeNotifyPrivilege / session-boundary traversal" — this is what the LGTM note claims. Rule: material is authority for descriptive claims. I can state the note claims SeChangeNotifyPrivilege, but I should be careful. Actually, I could mention that the member note cites SeChangeNotifyPrivilege while standard Windows documentation associates cross-session process access with SeDebugPrivilege when the target is owned by another user... but rule 4 says claims must trace to material or well-established Windows internals documentation. SeDebugPrivilege (SE_DEBUG_NAME) enabling OpenProcess on processes owned by other users/SYSTEM is well-established MSDN documentation. I can include both: note claims SeChangeNotifyPrivilege; MSDN documents SeDebugPrivilege as the privilege enabling debug-level access to other users' processes. Hmm, but I want to avoid inventing. The well-established fact: OpenProcess on a process owned by another user requires SeDebugPrivilege for access rights beyond what the DACL grants. That's MSDN-documented (SE_DEBUG_NAME, "Debug programs" — "Required to debug and adjust the memory of a process owned by another account"). I'll include that as OS internals context grounded in MSDN.

WTS APIs: WTSEnumerateProcessesEx (WTS_CURRENT_SERVER_HANDLE, WTS_PROCESS_INFO_LEVEL, WTSEnumerateProcessesExW). Returns array of WTS_PROCESS_INFO_EX structures: SessionId, ProcessId, pProcessName, pUserSid, NumberOfThreads, HandleCount, PagefileUsage, PeakPagefileUsage, WorkingSetSize, PeakWorkingSetSize, UserTime, KernelTime. That's well-established MSDN documentation. The material confirms it provides "detailed information about each process" including session tied to process, and returns count.

WTSEnumerateProcessesEx signature:
```
BOOL WTSEnumerateProcessesExW(
  [in]      HANDLE hServer,
  [in, out] DWORD  *pLevel,
  [in]      DWORD  SessionId,
  [out]     LPSTR  *ppProcessInfo,
  [out]     DWORD  *pCount
);
```
SessionId: WTS_ANY_SESSION (0xFFFFFFFF) to enumerate all sessions, or specific session ID. pLevel must be 1 (WTS_PROCESS_INFO_EX) — actually pLevel: "Specifies the type of information to enumerate. This parameter must be 1, which causes the function to return WTS_PROCESS_INFO_EX structures" — wait, actually passing 0 returns WTS_PROCESS_INFOW? The docs: "If this parameter is 1 on input, the function returns extended information (WTS_PROCESS_INFO_EX). If 0, basic WTS_PROCESS_INFOW". Hmm. Let me be careful. MSDN: pLevel — "Pointer to a DWORD variable that, on input, specifies the type of information to return. To return an array of WTS_PROCESS_INFO_EX structures, set this to one. To return an array of WTS_PROCESS_INFOW structures, set this to zero." Yes that's right. The Ex function can behave like the basic one if level 0.

WTS_PROCESS_INFO_EX structure (MSDN):
```
typedef struct _WTS_PROCESS_INFO_EXA {
  DWORD         SessionId;
  DWORD         ProcessId;
  LPSTR         pProcessName;
  PSID          pUserSid;
  DWORD         NumberOfThreads;
  DWORD         HandleCount;
  DWORD         PagefileUsage;
  DWORD         PeakPagefileUsage;
  DWORD         WorkingSetSize;
  DWORD         PeakWorkingSetSize;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
} WTS_PROCESS_INFO_EXA;
```
Yes, that's documented.

WTSFreeMemoryExW to free. WTSEnumerateSessionsEx for session enumeration. WTSQuerySessionInformation with WTSSessionId / WTSUserName to map session to user. These are well-established.

The note mentions "WTS_EnumProcessSessions" (garbled OCR of the slide title "Example: WTSEnumProcessSessions"?). Unit 31 says C code demonstrating "WTS_EnumProcessSessions API" for identifying cross-session process injection. This is likely OCR-garbled. I'll reference WTSEnumerateProcessesEx and WTSEnumerateSessionsEx as the documented APIs, noting the material's slide shows the enumeration example.

Session basics (Windows Internals 7ed, well-established):
- Session 0: services and system processes since Vista (Session 0 isolation).
- Interactive sessions start at 1.
- Each session has its own Window Station(s), Desktop, Win32k instance, csrss.exe, wininit/winlogon.
- Process token contains a SessionId (TokenSessionId, TOKEN_INFORMATION_CLASS). 
- Cross-session injection: target process runs in different session — e.g., from user session 1 into a service in session 0 (requires SYSTEM-level or SeDebugPrivilege typically, plus appropriate DACL), or from session 1 into another user's session 2 process (requires SeDebugPrivilege or matching DACL).
- OpenProcess access checks: standard access check against target process's security descriptor; SeDebugPrivilege bypasses for PROCESS_ALL_ACCESS-ish requests... (well-established: with SeDebugPrivilege enabled, the kernel grants PROCESS_ALL_ACCESS to any process regardless of DACL — this is the "debug programs" privilege behavior).

CRTO OPSEC note: "Don't perform cross-platform injection" (arch mismatch — x86 vs x64). That's cross-platform, not cross-session, but adjacent targeting concern: target selection must match architecture. Also CRTO ps output includes Arch, User columns — targeting criteria.

Detection: The material doesn't explicitly discuss detection for cross-session injection specifically. Rule: "If the material does not cover detection for this technique, write: Training material does not discuss detection for this technique." But I can also describe detection surface that follows from mechanism grounded in... rule 4 says claims must trace to material or well-established docs. Hmm. The template says detection considerations should describe what training material describes. The material (atlas-post-exploit-part9 unit 24) mentions handle leaks, PROCESS_ALL_ACCESS warnings, Process Explorer / handle.exe — that's detection-adjacent (defenders can see leaked handles). CRTO unit 17 gives OPSEC guidance (don't cross-platform inject). Unit 34 mentions process enumeration for detecting security products. I think the honest approach: state that the training material does not provide dedicated detection content for cross-session injection, then note the adjacent detection/OPSEC guidance the material does contain (handle leak visibility via Process Explorer/handle.exe, excessive access rights like PROCESS_ALL_ACCESS as a red flag to defenders, CRTO's cross-platform OPSEC warning). That's grounded in the provided units. I should be careful not to invent ETW providers/Sysmon IDs. I can say "Training material does not discuss dedicated detection for this technique" and then list the adjacent items with citations to units. Actually the template allows Telemetry sources / Bypass options / Residual artifacts — if material doesn't cover, write the single line. I'll write the single line plus the material-grounded adjacent observations clearly attributed. Hmm — "Do not invent detections." The safest: write the mandated sentence, then a short paragraph noting the material's adjacent observations (handles leak detection, PROCESS_ALL_ACCESS caution, OPSEC cross-platform) explicitly framed as related material guidance, not detections I invented. Actually that might violate "do not invent" less if clearly attributed. The unit 24 material literally says Process Explorer and handle.exe can find leaked handles, and warns against PROCESS_ALL_ACCESS. That is detection-relevant content in the material. I'll present it as such.

Mechanism steps:
1. Obtain caller's session context / enumerate sessions via WTSEnumerateSessionsEx (optional) to map session IDs to users (WTSQuerySessionInformation WTSUserName).
2. Call WTSEnumerateProcessesExW with WTS_CURRENT_SERVER_HANDLE (or WTSOpenServer for remote), pLevel=1, SessionId=WTS_ANY_SESSION to retrieve all processes across sessions. Material notes the API returns the count (unlike EnumProcesses).
3. Iterate returned WTS_PROCESS_INFO_EX array: filter by SessionId (target session != caller session), pUserSid (target user/SYSTEM), pProcessName (high-value target), architecture considerations.
4. Enable required privileges: SeDebugPrivilege per MSDN for other-user processes; member note cites SeChangeNotifyPrivilege for session-boundary traversal.
5. OpenProcess on target PID with required access (material unit 24 warns against PROCESS_ALL_ACCESS; request minimal rights).
6. Perform standard injection per T-007/T-013 methods: VirtualAllocEx / WriteProcessMemory / CreateRemoteThread chain (unit 24 classic chain), or syscall-based variants.
7. Clean up: WTSFreeMemoryEx, close handles.

OS Internals Context:
- Sessions: since Vista, session 0 isolation — services isolated in session 0; interactive logons in sessions 1+.
- Token structure: TokenSessionId field (DWORD at specific offset); each process's EPROCESS->Token stores session ID; accessible via GetTokenInformation(TokenSessionId).
- WTS_PROCESS_INFO_EX fields.
- The session boundary implications: separate win32k instances, separate window stations/desktops — GUI interaction impossible cross-session, but process injection operates on process objects (kernel) not windowing layer, so the boundary is an access-control boundary (token/DACL), not an address-space boundary.
- NtQuerySystemInformation alternative (units 32-35 of part2) — SYSTEM_PROCESS_INFORMATION doesn't have session? Actually it does not include session ID directly in the struct shown... The documented SYSTEM_PROCESS_INFORMATION doesn't contain a SessionId field (there's a SessionId in some versions? No — SYSTEM_PROCESS_INFORMATION has no SessionId; there's SYSTEM_SESSION_PROCESS_INFORMATION class 53). I'll not go down that path beyond noting the material covers NtQuerySystemInformation as an alternative enumeration with SYSTEM_PROCESS_INFORMATION struct.
- csrss per session.

Key Implementation Details: no Rust source implements this. commands.rs uses sysinfo crate for process listing (GET_PROCESS_LIST) — not WTS-based, no session IDs. iat_camo.rs is unrelated. State "No current implementation in the HUGIN source." Then describe what an implementation would look like: wtsapi32 bindings, WTS_PROCESS_INFO_EX struct definition, filter predicate (session != current), hand-off to existing injection dispatch.

Why It Matters: distinct targeting criterion — vault's T-007/T-013 cover mechanisms, not targeting; cross-session targeting expands reachable processes (SYSTEM services in session 0, other users' processes) from a single foothold; selection of session-aware enumeration changes both capability and detection profile vs Toolhelp/EnumProcesses.

Related techniques:
- T-007 Pool Party — cross-session selection feeds a target into any injection mechanism incl. Pool Party.
- T-013 Remaining Methods — catalogue of injection primitives this targeting stage precedes.
- T-015 PPID Spoofing — hmm, relationship? Note 3 relates to T-015 with tag 'token'. The relationship: both concern handle/token requirements when crossing security boundaries; PPID spoofing manipulates parent attribution while cross-session injection manipulates session targeting — both are process-object attribute/targeting manipulations via NT APIs. Keep it to: member note links cross-session operation to token/handle requirements that also underlie PPID spoofing's parent-handle acquisition via NtOpenProcess. That's a fair one-line relationship grounded in the notes.
- T-023 Client Capabilities — client process list (GET_PROCESS_LIST) is the existing in-client enumeration; cross-session enumeration would extend it. Grounded: note 2 relates to T-023. The client has sysinfo-based process listing without session awareness.

Tags: cross-session, wts, terminal-services, session-id, process-enumeration, injection-targeting, sedebugprivilege, token, session-0. Pick 5-10 kebab-case: [cross-session, wts-enumeration, terminal-services, session-targeting, process-injection, session-0, token-access, target-selection].

member_notes: ['lgtm:cross-session-injection-primitive', 'lgtm:cross-session-injection-as-distinct-primitive', 'lgtm:cross-session-injection-variant']

MITRE: T1055. URL https://attack.mitre.org/techniques/T1055/

References: atlas-binary-analysis-part2.md, atlas-exploit-dev-part7.md, atlas-post-exploit-part9.md. LGTM notes IDs. Public references: SANS SEC670 material named in atlas. MSDN for WTS? "do not invent references" — public references optional, only those named in the material. The atlas names SANS SEC670 / MalDev Academy / CRTO as sources. I can cite those as named.

Length: target 1200-1800 words body. Let me write it.

Check frontmatter rules:
- id: T-047
- name: Cross-Session Process Injection via WTS Enumeration (7 words, ok 4-8)
- category: process-injection ✓
- tier: A ✓
- crate: none
- source_file: none — wait, template says `source_file: <relative path from repo root, or "none">`. So `source_file: none`? Hmm, in T-007 card frontmatter it's `source_file: dark_crystal/crowd/src/pool_party.rs`. For none, I'll write `source_file: none`. But rule says `source_file` must be a real path or exactly `none`. OK.
- mitre: T1055
- mitre_secondary: could omit. The technique is purely process injection targeting. I'll omit secondary to avoid overreach. Actually T1134 token manipulation isn't what this is — injection into another session is still T1055. Omit.
- tags: 5-10 kebab-case ✓
- origin: atlas-synthesis
- member_notes: exact list ✓

Banned words check: avoid elegant, clever, amazing (material says "amazing part" — I must not quote that as fanboy; I can paraphrase "provides detailed per-process information"). Avoid "notably", "worth noting", "key insight". Third person declarative.

Mechanism — numbered concrete steps.

OS Internals: sessions, winlogon/csrss per session, TokenSessionId, SeDebugPrivilege, session 0 isolation, WTS API layer (termsrv/Remote Desktop Services role in enumeration — WTSEnumerateProcessesEx on local server uses WTS_CURRENT_SERVER_HANDLE and works without RDS role installed; the API is exported by wtsapi32.dll). Kernel side: enumeration ultimately queries process list; session ID stored in EPROCESS token... Actually session ID for a process: EPROCESS has a Session field? EPROCESS->Session (PVOID pointer to MM_SESSION_SPACE / _MM_SESSION_SPACE). The session ID in WTS_PROCESS_INFO_EX comes from the process's session. TokenSessionId on the token. GetTokenInformation TokenSessionId is documented. EPROCESS.Session pointer to _MM_SESSION_SPACE exists in kernel — well-established from Windows Internals. I can mention EPROCESS.Session field. Keep grounded.

Cross-session handle access: kernel access check when calling NtOpenProcess — the Object Manager process manager performs access check against target EPROCESS security descriptor; SeDebugPrivilege grants the requested access mask regardless. This is well-established (Windows Internals / MSDN SE_DEBUG_NAME).

Also note: injecting into session 0 services from a user session requires elevation to a context holding SeDebugPrivilege (typically administrator with the privilege enabled, or SYSTEM). Another user's interactive session process similarly. Same-user cross-session (fast user switching) may still be blocked by DACL since the process DACLs typically grant the owner — actually same user owning processes in another session: the process security descriptor grants access to the owner SID, so OpenProcess by the same SID may succeed without SeDebugPrivilege depending on requested access. That's a reasonable well-established point but let me keep it measured: "the session itself is not the access check; the check is the target's DACL plus privileges" — grounded in Windows access check model.

Detection section: mandated sentence + material-adjacent guidance. Let me structure:
- "Training material does not discuss detection for this technique." Then: "Adjacent material provides partial operational guidance:" — handle leaks visible via Process Explorer / Sysinternals handle.exe (atlas-post-exploit-part9 unit 24); request minimal access rather than PROCESS_ALL_ACCESS (same unit); CRTO's OPSEC guidance against cross-platform injection (unit 17) — architecture match between injector and target. Residual artifacts: none specific in material.

Hmm, the template says "If the material does not cover detection for this technique, write: 'Training material does not discuss detection for this technique.' Do not invent detections." I'll lead with that exact sentence, then a short subsection framing the adjacent items as material-provided operational considerations rather than detections. I think that's compliant and honest.

Word count target ~1300-1500. Let me draft.

Draft:

---
frontmatter
---

# Cross-Session Process Injection via WTS Enumeration — Session-Aware Target Selection for Injection

## Summary
Cross-session process injection selects an injection target running in a different Terminal Services (WTS) session than the calling process, using session-aware process enumeration to locate it. The technique uses WTSEnumerateProcessesExW from wtsapi32.dll, which returns the session ID alongside each process, enabling an operator to filter for targets in session 0 (services) or in other users' interactive sessions. The injection itself reuses the standard primitives catalogued in T-007 and T-013; what this technique adds is the targeting stage, which changes which processes are reachable from a single foothold. The primary constraint is access control rather than the session boundary itself: opening a process owned by another user or by SYSTEM requires the target's DACL to permit it or SeDebugPrivilege on the caller's token.

Hmm "what this technique adds" fine. 

## Mechanism
1. Resolve the caller's own session ID (GetTokenInformation with TokenSessionId, or ProcessIdToSessionId on GetCurrentProcessId) to establish the local session baseline.
2. Optionally enumerate sessions with WTSEnumerateSessionsExW and resolve each to a user via WTSQuerySessionInformationW (WTSUserName) so targets can be selected by owning user.
3. Call WTSEnumerateProcessesExW against WTS_CURRENT_SERVER_HANDLE with pLevel set to 1 and SessionId set to WTS_ANY_SESSION. The API returns a count (material contrasts this with EnumProcesses, which requires deriving the count from bytes returned) and a pointer to an array of WTS_PROCESS_INFO_EX structures.
4. Iterate the array. Each entry carries SessionId, ProcessId, pProcessName, pUserSid, thread/handle counts, memory usage, and CPU times. Filter on SessionId != caller session and match pProcessName or pUserSid against the desired target (e.g., a service process in session 0, or a specific user's process in another interactive session).
5. Confirm architecture compatibility between injector and target — CRTO material warns against cross-platform injection (OPSEC guidance in process-listing output includes Arch and User columns).
6. Enable SeDebugPrivilege (SE_DEBUG_NAME) on the current token via AdjustTokenPrivileges when the target is owned by another account; the member notes additionally cite SeChangeNotifyPrivilege in the context of session-boundary traversal.
7. Open the target with NtOpenProcess/OpenProcess requesting the minimal access mask the chosen injection primitive needs; SEC670 material warns against requesting PROCESS_ALL_ACCESS because leaked or over-privileged handles are visible.
8. Execute the chosen injection primitive (T-007/T-013) — the classic chain shown in the material is VirtualAllocEx → WriteProcessMemory → CreateRemoteThread, but any vault injection method applies once a suitable handle exists.
9. Free the enumeration buffer with WTSFreeMemoryExW and close all process handles.

## OS Internals Context
- Sessions: since Vista, Windows isolates services in session 0; first interactive logon gets session 1, etc. Each session has its own csrss.exe instance, win32k instance, window stations, and desktops. Kernel tracks per-session memory in _MM_SESSION_SPACE, pointed to by the Session field of EPROCESS.
- TokenSessionId: each access token stores a session ID retrievable via GetTokenInformation(TokenSessionId). WTS enumeration surfaces this per process.
- The boundary: session separation is primarily a windowing/GUI boundary. Process injection operates on process objects through the kernel, so the effective gate is the standard access check: target process DACL, caller token privileges. SeDebugPrivilege, when present and enabled, causes the kernel to grant requested process access regardless of the target's DACL ("Debug programs" user right, MSDN).
- WTS API: WTSEnumerateProcessesExW exported by wtsapi32.dll. pLevel=1 returns WTS_PROCESS_INFO_EX. SessionId parameter: WTS_ANY_SESSION enumerates all. The material notes it works as a local query and that unlike EnumProcesses it returns the count directly.
- Alternative enumeration: the same SEC670 section covers NtQuerySystemInformation (SystemProcessInformation class) returning SYSTEM_PROCESS_INFORMATION (NextEntryOffset, NumberOfThreads, CreateTime, ImageName, UniqueProcessId, InheritedFromUniqueProcessId, Threads[]) — a native, session-blind... wait, is it session-blind? SYSTEM_PROCESS_INFORMATION doesn't include SessionId. I should say "does not surface the session ID in the structure documented in the material" — careful: the struct as documented by x64dbg doesn't show SessionId. Safe phrasing: "the SYSTEM_PROCESS_INFORMATION layout documented in the material does not carry a session field, which is what makes the WTS API the session-aware option."
- Session 0 targets: system services (svchost, lsass, spoolsv) live in session 0; from a user session, reaching them means both crossing the session boundary and satisfying the DACL/privilege check — typically requiring an elevated or SYSTEM context.

## Key Implementation Details
**No current implementation in the HUGIN source.** ... Verify: client_rust/src/commands.rs implements GET_PROCESS_LIST via the sysinfo crate (pid, name, cpu, mem, user, status) with no session ID and no WTS calls; iat_camo.rs matched keyword grep on injection-adjacent terms but only performs benign API calls for IAT camouflage. Neither implements cross-session targeting. Describe an implementation: extern bindings to wtsapi32 (WTSEnumerateProcessesExW, WTSFreeMemoryExW, WTSEnumerateSessionsExW, WTSQuerySessionInformationW), a #[repr(C)] WTS_PROCESS_INFO_EX definition, a predicate filter (SessionId != own, name/SID match), output a PID + session pair consumed by the crowd injection dispatcher; allocation via the returned ppProcessInfo buffer, freed with WTSFreeMemoryExW.

## Why It Matters
T-007 and T-013 catalogue how to inject; this card documents where to aim. Without session-aware enumeration, target selection defaults to processes in the caller's own session, which on a multi-user host or server excludes session-0 services and other users' processes — often the highest-value targets (credential material, SYSTEM tokens, management agents). The WTS enumeration stage converts a single foothold into host-wide target visibility using a documented API rather than raw native queries, and the member notes record that SEC670 frames it as a distinct operational capability with different token/handle requirements than in-session injection.

## Detection Considerations
Training material does not discuss detection for this technique. Then adjacent observations: The material provides adjacent operational guidance relevant to observability. SEC670's handle discussion (atlas-post-exploit-part9, unit 24) states leaked handles are visible through Process Explorer and Sysinternals handle.exe, and cautions against PROCESS_ALL_ACCESS — both apply to the cross-session OpenProcess stage. CRTO's process-injection OPSEC note (unit 17) warns against cross-platform injection, i.e., an x86 injector writing into an x64 target, which produces crashes and obvious artifacts; target selection must match architecture. No ETW providers, Sysmon event IDs, or residual artifacts for this technique are documented in the material.

## Related Techniques
- T-007 Pool Party — one of the injection mechanisms a cross-session-selected target PID feeds into; Pool Party's handle enumeration via NtQuerySystemInformation is session-agnostic once a handle exists... careful — Pool Party needs a handle to the target process; cross-session selection provides the PID. One line.
- T-013 Additional Injection Methods — the primitive catalogue executed after target selection; classic VirtualAllocEx/WriteProcessMemory/CreateRemoteThread chain from the material corresponds to these.
- T-015 PPID Spoofing — both techniques acquire handles across security boundaries (parent handle for PPID spoof, target handle for cross-session injection); member notes tie cross-session operation to the differing token/handle requirements.
- T-023 Client Capabilities — the existing client process list (GET_PROCESS_LIST) is the non-session-aware enumeration this technique would extend for targeting.

## References
- Atlas material: atlas-binary-analysis-part2.md (units 30-31), atlas-exploit-dev-part7.md (unit 36), atlas-post-exploit-part9.md (unit 35; adjacent units 17, 24, 34)
- MITRE ATT&CK: T1055 — Process Injection, https://attack.mitre.org/techniques/T1055/
- LGTM notes: lgtm:cross-session-injection-primitive, lgtm:cross-session-injection-as-distinct-primitive, lgtm:cross-session-injection-variant
- Public references: SANS SEC670 "Red Teaming Tools: Developing Custom Tools for Windows" (named source in atlas material); CRTO book (named source)

## Source Reference
No current implementation. See atlas material and MITRE reference for public tooling.

Word count check — I'll aim to flesh out OS internals a bit more to hit 1200+.

Also careful: member note 1 says "requiring SeChangeNotifyPrivilege / session-boundary traversal". SeChangeNotifyPrivilege is "Bypass traverse checking". I'll present it as the note's claim. Also "WTSEnumProcessSessions" garbled name — I'll note the slide caption references the enumeration example without asserting a non-existent API name. Actually I'll just use the real API names and attribute structure.

Also WTS_CURRENT_SERVER_HANDLE — documented. WTS_ANY_SESSION — hmm, for WTSEnumerateProcessesEx the SessionId parameter: "Indicates the session for which to enumerate processes. To enumerate processes for all sessions on the server, specify WTS_ANY_SESSION." Yes documented.

WTS_PROCESS_INFO_EX fields — documented as above. Good.

pUserSid — yes, PSID pUserSid in WTS_PROCESS_INFO_EX. Good.

WTSFreeMemoryEx — documented: WTSFreeMemoryExW(WTS_PROCESS_INFO_EX class?, pProcessInfo, count). Signature: BOOL WTSFreeMemoryExW(WTS_TYPE_CLASS WTSTypeClass, PVOID pMemory, ULONG NumberOfEntries). Good enough; I can just say freed with WTSFreeMemoryExW without full signature.

ProcessIdToSessionId — documented kernel32 API. Good.

Length target: let me count roughly as I write. Aim ~1400 words body.

One more check on banned phrases: "the key insight" no; "essentially" no; "interestingly" no; "worth noting" no. Avoid "amazing" even in quotes — I'll paraphrase. Avoid "nice touch" quote too (fanboy-ish quoting; paraphrase: "returns the count directly").

Format for Related Techniques per template: "- **T-NNN Name** — explanation".

Header: "# Cross-Session Process Injection via WTS Enumeration — Session-Aware Target Selection Beyond the Caller's Logon Session". Keep one-line purpose shorter: "— Session-Aware Target Selection for Injection Across Logon Sessions".

Write final.