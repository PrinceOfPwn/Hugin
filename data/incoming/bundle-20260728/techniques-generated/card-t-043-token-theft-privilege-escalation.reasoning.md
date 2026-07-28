Let me analyze the task carefully.

I need to produce a technique card for T-043: Token Theft (TokenThief) via OpenProcessToken and Duplication.

Key inputs:
1. Cluster spec: T-043, privesc category, tier A, 6 member notes, would_relate_to: T-021, T-023, T-015
2. Related T-NNN cards: T-015 (PPID Spoofing), T-021 (Crypto & Obfuscation), T-023 (Client Capabilities)
3. Rust source files: 
   - `src/dark_crystal/crates/core/src/escalation/uac.rs` — this is a UAC bypass via slui.exe. It uses OpenProcessToken + GetTokenInformation for elevation CHECK, but does NOT implement token theft (no OpenProcess on another process, no DuplicateTokenEx, no CreateProcessWithTokenW). So this does NOT implement the technique.
   - `src/dark_crystal/crowd/src/persist/phantom_restart.rs` — uses OpenProcessToken + AdjustTokenPrivileges to enable SeShutdownPrivilege on its OWN token. That's privilege adjustment on own token, not token theft from another process. Does NOT implement the technique.

So per rule 8: neither file implements the primary mechanism (stealing a token from another process via OpenProcessToken on a remote process handle + DuplicateTokenEx + CreateProcessWithTokenW/ImpersonateLoggedOnUser). The uac.rs file uses OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY) only to check elevation status — that's not token theft. phantom_restart.rs uses OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) to enable SeShutdownPrivilege — that's adjusting privileges on its own token, which is a related primitive but not token theft/duplication.

So `source_file: none` and `crate: none`. Wait — crate must be `dark_crystal`, `client_rust`, or `none`. Since no implementation, `crate: none`, `source_file: none`.

Hmm, but wait. Let me reconsider. The mechanism described is: open a handle to a higher-privilege process (e.g., winlogon.exe) → OpenProcessToken → DuplicateTokenEx → CreateProcessWithTokenW. Neither of the provided files does this. Correct: no current implementation.

4. Atlas material: I have 5 atlas files:
   - atlas-binary-analysis-part4.md: unit 30 (course roadmap with Lab 3.5 TokenThief), unit 31 (OpenProcessToken slide)
   - atlas-labs-part2.md: unit 1 (Lab 3.5 TokenThief)
   - atlas-post-exploit-part14.md: units 19-22 (integrity levels, stealing tokens source review, Lab 3.5, OpenProcessToken review questions), units 25-27 (OpenProcessToken review Q&A)
   - atlas-post-exploit-part16.md: units 18, 20, 21 (Lab 3.5, OpenProcessToken review), unit 24 (integrity levels), 25, 26 (whoami/priv)
   - atlas-post-exploit-part4.md: units 13-15 (access tokens, primary vs impersonation, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES), 16-17 (integrity levels), 18 (whoami/priv), 20 (OpenProcessToken API details), 21-22 (Stealing Tokens source review, Lab 3.5)
   - atlas-privesc-part1.md: unit 1 (AdjustTokenPrivileges API), units 3-4 (six integrity levels), unit 5 (SeBackup/SeRestore ACL bypass), unit 6 (LookupPrivilegeValue/OpenProcessToken/AdjustTokenPrivileges programmatic), unit 7 (token stealing lab point), units 10-11 (Meterpreter getsystem module summary), units 19-21 (integrity levels, SeBackup/Restore, OpenProcessToken details), units 26-27 (Windows privileges, SeDebugPrivilege), unit 30-32 (SE_PRIVILEGE_*, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES), units 39-40 (SeTakeOwnershipPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeDebugPrivilege — Admin to SYSTEM)

Key technical facts from the material:
- OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle) — BOOL return, obtains handle to a process's access token (unit 20/21 in part4, privesc unit 21, binary-analysis unit 31)
- "You cannot change any privileges in a token without having a handle to it. The OpenProcessToken gets you that token handle"
- AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength) — enables or disables privileges, "last and final step" (privesc unit 1)
- LookupPrivilegeValue → OpenProcessToken → AdjustTokenPrivileges is the programmatic sequence (privesc unit 6)
- Access tokens: given after successful authentication; contain SID/logon SID, privileges, default DACL; primary or impersonation (part4 units 13-15)
- TOKEN_PRIVILEGES contains LUID_AND_ATTRIBUTES: Luid + bit flags (ENABLED, ENABLED_BY_DEFAULT, REMOVED, USED_FOR_ACCESS) (part4 unit 13, privesc units 30-32)
- Six integrity levels: Untrusted(0), Low(1), Medium(2), High(3), System(4), Protected(5). Anonymous group started processes / AppContainer / typical UAC / UAC elevated / system services (wininit, winlogon, lsass) / kernel-mode only. Query via GetTokenInformation. SIDs S-1-16-0x0 format. (privesc units 3-4, part14 unit 19, part16 unit 24)
- SeDebugPrivilege needed for obtaining process handles to certain processes (privesc units 24-27)
- SeBackupPrivilege/SeRestorePrivilege bypass ACL checks (privesc units 5, 20, 37-38)
- SeTakeOwnershipPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeDebugPrivilege — escalate Admin to SYSTEM (privesc units 39-40)
- Lab 3.5 TokenThief — "The point of this lab was to explore the steps and APIs involved with stealing a token for escalating privileges" (privesc units 7, 17)
- Stealing Tokens: source code review section (part4 unit 21, part14 unit 20)
- OpenProcessToken review questions — the API that gives you a handle to a process' token (part14 units 25-27, part16 units 20-21)
- Meterpreter getsystem — learning how it works on the back end (privesc units 10-11)
- Cluster spec consolidated description: OpenProcessToken to obtain token from higher-integrity process, DuplicateTokenEx to create copy with MAXIMUM_ALLOWED rights, CreateProcessWithTokenW to spawn child with stolen token's privilege level. Admin-to-SYSTEM, High-IL-to-SYSTEM.
- Note 3 mentions: OpenProcess with SeDebugPrivilege -> OpenProcessToken -> DuplicateTokenEx -> CreateProcessAsUser
- Note 6 mentions detection: Kernel-Process TokenOpen ETW events, 4688 High Mandatory Level without consent UI; tradecraft: which source PID to target, which access mask to request, how to clean up duplicated handles
- Note 2 mentions: MakeToken/ImpersonateLoggedOnUser/DuplicateTokenEx primitive family
- Note 5 mentions: TOKEN_PRIMARY, TOKEN_IMPERSONATE, SeImpersonatePrivilege

MITRE mapping: The best fit is T1134.001 (Access Token Manipulation: Token Impersonation/Theft). T1134 is Access Token Manipulation; sub-technique .001 is Token Impersonation/Theft. That's the right one. Secondary could be T1134.002 (Create Process with Token) since CreateProcessWithTokenW is used. And maybe T1068 (Exploitation for Privilege Escalation)? No — not exploitation. T1548 (Abuse Elevation Control Mechanism)? That's more UAC bypass. The primary is definitely T1134.001. Secondary: T1134.002.

T-015 card uses mitre T1134.004 (Parent PID Spoofing) — same parent technique T1134, consistent.

Category: privesc — it's in the enum. Tier: A (proposed).

Now for source verification:
- uac.rs: implements UAC bypass via slui.exe registry poisoning. Uses OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY) + GetTokenInformation(TokenElevation) to check if elevated. This is NOT token theft. It doesn't open another process's token, doesn't duplicate, doesn't spawn with token. Verdict: does not implement T-043.
- phantom_restart.rs: uses OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) + LookupPrivilegeValueW + AdjustTokenPrivileges to enable SeShutdownPrivilege on its own token. This is the privilege-adjustment primitive (a component of the token manipulation family) but NOT token theft from another process. Verdict: does not implement T-043.

So: `crate: none`, `source_file: none`. In Key Implementation Details, I write the "No current implementation" text and describe what an implementation would look like. I can also note the adjacent usage: the codebase uses OpenProcessToken only for self-token elevation checks (uac.rs) and privilege adjustment (phantom_restart.rs), but not cross-process token theft. Actually the template says: "If no source implements this technique: Write: '**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in <source language/tool>.'" Then briefly describe what an implementation would look like. The atlas material is C/C++ (SEC670 labs). So "in C/C++".

I can mention that the grep-matched files use OpenProcessToken on the current process only — good to explicitly note why they don't count, per rule 8 spirit. I'll keep that brief.

Mechanism steps (from material + cluster spec):
1. Enable SeDebugPrivilege in the implant's own token: OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) → LookupPrivilegeValueW(NULL, SE_DEBUG_NAME) → AdjustTokenPrivileges. The material explicitly covers this sequence (privesc unit 6: "Privileges: Programmatically; LookupPrivilegeValue; OpenProcessToken; AdjustTokenPrivileges" and unit 1 AdjustTokenPrivileges details).
2. Enumerate processes to find a SYSTEM-IL target — winlogon.exe named in the material (part4 unit 16-17 mention winlogon.exe at System IL; note 1 says "open a SYSTEM token on winlogon.exe"). Process enumeration via CreateToolhelp32Snapshot (Lab 2.3 in part16 unit 16, and T-015 uses it).
3. OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION, pid) — requires SeDebugPrivilege for SYSTEM processes (privesc units 24-27).
4. OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken) — material: "Obtains a handle to a process' access token", BOOL return, 3 params.
5. DuplicateTokenEx(hToken, MAXIMUM_ALLOWED / TOKEN_ALL_ACCESS, NULL, SecurityImpersonation/SecurityDelegation, TokenPrimary, &hNewToken) — cluster spec says DuplicateTokenEx with MAXIMUM_ALLOWED rights to create copy.
6. CreateProcessWithTokenW(hNewToken, ...) to spawn child process with stolen token → child runs at SYSTEM IL. Note 3 mentions CreateProcessAsUser alternative.
7. Alternative: ImpersonateLoggedOnUser(hDupToken) to impersonate on current thread instead of spawning a new process; SetThreadToken / revert with RevertToSelf. Note 2 mentions ImpersonateLoggedOnUser.
8. Cleanup: CloseHandle on duplicated token handles, process handle (note 6 tradecraft).

OS Internals Context:
- Access token structure: primary vs impersonation tokens, contents (user SID, group SIDs, logon SID, privileges as TOKEN_PRIVILEGES/LUID_AND_ATTRIBUTES, default DACL, integrity level SID). Material part4 units 13-15.
- TOKEN_PRIMARY vs TOKEN_IMPERSONATE types (note 5). Primary tokens assigned to processes; impersonation tokens to threads.
- Six integrity levels with SID format S-1-16-0x1000 etc. Material gives S-1-16-0x0 prefix; levels 0-5. System IL processes: wininit, winlogon, lsass (privesc unit 3-4).
- Mandatory Integrity Control: a process cannot open a handle to a higher-IL process/token without appropriate access; SeDebugPrivilege bypasses this for PROCESS_QUERY_INFORMATION on SYSTEM processes when caller is admin (High-IL).
- Privileges: Enabled vs Disabled state; SE_PRIVILEGE_ENABLED_BY_DEFAULT etc. (privesc units 26-32).
- The kernel side: token objects are executive objects (nt!_TOKEN), referenced by EPROCESS.Token (a _EX_FAST_REF). Hmm — is this "well-established Windows internals"? Yes, EPROCESS.Token is documented in Windows Internals. The material doesn't go into _TOKEN structure, so I should be careful. I can mention that tokens are securable executive objects managed by the kernel object manager, reference-counted; duplication creates a new token object referencing the same logon session (via the authentication ID / LUID). The logon session concept is in Windows Internals 7ed. Duplicating a token copies the token with a new object but same logon ID; that's why the duplicated token retains SYSTEM context. This is documented behavior. I should keep it modest and grounded.
- DuplicateTokenEx parameters: impersonation level (SecurityAnonymous/Identification/Impersonation/Delegation) and token type (TokenPrimary/TokenImpersonation). CreateProcessWithTokenW requires a primary token; ImpersonateLoggedOnUser requires an impersonation token. This is MSDN-documented contract. The material doesn't spell this out but it's well-established Windows documentation — allowed under rule 4 ("Well-established Windows internals documentation (Windows Internals 7ed, MSDN, ntdll headers)"). I'll keep it tight.
- CreateProcessWithTokenW requires SeImpersonatePrivilege (actually SE_IMPERSONATE_NAME) on the caller — MSDN documented. The material mentions SeImpersonatePrivilege in note 5. Good.
- whoami /priv shows privileges tied to primary token; enabled on the fly (privesc units 19, 36).

Why It Matters: distinct from UAC bypass (T-021/T-017 coverage) and PPID spoofing (T-015) — operates at token layer not process-creation attribute layer; basis for Meterpreter getsystem (material units 10-11); reusable for lateral movement (note 2, note 6). No consent UI — elevation happens without UAC prompt (note 6: "4688 High Mandatory Level without consent UI").

Detection Considerations:
- Note 6 explicitly: Kernel-Process TokenOpen ETW events (GUID not documented in material — Microsoft-Windows-Kernel-Process has an event for token open; I must not invent GUID). Event ID? The note says "Kernel-Process TokenOpen ETW events" — I'll write GUID not documented in material.
- 4688 High Mandatory Level without consent UI — Security event 4688 (process creation) where child has High/System mandatory level but no UAC consent was recorded. From note 6.
- Sysmon Event ID 1 (process creation) would show the child process with SYSTEM integrity and parent = implant process. Is Sysmon EID 1 well-established? Yes, but rule says if the material does not cover detection, write the line. The material (note 6) does cover detection partially: ETW TokenOpen, 4688 anomaly. Note 6 also mentions tradecraft: source PID selection, access mask minimization, handle cleanup. I can include those as bypass/residual considerations attributed to the notes.
- SeDebugPrivilege usage: enabling SeDebugPrivilege generates Security event 4703 (token privilege adjusted)? Is that documented? 4703 is "A user right was adjusted". Sensitive privilege use is 4673/4674. I'm not fully sure of exact mapping the material intends; the material doesn't mention these event IDs. I should not invent. I'll mention only what's in note 6 plus generic statement that the material does not further detail telemetry. Actually — "Training material does not discuss detection for this technique" would be wrong since note 6 does discuss it. So I cover note 6's content: TokenOpen ETW, 4688 anomaly, tradecraft considerations (source PID, access mask, handle cleanup as opsec). Residual artifacts: duplicated token handles remain until closed; child process parented to the implant (note 6 implies handle cleanup). I'll be careful to attribute.

Related Techniques:
- T-015 PPID Spoofing — same T1134 parent family (access token manipulation / process creation attribute), but T-015 manipulates the parent-process attribute at creation; T-043 manipulates the token assigned at creation. Cluster notes say T-015 "touches parent-process attribute manipulation but the vault has no dedicated technique card for token duplication". Relationship: complementary process-creation evasion; can be combined (spawn with stolen token + spoofed parent).
- T-021 Crypto & Obfuscation — contains UAC bypass via slui.exe (Medium→High IL auto-elevation). T-043 picks up where UAC bypass ends: High→System. Note 1: "The vault's T-021/T-023 UAC bypass coverage addresses auto-elevation but does not document the broader token-theft primitive". So relationship: T-021's UAC bypass gets you to High-IL admin; T-043 escalates High→SYSTEM.
- T-023 Client Capabilities — contains credential harvest (lsass_dump) and UAC bypass (CMSTP); lsass_dump requires SeDebugPrivilege/SYSTEM — token theft is the escalation path that enables those capabilities. Note 2/6: vault folds token logic implicitly into T-023. Relationship: T-023's LSASS dump and other privileged capabilities depend on the elevation T-043 provides.

References:
- Atlas: atlas-binary-analysis-part4.md, atlas-labs-part2.md, atlas-post-exploit-part14.md, atlas-post-exploit-part16.md, atlas-post-exploit-part4.md, atlas-privesc-part1.md
- MITRE: T1134.001 https://attack.mitre.org/techniques/T1134/001/ ; secondary T1134.002 https://attack.mitre.org/techniques/T1134/002/
- LGTM notes: the 6 IDs
- Public references: Meterpreter getsystem (named in material units 10-11). That's named in material — allowed. Don't invent others.

Tags (5-10 kebab-case): token-theft, privilege-escalation, openprocesstoken, duplicatetokenex, createprocesswithtokenw, impersonation, sedebugprivilege, integrity-levels, admin-to-system, access-tokens. That's 10. Good.

Frontmatter:
```yaml
---
id: T-043
name: Token Theft via OpenProcessToken and Duplication
category: privesc
tier: A
crate: none
source_file: none
mitre: T1134.001
mitre_secondary: [T1134.002]
tags: [token-theft, privilege-escalation, openprocesstoken, duplicatetokenex, createprocesswithtokenw, impersonation, sedebugprivilege, integrity-levels, admin-to-system, access-tokens]
origin: atlas-synthesis
member_notes: ['lgtm:token-theft-privilege-escalation', 'lgtm:token-impersonation-theft-card', 'lgtm:proposed-token-theft-technique', 'lgtm:proposed-token-stealing-lpe-card', 'lgtm:token-theft-and-impersonation-primitive', 'lgtm:proposed-token-theft-technique-card']
---
```

Name: "Token Theft via OpenProcessToken and Duplication" — 7 words. Good (4-8 words). The canonical name is "Token Theft (TokenThief) via OpenProcessToken and Duplication" — 8 words if you count "(TokenThief)". I'll use "Token Theft (TokenThief) via OpenProcessToken and Duplication" to match canonical. Hmm, name should be human readable 4-8 words. Canonical: Token(1) Theft(2) (TokenThief)(3) via(4) OpenProcessToken(5) and(6) Duplication(7) = 7 words. Fine, use canonical.

H1: `# Token Theft via OpenProcessToken — Steal SYSTEM Tokens to Spawn Elevated Processes` — one-line purpose. Let me craft: `# Token Theft (TokenThief) — Duplicate a Higher-Integrity Token and Spawn Under It`. 

Word count target 1200-1800 body words. Let me draft carefully.

Section: Summary (3-5 sentences, first standalone):
Token theft opens the access token of a higher-privilege process, duplicates it, and assigns the copy to a new child process or to the calling thread, yielding execution at the victim token's privilege level. The technique chains OpenProcess (with SeDebugPrivilege), OpenProcessToken, DuplicateTokenEx, and CreateProcessWithTokenW (or ImpersonateLoggedOnUser) to move from High-IL administrator to SYSTEM without a UAC consent prompt. SEC670 teaches it as Lab 3.5 "TokenThief," targeting winlogon.exe-class SYSTEM processes, and it is the documented basis for Meterpreter's getsystem. Primary detection surface: ETW Kernel-Process token-open events and process-creation telemetry showing an elevated-IL child with no corresponding consent-UI activity.

Mechanism (numbered):
1. Enable SeDebugPrivilege on own token: OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hSelf) → LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid) → AdjustTokenPrivileges(hSelf, FALSE, &tkp...). Material: privileges are present-but-disabled in High-IL tokens and can be enabled on the fly (privesc units 19, 36, 26-27); programmatic sequence LookupPrivilegeValue→OpenProcessToken→AdjustTokenPrivileges (unit 6); AdjustTokenPrivileges is "the last and final step" (unit 1).
2. Locate a donor process running at System IL — winlogon.exe named by material; enumeration via CreateToolhelp32Snapshot (Lab 2.3). Note 6 tradecraft: source PID selection matters.
3. OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid) — SeDebugPrivilege makes this succeed against SYSTEM processes from a High-IL caller (privesc units 24-27; "certain actions, such as obtaining process handles for specific processes, require specific privileges like SeDebugPrivilege").
4. OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken) — "Obtains a handle to a process' access token," BOOL return (binary-analysis unit 31, part4 unit 20, privesc unit 21). Note 6: access-mask selection is a tradecraft consideration.
5. DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDup) — cluster spec: duplicate with MAXIMUM_ALLOWED rights. Token type primary so it can be assigned to a process.
6. CreateProcessWithTokenW(hDup, 0, path, ...) → child inherits the stolen token's identity, groups, privileges, and System integrity level (cluster spec; note 4: spawn System-IL child from High-IL admin).
7. Variant: DuplicateTokenEx with TokenImpersonation + ImpersonateLoggedOnUser → current thread adopts donor context; RevertToSelf to drop (note 2: MakeToken/ImpersonateLoggedOnUser/DuplicateTokenEx family). Note 3 lists CreateProcessAsUser as the alternate spawn API.
8. Close duplicated handles and the process handle after spawn (note 6: "how to clean up duplicated handles").

OS Internals Context:
- Token contents: user SID, group SIDs, logon SID, privileges (TOKEN_PRIVILEGES → array of LUID_AND_ATTRIBUTES: LUID + attribute bits SE_PRIVILEGE_ENABLED, _ENABLED_BY_DEFAULT, _REMOVED, _USED_FOR_ACCESS), default DACL, type (primary/impersonation) — part4 units 13-15, privesc units 30-32.
- Primary vs impersonation: primary bound to process (every process created after logon carries one tied to the user), impersonation bound to threads (part4 units 13-15). Duplication converts between types: TokenPrimary required for CreateProcessWithTokenW; TokenImpersonation for thread impersonation (MSDN contract).
- Integrity levels: six — Untrusted(0), Low(1), Medium(2), High(3), System(4), Protected(5); queried via GetTokenInformation (TokenIntegrityLevel); SIDs S-1-16-0x0 form; System IL hosts wininit, winlogon, lsass; Protected set only by kernel-mode callers (privesc units 3-4, 19, 33). MIC prevents lower-IL processes from opening higher-IL objects for write; the token-steal path only needs query/read-style access masks, which High-IL + SeDebugPrivilege grants.
- Kernel side: token is a securable executive object; the duplicated token is a new object pointing at the same logon session (same authentication ID), so the child authenticates as the donor's security context. EPROCESS references the token. (Windows Internals documented.)
- Why SeDebugPrivilege suffices: it short-circuits the access check on OpenProcess against any process, including SYSTEM — privesc unit 26-27. Also mention SeImpersonatePrivilege needed for CreateProcessWithTokenW/impersonation calls (note 5 lists SeImpersonatePrivilege; MSDN documents the requirement).
- whoami /priv behavior: privileges present but disabled until AdjustTokenPrivileges (privesc units 18-19, 35-36).

Key Implementation Details:
**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C/C++ (SEC670 Lab 3.5 TokenThief source review).
Note on the two grep-matched files: uac.rs calls OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY) only to read TokenElevation for a self-elevation check; phantom_restart.rs calls OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES) only to enable SeShutdownPrivilege on its own token. Neither opens a foreign process token nor duplicates one, so neither implements this technique.
Then describe an implementation sketch: donor-PID resolver (CreateToolhelp32Snapshot walk, prefer winlogon.exe), SeDebugPrivilege enable helper (same LookupPrivilegeValue→AdjustTokenPrivileges shape as phantom_restart.rs's enable_shutdown_privilege), FFI bindings for DuplicateTokenEx/CreateProcessWithTokenW via windows_targets::link! per wrappers.rs pattern, RAII guard closing token handles (vault's RAII pattern). Roughly one paragraph. Careful: no "future improvement" language? Rule 3 says no suggestions/variant ideas — but the template explicitly says to describe what an implementation would look like. The template overrides; it's descriptive, not a suggestion. Keep it one paragraph, factual.

Why It Matters (2-4 sentences):
Token theft fills the Admin→SYSTEM gap that the vault's UAC-bypass coverage (T-021 slui, T-023 CMSTP) stops short of: those reach High IL, this reaches System IL. It operates at the token-object layer rather than the memory-injection layer (T-013) or the process-attribute layer (T-015), so it composes with any execution primitive rather than competing with them. SEC670 treats it as the conceptual basis of Meterpreter's getsystem, and it doubles as a lateral-movement primitive via impersonation of domain tokens. No UAC consent UI appears anywhere in the chain, which removes the user-interaction dependency that constrains auto-elevation.

Detection Considerations:
- Telemetry (from note 6): ETW Microsoft-Windows-Kernel-Process token-open events observe OpenProcessToken against foreign processes (GUID not documented in material); Security 4688 process-creation events showing a High/System Mandatory Level child with no consent-UI record. The material does not document Sysmon IDs or additional providers for this technique.
- Bypass/tradecraft (note 6): choose donor PID carefully, request minimal access masks rather than TOKEN_ALL_ACCESS, close duplicated handles promptly.
- Residual artifacts: open handles to the donor process and its token during the theft window; child process parented to the implant in process-creation telemetry; privileges enabled on the implant's own token (SeDebugPrivilege adjustment persists in the token).
Also material (privesc unit 1) notes AdjustTokenPrivileges is visible as the "final step" — no, don't overreach. Keep to notes.

Related Techniques:
- T-015 PPID Spoofing — T-015 manipulates the parent-process attribute of a new process; T-043 manipulates the token the new process receives. Same T1134 family; combinable in one NtCreateUserProcess-style launch.
- T-021 Crypto & Obfuscation — hosts the slui.exe UAC bypass (Medium→High IL); T-043 is the follow-on step that converts High-IL admin into SYSTEM.
- T-023 Client Capabilities — privileged capabilities catalogued there (LSASS dump via MiniDumpWriteDump, CMSTP UAC bypass) require SeDebugPrivilege/SYSTEM context; token theft is the escalation primitive that supplies it.

References:
- Atlas: list all six files.
- MITRE: T1134.001 URL, T1134.002 URL.
- LGTM: 6 IDs.
- Public: SEC670 Lab 3.5 TokenThief; Meterpreter getsystem (named in material).

Source Reference: "No current implementation. See atlas material and MITRE reference for public tooling."

Now check length. Let me draft the actual prose and count roughly. Target 1200-1800 words body. I'll aim ~1400.

Check banned words: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable. Avoid "clean up" — hmm, "clean" is banned as fanboy word; "clean up duplicated handles" is a functional phrase from the note. Safer: "close duplicated handles". Use "close" instead of "clean up" to be safe. Banned phrases: "worth noting", "it is important to note", etc. Avoid.

Also avoid "essentially", "at its core", "interestingly".

No exclamation marks. Note the material has "Stealing Tokens Source code review!" — don't quote with exclamation.

Frontmatter tags: need 5-10 kebab-case. My list has 10. "openprocesstoken" — the notes use 'openprocesstoken' as tag. Keep as-is (they're kebab-compatible lowercase). Fine.

MITRE format: T1134.001. URL: https://attack.mitre.org/techniques/T1134/001/ — correct format.

Category: privesc — in enum. Tier: A. crate: none. source_file: none (bare word, not quoted — template shows `source_file: <relative path or "none">`. In the example frontmatter for T-015 it's a path. I'll use `source_file: none` unquoted; spec says 'must be a real path or exactly `none`'. Unquoted none in YAML parses as string "none"? Actually YAML `none` is a string (only `null`/`~` are null). Fine. Use `source_file: none` and `crate: none`.

Now, one consideration on the Mechanism step for DuplicateTokenEx: cluster spec says "DuplicateTokenEx to create copy with MAXIMUM_ALLOWED rights". MAXIMUM_ALLOWED is a valid access mask for DuplicateTokenEx's dwDesiredAccess parameter (MSDN documents that DuplicateToken and DuplicateTokenEx accept MAXIMUM_ALLOWED). Good.

Impersonation level for primary token duplication: when duplicating to TokenPrimary, the impersonation level parameter still must be supplied; SecurityImpersonation is typical. MSDN: "To create a primary token, the impersonation level is ignored"? Actually for DuplicateTokenEx, if TokenType is TokenPrimary, the ImpersonationLevel parameter is still passed but the resulting primary token doesn't use it for impersonation... To avoid overclaiming, I'll say the material's notes describe DuplicateTokenEx producing the duplicate and that the token type parameter selects TokenPrimary for process creation vs TokenImpersonation for thread impersonation. Keep impersonation-level detail minimal: "an impersonation level (e.g., SecurityImpersonation)". That's standard MSDN contract; safe.

CreateProcessWithTokenW requires SeImpersonatePrivilege — MSDN: "The caller must have the SE_IMPERSONATE_NAME privilege" — actually the requirement: CreateProcessWithTokenW requires SE_IMPERSONATE_NAME. Note 5 mentions SeImpersonatePrivilege as one of the structures/concepts. Hmm, note 5: "operates on Windows token structures (TOKEN_PRIMARY, TOKEN_IMPERSONATE, SeImpersonatePrivilege)". So SeImpersonatePrivilege is named in the notes. Safe to state the requirement as MSDN-documented.

CreateProcessAsUserW requires SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege (MSDN). Note 3 mentions CreateProcessAsUser. I can mention it as alternate with its stronger privilege requirement — that's why CreateProcessWithTokenW is the lab's choice. Is that overreach? MSDN documents SeAssignPrimaryTokenPrivilege requirement for CreateProcessAsUserW. It's well-established. I'll state it briefly.

Integrity level SIDs: material says "S-1-16-0x0" format (privesc units 3-4 key cues: "S-1-16-0x0"). The actual RIDs: Untrusted S-1-16-0x0 (0), Low 0x1000 (4096), Medium 0x2000, High 0x3000, System 0x4000, Protected 0x5000. Material gives "S-1-16-0x0" and the six levels 0-5. I'll describe: mandatory-label SIDs of the form S-1-16-<rid>, where the RID encodes the level (0x0 Untrusted through 0x5000 Protected). The 0x1000 increments are well-established (WINDOWS INTERNALS/MSDN SECURITY_MANDATORY_* constants). Safe.

Also: "Tokens can have an integrity level (IL) tied to them, which can be queried using th[e GetTokenInformation API]" — material. Good.

One more internals point: the theft works because OpenProcessToken's access check is against the token object's DACL and the caller's privileges; a High-IL caller with SeDebugPrivilege enabled passes the check for TOKEN_DUPLICATE on a SYSTEM process's token. And winlogon.exe runs at System IL (material units: "System services and processes; wininit, winlogon, lsass").

Also the impersonation variant: thread gets impersonation token via ImpersonateLoggedOnUser or SetThreadToken; RevertToSelf drops it. Note 2 names ImpersonateLoggedOnUser. RevertToSelf is standard pairing — MSDN. Fine.

Now Detection: note 6 says "Kernel-Process TokenOpen ETW events" — provider Microsoft-Windows-Kernel-Process, event for token open (EID 10 exists in some channels? Microsoft-Windows-Kernel-Process/Analytic has EVENT_ID 10 for token open? I recall "Kernel-Process" ETW event ID 10 is TokenOpen in the Microsoft-Windows-Kernel-Process provider used by MDE/Sigma "win_token_abuse". Sigma rule "Access Token Manipulation" uses Microsoft-Windows-Kernel-Process/Analytic Event ID 10. That's fairly well-established publicly. But rule 4 says don't fabricate ETW provider GUIDs; event IDs for ETW — the note doesn't give an ID. I'll write: provider Microsoft-Windows-Kernel-Process (event ID not documented in material; publicly tracked as the TokenOpen event, GUID not documented in material). Hmm — safer to just say "Kernel-Process TokenOpen ETW events (provider/event IDs not further specified in the material)". That complies.

4688: "4688 High Mandatory Level without consent UI" — Security event 4688 (process creation) with TokenElevationType/ Mandatory Label showing High/System without a consent.exe/UAC prompt correlation. State it as note 6 states.

Tradecraft from note 6: "which source PID to target, which access mask to request, how to clean up duplicated handles" — include under bypass options as material-described operator considerations.

Residual artifacts: I must not invent beyond reason. From the mechanism itself + notes: handles to donor process/token (note 6 cleanup implies they linger if not closed); child process with SYSTEM IL and implant as parent visible in 4688 (note 6); SeDebugPrivilege left enabled in own token (mechanism step 1 — a token-state artifact, factual). These are reasonable and trace to notes/mechanism.

Word budget. Let me write it now.

Draft:

---

Summary (~120 words)

Mechanism (~350 words, 8 steps)

OS Internals (~400 words)

Key Implementation Details (~200 words)

Why It Matters (~110 words)

Detection (~180 words)

Related (~110 words)

Total ~1470 + refs. Good.

Let me be careful about step numbering being concrete actions.

Mechanism steps:

1. Enable SeDebugPrivilege in the implant's own primary token. OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hSelfTok); LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid); populate TOKEN_PRIVILEGES (PrivilegeCount=1, Privileges[0].Luid=luid, Attributes=SE_PRIVILEGE_ENABLED); AdjustTokenPrivileges(hSelfTok, FALSE, &tkp, 0, NULL, NULL). The material presents this LookupPrivilegeValue → OpenProcessToken → AdjustTokenPrivileges sequence as the programmatic privilege-adjustment path and notes AdjustTokenPrivileges is the final step that flips a present-but-disabled privilege to Enabled.

2. Enumerate running processes and select a donor at System integrity level. The material names winlogon.exe alongside wininit and lsass as System-IL processes; enumeration uses CreateToolhelp32Snapshot (Lab 2.3). The notes flag source-PID selection as an operator decision — a stable, long-lived SYSTEM process is preferred... hmm "preferred" — is that in the material? Note 6 says "which source PID to target" is a tradecraft consideration. I'll say: the notes identify donor-PID choice as a tradecraft decision without prescribing a specific target beyond the material's winlogon.exe example.

3. OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, donorPid) → hDonor. With SeDebugPrivilege enabled, the access check against a SYSTEM process's EPROCESS succeeds; without it, OpenProcess on winlogon.exe fails for a High-IL admin. (privesc units 24-27.)

4. OpenProcessToken(hDonor, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hDonorTok). Material: "Obtains a handle to a process' access token," BOOL return; "You cannot change any privileges in a token without having a handle to it. The OpenProcessToken gets you that token handle." Access mask choice is a tradecraft decision (note 6): TOKEN_DUPLICATE is the minimum needed for the next step.

5. DuplicateTokenEx(hDonorTok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hPrimary). Produces a new token object — a copy of the donor's token, requested with MAXIMUM_ALLOWED per the cluster description — typed TokenPrimary so it can be assigned to a child process. Same call with TokenImpersonation yields the impersonation-token variant.

6a. Spawn path: CreateProcessWithTokenW(hPrimary, 0, lpApplicationName, ...) creates the child running under the stolen token — the notes describe spawning a System-IL child from the High-IL admin context. Caller needs SE_IMPERSONATE_NAME (SeImpersonatePrivilege), which admins hold. Note 3 records CreateProcessAsUser as the alternate spawn API (which additionally requires SeAssignPrimaryTokenPrivilege).

6b. Impersonate path: ImpersonateLoggedOnUser(hDupImp) attaches the donor's security context to the calling thread; the thread then acts as SYSTEM for subsequent object access until RevertToSelf. Note 2 names the MakeToken/ImpersonateLoggedOnUser/DuplicateTokenEx primitive family.

7. Close handles: CloseHandle(hPrimary), CloseHandle(hDonorTok), CloseHandle(hDonor). Note 6 lists duplicated-handle cleanup as an explicit tradecraft item; leaked handles to a SYSTEM token are a forensic artifact.

OS Internals Context paragraphs:

Para 1 — token anatomy: Access tokens are issued after successful authentication; every process created after logon carries a primary token tied to the user. Contents enumerated by the material: user SID and logon SID, privileges, default DACL, and a type flag distinguishing primary from impersonation. Privileges live in TOKEN_PRIVILEGES as an array of LUID_AND_ATTRIBUTES — a LUID identifying the privilege plus attribute bits (SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_REMOVED, SE_PRIVILEGE_USED_FOR_ACCESS). Enabled vs Disabled: High-IL tokens carry many privileges present-but-disabled, flippable on the fly via AdjustTokenPrivileges; standard users hold little beyond SeChangeNotifyPrivilege enabled.

Para 2 — integrity levels: Six levels, Untrusted(0) through Protected(5), queryable via GetTokenInformation(TokenIntegrityLevel); the token stores the IL as a mandatory-label SID of the form S-1-16-<rid>. System IL hosts wininit, winlogon, lsass; Protected is settable only by kernel-mode callers. MIC blocks lower-IL processes from writing to higher-IL objects, but the theft path requests query/duplicate-style access, which a High-IL caller with SeDebugPrivilege obtains — SeDebugPrivilege effectively neutralizes the per-process access check, which is why step 1 gates the whole chain.

Para 3 — kernel view & duplication semantics: A token is a securable executive object; the process object (EPROCESS) holds a reference to its primary token, and threads optionally reference an impersonation token. DuplicateTokenEx allocates a new token object that shares the donor's logon session (same authentication ID); the copy therefore authenticates as NT AUTHORITY\SYSTEM wherever the donor did, and it survives independently of the donor handle's lifetime until its own last handle closes. TokenPrimary vs TokenImpersonation is chosen at duplication time and cannot be flipped afterward — a primary token cannot be used for thread impersonation and an impersonation token cannot be assigned to a process; CreateProcessWithTokenW vs ImpersonateLoggedOnUser each demand the matching type (MSDN contract).

Is "shares the donor's logon session (same authentication ID)" well-established? Yes — token duplication copies the token including AuthenticationId; logon sessions keyed by LUID (Windows Internals 7ed). Fine.

Key Implementation Details:

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C/C++ (SEC670 Lab 3.5 "TokenThief" source review).

Two files surfaced by keyword grep were checked and rejected. `dark_crystal/crates/core/src/escalation/uac.rs` calls OpenProcessToken only on GetCurrentProcess() with TOKEN_QUERY to read TokenElevation for a self-elevation check — no foreign token is opened. `dark_crystal/crowd/src/persist/phantom_restart.rs` calls OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) to enable SeShutdownPrivilege on its own token — the same LookupPrivilegeValueW → AdjustTokenPrivileges shape as step 1, but no cross-process token access and no duplication. Neither implements this technique.

An implementation would follow the vault's existing FFI pattern: windows_targets::link! bindings for DuplicateTokenEx and CreateProcessWithTokenW alongside wrappers.rs, a donor-PID resolver over CreateToolhelp32Snapshot (as ppid.rs already does for parent lookup), a SeDebugPrivilege-enable helper mirroring phantom_restart.rs's enable_shutdown_privilege, and RAII guards that close the donor process handle and both token handles on drop. 

Why It Matters:

The vault's elevation coverage stops at High IL — T-021's slui.exe bypass and T-023's CMSTP bypass both convert Medium to High via auto-elevation; neither reaches SYSTEM. Token theft is the High→System step and the material explicitly frames it as the backend of Meterpreter's getsystem. It operates on token objects rather than injected memory (T-013) or creation attributes (T-015), so it composes with any downstream execution or capability — T-023's LSASS dump presumes exactly the SeDebugPrivilege/SYSTEM context this technique delivers. No UAC consent UI appears anywhere in the chain, removing the user-interaction dependency that constrains auto-elevation.

That's 4 sentences. Good.

Detection Considerations:

The training notes (note 6) record a specific detection footprint; other telemetry below is limited to what the material states.

- Telemetry sources: token-open activity is visible through Kernel-Process TokenOpen ETW events (provider and event IDs not further specified in the material); Security event 4688 process-creation records a child running at High/System Mandatory Level with no corresponding consent-UI (UAC prompt) activity, which is the anomaly the notes flag. The material documents no Sysmon event IDs or additional providers for this technique.
- Bypass options: the notes list three operator-controlled variables — donor PID selection, the access mask requested from OpenProcessToken (minimal masks such as TOKEN_DUPLICATE instead of broad rights), and prompt closure of duplicated handles.
- Residual artifacts: during the theft window the implant holds handles to the donor process and its token; the spawned child appears in process-creation telemetry with SYSTEM integrity parented to the implant; SeDebugPrivilege remains enabled in the implant's own token after step 1 unless explicitly re-disabled.

Related Techniques:

- **T-015 PPID Spoofing** — T-015 forges the parent-process attribute at process creation; T-043 forges the token the new process receives. Same T1134 family, different creation parameter; the notes position token duplication as the distinct primitive PPID spoofing does not cover.
- **T-021 Cryptography and Obfuscation** — hosts the slui.exe UAC bypass that reaches High IL; T-043 is the follow-on that converts High-IL admin context into SYSTEM.
- **T-023 Client Capabilities** — privileged capabilities there (LSASS dump via MiniDumpWriteDump, CMSTP UAC bypass) require SeDebugPrivilege or SYSTEM context; token theft supplies that context, and the notes flag that token logic is currently only implicit in T-023.

References:

- Atlas material: atlas-binary-analysis-part4.md, atlas-labs-part2.md, atlas-post-exploit-part4.md, atlas-post-exploit-part14.md, atlas-post-exploit-part16.md, atlas-privesc-part1.md
- MITRE ATT&CK: T1134.001 Token Impersonation/Theft (https://attack.mitre.org/techniques/T1134/001/); T1134.002 Create Process with Token (https://attack.mitre.org/techniques/T1134/002/)
- LGTM notes: the six IDs
- Public references: SANS SEC670 Lab 3.5 "TokenThief" (source-review lab); Meterpreter getsystem command (named in the material as the technique's backend implementation)

Source Reference:

No current implementation. See atlas material and MITRE reference for public tooling. Grep-matched files `dark_crystal/crates/core/src/escalation/uac.rs` and `dark_crystal/crowd/src/persist/phantom_restart.rs` were verified to use OpenProcessToken only against the current process and do not implement this technique.

Hmm — the Source Reference template: "If no source: 'No current implementation. See atlas material and MITRE reference for public tooling.'" I'll keep close to that with the verification note appended (justified by rule 8).

Now check H1 format: `# <Technique Name> — <One-Line Purpose>`.

`# Token Theft via OpenProcessToken and Duplication — Steal a SYSTEM Token and Spawn Under It`

Name in frontmatter: "Token Theft (TokenThief) via OpenProcessToken and Duplication" — canonical. 7 words. OK.

Word count check — let me estimate: Summary ~130, Mechanism ~430, OS Internals ~420, Key Impl ~230, Why ~120, Detection ~200, Related ~120, References don't count toward body (they do count as body content? "excluding frontmatter and headers" — references and source reference count as body I think). Total body ~1650+. Within target.

Check banned words in draft: "clean" — I removed. "notable" — no. "robust" — no. "elegant" — no. "textbook" — no. "essentially" — check... I wrote "effectively neutralizes" instead. Good. "the key insight" — no. "worth noting" — no. "interestingly" — no. Exclamation marks — none. First person — none. Rhetorical questions — none.

Rule: don't define widely-known terms (PEB, syscall, RVA, DLL). I define access token contents — that's technique-specific, fine.

One thing: "MAXIMUM_ALLOWED per the cluster description" — slightly awkward; rephrase: "requested with MAXIMUM_ALLOWED rights, per the consolidated description". Or just state it as the described mask. The cluster spec IS material. Fine.

Check frontmatter enum: category `privesc` — yes in enum. tier A. crate: none. 

mitre_secondary format: `[T1134.002]`.

Tags: [token-theft, privilege-escalation, openprocesstoken, duplicatetokenex, createprocesswithtokenw, impersonation, sedebugprivilege, integrity-levels, admin-to-system, access-tokens] — 10 entries, kebab-case. Good.

member_notes exact list from spec — copy exactly.

One more check on the "Mechanism" — material grounding for step 6a "child running under the stolen token": cluster spec says "CreateProcessWithTokenW to spawn child with stolen token's privilege level. Enables Admin-to-SYSTEM". Note 4: "spawn a System-IL child from a High-IL admin context". Good.

For OpenProcess access mask: material privesc unit 21 mentions PROCESS_QUERY_INFORMATION in key cues ("OpenProcessToken, process token handle, AdjustTokenPrivileges, PROCESS_QUERY_INFORMATION"). Good — PROCESS_QUERY_INFORMATION is named in material.

For CreateToolhelp32Snapshot enumeration — part16 unit 16 (Lab 2.3 CreateToolhelp). Good.

For winlogon.exe as donor — note 1: "open a SYSTEM token on winlogon.exe"; material part4 units 16-17 mention winlogon.exe IL; privesc units 3-4 list winlogon among System-IL processes. Good.

AdjustTokenPrivileges parameter list from privesc unit 1: TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength. I can include exact signature. OpenProcessToken signature from part4 unit 20 / privesc unit 21: ProcessHandle, DesiredAccess, TokenHandle.

DuplicateTokenEx signature: not in material explicitly (material notes name it). Signature from MSDN: (ExistingTokenHandle, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, DuplicateTokenHandle). Well-established MSDN — allowed.

CreateProcessWithTokenW signature: (hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation). I won't enumerate all params, just name it.

OK. Also should the card mention "TokenThief" lab explicitly in Summary/Mechanism — yes, in Summary and References.

Potential subtlety: note 3 says sequence "OpenProcess with SeDebugPrivilege -> OpenProcessToken -> DuplicateTokenEx -> CreateProcessAsUser". Cluster consolidated says CreateProcessWithTokenW. I'll present CreateProcessWithTokenW as primary (consolidated description + note 4 + note 6) and CreateProcessAsUser as the recorded alternate (note 3).

Also mention impersonation for lateral movement (notes 2, 6 mention lateral movement) — in Why It Matters or mechanism variant. Note 2: "operational use for lateral movement and privilege escalation". I'll reference in Why It Matters briefly. Wait — Why It Matters limited to 2-4 sentences. I have 4. I could fold lateral movement into sentence 2 or 4. Let me restructure:

Sentence 1: fills High→SYSTEM gap left by UAC bypass cards.
Sentence 2: operates at token layer, composes with any execution primitive; conceptual basis of Meterpreter getsystem per material.
Sentence 3: doubles as lateral-movement primitive via impersonation of logged-on domain tokens (notes 2/6).
Sentence 4: no consent UI anywhere in chain → no user-interaction dependency.

"impersonation of logged-on domain tokens" — hmm, token theft from a process running as a domain user yields that user's token usable for network auth only if... actually impersonation tokens for network access need delegation-level credentials; CreateProcessWithTokenW gives local context. The notes say "lateral movement" loosely. I'll say "the notes also record it as a lateral-movement primitive through thread impersonation" — attribute to notes, keep vague as the notes are vague. Safe.

Length check on Mechanism — 8 numbered steps might be long but the rule says don't truncate. Fine.

Also ensure I mention T-013? Note 4 would_relate_to includes T-013, but cluster spec's would_relate_to for the CARD is ['T-021', 'T-023', 'T-015']. Rule 9: only reference cards from the would_relate_to list or explicitly discussed in related T-NNN cards provided. So only T-021, T-023, T-015. I mention T-013 in Why It Matters prose ("rather than injected memory (T-013)") — is that a cross-reference violation? The Related Techniques section is the cross-reference section; mentioning T-013 in prose as a contrast... safer to drop the T-013 mention to comply strictly with rule 9. I'll rephrase: "operates on token objects rather than on injected memory or creation attributes" without the T-013 tag. Actually mentioning T-015 there is fine since it's in the list. I'll say "rather than process memory injection or the parent-attribute manipulation of T-015".

Let me also double check "SECURITY_MANDATORY" — I won't cite constants.

"MIC blocks lower-IL processes from writing to higher-IL objects" — well-established (Windows Integrity Mechanism, No Write Up). Fine.

Also "EPROCESS holds a reference to its primary token" — Windows Internals documented (EPROCESS.Token field, EX_FAST_REF). I'll phrase generally: "the kernel's process object references the primary token; each thread may additionally reference an impersonation token". Avoid naming EPROCESS field offsets. Actually naming EPROCESS is fine per template's structure list.

Now finalize exact YAML. Also `origin: atlas-synthesis` per template.

Write final output — one markdown file, nothing else.