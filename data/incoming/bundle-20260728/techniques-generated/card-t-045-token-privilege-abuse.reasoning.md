Let me analyze the inputs carefully.

**Cluster spec**: T-045 — Token Privilege Abuse: SeDebugPrivilege and Privilege Manipulation. Category: privesc. Tier: A. Member note: `lgtm:token-privilege-abuse-proposed-technique`. would_relate_to: T-016, T-023.

**Related cards provided**: T-016 (EDR Evasion Suite) and T-023 (Client Capabilities Suite). I need to cross-reference these. T-023 mentions LSASS dump via MiniDumpWriteDump with PROCESS_ALL_ACCESS — that's where SeDebugPrivilege comes in (enabling SeDebugPrivilege allows opening lsass with PROCESS_ALL_ACCESS). T-016 references handle operations.

**Matching Rust source files**: Two files were included:
1. `src/dark_crystal/crowd/src/persist/phantom_restart.rs` — This contains `enable_shutdown_privilege()` which uses OpenProcessToken + LookupPrivilegeValueW + AdjustTokenPrivileges to enable **SeShutdownPrivilege**. This is a real, verified use of the AdjustTokenPrivileges mechanism — the exact same API pattern (OpenProcessToken with TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, LookupPrivilegeValueW, AdjustTokenPrivileges with SE_PRIVILEGE_ENABLED). But it enables SeShutdownPrivilege, not SeDebugPrivilege. Does this count as implementing the technique? The card is about "Token Privilege Abuse: SeDebugPrivilege and Privilege Manipulation" — the core mechanism is AdjustTokenPrivileges-based privilege enablement. The phantom_restart.rs file implements the privilege-enablement primitive (for SeShutdownPrivilege as part of persistence). Per rule 8: "for the file to count as an implementation of this technique, at least ONE function in it must implement the primary mechanism the card describes." The primary mechanism is AdjustTokenPrivileges to enable privileges in the current token. `enable_shutdown_privilege()` does exactly that. So I can reference it as a partial implementation — it implements the AdjustTokenPrivileges primitive but for SeShutdownPrivilege in the persistence context, not the full SeDebug/SeBackup/SeRestore/token-stealing chain. I should be precise about this.

2. `src/dark_crystal/crowd/src/persist/schtask.rs` — This is scheduled task persistence via COM ITaskService. It does NOT implement token privilege manipulation. No AdjustTokenPrivileges, no privilege enablement. It matched the grep probably on "privilege" keywords in comments (e.g., "Run level: TOKEN (sin elevación — invisible para UAC)" and "LeastPrivilege"). This is a false match for this technique — I should not attribute it.

So: `source_file` in frontmatter — hmm. The phantom_restart.rs does implement the AdjustTokenPrivileges primitive. But the file's primary role is persistence (T-017 territory per the manifest — "PhantomPersist + 30-min monitor" maps to T-008-persistence in the old manifest). Should I list it as source_file? The rule says verify whether the file actually implements the technique. The technique's primary mechanism per the cluster spec: "Token privilege abuse via AdjustTokenPrivileges to enable privileges in current token (SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeImpersonatePrivilege)." phantom_restart.rs implements AdjustTokenPrivileges to enable a privilege in the current token — SeShutdownPrivilege. That's the same mechanism, different privilege, in service of persistence rather than the escalation chain. I think the honest approach: reference it in Key Implementation Details as the only in-source use of the AdjustTokenPrivileges primitive, note it enables SeShutdownPrivilege (not SeDebug/SeBackup/SeRestore), and state that the full privilege-abuse chain (SeDebug → OpenProcess, SeBackup/SeRestore ACL bypass, token stealing) has no dedicated implementation. For frontmatter `source_file`, I could put the phantom_restart.rs path since it does contain a verified AdjustTokenPrivileges implementation... but that might mislead since the file is a persistence module. Let me think.

The frontmatter field is `source_file: <relative path from repo root, or "none">`. The manifest in system context maps files to cards. If I put phantom_restart.rs, that claims this file implements T-045. It implements the primitive but not the technique's purpose (privilege escalation via SeDebug etc.). The safer, more honest option: `source_file: none` with explanation in Key Implementation Details that the AdjustTokenPrivileges primitive appears in phantom_restart.rs (for SeShutdownPrivilege, persistence context), but no dedicated implementation of the SeDebug/SeBackup/SeRestore/token-stealing chain exists. Hmm, but rule says "False attribution is worse than 'no current implementation'". Given the file genuinely contains the exact API sequence that is the foundation of this technique, I think mentioning it in the body is right, but the frontmatter source_file... The template says "source_file: <relative path from repo root, or 'none'>". 

Actually, let me reconsider. The card documents "Token Privilege Abuse: SeDebugPrivilege and Privilege Manipulation". The mechanism steps would be: OpenProcessToken(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) → LookupPrivilegeValueW → AdjustTokenPrivileges with SE_PRIVILEGE_ENABLED → then use the privilege (OpenProcess on lsass for SeDebug; open files with FILE_FLAG_BACKUP_SEMANTICS for SeBackup/SeRestore; DuplicateTokenEx for SeImpersonate/token stealing). phantom_restart.rs implements steps 1-3 for SeShutdownPrivilege. That's a partial implementation of the general primitive. I'll set `source_file: none` and explain precisely in Key Implementation Details — that's the most accurate. Actually wait — would it be better to list the path? The instruction: "If the source truly implements it, reference the file. If not, ignore the file and state 'no current implementation in source.'" The file implements a related primitive but not the technique as scoped (SeDebug/SeBackup/SeRestore/SeImpersonate abuse chain). The schtask.rs definitely does not. I'll reference phantom_restart.rs in the body as containing the shared primitive with exact function names, but keep frontmatter `source_file: none` and `crate: none`... hmm, crate: if source_file is none, crate should probably be none too. The template enum: dark_crystal|client_rust|none. Since no dedicated implementation, `crate: none`.

Hmm, but actually, let me reconsider once more. The Key Implementation Details section has two branches: (a) verified source implements → reference file/functions; (b) no source → write the "No current implementation" sentence + describe what implementation would look like. My situation is hybrid. I think the cleanest compliant approach: treat it as "no dedicated implementation" — write the required sentence, then note the partial primitive in phantom_restart.rs, then describe what a full implementation would look like. That covers both honestly.

**Atlas material**: The relevant units for this card:
- Unit 5, 6, 12: EnableDebug function — BOOL EnableDebug(HANDLE Token, LPCTSTR Privilege, BOOL EnablePrivilege), AdjustTokenPrivileges returning TRUE/FALSE.
- Unit 13: AdjustTokenPrivileges full signature: TokenHandle, DisableAllPrivileges, NewState (PTOKEN_PRIVILEGES), BufferLength, PreviousState, ReturnLength. "really the last and final step."
- Unit 14: token stealing lab — steps and APIs for stealing a token to escalate privileges.
- Unit 28/29: review question — SE_RESTORE_NAME gives complete write access regardless of ACL (the question lists SE_BACKUP_NAME, SE_RESTORE_NAME, SE_WRITE_NAME; unit 40 answers: SE_BACKUP_NAME → complete read access regardless of ACL; SE_RESTORE_NAME → complete write access regardless of ACL).
- Unit 32: Why escalate — non-admin vs admin, SeDebugPrivilege for process handles.
- Unit 33/34: Windows privileges, enabled vs disabled states. "Enabled: privilege is present and set in your token. Disabled: present but not set; could be enabled." SeDebugPrivilege required for obtaining process handles.
- Unit 35/36: SE_PRIVILEGE_* attributes: SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_REMOVED, SE_PRIVILEGE_USED_FOR_ACCESS. LUID_AND_ATTRIBUTES structure. "Privileges are tied to what can be done, not to an object."
- Unit 37: integrity levels (Untrusted 0 → Protected 5), GetTokenInformation.
- Unit 38/39: whoami /priv output for non-admin: SeChangeNotifyPrivilege enabled, SeShutdownPrivilege disabled, etc.
- Unit 40: SE_BACKUP_NAME/SE_RESTORE_NAME bypass ACLs — read and write respectively.

MITRE: best fit — T1134 Access Token Manipulation. Specifically T1134.001 (Token Impersonation/Theft) for token stealing, and T1134.002 (Create Process with Token). But the AdjustTokenPrivileges/SeDebugPrivilege enablement itself maps to T1134 (Access Token Manipulation) parent. ATT&CK also has T1548 (Abuse Elevation Control Mechanism) but that's UAC bypass. The cluster is "privilege abuse via AdjustTokenPrivileges" — T1134 is the best single fit. Secondary: T1134.001, T1134.002. Format: mitre: T1134, mitre_secondary: [T1134.001, T1134.002].

Tags: 5-10 kebab-case: [token-privileges, adjusttokenprivileges, sedebugprivilege, sebackupprivilege, serestoreprivilege, seimpersonateprivilege, token-theft, lpe, access-token, privilege-escalation] — that's 10, good. Maybe trim to 9.

Tier: A (per spec). Category: privesc.

**Mechanism section** — numbered steps:
1. Enumerate current privileges: whoami /priv or GetTokenInformation(TokenPrivileges) to see which privileges are present-but-disabled (a privilege must be present in the token to be enabled; AdjustTokenPrivileges cannot add privileges not granted to the account).
2. OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken).
3. LookupPrivilegeValueW(NULL, SE_DEBUG_NAME / "SeDebugPrivilege", &luid) — resolve privilege name to LUID.
4. Populate TOKEN_PRIVILEGES { PrivilegeCount = 1, Privileges[0].Luid = luid, Privileges[0].Attributes = SE_PRIVILEGE_ENABLED }.
5. AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL) — check both return value and GetLastError() == ERROR_SUCCESS (ERROR_NOT_ALL_ASSIGNED means privilege not present).
6. Weaponize per privilege:
   - SeDebugPrivilege → OpenProcess(PROCESS_ALL_ACCESS / PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, lsass.exe or any PID) — kernel's access check grants when SeDebugPrivilege enabled.
   - SeBackupPrivilege → CreateFile with FILE_FLAG_BACKUP_SEMANTICS + read any file regardless of ACL (read SAM/SYSTEM hives).
   - SeRestorePrivilege → write access regardless of ACL; also enables taking ownership, restoring files/registry.
   - SeImpersonatePrivilege → token impersonation/theft: OpenProcessToken on a SYSTEM process, DuplicateTokenEx, ImpersonateLoggedOnUser or CreateProcessWithTokenW.

Wait — the material (unit 40) says SE_BACKUP_NAME grants complete read regardless of ACL, SE_RESTORE_NAME complete write regardless of ACL. Unit 28 poses the question. Material wins — I'll state what material says.

Unit 14 mentions "token stealing" as a lab. The cluster description mentions SeImpersonatePrivilege enables token stealing. Material doesn't detail the token-stealing API steps explicitly beyond "explore the steps and APIs involved with stealing a token." I can describe the canonical chain (OpenProcess → OpenProcessToken → DuplicateTokenEx → ImpersonateLoggedOnUser/CreateProcessWithToken) as well-established Windows documentation — rule 4 allows "well-established Windows internals documentation (Windows Internals 7ed, MSDN, ntdll headers)". That's fine.

**OS Internals Context**: 
- Access token structure: privileges stored as array of LUID_AND_ATTRIBUTES in the token (TOKEN_PRIVILEGES). Each entry: LUID (locally unique identifier, 64-bit, assigned at boot — not stable across reboots, hence LookupPrivilegeValue), Attributes bitmask.
- SE_PRIVILEGE_ENABLED (0x2), SE_PRIVILEGE_ENABLED_BY_DEFAULT (0x1), SE_PRIVILEGE_REMOVED (0x4), SE_PRIVILEGE_USED_FOR_ACCESS (0x80000000). From unit 35.
- Privileges vs rights: privileges are system-related operation rights tied to account, not object ACLs (unit 34/35: "not necessarily tied directly to an object, but rather tied to what can be done").
- Enabled vs Disabled state (units 33/34): present-and-set vs present-but-not-set. A privilege can only be enabled if it exists in the token; AdjustTokenPrivileges returns ERROR_NOT_ALL_ASSIGNED otherwise.
- Kernel access check: SeDebugPrivilege is checked in the process-open path — when SeDebugPrivilege is enabled in the calling thread's token, the access check for OpenProcess grants requested access regardless of target's DACL (except PPL — Protected Process Light; material doesn't mention PPL... rule: don't invent. PPL is well-established Windows internals; I can mention it as a documented boundary. Windows Internals documents that SeDebugPrivilege doesn't bypass PPL. That's fair and useful. Actually let me be careful — is it worth it? A reader with Win Internals knowledge should learn something. The PPL caveat is a real operational constraint on SeDebugPrivilege. I'll include one sentence, framed as documented behavior.)
- SeBackup/SeRestore: checked by the I/O manager when FILE_FLAG_BACKUP_SEMANTICS is passed; the object manager grants ACCESS_SYSTEM_SECURITY-ish bypass... Actually the mechanism: CreateFile with FILE_FLAG_BACKUP_SEMANTICS signals backup intent; NTFS checks for SeBackupPrivilege (read) / SeRestorePrivilege (write) instead of the file DACL. Well-established.
- Token stealing: token is a kernel object; DuplicateTokenEx creates a new token from an existing one; SecurityImpersonation vs TokenImpersonation levels; primary vs impersonation tokens. SeImpersonatePrivilege is required to impersonate a token after capture (ImpersonateLoggedOnUser checks it — actually, the impersonation of a token requires SeImpersonatePrivilege unless the token's authentication ID matches the caller's... there's nuance: after Windows XP SP2-ish, impersonating requires SeImpersonatePrivilege). Keep it to what's well established: CreateProcessWithTokenW requires SeImpersonatePrivilege. That's documented MSDN.
- LUID not stable across boots → LookupPrivilegeValue needed. Material doesn't say this but it's well-established.
- whoami /priv (units 38/39) shows non-admin tokens carry few privileges, mostly disabled (SeShutdownPrivilege disabled).

**Detection**: Material does NOT discuss detection for this technique. Per rule: write "Training material does not discuss detection for this technique." But the template says the Detection section lists telemetry sources, bypass options, residual artifacts "the training material describes". If material doesn't cover it, I write the single line. Should I add anything from well-established knowledge? Rule 4 + template say don't invent detections. The template's exact instruction: "If the material does not cover detection for this technique, write: `Training material does not discuss detection for this technique.`" — I'll write that line, and I think it's acceptable to add a sentence pointing to T-016's coverage of handle-access telemetry? Hmm, T-016 is evasion, not detection of token manipulation. Better keep it minimal: the single line. Maybe add that T-016 documents evasion primitives (block-handle etc.) that interact with this surface? The related card T-016 includes "Block External Handles" which is about blocking others from opening handles to us — not detection. I'll keep the Detection section to the mandated line, possibly with one sentence noting the adjacency. Actually the instruction is pretty explicit: write that line. I'll write just that line to be safe. Hmm, but it says "Do not invent detections" — writing only the line is safest and compliant.

**Why It Matters**: Why a standalone card vs footnote on T-016/T-023? The AdjustTokenPrivileges → SeDebugPrivilege chain is a reusable primitive across escalation scenarios independent of injection or evasion — per the cluster note. T-016 references handle operations implicitly (block external handles) but never covers enabling privileges on one's own token. T-023's LSASS dump assumes PROCESS_ALL_ACCESS on lsass without documenting the privilege enablement that makes it possible on a non-SYSTEM token. So this card fills the gap: the privilege-enablement layer that gates downstream capabilities.

**Related Techniques**:
- T-016 EDR Evasion Suite — SeDebugPrivilege-enabled OpenProcess is the handle-acquisition path that T-016's handle-blocking and NTDLL-unhooking primitives intersect with; T-016 references SeDebugPrivilege implicitly through handle operations.
- T-023 Client Capabilities Suite — the LSASS dump capability (MiniDumpWriteDump with PROCESS_ALL_ACCESS) depends on SeDebugPrivilege being enabled in the calling token; UAC bypass (CMSTP) produces a token whose privileges then must be enabled.

Both are justified from the provided cards: T-023 explicitly lists LSASS dump via MiniDumpWriteDump with PROCESS_ALL_ACCESS; T-016 covers block-handle.

**References**: atlas-privesc-part3.md; MITRE T1134 (https://attack.mitre.org/techniques/T1134/), T1134.001, T1134.002; LGTM note lgtm:token-privilege-abuse-proposed-technique; public: SANS SEC670 (named in material), Windows Internals for token structures. Don't invent blog references.

**Source Reference**: "No current implementation..." plus note about phantom_restart.rs partial primitive. Per template: if no source: "No current implementation. See atlas material and MITRE reference for public tooling." I'll adapt: state no dedicated implementation; the AdjustTokenPrivileges primitive appears in crowd/src/persist/phantom_restart.rs (enable_shutdown_privilege) for SeShutdownPrivilege in the persistence path.

**Key Implementation Details**: 
Write: "**No current implementation in the HUGIN source.** This card documents the technique for future implementation..." Then note: the shared primitive (OpenProcessToken + LookupPrivilegeValueW + AdjustTokenPrivileges with SE_PRIVILEGE_ENABLED) is implemented once in the codebase — `dark_crystal/crowd/src/persist/phantom_restart.rs::enable_shutdown_privilege()` — which enables SeShutdownPrivilege to authorize ExitWindowsEx during PhantomPersist's shutdown interception. It demonstrates the exact call pattern but not the escalation-oriented privileges. schtask.rs matched keyword grep but does not implement privilege manipulation — say so? The rule says "If not, ignore the file." I can briefly note it's unrelated... Actually better to just not mention schtask.rs at all, per "ignore the file." Hmm, but being explicit about verification could help. The instruction says ignore. I'll ignore it.

Then describe what an implementation would look like: a generic `enable_privilege(&str) -> bool` helper following the SEC670 EnableDebug signature; a privilege-abuse module with per-privilege weaponization (OpenProcess target for SeDebug, FILE_FLAG_BACKUP_SEMANTICS copy for SeBackup/SeRestore, DuplicateTokenEx chain for SeImpersonate); resolution through existing wrappers (RecycledGate) to keep IAT clean. One paragraph-ish.

**Length**: target 1200-1800 words body. Let me draft with enough depth.

**Frontmatter**:
```yaml
---
id: T-045
name: Token Privilege Abuse: SeDebugPrivilege and Privilege Manipulation
category: privesc
tier: A
crate: none
source_file: none
mitre: T1134
mitre_secondary: [T1134.001, T1134.002]
tags: [adjusttokenprivileges, sedebugprivilege, sebackup-privilege, serestore-privilege, seimpersonate-privilege, token-theft, access-token, lpe]
origin: atlas-synthesis
member_notes: ['lgtm:token-privilege-abuse-proposed-technique']
---
```

Wait — name should be "4-8 words" human readable per template: "Token Privilege Abuse: SeDebugPrivilege and Privilege Manipulation" — that's 8 tokens-ish. Fine.

Tags count: 8 — within 5-10.

**H1**: `# Token Privilege Abuse — Enabling Dormant Token Privileges for Escalation` — one-line purpose.

**Summary** (3-5 sentences, first standalone): Token privilege abuse enables privileges already present-but-disabled in the current process token via AdjustTokenPrivileges, converting group membership into concrete capabilities without any credential theft or exploit. Windows grants accounts privileges (SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeImpersonatePrivilege) that ship in a disabled state and must be explicitly enabled per-token before use. SeDebugPrivilege converts OpenProcess into an all-access pass against arbitrary PIDs, SeBackup/SeRestore bypass file ACLs for read/write, and SeImpersonatePrivilege authorizes token impersonation and theft chains. The technique is a precondition layer for LSASS dumping, service manipulation, and registry hive theft. Detection surface: hmm, material doesn't discuss detection — Summary asks for "primary detection surface" though. I can say something careful: the operations it unlocks (handle opens, privileged file access) are what sensors observe... but rule says don't invent detections. The summary template says include "the primary detection surface." I can phrase from material-adjacent facts: the token manipulation itself is a silent in-memory attribute change; observability falls on the downstream privileged operations. That's a factual statement about the mechanism, not an invented telemetry claim. Acceptable.

**Mechanism** — numbered steps, concrete:
1. Determine token contents (whoami /priv; GetTokenInformation TokenPrivileges class) — identify present-but-disabled privileges. Material: units 34, 38, 39.
2. OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY).
3. LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid) etc.
4. Fill TOKEN_PRIVILEGES / LUID_AND_ATTRIBUTES with Attributes = SE_PRIVILEGE_ENABLED (0x2). Material unit 35 lists the attribute flags.
5. AdjustTokenPrivileges(hToken, FALSE, &newState, 0, NULL, NULL) — full signature from unit 13; "last and final step." Check GetLastError for ERROR_NOT_ALL_ASSIGNED (well-established; material says check BOOL return — units 5/6/12/13).
6. Branch per privilege:
   a. SeDebugPrivilege → OpenProcess(PROCESS_ALL_ACCESS or PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, target PID) — unit 32/34: needed for process handles.
   b. SeBackupPrivilege (SE_BACKUP_NAME) → read any file regardless of ACL (unit 40) — backup-semantics file opens.
   c. SeRestorePrivilege (SE_RESTORE_NAME) → complete write regardless of ACL (units 28/40).
   d. SeImpersonatePrivilege → token stealing chain (unit 14): open a SYSTEM process token, DuplicateTokenEx, impersonate or spawn.
7. Optionally capture PreviousState to restore the prior attribute mask afterward.

**OS Internals Context**:
- Token stores privileges as LUID_AND_ATTRIBUTES array; LUID is boot-local → LookupPrivilegeValue(W) resolves the string name (SE_DEBUG_NAME = "SeDebugPrivilege") to the LUID valid for this boot.
- Attribute bits: SE_PRIVILEGE_ENABLED_BY_DEFAULT 0x1, SE_PRIVILEGE_ENABLED 0x2, SE_PRIVILEGE_REMOVED 0x4, SE_PRIVILEGE_USED_FOR_ACCESS 0x80000000 (unit 35 names them; values are well-established from winnt.h).
- Enabled vs Disabled semantics (units 33/34): Disabled means present, authorized, not set; can be enabled. Enabled means present and set. AdjustTokenPrivileges cannot introduce a privilege the account doesn't hold — ERROR_NOT_ALL_ASSIGNED; non-admin tokens show a short list (units 38/39: SeChangeNotifyPrivilege enabled, SeShutdownPrivilege disabled, SeIncreaseWorkingSetPrivilege disabled...).
- Privileges vs object ACLs (units 34/35): privileges are tied to what can be done (system operations), not tied to an object.
- Kernel side: AdjustTokenPrivileges → NtAdjustPrivilegesToken in ntoskrnl; the change is an in-memory edit to the token object's privilege bitmap (SEP_TOKEN_PRIVILEGES in the TOKEN structure): three 64-bit masks — Present, Enabled, EnabledByDefault. This is well-established (Windows Internals documents Present/Enabled/EnabledByDefault masks in the token). Good depth.
- Access-check behavior: when a thread with SeDebugPrivilege enabled opens a process/thread, the kernel grants the requested access regardless of the target's DACL — that's why unit 34 ties SeDebugPrivilege to "obtaining process handles." Documented boundary: PPL-protected processes (e.g., lsass as PPL) still refuse access even with SeDebugPrivilege — Windows Internals documented. Also opening a handle to a protected process fails.
- Backup/restore semantics: FILE_FLAG_BACKUP_SEMANTICS on CreateFile signals backup intent; the I/O manager then checks SeBackupPrivilege for read / SeRestorePrivilege for write instead of the file's DACL. Well-established + unit 40.
- Token stealing internals (unit 14 territory): tokens are executive objects; OpenProcessToken yields a handle to the target's token; DuplicateTokenEx converts between impersonation and primary tokens (TokenImpersonation vs TokenPrimary); ImpersonateLoggedOnUser applies an impersonation token to the calling thread; CreateProcessWithTokenW spawns with a duplicated primary token and requires SeImpersonatePrivilege. All MSDN-documented.
- Integrity levels are a separate axis (unit 37): privilege enablement does not change IL; a High-IL token is still required for many targets.

**Why It Matters** (2-4 sentences): fills gap per cluster note; reusable precondition across escalation; T-016 assumes handles, T-023 assumes lsass access — this card documents the step that makes those possible from an admin-but-not-SYSTEM token.

**Detection**: mandated line only.

**Related Techniques**:
- T-016 EDR Evasion Suite — relationship: SeDebugPrivilege-gated handle acquisition is the precursor to the handle manipulation T-016 covers (block external handles, NTDLL unhook in remote process); T-016 references SeDebugPrivilege implicitly.
- T-023 Client Capabilities Suite — LSASS dump via MiniDumpWriteDump(PROCESS_ALL_ACCESS) depends on SeDebugPrivilege enablement; CMSTP UAC bypass yields the elevated token whose privileges this technique then enables.

**References**:
- Atlas: atlas-privesc-part3.md
- MITRE: T1134 (https://attack.mitre.org/techniques/T1134/), T1134.001 (https://attack.mitre.org/techniques/T1134/001/), T1134.002
- LGTM: lgtm:token-privilege-abuse-proposed-technique
- Public: SANS SEC670 "Red Teaming Tools: Developing Custom Tools for Windows" (Book 3, Operational Actions) — named in material. Maybe also Microsoft MSDN AdjustTokenPrivileges. Keep minimal.

**Source Reference**: No current implementation as dedicated module; the AdjustTokenPrivileges primitive exists in dark_crystal/crowd/src/persist/phantom_restart.rs (enable_shutdown_privilege, lines ~95-120 area) for SeShutdownPrivilege. See atlas material for SEC670 reference implementation (EnableDebug).

Word count check — I need 1200-1800 body words. My planned content should hit that with the OS Internals section being substantial. Let me write it fully now.

Also note frontmatter rule: `tier: A`. The related cards use "mixed" but enum says S|A|B|C for my card — spec says A. Good.

One more consideration on `crate`: enum is dark_crystal|client_rust|none. Since source_file: none → crate: none. 

Careful with banned words: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable. Avoid "worth noting", "the key insight", "it is important to note", "essentially", "at its core". Third person, declarative.

Check "textbook" — banned. In Key Implementation Details template there's a phrase "deviations from the 'textbook' implementation" — that's in the template instructions, but I shouldn't use the word in output.

Let me draft the card.

Draft:

---
frontmatter as above
---

# Token Privilege Abuse — Enabling Dormant Token Privileges for Local Escalation

## Summary

Token privilege abuse enables privileges that are present-but-disabled in the current process token by calling AdjustTokenPrivileges, converting dormant account rights into active capabilities without any exploit or credential theft. Windows assigns privileges such as SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege, and SeImpersonatePrivilege to accounts and groups, but delivers them in a disabled state; each process must explicitly enable the privilege in its own token before the kernel will honor it (SEC670 units 33-35). Once enabled, SeDebugPrivilege turns OpenProcess into an all-access handle request against arbitrary PIDs, SE_BACKUP_NAME grants read access to any file regardless of its ACL, SE_RESTORE_NAME grants the equivalent write access, and SeImpersonatePrivilege authorizes the token-impersonation and token-theft chain. The AdjustTokenPrivileges call itself is a silent in-memory edit to the token object — observability falls almost entirely on the downstream privileged operations it unlocks.

That's 5 sentences. Good.

## Mechanism

1. Inventory the current token's privileges before attempting escalation. The training material demonstrates this with `whoami /priv` (units 38-39), where a non-admin token shows a short list — SeChangeNotifyPrivilege enabled by default, SeShutdownPrivilege and SeIncreaseWorkingSetPrivilege present but Disabled — while an elevated administrative token carries SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege, and SeImpersonatePrivilege in the Disabled state. Programmatically the same data comes from GetTokenInformation with the TokenPrivileges class.
2. Open the current process token with the rights required for modification: OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken).
3. Resolve the target privilege name to its LUID via LookupPrivilegeValueW(NULL, "SeDebugPrivilege", &luid). LUIDs are assigned per boot, so the string constant (SE_DEBUG_NAME) must be translated at runtime.
4. Populate a TOKEN_PRIVILEGES structure: PrivilegeCount = 1, and a single LUID_AND_ATTRIBUTES entry pairing the resolved LUID with Attributes = SE_PRIVILEGE_ENABLED. Unit 35 enumerates the attribute flags this field accepts: ENABLED, ENABLED_BY_DEFAULT, REMOVED, USED_FOR_ACCESS.
5. Commit the change with AdjustTokenPrivileges(hToken, FALSE, &newState, 0, NULL, NULL) — the full signature in unit 13 takes TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, and ReturnLength. The material calls this "the last and final step" of the sequence (unit 13) and demonstrates the SEC670 reference wrapper EnableDebug(Token, Privilege, EnablePrivilege) returning the BOOL from AdjustTokenPrivileges (units 5, 6, 12). A complete check also inspects GetLastError: ERROR_NOT_ALL_ASSIGNED indicates the privilege was never present in the token and cannot be enabled.
6. Weaponize according to the privilege enabled:
   - SeDebugPrivilege: call OpenProcess with broad access (PROCESS_ALL_ACCESS, or PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) against any non-protected PID — including services and lsass.exe. Units 32 and 34 tie SeDebugPrivilege directly to obtaining process handles that standard users cannot get.
   - SeBackupPrivilege (SE_BACKUP_NAME): open files with backup semantics; the filesystem grants complete read access regardless of the file's ACL (unit 40).
   - SeRestorePrivilege (SE_RESTORE_NAME): the write counterpart — complete write access regardless of the ACL (units 28, 40).
   - SeImpersonatePrivilege: execute the token-stealing chain the material frames as a dedicated escalation lab (unit 14) — open a SYSTEM process, open its token, duplicate it, and either impersonate it on the current thread or launch a new process under it.
7. Optionally pass a PreviousState buffer in step 5 to capture the original attribute mask, then restore it after the privileged operation to leave the token as found.

## OS Internals Context

Token structure and privilege masks. A Windows access token stores its privilege set as an array of LUID_AND_ATTRIBUTES, and the kernel-side TOKEN object maintains three parallel 64-bit privilege masks: Present, Enabled, and EnabledByDefault. AdjustTokenPrivileges (NtAdjustPrivilegesToken in ntoskrnl.exe) flips bits in the Enabled mask — it cannot set a bit that is absent from Present, which is the in-kernel expression of the material's Enabled/Disabled distinction (units 33-34): Disabled means the privilege is authorized and present in the token but not set; Enabled means present and set. SE_PRIVILEGE_REMOVED (0x4) deletes the privilege from the token entirely for the remainder of the logon session — a one-way operation useful for hardening but irrelevant to escalation. SE_PRIVILEGE_USED_FOR_ACCESS (0x80000000) is set by the system to record that the privilege was actually exercised to gain access to an object or service (unit 35).

Privileges versus ACLs. The material draws the line precisely (units 34-35): privileges are not tied to an object, they are tied to what can be done — system-related operations such as loading drivers, changing the time, or debugging processes. The DACL on an object is irrelevant when a privilege check short-circuits it, which is the entire basis of the SeBackup/SeRestore abuse in unit 40.

Kernel access-check behavior for SeDebugPrivilege. When a thread whose token has SeDebugPrivilege enabled calls OpenProcess or OpenThread, the kernel's access check grants the requested access mask regardless of the target process's DACL. This is why unit 34 presents the privilege as the gate for obtaining process handles. The documented boundary is Protected Process Light: PPL-protected targets (lsass.exe when Credential Guard / RunAsPPL is configured) refuse the open even from a SeDebugPrivilege-enabled caller, because the PPL signer check runs ahead of the privilege grant.

Backup semantics in the I/O path. CreateFile accepts FILE_FLAG_BACKUP_SEMANTICS, which signals backup or restore intent to the I/O manager. With that flag, NTFS consults the caller's token for SeBackupPrivilege (read operations) or SeRestorePrivilege (write operations) instead of enforcing the file's DACL — producing the "complete read/write regardless of ACL" behavior the material describes (unit 40). The privilege must be enabled in the token first; a disabled privilege fails the check exactly as if it were absent.

Token theft internals. Tokens are executive objects referenced by handle. The chain unit 14 points at uses OpenProcessToken on a high-privilege process to obtain a handle to its token, DuplicateTokenEx to produce a new token of the desired type (SecurityImpersonation-level impersonation token or a primary token), then either ImpersonateLoggedOnUser to adopt the identity on the current thread or CreateProcessWithTokenW to spawn a child under the duplicated primary token — the latter API itself requires SeImpersonatePrivilege. The impersonation level negotiated at duplication time (SecurityAnonymous through SecurityDelegation) constrains whether the token can be used locally or forwarded across the network.

Integrity level is a separate axis. Unit 37's six integrity levels (Untrusted 0 through Protected 5) do not change when privileges are enabled; a Medium-IL process that enables privileges it somehow holds still fails mandatory-integrity checks against High-IL targets. Privilege enablement composes with — and normally follows — an integrity-raising step such as the UAC bypass material in the same module.

Hmm wait, "a Medium-IL process that enables privileges it somehow holds" — administrative privileges are stripped from the filtered (Medium-IL) token by UAC, so a medium token won't hold SeDebugPrivilege. That's accurate phrasing.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for the reference implementation in C++ (SEC670's EnableDebug wrapper, units 5-6).

The AdjustTokenPrivileges primitive itself appears once in the codebase, in a persistence context rather than an escalation one: dark_crystal/crowd/src/persist/phantom_restart.rs::enable_shutdown_privilege() performs the exact sequence — OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), LookupPrivilegeValueW on "SeShutdownPrivilege", a zeroed TOKEN_PRIVILEGES with PrivilegeCount = 1 and SE_PRIVILEGE_ENABLED, then AdjustTokenPrivileges — to authorize the ExitWindowsEx(EWX_RESTARTAPPS | EWX_FORCE) call inside PhantomPersist's WM_QUERYENDSESSION handler. It demonstrates the call pattern but enables a shutdown privilege, not any of the escalation privileges this card covers.

A dedicated implementation would expose a generic enable_privilege(name: &str) -> bool helper mirroring the SEC670 EnableDebug signature, then layer per-privilege consumers: an OpenProcess(PROCESS_ALL_ACCESS) wrapper for SeDebugPrivilege feeding the injection and credential-harvest paths, a FILE_FLAG_BACKUP_SEMANTICS file-copy path for SeBackup/SeRestore, and a DuplicateTokenEx-based impersonation path for SeImpersonatePrivilege. Routing the NT-level equivalents (NtAdjustPrivilegesToken, NtOpenProcessToken) through the existing RecycledGate dispatcher (T-001) would keep the sequence out of the IAT, consistent with the rest of crowd.

Wait — T-001 reference: I can mention RecycledGate exists; but Related Techniques must only include T-016/T-023 per restraint. Mentioning T-001 inline in Key Implementation Details — the rule says Related Techniques section only references cards from would_relate_to or explicitly discussed. Inline mention is probably fine but safer to phrase without the T-number? The rule 9 is about the Related Techniques section. Inline contextual mention of the existing dispatcher is factual (the vault has it; phantom_restart uses winapi directly though). I'll keep a brief mention without making it a related-technique entry. Actually to be conservative, I can say "the existing indirect-syscall dispatcher" without a T-number. Fine.

## Why It Matters

The vault previously referenced SeDebugPrivilege only implicitly — through T-016's handle operations and T-023's LSASS dump — without documenting the token manipulation that makes those operations possible from an elevated-but-not-SYSTEM context. The AdjustTokenPrivileges + privilege-enablement chain is a standalone precondition layer: it is reusable across injection, credential access, and persistence scenarios and is independent of any specific evasion or exploitation primitive. As a dedicated card it captures the full SEC670 tradecraft block — privilege inventory, enablement, per-privilege weaponization, and token stealing — in one place rather than as scattered assumptions inside other cards.

3 sentences. Good.

## Detection Considerations

Training material does not discuss detection for this technique.

## Related Techniques

- **T-016 EDR Evasion Suite** — T-016 references SeDebugPrivilege implicitly through its handle operations (block external handles, remote NTDLL unhook); this card documents the privilege enablement that authorizes those cross-process handle acquisitions in the first place.
- **T-023 Client Capabilities Suite** — the LSASS dump capability (MiniDumpWriteDump with PROCESS_ALL_ACCESS) requires SeDebugPrivilege enabled in the calling token; the CMSTP UAC bypass produces the elevated token whose disabled privileges this technique then enables.

## References

- Atlas material: atlas-privesc-part3.md (units 5, 6, 12-14, 28, 32-40)
- MITRE ATT&CK: T1134 Access Token Manipulation (https://attack.mitre.org/techniques/T1134/); sub-techniques T1134.001 Token Impersonation/Theft (https://attack.mitre.org/techniques/T1134/001/) and T1134.002 Create Process with Token (https://attack.mitre.org/techniques/T1134/002/)
- LGTM notes: lgtm:token-privilege-abuse-proposed-technique
- Public references: SANS SEC670, "Red Teaming Tools: Developing Custom Tools for Windows," Book 3 — Operational Actions (privilege module); Microsoft documentation for AdjustTokenPrivileges and privilege constants

## Source Reference

No current implementation as a dedicated module. The AdjustTokenPrivileges primitive appears in dark_crystal/crowd/src/persist/phantom_restart.rs (enable_shutdown_privilege, SeShutdownPrivilege for PhantomPersist). See atlas material for the SEC670 EnableDebug reference implementation and the MITRE reference for public tooling.

Now word count. Let me estimate the body: Summary ~180, Mechanism ~450, OS Internals ~480, Key Impl ~230, Why ~110, Detection ~10, Related ~90, References ~60, Source ~50. Total ≈ 1660. Within 1200-1800 target. Good.

Check banned words: "elegant" no, "clean" — I wrote "keep the sequence out of the IAT" — fine, didn't use clean. "notable" no. "essentially" no. "worth noting" no. "key insight" no. "sophisticated" no. "textbook" no. "robust" no. "solid" no. "clever" no. Check "precisely" — allowed. "The material draws the line precisely" — fine.

Check first-person: none. Rhetorical questions: none. Exclamation marks: none.

Rule: no quantitative evaluation — none. Tier qualitative A.

Frontmatter format check:
- mitre: T1134 — valid format T####.
- mitre_secondary: [T1134.001, T1134.002] — valid.
- tags: 8 entries kebab-case. "adjusttokenprivileges" is one word — kebab-case is about hyphens; single lowercase word fine. Maybe better: [token-privileges, adjusttokenprivileges, sedebugprivilege, sebackup-privilege, serestore-privilege, seimpersonate-privilege, token-theft, lpe] — 8.
- member_notes exact: ['lgtm:token-privilege-abuse-proposed-technique'].
- origin: atlas-synthesis.
- crate: none, source_file: none.

One concern: the name in frontmatter "Token Privilege Abuse: SeDebugPrivilege and Privilege Manipulation" — contains a colon inside YAML value. YAML: `name: Token Privilege Abuse: SeDebugPrivilege and Privilege Manipulation` — a colon followed by space inside a plain scalar is problematic in YAML. Existing cards like "T-002: Hell's/Halo's/Tartarus Gate + FreshyCalls" — the frontmatter in the index shows names without colons. To be safe, quote it: `name: "Token Privilege Abuse: SeDebugPrivilege and Privilege Manipulation"`. Yes, quote it.

Also h1: `# Token Privilege Abuse — Enabling Dormant Token Privileges for Local Escalation`. Good — matches "<Technique Name> — <One-Line Purpose>".

Unit references: I cite units inline (units 5, 6, 12, 13, 14, 28, 32, 33-40). The member note's source_units: 5, 6, 13, 14, 28, 32, 34, 35, 40 — I also use 33, 37, 38, 39 from the atlas batch which are in the provided atlas file, fine since atlas material is authority and it's all provided.

One check on unit 28: "What privilege gives complete write access regardless of the ACL? A SE_BACKUP_NAME B SE_RESTORE_NAME C SE_WRITE_NAME" — and unit 40 confirms SE_RESTORE_NAME = write, SE_BACKUP_NAME = read. My text matches.

SeDebugPrivilege and PPL: is that "well-established Windows internals documentation"? Yes — Windows Internals 7ed covers PPL and that SeDebugPrivilege doesn't override PPL signer checks. Also Microsoft docs state "If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor" but PPL processes are excluded. Keep the claim modest: "refuse the open even from a SeDebugPrivilege-enabled caller, because the PPL signer check runs ahead of the privilege grant." Accurate.

ERROR_NOT_ALL_ASSIGNED (1300L) — documented MSDN behavior of AdjustTokenPrivileges: returns success but not all privileges assigned; must check GetLastError even when return is TRUE. I wrote "A complete check also inspects GetLastError" — good, matches MSDN. Note: AdjustTokenPrivileges returns TRUE even when ERROR_NOT_ALL_ASSIGNED. My phrasing "A complete check also inspects GetLastError: ERROR_NOT_ALL_ASSIGNED indicates the privilege was never present in the token and cannot be enabled." Slightly off — it means not all specified privileges could be assigned (privilege not held). "never present in the token" is essentially right. Keep.

TOKEN_PRIVILEGES mask values: SE_PRIVILEGE_ENABLED_BY_DEFAULT 0x1, ENABLED 0x2, REMOVED 0x4, USED_FOR_ACCESS 0x80000000 — correct winnt.h values.

Token masks Present/Enabled/EnabledByDefault: Windows Internals documents SEP_TOKEN_PRIVILEGES with Present, Enabled, EnabledByDefault bitmaps. Good.

CreateProcessWithTokenW requires SE_IMPERSONATE_NAME — MSDN documented. Good.

Impersonation levels SecurityAnonymous..SecurityDelegation — documented.

Now, "FILE_FLAG_BACKUP_SEMANTICS ... NTFS consults the caller's token for SeBackupPrivilege (read) or SeRestorePrivilege (write)" — documented behavior. Good.

One more: "a Medium-IL process ... still fails mandatory-integrity checks against High-IL targets" — fine.

In Mechanism step 6d: "open a SYSTEM process, open its token, duplicate it" — note that opening a SYSTEM process itself typically requires SeDebugPrivilege already enabled. There's a chicken-and-egg: token theft from SYSTEM processes needs SeDebugPrivilege; SeImpersonate-based theft (named pipe, etc.) doesn't. The material doesn't detail this; to avoid inventing, keep the chain generic as framed by unit 14 and the cluster description ("SeImpersonatePrivilege enables token stealing"). My step 6 says "execute the token-stealing chain ... open a SYSTEM process, open its token, duplicate it, and either impersonate it on the current thread or launch a new process under it." This is the canonical chain; fine per well-established docs. I won't add the chicken-and-egg caveat beyond what's supportable... Actually a brief accurate note adds depth: opening another process's token presupposes handle access to that process (itself commonly gated by SeDebugPrivilege). That's factual and useful. I'll add one clause.

Also in OS Internals token-theft paragraph, add that prerequisite sentence.

Length re-check with additions ~1700 words. Fine.

YAML quoting for name with colon: use double quotes.

Final formatting — output only the markdown file, no preamble. Ensure sections in exact order and no extra sections.

Write it.