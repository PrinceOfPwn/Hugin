Let me analyze the inputs:

1. **Cluster spec**: T-042, "SeBackupPrivilege / SeRestorePrivilege: ACL Bypass for File Access", category `privesc`, tier `S`, member notes `['lgtm:proposed-acl-bypass-privilege-card']`, would_relate_to = [] (empty).

2. **Rust source files provided**:
   - `src/client_rust/src/browser_hook.rs` — Browser extension sideloading. Does NOT implement SeBackupPrivilege/SeRestorePrivilege ACL bypass. Keyword grep hit, but no `AdjustTokenPrivileges`, `SE_BACKUP_NAME`, `CreateFile` with `FILE_FLAG_BACKUP_SEMANTICS`, etc. Not an implementation.
   - `src/client_rust/src/commands.rs` — Command dispatcher. No privilege manipulation related to backup/restore. Not an implementation.
   - `src/dark_crystal/crates/core/src/experimental/iat_camouflage.rs` — IAT camouflage. Not related. Not an implementation.

   So: **no current implementation in HUGIN source**. I must state that explicitly per rule 8 and the Key Implementation Details template.

3. **Atlas material**: `atlas-privesc-part1.md`. Key units: 5, 12, 20, 37, 38 (the cluster's source units) plus supporting units:
   - Unit 1: AdjustTokenPrivileges signature and use — "the last and final step" for enabling privileges.
   - Unit 6: LookupPrivilegeValue, OpenProcessToken, AdjustTokenPrivileges programmatic chain.
   - Unit 21: OpenProcessToken signature — you cannot change privileges without a handle to the token.
   - Unit 5/20/37/38: The core claim — SeBackupPrivilege and SeRestorePrivilege are "the two privileges that bypass that check" (the standard privilege/ACL check). SE_BACKUP_NAME → complete read access regardless of file's ACL; SE_RESTORE_NAME → complete write access regardless. Unit 37 adds: these trump the standard check for FILE_GENERIC_READ and FILE_GENERIC_WRITE. MSDN describes these as ones that are "u..." (truncated — likely "used to grant backup/restore access"). Points to winnt.h for privilege constants.
   - Unit 12: Quiz — "What privilege gives complete write access regardless of the ACL?" Answer: SE_RESTORE_PRIVILEGE.
   - Unit 26/27: Privileges defined as rights to perform system-related operations; enabled vs disabled states.
   - Unit 30/32: TOKEN_PRIVILEGES structure, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED / ENABLED_BY_DEFAULT / REMOVED / USED_FOR_ACCESS flags.
   - Unit 35/36: whoami /priv — standard user has few privileges (only SeChangeNotify enabled); High-IL process has many privileges present but mostly disabled, can be "enabled on the fly on an as needed basis."
   - Unit 3/4/19/33: Integrity levels — context for who holds these privileges.
   - Unit 39/40: Other privileges (SeTakeOwnershipPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeDebugPrivilege) for admin→SYSTEM escalation.

Now I need to write the card. Structure:

- Frontmatter:
  - id: T-042
  - name: SeBackupPrivilege / SeRestorePrivilege: ACL Bypass for File Access (or shortened "SeBackup/SeRestore ACL Bypass"). The template says 4-8 words for human readable name. "SeBackupPrivilege and SeRestorePrivilege ACL Bypass for File Access" — that's fine. Let me use something like "SeBackup/SeRestore Privilege ACL Bypass". Cluster canonical name is "SeBackupPrivilege / SeRestorePrivilege: ACL Bypass for File Access". I'll use the canonical name.
  - category: privesc
  - tier: S
  - crate: none
  - source_file: none
  - mitre: Best fit ATT&CK technique. This is about abusing backup/restore privileges to read/write files regardless of ACL. Candidates:
    - T1078 (Valid Accounts) — no.
    - T1134 (Access Token Manipulation) — this covers token manipulation including enabling privileges. T1134.001 is Token Impersonation/Theft; T1134.002 is Create Process with Token; T1134.005 SID-History Injection. AdjustTokenPrivileges to enable SeBackupPrivilege is often mapped under T1134 Access Token Manipulation.
    - T1003.002 (OS Credential Dumping: Security Account Manager) — that's a use case (reading SAM hive), but the technique itself is broader.
    - T1006 (Direct Volume Access) — no, that's reading via \\.\PhysicalDrive.
    - T1070? no.
    - The single best fit: T1134 (Access Token Manipulation) since the core mechanism is enabling token privileges to bypass access checks. Actually, MITRE has T1134 "Access Token Manipulation" with description: "Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls." Enabling SeBackupPrivilege in your token to bypass DACLs fits. I'll use T1134 as primary. Secondary: T1003.002 (SAM) and maybe T1552? No — DPAPI keys would be T1552.004? Hmm. Let me keep secondary as T1003.002 only, since SAM reading is explicitly named in the cluster spec. Also possibly T1083? No.

    Actually, is there a better fit? "Abuse Elevation Control Mechanism" T1548 — sub-techniques: .001 Setuid/Setgid, .002 Bypass UAC, .003 Sudo, .004 Elevated Execution with Prompt. Not really. The privilege-based ACL bypass is token manipulation. T1134 is the standard mapping for AdjustTokenPrivileges abuse. Go with T1134, secondary [T1003.002].

  - tags: kebab-case, 5-10: acl-bypass, sebackup-privilege, serestore-privilege, token-privileges, file-system, dacl-bypass, adjusttokenprivileges, lpe, credential-access, ntfs
  - origin: atlas-synthesis
  - member_notes: ['lgtm:proposed-acl-bypass-privilege-card']

- Title: `# SeBackupPrivilege / SeRestorePrivilege — ACL Bypass for File Access` with one-line purpose. Template: `# <Technique Name> — <One-Line Purpose>`. So: `# SeBackupPrivilege / SeRestorePrivilege ACL Bypass — Unrestricted File Read/Write Regardless of DACL`

- Summary: 3-5 sentences. First sentence standalone. What it does: SeBackupPrivilege and SeRestorePrivilege are the two Windows privileges that bypass the standard access check entirely; a process holding SeBackupPrivilege (SE_BACKUP_NAME) is granted complete read access to any securable file-system object regardless of its DACL, and SeRestorePrivilege (SE_RESTORE_NAME) grants complete write access. OS primitive: token privileges checked by the I/O manager / object manager during file open; privileges live in the access token (TOKEN_PRIVILEGES / LUID_AND_ATTRIBUTES). Why an operator uses it: read SAM/SYSTEM hives, NTDS.dit, DPAPI master keys, other users' files; write to ACL-protected locations. Detection surface: enabling privileges via AdjustTokenPrivileges is observable (Windows Security event 4672/4673/4674 — wait, I need to be careful: material does not discuss detection. Rule: "If the material does not cover detection for this technique, write: `Training material does not discuss detection for this technique.` Do not invent detections."

The atlas material does not discuss detection for this technique. Units 1, 6, 21 discuss the API chain. No ETW/Sysmon/event IDs mentioned. So Detection Considerations must be the single-line statement. I can mention "telemetry sources: not documented" — but the template says if material doesn't cover detection, write that exact line. I'll follow it: write the line. Maybe I can structure with the three bullets each saying not documented? The instruction says: "If the material does not cover detection for this technique, write: `Training material does not discuss detection for this technique.` Do not invent detections." So just that line. I'll write the line verbatim, perhaps with a brief note that the operational API sequence (AdjustTokenPrivileges) is documented in the material but no telemetry sources are named. Hmm — safer to just use the line plus a sentence clarifying what the material does document (the API chain), without inventing detection content. Actually the rule is strict: write that line. I'll add a minimal clarifying sentence that does not invent detections: the material documents the API surface used to enable the privileges (OpenProcessToken, LookupPrivilegeValue, AdjustTokenPrivileges) but names no ETW providers, event IDs, or residual-artifact guidance. That's factual about the material, not invented detection. I think that's acceptable and helpful. Keep it short.

- Mechanism: Numbered steps. Based on material units 6, 21, 1, 5/20/37:
  1. Verify the privilege is present in the token — whoami /priv shows privileges present but Disabled (units 35/36: High-IL process has many privileges present but disabled; they can be enabled on the fly as needed).
  2. OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken) — obtain handle to own access token (unit 21: "You cannot change any privileges in a token without having a handle to it").
  3. LookupPrivilegeValue(NULL, SE_BACKUP_NAME / "SeBackupPrivilege", &luid) — translate the string privilege name to a LUID (unit 6).
  4. Populate TOKEN_PRIVILEGES with one LUID_AND_ATTRIBUTES entry: Luid = resolved LUID, Attributes = SE_PRIVILEGE_ENABLED (unit 30: attributes ENABLED, ENABLED_BY_DEFAULT, REMOVED, USED_FOR_ACCESS).
  5. AdjustTokenPrivileges(hToken, FALSE, &newState, 0, NULL, NULL) — "the last and final step" to enable the privilege (unit 1).
  6. Open the target file requesting the access the privilege grants: with SeBackupPrivilege enabled, read access is granted regardless of the file's DACL (unit 5: "Regardless of the file's ACL, granted complete read access"); with SeRestorePrivilege, complete write access (unit 12 quiz: SE_RESTORE_PRIVILEGE is the privilege that gives complete write access regardless of ACL). Unit 37 adds these trump the standard check for FILE_GENERIC_READ and FILE_GENERIC_WRITE.
  7. Read/copy target data (SAM, SYSTEM hives, NTDS.dit, DPAPI keys, restricted user files) or write to ACL-protected locations (cluster description).

Wait — the material says these privileges "bypass the ACL check" and are granted complete read/write access "regardless of the file's ACL." It doesn't mention FILE_FLAG_BACKUP_SEMANTICS or backup APIs (BackupRead/BackupWrite). Should I include that? Rule 4: material is authority, but I can also use "well-established Windows internals documentation." FILE_FLAG_BACKUP_SEMANTICS is well-established MSDN: to open a file with backup semantics you pass FILE_FLAG_BACKUP_SEMANTICS to CreateFile, and SeBackupPrivilege/SeRestorePrivilege are checked at open time. The material itself doesn't mention it. I can mention in OS Internals Context the well-established detail that the privileged open uses backup semantics (FILE_FLAG_BACKUP_SEMANTICS) — that's standard MSDN/Windows Internals knowledge, allowed under rule 4. But I should be careful not to fabricate details about what the training material says. I can clearly frame: "the material states X; in Windows this is realized via Y (MSDN)". That's within bounds since Windows Internals/MSDN are allowed sources. Keep it accurate: CreateFile with FILE_FLAG_BACKUP_SEMANTICS triggers the check for SE_BACKUP_PRIVILEGE/SE_RESTORE_PRIVILEGE in the I/O manager; if the privilege is enabled in the token, access check short-circuits. Also registry: RegSaveKey/RegRestoreKey require these privileges. The material doesn't mention RegSaveKey. SAM hive reading: you can't read C:\Windows\System32\config\SAM normally even as admin (locked by SYSTEM), but with SeBackupPrivilege + backup semantics you can copy it. That's well-established. The cluster spec itself says "read SAM/SYSTEM registry hives from disk, read restricted user files, write to ACL-protected locations." I can use that.

- OS Internals Context: Cover:
  - Access token structure: TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES (Luid + Attributes bitmask) — units 30/32. Attribute flags: SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_REMOVED, SE_PRIVILEGE_USED_FOR_ACCESS (unit 30).
  - Enabled vs Disabled states: privileges present but disabled can be enabled on the fly (units 26, 35, 36). Only privileges already present in the token can be enabled; AdjustTokenPrivileges cannot add privileges not granted to the account.
  - The two privileges as the exception: "Most privileges allow you to perform some operation, but still only after the system does a privilege check. Well, there are two privileges that bypass that check: SeBackupPrivilege and SeRestorePrivilege" (unit 5/20 verbatim-ish). MSDN describes them as ones that... (truncated in material; don't complete the quote with invention).
  - winnt.h: SE_BACKUP_NAME / SE_RESTORE_NAME string constants (units 5, 20, 37, 38).
  - Where the check happens: file system access check at open; privileges trump FILE_GENERIC_READ / FILE_GENERIC_WRITE checks (unit 37). I can note, from Windows Internals knowledge, that the I/O manager's access check (SeAccessCheck in the object manager / FastIo path in NTFS) consults the token's privilege array when the open specifies backup/restore intent, bypassing DACL evaluation. Keep it careful.
  - Integrity levels context: these privileges appear in High-IL admin tokens (and SYSTEM/service accounts like Backup Operators); unit 3/19 list ILs (Untrusted 0 … Protected 5); unit 36: High-IL process has a large increase in present privileges, mostly disabled, enabled on the fly as needed.
  - Kernel/user boundary: enabling the privilege is a user-mode operation against your own token (no admin beyond holding the privilege); the ACL bypass is enforced kernel-side at object open.
  - winnt.h constants — string names vs LUIDs; LookupPrivilegeValue translates name→LUID locally (it reads from local LSA; well-established).

- Key Implementation Details: No implementation. Per template: "**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C (SEC670 Win32 API examples)." Then a paragraph on what an implementation would look like: FFI bindings to OpenProcessToken/LookupPrivilegeValueW/AdjustTokenPrivileges via windows_targets::link! (matching HUGIN's wrappers.rs pattern), a TOKEN_PRIVILEGES struct with one LUID_AND_ATTRIBUTES, enabling SE_BACKUP_NAME and SE_RESTORE_NAME, then opening targets with CreateFileW + FILE_FLAG_BACKUP_SEMANTICS for read (backup) and write (restore), streaming reads for SAM/SYSTEM hives. Mention the provided source files were verified and do not implement this: browser_hook.rs (browser extension sideloading), commands.rs (client command dispatch), iat_camouflage.rs (IAT camouflage) — none touch token privileges or backup-semantics file opens. That's honest verification.

- Why It Matters: 2-4 sentences. Distinct from ACL manipulation (T-017 COM hijack etc. — no, actually the vault has no file-ACL technique). The cluster says: "The vault does not currently cover file-ACL bypass as a standalone technique... distinct operational primitive (read SAM/SYSTEM registry hives from disk, read restricted user files, write to ACL-protected locations) used in the post-exploitation phase rather than the injection phase." Also distinct from ownership/DACL rewriting (SeTakeOwnershipPrivilege, SetSecurityInfo) because it requires no modification to the object's security descriptor — no change to the target, only to the caller's token, and only two privileges bypass the check entirely rather than satisfying it.

- Detection Considerations: The exact line, plus maybe a sentence noting what material documents. Keep to the line to be safe. Actually I'll write the line, then one sentence: "The material documents the enabling API sequence (OpenProcessToken → LookupPrivilegeValue → AdjustTokenPrivileges, units 1, 6, 21) but names no ETW providers, Sysmon event IDs, kernel callbacks, or residual artifacts for this technique." That's meta-commentary about the material, not invented detection. I think that's fine and more useful.

- Related Techniques: would_relate_to is []. No related T-NNN cards were provided as inputs. Rule 9: only include cross-references justifiable from inputs. The note's would_relate_to is "(new territory)". So... the section must exist but with what? The template says Related Techniques section cross-references other cards; restraint rule says don't invent. With an empty list and no provided cards, I should write that there are no cross-references — e.g., "None. The cluster spec lists no `would_relate_to` entries; this technique is new territory for the vault with no existing T-NNN card covering adjacent ground." Hmm, but could I reference T-016 (EDR evasion) or T-017 (persistence)? Not justified by inputs. The material mentions token stealing (units 2, 7, 17 — Lab 3.5 TokenThief) and UAC bypass (Lab 3.7), and SeDebugPrivilege etc. — but those don't map to existing vault cards directly. The vault has no token-theft card. So state none. Write a single line explaining sparseness (rule 7 allows single-line explanation when material is sparse).

Wait — should I consider T-023 client capabilities (credential harvest — lsass_dump, extract_wifi)? The manifest mentions `src/experimental/harvest/lsass_dump.rs` (MiniDumpWriteDump) and `extract_wifi.rs`. LSASS dump is process-memory, not file-ACL bypass. Not a real relationship per inputs; the cluster spec explicitly says would_relate_to = []. I'll keep Related Techniques as "none" with explanation. That's the honest answer.

- References:
  - Atlas material: atlas-privesc-part1.md
  - MITRE ATT&CK: T1134 with URL https://attack.mitre.org/techniques/T1134/ and secondary T1003.002 (https://attack.mitre.org/techniques/T1003/002/). The template format: "MITRE ATT&CK: <T####.### with URL>". I'll list both.
  - LGTM notes: lgtm:proposed-acl-bypass-privilege-card
  - Public references: none named in material beyond MSDN/winnt.h. The material references MSDN descriptions of the privileges and winnt.h header. I can cite "MSDN — privilege constants (winnt.h): SE_BACKUP_NAME, SE_RESTORE_NAME (referenced in units 5, 20, 37)". That's grounded in the material. Don't invent blog posts.

- Source Reference: "No current implementation. See atlas material and MITRE reference for public tooling." Also note the three included .rs files were reviewed and do not implement the technique. Actually per template: `<If no source: "No current implementation. See atlas material and MITRE reference for public tooling.">` — I'll use that, plus the verification note can live in Key Implementation Details. Maybe add one line here listing the reviewed files. Fine.

Length: target 1200-1800 words body. Let me draft with enough depth. Mechanism steps, OS internals (token structures, attribute flags, ILs, enabled/disabled semantics, kernel-side enforcement, backup semantics from MSDN), Key Implementation Details paragraph, Why It Matters. Detection is one line-ish, Related is one line. So I need the other sections to carry the word count. Let me be thorough in Mechanism and OS Internals Context.

Banned words check: avoid "elegant, clever, textbook, interestingly, worth noting, essentially, at its core, it is important to note". Watch "notable" — banned. "sophisticated" — banned. Fine.

No fanboy, no ratings, no suggestions. Careful in Key Implementation Details: the template explicitly asks "Then briefly describe what an implementation would look like" — that's required by the template, not a "suggestions section." OK.

Also careful: don't fabricate API flags. Well-established: OpenProcessToken needs TOKEN_ADJUST_PRIVILEGES (and TOKEN_QUERY). AdjustTokenPrivileges signature from unit 1: TokenHandle, DisableAllPrivileges, NewState (PTOKEN_PRIVILEGES), BufferLength, PreviousState, ReturnLength. BOOL return. TOKEN_PRIVILEGES contains PrivilegeCount + array of LUID_AND_ATTRIBUTES {LUID Luid; DWORD Attributes}. Attributes SE_PRIVILEGE_ENABLED (0x00000002). LookupPrivilegeValueA/W(systemName opt, name, out LUID). SE_PRIVILEGE_ENABLED_BY_DEFAULT (0x1), SE_PRIVILEGE_REMOVED (0x4), SE_PRIVILEGE_USED_FOR_ACCESS (0x80000000). These match unit 30's list (ENABLED, ENABLED_BY_DEFAULT, REMOVED, USED_FOR_ACCESS) — good.

FILE_GENERIC_READ / FILE_GENERIC_WRITE — unit 37 explicitly ties these to the bypass: "these privileges trump the standard check for FILE_GENERIC_READ and FILE_GENERIC_WRITE." Good, use that.

FILE_FLAG_BACKUP_SEMANTICS (0x02000000) — MSDN-established; I'll include with framing "per MSDN" and note the material itself does not name the flag, but the privileged open is realized through backup semantics. Careful phrasing: "The material does not name the open-time mechanism; per MSDN, ..." That's transparent.

Also well-established: SeBackupPrivilege also permits opening registry hives via RegSaveKey/RegLoadKey? RegSaveKey requires SE_BACKUP_PRIVILEGE. That's MSDN-established. Cluster mentions reading SAM/SYSTEM registry hives from disk. I'll mention that the canonical use is copying %SystemRoot%\System32\config\SAM and SYSTEM — established practice (also requires bypassing the exclusive lock held by the system; BackupRead semantics allow reading files open with deny-read sharing? Actually the config hives are open by SYSTEM with locks; reading via backup semantics handles the ACL, but the sharing lock is separate — copy via raw/backup APIs like reg save or Esentutl /y or vssadmin. Hmm — I should be careful not to overclaim. The material/cluster says "read SAM/SYSTEM registry hives from disk" — I'll state it as the operational use per cluster spec without deep-diving lock mechanics. I can say: per the cluster description, the canonical targets are SAM and SYSTEM hives, NTDS.dit on domain controllers, and DPAPI master keys. Keep it at that level.

Wait — actually the live SAM hive can be read by SYSTEM... a normal file read on C:\Windows\System32\config\SAM fails even for admins due to ACL (only SYSTEM has access) — SeBackupPrivilege fixes the ACL side. There's also a file-locking aspect. I'll avoid asserting details about the lock; just say "grants read access to SAM/SYSTEM hives on disk" per material. Fine.

Integrity levels: unit 3/19 — Untrusted(0), Low(1), Medium(2), High(3), System(4), Protected(5); High = UAC elevated processes; System = services (wininit, winlogon, lsass). Use in OS internals: where these privileges live (High-IL admin tokens, SYSTEM service tokens, Backup Operators group). Backup Operators membership — established Windows knowledge; cluster says "Often granted to backup operators, admins, or SYSTEM services" — that's from the cluster description, so I can use it.

Let me also double check MITRE: T1134 Access Token Manipulation — "Adversaries may modify access tokens... bypass access controls." The ATT&CK page explicitly mentions: "An adversary can use built-in Windows API functions to copy access tokens... or leverage AdjustTokenPrivileges." I believe ATT&CK T1134 mentions token privileges. Yes, I'm confident T1134 is right. Secondary T1003.002 (SAM) — cluster explicitly names SAM. Also possibly T1552.004 (Private Keys) for DPAPI? DPAPI master keys → T1552.004 is "Private Keys". Eh, keep secondary to [T1003.002] — one is enough, and I'm confident.

Word count: Let me draft fully and count roughly. Aim ~1400-1600 words body.

Draft:

Frontmatter:

```yaml
---
id: T-042
name: SeBackupPrivilege / SeRestorePrivilege: ACL Bypass for File Access
category: privesc
tier: S
crate: none
source_file: none
mitre: T1134
mitre_secondary: [T1003.002]
tags: [acl-bypass, sebackup-privilege, serestore-privilege, token-privileges, adjusttokenprivileges, file-system, dacl-bypass, lpe, credential-access]
origin: atlas-synthesis
member_notes: ['lgtm:proposed-acl-bypass-privilege-card']
---
```

9 tags, good.

Title: `# SeBackupPrivilege / SeRestorePrivilege ACL Bypass — Unrestricted File Read and Write Regardless of DACL`

Summary (~5 sentences):
- S1: SeBackupPrivilege (SE_BACKUP_NAME) and SeRestorePrivilege (SE_RESTORE_NAME) are the only two Windows privileges that bypass the standard access check entirely — a token holding SeBackupPrivilege is granted complete read access to a file regardless of its ACL, and a token holding SeRestorePrivilege is granted complete write access regardless of its ACL (SEC670, units 5/20/37).
- The privileges ride in the process access token as LUID_AND_ATTRIBUTES entries; they ship disabled in most tokens and are enabled on demand through the OpenProcessToken → LookupPrivilegeValue → AdjustTokenPrivileges chain.
- Operators use them in the post-exploitation phase to read otherwise-inaccessible objects — SAM and SYSTEM registry hives, NTDS.dit, DPAPI master keys, other users' files — and to write into ACL-protected locations.
- Unlike ACL editing or ownership takeover, the bypass requires no modification to the target object's security descriptor; only the caller's token changes.
- Material does not discuss detection... maybe leave detection for the section. Instead: Primary accounts carrying these privileges: administrators (High-IL), SYSTEM services, Backup Operators.

Mechanism steps:

1. Confirm the privileges are present in the current token. The material shows whoami /priv output: standard (Medium-IL) users hold almost nothing (only SeChangeNotify enabled), whereas a High-IL process has a large set of privileges present but Disabled — including SeBackupPrivilege and SeRestorePrivilege — which "can be enabled on the fly on an as needed basis" (units 35, 36).
2. OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken). Unit 21: "You cannot change any privileges in a token without having a handle to it."
3. LookupPrivilegeValue(NULL, "SeBackupPrivilege", &luid) — resolve the SE_BACKUP_NAME string constant (declared in winnt.h, units 5/20/37) to the locally assigned LUID. Repeat for "SeRestorePrivilege" (SE_RESTORE_NAME).
4. Fill TOKEN_PRIVILEGES {PrivilegeCount = 1..2; Privileges[] = LUID_AND_ATTRIBUTES{Luid, SE_PRIVILEGE_ENABLED}}. Attribute flags per unit 30: ENABLED, ENABLED_BY_DEFAULT, REMOVED, USED_FOR_ACCESS.
5. AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL) — DisableAllPrivileges = FALSE so only the listed privileges are touched; unit 1 calls this "the last and final step" of the enable sequence. Verify via GetLastError() == ERROR_SUCCESS (well-established: ERROR_NOT_ALL_ASSIGNED indicates the privilege was not present in the token). Hmm, ERROR_NOT_ALL_ASSIGNED — that's well-established MSDN (GetLastError returns ERROR_NOT_ALL_ASSIGNED if not all privileges could be assigned). I can include; it's MSDN knowledge. Keep.
6. Open the protected object with the access the enabled privilege covers. Per unit 37, the privileges "trump the standard check for FILE_GENERIC_READ and FILE_GENERIC_WRITE": with SeBackupPrivilege enabled, a read open succeeds against any file ACL; with SeRestorePrivilege enabled, a write open succeeds against any file ACL.
7. Read the target (copy SAM/SYSTEM hives, NTDS.dit, DPAPI keys, restricted user files) or write to the ACL-protected destination. No SetSecurityInfo, no ownership change, no DACL rewrite on the object.
8. Optionally revert: AdjustTokenPrivileges with SE_PRIVILEGE_REMOVED / attribute 0 to disable again, returning the token to its prior state (PreviousState out-param of AdjustTokenPrivileges captures the old state — unit 1 signature includes PreviousState/ReturnLength).

That's a solid mechanism. Step on the actual open: material doesn't name FILE_FLAG_BACKUP_SEMANTICS. I put that in OS Internals with MSDN framing.

OS Internals Context:

- Token privilege storage: access token carries a privilege array of LUID_AND_ATTRIBUTES (unit 30/32): LUID identifies the privilege (locally assigned, resolved via LookupPrivilegeValue); Attributes bitmask from the SE_PRIVILEGE_* family — ENABLED (present and set/authorized), ENABLED_BY_DEFAULT, REMOVED, USED_FOR_ACCESS (unit 30). Enabled vs Disabled distinction (unit 26): "Enabled — privilege is present and set... Disabled — present but not set, could be enabled."
- The two-privilege exception: unit 5 verbatim-ish: "Most privileges allow you to perform some operation, but still only after the system does a privilege check. Well, there are two privileges that bypass that check: SeBackupPrivilege and SeRestorePrivilege." MSDN-described (material truncates the quote). SE_BACKUP_NAME/SE_RESTORE_NAME are string constants in winnt.h (units 5, 37, 38).
- Where enforcement happens: file open path — the access check that would normally evaluate the object's DACL against the requested FILE_GENERIC_READ/FILE_GENERIC_WRITE mask is short-circuited when the corresponding privilege is enabled (unit 37). From Windows Internals/MSDN: when a caller opens a file with backup intent (CreateFile FILE_FLAG_BACKUP_SEMANTICS), the I/O manager checks the token for SE_BACKUP_PRIVILEGE (read) / SE_RESTORE_PRIVILEGE (write) instead of performing the DACL walk; this is the user-mode-realizable form of the bypass the material describes. The material does not name the flag; the privilege-level behavior it documents is the same check site.
- Enabled/disabled lifecycle and constraints: AdjustTokenPrivileges can only enable privileges already present in the token; it cannot grant new ones. Standard users lack the privileges entirely (unit 35); High-IL admin tokens carry them disabled by default (unit 36); they are "enabled on the fly on an as needed basis" (unit 36). SE_PRIVILEGE_REMOVED strips a privilege from the token (unit 30).
- Token/IL placement: integrity levels (units 3/19): Untrusted 0, Low 1, Medium 2 (typical UAC-on processes), High 3 (UAC-elevated), System 4 (wininit, winlogon, lsass), Protected 5 (kernel-mode callers only). SeBackup/SeRestore typically appear in High-IL and System tokens, plus Backup Operators group members (cluster description).
- Kernel/user boundary: the enable operation is purely user-mode against the caller's own token (no cross-process handle, no SeDebugPrivilege required for self-token); the bypass itself is enforced kernel-side at object open — the kernel sees a normal NtCreateFile/NtOpenFile whose access check returns success because of the token privilege, not because of any handle trick or injection.
- Distinction from sibling privileges (units 39/40): SeTakeOwnershipPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeDebugPrivilege are the material's "more privileges" for Admin→SYSTEM movement; unlike SeTakeOwnershipPrivilege (which changes the object's owner so a later DACL edit can succeed), SeBackup/SeRestore never modify the object.

Key Implementation Details:

- "**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C (SEC670 Win32 API walkthroughs)."
- Verification note: three Rust files were provided — browser_hook.rs implements MV3 extension sideloading, commands.rs implements the client command dispatcher, iat_camouflage.rs implements IAT camouflage profiles; none of them call OpenProcessToken, AdjustTokenPrivileges, LookupPrivilegeValue, or open files with backup semantics. No file in the manifest maps to token-privilege manipulation.
- What an implementation would look like: a `priv_backup.rs`-style module following the wrappers.rs pattern (windows_targets::link! FFI), binding OpenProcessToken, LookupPrivilegeValueW, AdjustTokenPrivileges from advapi32; a TOKEN_PRIVILEGES buffer with two LUID_AND_ATTRIBUTES entries set to SE_PRIVILEGE_ENABLED; an enable()/disable() pair capturing PreviousState for clean revert; and a read path issuing CreateFileW with FILE_FLAG_BACKUP_SEMANTICS (MSDN) to stream protected files (SAM/SYSTEM/SECURITY hives, NTDS.dit, DPAPI masterkeys) into the exfil channel, and a write path for restore-side operations. Guarded behind a Cargo feature gate consistent with the crate's minimal-footprint build model.

Careful — "an implementation would look like" paragraph is required by template. Avoid words like "could consider". Fine.

Why It Matters (2-4 sentences):
- The vault has no card covering file-ACL bypass; the two privileges are the only privileges that skip the access check outright rather than satisfying it, which makes this a distinct primitive rather than a variant of ACL editing or ownership takeover.
- It fills the post-exploitation file-access gap: reading SAM/SYSTEM hives, NTDS.dit, DPAPI keys, and restricted user files, plus writing to ACL-protected locations — all without touching the target object's security descriptor, so no DACL/ownership artifacts are left on the object.
- Because the privileges ride in High-IL admin, SYSTEM service, and Backup Operators tokens that implants commonly already hold, the enable cost is three Win32 calls against the caller's own token — no injection, no cross-process handles, no kernel interaction beyond the final open.

Hmm "no kernel interaction beyond the final open" — fine.

Detection Considerations:
"Training material does not discuss detection for this technique. The material documents only the enabling API sequence (OpenProcessToken → LookupPrivilegeValue → AdjustTokenPrivileges; units 1, 6, 21) and the resulting access behavior; it names no ETW providers, Sysmon event IDs, kernel callbacks, or residual artifacts."

Related Techniques:
"None. The cluster spec assigns an empty `would_relate_to` list, and the member note marks this technique as new territory for the vault; no existing T-NNN card provided with this request covers adjacent ground (token manipulation, ACL editing, or credential-store access) closely enough to cross-reference."

Hmm, T-023 client capabilities includes credential harvest (lsass dump, wifi) — but that's memory/wifi, not file ACL. Not justified. Keep "none."

References:
- Atlas material: atlas-privesc-part1.md (units 1, 3, 5, 6, 12, 19, 20, 21, 26, 30, 32, 35-40)
- MITRE ATT&CK: T1134 Access Token Manipulation — https://attack.mitre.org/techniques/T1134/ ; T1003.002 OS Credential Dumping: Security Account Manager — https://attack.mitre.org/techniques/T1003/002/
- LGTM notes: lgtm:proposed-acl-bypass-privilege-card
- Public references: MSDN privilege constants in winnt.h (SE_BACKUP_NAME, SE_RESTORE_NAME), cited by the material (units 5, 20, 37); MSDN AdjustTokenPrivileges/OpenProcessToken documentation (units 1, 21). No external tools or blog posts are named in the material.

Source Reference:
"No current implementation. See atlas material and MITRE reference for public tooling. The three Rust files provided with this request (src/client_rust/src/browser_hook.rs, src/client_rust/src/commands.rs, src/dark_crystal/crates/core/src/experimental/iat_camouflage.rs) were reviewed and do not implement this technique."

Now word count check. Let me estimate as I write the final. Need ≥800, target 1200-1800. My planned content should hit ~1400. Let me write it out carefully, keeping declarative third-person present tense.

Check banned words once more in draft: avoid "interesting" — material says "There is an interesting tidbit" — I quote the material? Quoting is okay but better paraphrase without the word. "interesting" isn't on the banned list explicitly (list: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable). "Interesting" isn't banned but "interestingly" is. I'll avoid anyway.

No exclamation marks. The material's slide says "Abuse privileges to bypass ACLs!" — I won't quote with exclamation.

Careful with "complete read access" phrasing from material: "Regardless of the file's ACL, granted complete read access" — good to paraphrase/quote.

One more consideration on frontmatter `name`: canonical name from cluster is "SeBackupPrivilege / SeRestorePrivilege: ACL Bypass for File Access". Use exactly that. The h1 can be "# SeBackupPrivilege / SeRestorePrivilege ACL Bypass — Unrestricted File Access Regardless of DACL".

mitre_secondary format: [T1003.002] — template shows `[<additional ATT&CK IDs ...>]`. Use bracket list.

Write final now. Ensure exact section order and headers. Watch body word count — I'll aim long in Mechanism and OS Internals.

Also the Summary "first sentence must be complete and standalone." Good.

Let me also make sure I don't assert that BackupRead/RegSaveKey are required — I'll frame FILE_FLAG_BACKUP_SEMANTICS as MSDN-established realization, noting material doesn't name it. Good.

Final output: just the markdown file.