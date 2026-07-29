Let me analyze the inputs:

1. **Cluster spec**: T-029, "Security Descriptor and SDDL Reconnaissance for Privilege-Escalation Planning", category `discovery`, tier B, member note `lgtm:proposed-technique-security-descriptor-reconnaissance`, would_relate_to: T-023.

2. **Related T-NNN card**: T-023 Client Capabilities — includes recon (Byakugan network recon), sysinfo collection, credential harvesting. The relationship: T-029 is a reconnaissance capability that complements the client-side recon modules.

3. **Rust source files**:
   - `wrappers.rs` — NT API bindings (NtWriteVirtualMemory, NtCreateProcessEx, etc.). Has `InitializeObjectAttributes` with a `security_descriptor` parameter, but that's for creating objects, not reconnaissance of security descriptors. Does NOT implement this technique.
   - `block_handle.rs` — This one is interesting. It builds a SECURITY_DESCRIPTOR manually and applies it via NtSetSecurityObject to block external handles. This is SDDL/DACL *manipulation* (writing), not *reconnaissance* (reading). The cluster spec is specifically about reconnaissance: sc.exe sdshow, SDDL parsing, GetNamedSecurityInfo for READING descriptors. block_handle.rs does the inverse — it writes a DACL. However, it demonstrates manual SECURITY_DESCRIPTOR construction knowledge. Does it "implement the primary mechanism the card describes"? The card's primary mechanism is reading/parsing security descriptors for recon. block_handle.rs constructs and sets a security descriptor. That is NOT the primary mechanism (reading for recon). So per rule 8, I should NOT attribute it as an implementation. But it's worth mentioning in Key Implementation Details as related-but-inverse? The rule says: "for the file to count as an implementation of this technique, at least ONE function in it must implement the primary mechanism the card describes." The primary mechanism is retrieval and parsing of security descriptors (sc.exe sdshow equivalent, GetNamedSecurityInfo, SDDL parse). block_handle.rs does not do that. So: no current implementation, though I could briefly note the related write-side capability exists in block_handle.rs. Careful — the template says if no source implements, write the standard line and describe what an implementation would look like. I can mention block_handle.rs as the write-side counterpart in Why It Matters or Key Implementation Details, but source_file frontmatter must be `none`.
   - `payload_cfg.rs` — build-time config constants. Has `BLOCK_HANDLE: bool = true` toggle which references the SDDL-based handle blocking. Not an implementation of recon. Ignore.

   So `source_file: none`, `crate: none`. Hmm, but crate enum is dark_crystal|client_rust|none — use `none`.

4. **Atlas material** — atlas-privesc-part2.md. Relevant units:
   - Unit 28/29/30: SE_BACKUP_NAME / SE_RESTORE_NAME review question — which privilege gives complete write access regardless of ACL. The answer per the material: the question is posed; unit 30 shows "Unit Review Answers" with the options listed. The material excerpt for unit 30 doesn't explicitly state which is the answer — it shows the three options. Hmm. Careful. The review question: "What privilege gives complete write access regardless of the ACL?" Options A: SE_BACKUP_NAME, B: SE_RESTORE_NAME, C: SE_WRITE_NAME. The answer slide (unit 30) lists the three again without clearly marking. Well-established Windows knowledge: SE_RESTORE_NAME (SeRestorePrivilege) grants write access regardless of ACL (it grants WRITE_DAC, WRITE_OWNER, ACCESS_SYSTEM_SECURITY and the ability to set any owner). SE_BACKUP_NAME grants read access regardless of ACL (FILE_FLAG_BACKUP_SEMANTICS). The correct answer to "complete write access regardless of ACL" is SE_RESTORE_NAME. The cluster spec says "SE_BACKUP_NAME/SE_RESTORE_NAME as ACL-bypass privileges". The material poses the question; standard Windows documentation says SeRestorePrivilege = write. I can state: the material poses this as a review question; per Windows documentation, SeRestorePrivilege (SE_RESTORE_NAME) grants write access to any object regardless of the DACL, while SeBackupPrivilege (SE_BACKUP_NAME) grants read access. That's traceable to well-established documentation. Good.
   - Unit 35/36: ACE string layout — ace_type (A, D, OA, OD, AU, AL), ace_flags (CI, OI, NP, IO, ID, SA), generic rights (GA, GR, GW, GX), standard rights (RC, SD, WD, WO), directory rights (RP, WP, CC, DC, LC, SW), registry rights (KA, KR, KW, KX), file rights (FA, FR). SID constants like 'BA' for builtin admins.
   - Unit 37: sc.exe sdshow — viewing service security descriptor, e.g., BITS.
   - Unit 38/39: SDDL exercise solution — "D:" DACL with deny ACEs for IU (interactive user), SU (service user), BA (builtin admins); allow ACEs CCLCSWLOCRRC for IU/SU; CCLCSWRPWPDTLOCRRC for SY. Mentions testing with PowerShell Get-Service or sc.exe.
   - Unit 40: GetNamedSecurityInfoA — signature, parameters, object types (NTFS objects, services, keys, shares, file-mapping objects).
   - Units 12-16: SCM handles (OpenSCManager), EnumServicesStatus, QueryServiceStatus, unquoted paths, weak permissions — context for service LPE recon.
   - Units 1-7: LookupPrivilegeValue, OpenProcessToken, AdjustTokenPrivileges — enabling privileges (relevant for SE_BACKUP/RESTORE enabling).
   - Units 33/34: HKLM modification requires admin.

5. **MITRE**: Best fit. Security descriptor discovery... ATT&CK candidates:
   - T1082 System Information Discovery — too generic.
   - T1057 Process Discovery — no.
   - T1007 System Service Discovery — sc.exe sdshow queries services; but the card is broader (files, registry, shares). Hmm. There is no "Security Descriptor Discovery" technique in ATT&CK. Closest: T1007 System Service Discovery (sc query, sdshow is service-related). But the card spans files/registry too. There's T1083 File and Directory Discovery, T1012 Query Registry. Given the primary described workflow centers on services (sc.exe sdshow, service DACLs) and the goal is privilege-escalation planning, I think T1007 is the best single fit, with secondary T1083 and T1012. Actually, permission discovery... There's no dedicated technique. I'll use mitre: T1007, mitre_secondary: [T1083, T1012]. That's defensible.

6. **Tier**: B (proposed). Category: discovery.

7. **Tags** (5-10 kebab-case): sddl, security-descriptor, dacl, ace-parsing, sc-sdshow, getnamedsecurityinfo, service-recon, privesc-recon, se-restore-privilege. That's 9. Good.

8. **Structure** per template exactly. Sections: Summary, Mechanism, OS Internals Context, Key Implementation Details, Why It Matters, Detection Considerations, Related Techniques, References, Source Reference.

Detection: the material does NOT discuss detection for this technique. Per rule: "If the material does not cover detection for this technique, write: `Training material does not discuss detection for this technique.` Do not invent detections." The atlas material doesn't cover ETW/Sysmon for this. I must write that line. Can I add anything else? Rule says do not invent detections. I'll write the required line. Maybe I can note residual artifacts only if in material — no. Keep it to the line, possibly with a brief note that sc.exe sdshow and GetNamedSecurityInfo are read-only queries — hmm, that's borderline inventing. Safer: just the required sentence. Actually I could add the sentence and leave it. The template lists sub-bullets; with the rule, I write the one line. I'll write the one line and maybe a short paragraph that the workflow is read-only enumeration using documented query APIs, which is a factual restatement of the mechanism, not a detection claim. Hmm — "Do not invent detections." A statement about the technique being read-only isn't a detection claim. But telemetry sources etc. would be inventing. I'll write the required line and stop. Maybe also note the material does not discuss bypass options or residual artifacts. Keep minimal.

Related Techniques: only T-023 from would_relate_to. Relationship: T-023 covers client-side recon (Byakugan network recon, sysinfo); T-029 adds security-descriptor recon for LPE planning — feeds target selection to client operations. One line.

Key Implementation Details: No current implementation. Standard line: "**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C (Win32 API) and sc.exe/PowerShell command-line usage." Then one paragraph on what an implementation would look like: GetNamedSecurityInfoA with SE_OBJECT_TYPE for SE_SERVICE, SE_REGISTRY_KEY, SE_FILE_OBJECT; request DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION; parse via ConvertSecurityDescriptorToStringSecurityDescriptorA for SDDL, or walk ACL via GetAce; also an sc.exe sdshow equivalent via QueryServiceObjectSecurity. Mention that block_handle.rs (crowd) demonstrates manual SECURITY_DESCRIPTOR construction for the write side (NtSetSecurityObject), which provides the binary layout knowledge needed for a parser — that's a factual observation about included source, and it's fine to note it as related write-side capability, not as implementation. I think that's acceptable and valuable; it doesn't violate rule 8 because I'm not claiming it implements the technique — I explicitly say it does not.

Wait — rule: "If a source truly implements it, reference the file. If not, ignore the file and state 'no current implementation in source.'" Hmm, "ignore the file" — strictly, it says ignore. But Key Implementation Details template says describe what an implementation would look like. Mentioning block_handle as demonstrating the binary SD layout is arguably not ignoring. The safest reading: don't claim it implements; stating the inverse-side existence is informative but could be seen as contradicting "ignore the file." I'll mention it briefly in Why It Matters instead as the write-side counterpart already in the codebase? Hmm. Actually rule 8's explicit test is about attribution. A one-sentence note that crowd/block_handle.rs constructs a self-relative SECURITY_DESCRIPTOR for the inverse operation (handle blocking, documented in T-016) provides accurate context without attribution. The file header itself says it's "SDDL-based handle protection utility" mapped to T009-edr-evasion (T-016). I'll include one careful sentence in Key Implementation Details noting the codebase already contains the write-side primitive, which a parser would complement. I think this adds value and is factually grounded. But I must not list it as source_file. Fine.

Mechanism steps — concrete:
1. Enumerate services via EnumServicesStatus / OpenSCManager (material units 12-15) to build target list.
2. Retrieve descriptor: `sc.exe sdshow <service>` (unit 37) or programmatically GetNamedSecurityInfoA (unit 40) / QueryServiceObjectSecurity.
3. Parse SDDL: split into O:/G:/D:/S: sections; parse ACE strings (ace_type;ace_flags;rights;object_guid;inherit_guid;account_sid) per unit 35 layout.
4. Decode rights constants per object class (generic GA/GR/GW/GX, standard RC/SD/WD/WO, service-specific CC/DC/LC/RP/WP/SW/DT/LO/CR, registry KA/KR/KW/KX, file FA/FR...).
5. Decode SID abbreviations (BA, SY, IU, SU, WD etc.).
6. Evaluate against current token: identify non-admin principals with write-class rights (WD, WO, RP, WP, DT, SD, GA, FA...) on high-privilege objects → LPE candidates (change service config, replace binary, write registry).
7. Where DACL blocks access entirely, check token for SE_BACKUP_NAME / SE_RESTORE_NAME; enable via LookupPrivilegeValue/OpenProcessToken/AdjustTokenPrivileges (units 1-7) and retry with backup semantics.
8. Repeat across object types: services, registry keys (HKLM requires admin to modify — units 33/34), NTFS files, shares, file-mapping objects (unit 40).

OS Internals Context:
- SECURITY_DESCRIPTOR structure: self-relative vs absolute, header (Revision, Control flags SE_DACL_PRESENT/SE_SELF_RELATIVE), offsets to Owner, Group, Sacl, Dacl. I can reference block_handle.rs's manual layout as evidence of the 20-byte self-relative header — wait, that's Windows-documented; SECURITY_DESCRIPTOR self-relative is Revision(1)+Sbz1(1)+Control(2)+4 offsets(16) = 20 bytes. Documented in MS-DTYP. Fine.
- ACL: AclRevision, AclSize, AceCount; ACE header (AceType, AceFlags, AceSize) + ACCESS_MASK + SID.
- ACCESS_MASK: generic bits 28-31 (GENERIC_ALL etc.), standard rights 16-23 (READ_CONTROL 0x20000, WRITE_DAC 0x40000, WRITE_OWNER 0x80000, DELETE 0x10000), object-specific 0-15. Service-specific rights map: SERVICE_QUERY_CONFIG 0x0001 (CC), SERVICE_CHANGE_CONFIG 0x0002 (DC), SERVICE_QUERY_STATUS 0x0004 (LC), SERVICE_ENUMERATE_DEPENDENTS 0x0008 (SW... hmm). Let me check: SDDL service rights per MSDN: CC=SERVICE_QUERY_CONFIG, DC=SERVICE_CHANGE_CONFIG, LC=SERVICE_QUERY_STATUS, SW=SERVICE_ENUMERATE_DEPENDENTS, RP=SERVICE_START, WP=SERVICE_STOP, DT=SERVICE_PAUSE_CONTINUE, LO=SERVICE_INTERROGATE, CR=SERVICE_USER_DEFINED_CONTROL. Plus RC=READ_CONTROL, SD=DELETE, WD=WRITE_DAC, WO=WRITE_OWNER, GA=GENERIC_ALL... The material unit 38 shows "CCLCSWLOCRRC" allow for IU — consistent. And deny "DCLCWPDTSD" = DC(change config), LC(query status), WP(stop), DT(pause), SD(delete). Good — I can map these to documented service right constants. Careful: the material itself doesn't spell out the mapping of CC→SERVICE_QUERY_CONFIG, but MSDN documents SDDL service rights strings. That's well-established documentation. OK.
- Access check: SeAccessCheck / AccessCheck algorithm — DACL evaluated, deny-first ordering in canonical form, owner implicit READ_CONTROL/WRITE_DAC. The kernel side: ObOpenObjectByName → ObpLookupObjectName → SeAccessCheck against the object's security descriptor in the object header (OBJECT_HEADER.SecurityDescriptor). For services, the SCM stores service objects' security descriptors in the registry (HKLM\SYSTEM\CurrentControlSet\Services\<name>\Security\Security value) — this is documented Windows behavior. Is it in the material? Not explicitly. It is well-established. I can state the SCM applies the service's security descriptor, stored in the Security registry value. That's factual and documented (MSDN "Service Security and Access Rights"). Fine per rule 4 (well-established Windows internals documentation).
- SeBackupPrivilege/SeRestorePrivilege: when enabled, open with FILE_FLAG_BACKUP_SEMANTICS; SeBackupPrivilege grants read (GENERIC_READ + ACCESS_SYSTEM_SECURITY?) Actually SeBackupPrivilege grants read access regardless of ACL; SeRestorePrivilege grants write access (including WRITE_DAC, WRITE_OWNER) and the ability to take ownership. Documented. The material poses the question; the established answer: SeRestorePrivilege → write. Also SACL access requires ACCESS_SYSTEM_SECURITY which requires SeSecurityPrivilege. block_handle.rs comment mentions "may require SeSecurityPrivilege" — that's for SACL, but it sets DACL... whatever, not needed.
- SID structure: Revision, SubAuthorityCount, IdentifierAuthority (6 bytes big-endian), SubAuthorities. SDDL two-letter aliases (BA=builtin admins S-1-5-32-544, SY=S-1-5-18, IU=S-1-5-4 interactive, SU=S-1-5-6 service). These are documented. Unit 38 identifies IU/SU/BA/SY.

GetNamedSecurityInfoA signature from unit 40:
DWORD GetNamedSecurityInfoA(LPCSTR pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecInfo, PSID *ppsidOwner, PSID *ppsidGroup, PACL *ppDacl, PACL *ppSacl, PSECURITY_DESCRIPTOR *pSecDscrptr). Object types: NTFS objects (SE_FILE_OBJECT), services (SE_SERVICE), registry keys (SE_REGISTRY_KEY), shares (SE_LMSHARE), file-mapping objects (SE_KERNEL_OBJECT). Good.

Why It Matters: The vault documents write-side SDDL usage (handle blocking in T-016) and service LPE indirectly, but no card documents the read-side reconnaissance workflow: descriptor retrieval across object classes, SDDL/ACE parsing, privilege fallback via backup/restore privileges. It fills the gap between service enumeration (which finds services) and exploitation (which modifies them) by answering "which objects are writable by my current token" systematically. 2-4 sentences.

References: atlas-privesc-part2.md; MITRE T1007 URL https://attack.mitre.org/techniques/T1007/; LGTM note id; public references: SANS SEC670 (named in material), UACMe not relevant. Maybe mention MSDN SDDL/ACE strings — public references optional, only if named in material. SEC670 is the source itself. I'll list "SANS SEC670 Red Teaming Tools" as the source under atlas, and add Microsoft SDDL/ACE string documentation as public reference? Rule: "do not invent references" — public references should be ones named in the atlas material. MSDN isn't named. I'll omit public references or just include SEC670. The References template: "Public references: <optional — original tool authors, blog posts, papers named in the atlas material>". I'll write "SANS SEC670 Red Teaming Tools: Developing Custom Tools for Windows (source document, cited throughout atlas-privesc-part2.md)". Good.

Frontmatter:
```yaml
---
id: T-029
name: Security Descriptor and SDDL Reconnaissance
category: discovery
tier: B
crate: none
source_file: none
mitre: T1007
mitre_secondary: [T1083, T1012]
tags: [sddl, security-descriptor, dacl, ace-parsing, sc-sdshow, getnamedsecurityinfo, service-recon, privesc-recon, se-restore-privilege]
origin: atlas-synthesis
member_notes: [lgtm:proposed-technique-security-descriptor-reconnaissance]
---
```

Name: 4-8 words. "Security Descriptor and SDDL Reconnaissance" = 6 words. Good. H1: "# Security Descriptor and SDDL Reconnaissance — Weak-DACL Discovery for Privilege-Escalation Planning".

Word count: target 1200-1800 body words. Let me draft.

Summary (3-5 sentences, first standalone):
"Security descriptor reconnaissance is the read-side workflow of retrieving, parsing, and evaluating DACLs on Windows securable objects — services, registry keys, NTFS files, shares, and kernel objects — to identify weak permissions that enable local privilege escalation." Then: sc.exe sdshow exposes service DACLs as SDDL strings; GetNamedSecurityInfoA generalizes retrieval across object types; manual ACE-string parsing decodes ace_type, flags, rights, and SID abbreviations; when the DACL itself blocks access, SE_BACKUP_NAME/SE_RESTORE_NAME provide an ACL-independent fallback. Detection surface... material doesn't discuss detection. The Summary asks for primary detection surface per template but material doesn't cover it. Hmm — Summary template says include "the primary detection surface". Rule says don't invent detections. I can phrase neutrally: the workflow is read-only and uses documented query interfaces; the material does not document its detection surface. That satisfies both.

Mechanism: numbered steps as above, ~8 steps, concrete.

OS Internals Context: SECURITY_DESCRIPTOR self-relative layout (20-byte header: Revision, Sbz1, Control, offsets), ACL header + ACE layout (AceType/AceFlags/AceSize + ACCESS_MASK + SID), ACCESS_MASK bit regions, SDDL two-letter right mappings including service rights (CC/DC/LC/SW/RP/WP/DT/LO/CR per MSDN mapping, material shows CCLCSWLOCRRC strings), SID abbreviations (IU/S-1-5-4, SU/S-1-5-6, BA/S-1-5-32-544, SY/S-1-5-18), canonical ACE ordering (deny before allow), owner implicit rights (READ_CONTROL/WRITE_DAC), access check path (ObpLookupObjectName → SeAccessCheck; SCM stores service SDs under HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Security), backup/restore privilege semantics (SeBackupPrivilege read, SeRestorePrivilege write incl. WRITE_DAC/WRITE_OWNER; FILE_FLAG_BACKUP_SEMANTICS; enabled via LookupPrivilegeValue/OpenProcessToken/AdjustTokenPrivileges per units 1-7), ACCESS_SYSTEM_SECURITY for SACL requires SeSecurityPrivilege. Also sc.exe sdshow output for BITS is D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)... material unit 37 says run sc.exe sdshow BITS. I shouldn't fabricate the exact BITS output beyond what unit 38 shows as an exercise solution. Unit 38 shows a constructed DACL. I'll describe the parsing of the example from unit 38.

Key Implementation Details: no implementation line + paragraph describing implementation: use GetNamedSecurityInfoA per object class, request OWNER|GROUP|DACL_SECURITY_INFORMATION, convert with ConvertSecurityDescriptorToStringSecurityDescriptorA or walk ACL via GetAce + LookupAccountSidA; sc.exe sdshow equivalent via QueryServiceObjectSecurity; privilege pre-check via GetTokenInformation TokenPrivileges. Note block_handle.rs contains the write-side primitive (manual self-relative SD construction + NtSetSecurityObject), confirming the binary layout a parser must mirror. One careful sentence.

Why It Matters: gap statement, relation to T-016 write-side and T-023 recon.

Detection Considerations: required line only.

Related Techniques:
- **T-023 Client Capabilities Suite** — T-029 extends client-side reconnaissance (Byakugan network recon, sysinfo collection) into the authorization-metadata plane: descriptor evaluation feeds LPE target selection before harvest/escalation modules run.

References: atlas-privesc-part2.md; MITRE T1007 (+secondary T1083, T1012 URLs? template shows single URL; I'll include T1007 URL and mention secondaries); LGTM note; SEC670 public reference.

Source Reference: "No current implementation. See atlas material and MITRE reference for public tooling (sc.exe, GetNamedSecurityInfoA)."

Word budget: Summary ~110, Mechanism ~380, OS Internals ~450, Key Impl ~150, Why ~90, Detection ~15, Related ~40, References ~50 → ~1285. Good.

Check banned words: avoid "elegant, robust, sophisticated, notable, worth noting, it is important to note, essentially, at its core". Careful with "textbook" — banned. Avoid.

Check rule: no suggestions — the Key Implementation "what an implementation would look like" is mandated by the template, allowed.

MITRE secondary format: `mitre_secondary: [T1083, T1012]`.

Tags count 9 — fine (5-10).

Now write the card. Also make sure member_notes exactly `['lgtm:proposed-technique-security-descriptor-reconnaissance']`.

One more check on service SDDL rights mapping (MSDN "Service Security and Access Rights" / "ACE strings"):
- CC — SERVICE_QUERY_CONFIG
- DC — SERVICE_CHANGE_CONFIG
- LC — SERVICE_QUERY_STATUS
- SW — SERVICE_ENUMERATE_DEPENDENTS
- RP — SERVICE_START
- WP — SERVICE_STOP
- DT — SERVICE_PAUSE_CONTINUE
- LO — SERVICE_INTERROGATE
- CR — SERVICE_USER_DEFINED_CONTROL
- RC — READ_CONTROL
- SD — DELETE (note: in SDDL, "SD" = standard delete per material unit 35: "SD: standard delete")
- WD — WRITE_DAC
- WO — WRITE_OWNER
- GA/GR/GW/GX generic.
Directory/object rights per material: RP read property, WP write property, CC create child, DC delete child, LC list children, SW self write. Note these differ per object class — material lists "directory rights RP/WP/CC/DC/LC/SW". Yes, for directory services objects. Registry: KA all, KR read, KW write, KX execute. File: FA all, FR read. Good — I'll note rights constants are object-class-dependent, which the material itself structures by class (generic/standard/directory/registry/file). Service-specific constants come from MSDN documentation (well-established), consistent with unit 38's usage.

Unit 38 example parse: (D;;DCLCWPDTSD;;;IU) — deny interactive user: DC(change config), LC(query status), WP(stop), DT(pause/continue), SD(delete). (A;;CCLCSWLOCRRC;;;IU) — allow: query config, query status, enumerate dependents, interrogate, user-defined control, read control. (A;;CCLCSWRPWPDTLOCRRC;;;SY) — SYSTEM additionally gets start/stop/pause. This is a lockdown example: denies mutation to IU/SU/BA while allowing read-ish rights. Good teaching example for parsing.

ace_string field layout: (ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid) — six semicolon-separated fields. Material unit 35 gives the components; the six-field layout is documented MSDN. I'll present it.

Length checks fine. Write it.