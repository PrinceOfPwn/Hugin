# Cluster Spec — T-043: Token Theft (TokenThief) via OpenProcessToken and Duplication

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-043`
- **Canonical name**: Token Theft (TokenThief) via OpenProcessToken and Duplication
- **Proposed category**: `privesc`
- **Proposed tier**: `A`
- **Priority**: high — 6 member notes (strongest signal), explicit SANS Lab, distinct from T-021, clear operational value.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-021', 'T-023', 'T-015']

## Consolidated Description (from clustering)

Token theft for privilege escalation via OpenProcessToken to obtain token from higher-integrity process, DuplicateTokenEx to create copy with MAXIMUM_ALLOWED rights, and CreateProcessWithTokenW to spawn child with stolen token's privilege level. Enables Admin-to-SYSTEM, High-IL-to-SYSTEM, and cross-privilege impersonation. SANS Lab 3.5 establishes as distinct offensive primitive.

## Member LGTM Notes (6)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Access Token Theft (TokenThief Pattern)
- **id**: `lgtm:token-theft-privilege-escalation`
- **origin**: atlas-binary-analysis-part4
- **source_units**: ['unit 30', 'unit 31']
- **would_relate_to**: ['T-021', 'T-023']
- **tags**: ['token-theft', 'privilege-escalation', 'tokenthief', 'openprocesstoken']

**Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part4
**Would relate to:** T-021, T-023
**Source units:** unit 30, unit 31

SEC670's escalation module includes the TokenThief lab pairing OpenProcessToken with token duplication for privilege escalation. The vault's T-021/T-023 UAC bypass coverage addresses auto-elevation but does not document the broader token-theft primitive (open a SYSTEM token on winlogon.exe, duplicate it, assign to the implant's primary token, AdjustTokenPrivileges). This is a distinct escalation capability separate from UAC bypass and would merit its own card.

### Note 2: Token Theft and Impersonation as a Standalone Technique Card
- **id**: `lgtm:token-impersonation-theft-card`
- **origin**: atlas-labs-part2
- **source_units**: ['unit 1']
- **would_relate_to**: ['T-023', 'T-017']
- **tags**: ['token-impersonation', 'privilege-escalation', 'lateral-movement', 'sec670', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-labs-part2
**Would relate to:** T-023, T-017
**Source units:** unit 1

SEC670 Lab 3.5 'TokenThief' dedicates an entire lab to token theft and impersonation, indicating it is a distinct, teachable offensive capability. The vault currently distributes token-related logic implicitly across T-023 client capabilities (lsass_dump, wmi_exec) but has no card documenting the MakeToken/ImpersonateLoggedOnUser/DuplicateTokenEx primitive family or its operational use for lateral movement and privilege escalation.

### Note 3: Token Theft as Standalone Privilege Escalation Technique
- **id**: `lgtm:proposed-token-theft-technique`
- **origin**: atlas-post-exploit-part14
- **source_units**: ['unit 19', 'unit 20', 'unit 21', 'unit 22', 'unit 25', 'unit 26', 'unit 27']
- **would_relate_to**: ['T-021', 'T-023']
- **tags**: ['token-theft', 'privilege-escalation', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part14
**Would relate to:** T-021, T-023
**Source units:** unit 19, unit 20, unit 21, unit 22, unit 25, unit 26, unit 27

SEC670's TokenThief lab (Lab 3.5) and the OpenProcessToken review material cover token theft, duplication, and impersonation as a distinct offensive capability. T-023 includes credential harvest and T-021 includes UAC bypass, but neither documents the full token-theft primitive (OpenProcess with SeDebugPrivilege -> OpenProcessToken -> DuplicateTokenEx -> CreateProcessAsUser). This is a reusable tradecraft primitive worth its own T-NNN card or explicit expansion of T-023.

### Note 4: Token Stealing (TokenThief) Admin-to-SYSTEM LPE
- **id**: `lgtm:proposed-token-stealing-lpe-card`
- **origin**: atlas-privesc-part1
- **source_units**: ['unit 7', 'unit 10', 'unit 17', 'unit 18']
- **would_relate_to**: ['T-013', 'T-015']
- **tags**: ['lpe', 'token-stealing', 'getsystem', 'admin-to-system', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-privesc-part1
**Would relate to:** T-013, T-015
**Source units:** unit 7, unit 10, unit 17, unit 18

SEC670 Lab 3.5 TokenThief walks through the full OpenProcess + OpenProcessToken + DuplicateTokenEx + CreateProcessWithTokenW sequence to spawn a System-IL child from a High-IL admin context. The vault's T-013 (Remaining Methods) covers process hollowing and injection but not token duplication as a privilege escalation vector in its own right. This would be a distinct T-NNN card because it operates at a different layer — token manipulation, not memory injection — and is the conceptual basis for Meterpreter's getsystem techniques.

### Note 5: Token Theft (TokenThief) as a Standalone Privilege Technique
- **id**: `lgtm:token-theft-and-impersonation-primitive`
- **origin**: atlas-post-exploit-part16
- **source_units**: ['unit 18', 'unit 20', 'unit 21', 'unit 26']
- **would_relate_to**: ['T-015', 'T-023']
- **tags**: ['token-theft', 'openprocesstoken', 'impersonation', 'privilege-escalation', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part16
**Would relate to:** T-015, T-023
**Source units:** unit 18, unit 20, unit 21, unit 26

SEC670 Book 3 Lab 3.5 TokenThief teaches token theft as a distinct primitive and the OpenProcessToken API as its entry point. T-015 (PPID Spoofing) touches parent-process attribute manipulation but the vault has no dedicated technique card for token duplication, impersonation, or theft. Token theft is reusable across escalation, lateral movement, and persistence chains and operates on Windows token structures (TOKEN_PRIMARY, TOKEN_IMPERSONATE, SeImpersonatePrivilege) that merit standalone documentation.

### Note 6: Token Theft as a Distinct Technique
- **id**: `lgtm:proposed-token-theft-technique-card`
- **origin**: atlas-post-exploit-part4
- **source_units**: ['unit 13', 'unit 14', 'unit 15', 'unit 16', 'unit 17', 'unit 18', 'unit 19', 'unit 20', 'unit 21', 'unit 22']
- **would_relate_to**: ['T-015', 'T-023']
- **tags**: ['token-theft', 'privilege-escalation', 'lateral-movement', 'openprocesstoken']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part4
**Would relate to:** T-015, T-023
**Source units:** unit 13, unit 14, unit 15, unit 16, unit 17, unit 18, unit 19, unit 20, unit 21, unit 22

SEC670 dedicates Lab 3.5 (TokenThief) and multiple slides to OpenProcessToken-based primary-token theft from High-IL/SYSTEM processes followed by CreateProcessWithTokenW or ImpersonateLoggedOnUser. The vault currently folds token theft into T-023 Client Capabilities (credential harvest) and T-015 PPID Spoofing, but the OpenProcessToken → DuplicateTokenEx → spawn workflow is operationally distinct from parent-PID manipulation. The technique has its own detection footprint (Kernel-Process TokenOpen ETW events, 4688 High Mandatory Level without consent UI) and tradecraft considerations (which source PID to target, which access mask to request, how to clean up duplicated handles).

---

## Your Task

Produce the technique card for **T-043** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-043` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-021', 'T-023', 'T-015'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:token-theft-privilege-escalation', 'lgtm:token-impersonation-theft-card', 'lgtm:proposed-token-theft-technique', 'lgtm:proposed-token-stealing-lpe-card', 'lgtm:token-theft-and-impersonation-primitive', 'lgtm:proposed-token-theft-technique-card']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.