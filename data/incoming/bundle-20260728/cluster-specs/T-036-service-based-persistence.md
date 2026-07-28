# Cluster Spec — T-036: Windows Service-Based Persistence via SCM

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-036`
- **Canonical name**: Windows Service-Based Persistence via SCM
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: high — 5 member notes, SYSTEM persistence, distinct from T-017's existing five-layer suite.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-017']

## Consolidated Description (from clustering)

Windows Service-based persistence via OpenSCManager, CreateService, and ChangeServiceConfig. Services survive reboot and run in SYSTEM context via the SCM. Entry point is SCM interaction; tradecraft includes service hiding via SDDL DACL manipulation.

## Member LGTM Notes (5)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Windows Service-Based Persistence as a Distinct Persistence Layer
- **id**: `lgtm:service-based-persistence-as-distinct-technique`
- **origin**: atlas-binary-analysis-part4
- **source_units**: ['unit 32', 'unit 33', 'unit 34', 'unit 35', 'unit 36', 'unit 37']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'services', 'scm', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part4
**Would relate to:** T-017
**Source units:** unit 32, unit 33, unit 34, unit 35, unit 36, unit 37

SEC670 dedicates an entire services module (CreateService, QueryServiceStatusEx, QueryServiceConfig, ChangeServiceConfig, ServiceMain pattern) to service-based persistence. The vault's T-017 persistence suite currently lists COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not surface SCM service creation as a distinct layer despite the service binary's ServiceMain being a structurally different execution model from schtask or COM. This would merit its own sub-technique entry given the prevalence of services in real-world red team persistence.

### Note 2: Service-Based Persistence with SDDL DACL Hiding
- **id**: `lgtm:service-based-persistence-with-dacl-hiding`
- **origin**: atlas-exploit-dev-part3
- **source_units**: ['unit 11', 'unit 12']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'service', 'dacl', 'sddl', 'scm', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part3
**Would relate to:** T-017
**Source units:** unit 11, unit 12

The SEC670 material dedicates two units (11 and 12 — 'Programmatically Hide a Service' and Lab 4.4 'NotInService') to installing a custom service via the SCM APIs and then hiding it via SetNamedSecurityInfo DACL modification. The vault's T-017 Five-Layer Persistence card covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not document service-based persistence at all. Service + DACL hiding is a distinct persistence layer worth its own technique card because the DACL-hiding primitive is reusable across any service the operator installs.

### Note 3: Service ImagePath/binPath/FailureCommand Persistence
- **id**: `lgtm:proposed-service-modification-persistence`
- **origin**: atlas-misc-part1
- **source_units**: ['unit 1', 'unit 10']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'services', 'scm', 'imagepath', 'failurecommand', 'proposed']

**Kind:** proposed-technique
**Origin:** atlas-misc-part1
**Would relate to:** T-017
**Source units:** unit 1, unit 10

SEC670 Book 4 documents modifying existing services via ImagePath, binPath, and FailureCommand registry keys as a persistence mechanism. The vault's T-017 persistence suite does not include service-based persistence. Service persistence has unique operational properties (SCM-driven, auto-start, FailureCommand provides redundancy on service failure) that distinguish it from the documented five layers.

### Note 4: Custom Windows Service Persistence (SCM-based)
- **id**: `lgtm:service-persistence-card`
- **origin**: atlas-post-exploit-part12
- **source_units**: ['unit 1', 'unit 2', 'unit 4', 'unit 10', 'unit 12', 'unit 16']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'services', 'scm', 'sddl', 'coverage-gap', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part12
**Would relate to:** T-017
**Source units:** unit 1, unit 2, unit 4, unit 10, unit 12, unit 16

SEC670 dedicates a full module (units 1–22) to OpenSCManager / CreateService persistence and SDDL-based service hiding — a persistence vector absent from the vault's T-017 card (which covers COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist). Service persistence is operationally distinct: it survives reboots, runs under SYSTEM via the SCM, and pairs with SDDL-based enumeration hiding. Would merit its own T-NNN card given the depth of operational tradecraft (privilege gating, SDDL hiding syntax, cleanup pattern).

### Note 5: Windows Services Persistence Suite (Sibling to T-017)
- **id**: `lgtm:proposed-windows-services-persistence-card`
- **origin**: atlas-post-exploit-part6
- **source_units**: ['unit 9', 'unit 10', 'unit 11', 'unit 12', 'unit 14', 'unit 15', 'unit 17', 'unit 19', 'unit 21', 'unit 23', 'unit 24', 'unit 27', 'unit 30', 'unit 33']
- **would_relate_to**: ['T-017']
- **tags**: ['services', 'persistence', 'scm', 'sddl', 'service-failure-actions', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part6
**Would relate to:** T-017
**Source units:** unit 9, unit 10, unit 11, unit 12, unit 14, unit 15, unit 17, unit 19, unit 21, unit 23, unit 24, unit 27, unit 30, unit 33

SEC670 dedicates an entire module to service-based persistence: creating new services via SCM APIs, modifying ImagePath/binPath/FailureCommand on existing services, abusing SERVICE_FAILURE_ACTIONS.lpCommand as a re-execution trigger via ChangeServiceConfig2, and hiding services by stripping SDDL DACL permissions. The vault's T-017 covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist — service persistence is absent. This would merit its own T-NNN card or an additional layer under T-017 because the SCM lifecycle, the failure-action semantics, and the SDDL concealment primitive are operationally distinct from the existing five layers.

---

## Your Task

Produce the technique card for **T-036** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-036` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-017'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:service-based-persistence-as-distinct-technique', 'lgtm:service-based-persistence-with-dacl-hiding', 'lgtm:proposed-service-modification-persistence', 'lgtm:service-persistence-card', 'lgtm:proposed-windows-services-persistence-card']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.