# Cluster Spec — T-079: Domain and Active Directory Recon from Standard User Context

- **T-NNN ID**: `T-079`
- **Canonical name**: Domain and Active Directory Recon from Standard User Context
- **Proposed category**: `discovery`
- **Proposed tier**: `A`
- **Priority**: high — Two member notes with cross-source convergence (CRTO); fills a critical gap between initial access and lateral movement
- **would_relate_to**: ['T-023']

## Consolidated Description

CRTO documents AD enumeration via PowerView (Get-DomainComputer, Get-DomainUser, Get-DomainGPO, Get-DomainController, Find-DomainUserLocation) and ADSearch with custom LDAP filters — all runnable from standard user context without elevation. Running domain recon from a high-integrity process is operationally detrimental because it conflates the recon footprint with the elevated token (token duplication context, EDR attention). The vault's T-023 covers 'recon' generically but does not document the standard-user AD enumeration layer that bridges initial access and lateral movement; the card should enumerate PowerView cmdlets, ADSearch LDAP filter syntax, and the operational guidance that recon must be performed in the initial standard-user context.


## Member LGTM Notes (2)

### Note 1: Domain Recon from Standard User Context
- id: `lgtm:domain-recon-standard-user`
- origin: atlas-recon-part1
- would_relate_to: ['T-023']
- tags: ['domain-recon', 'integrity-level', 'tradecraft', 'ad-enum', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-recon-part1
**Would relate to:** T-023
**Source units:** unit 10

CRTO unit 10 surfaces domain reconnaissance as an action a standard domain user can perform without elevated integrity, and notes that running domain recon in a high-integrity process can be detrimental (token duplication context). The vault's recon coverage (T-023 byakugan.rs performs AD enum) does not currently document the integrity-level tradeoff — running recon as standard user vs high integrity — that CRTO flags as a tradecraft decision.

### Note 2: Active Directory Reconnaissance as Distinct Capability
- id: `lgtm:active-directory-recon-coverage-gap`
- origin: atlas-recon-part6
- would_relate_to: ['T-023']
- tags: ['ad-recon', 'powerview', 'ldap', 'coverage-gap', 'opsec']

**Kind:** coverage-gap
**Origin:** atlas-recon-part6
**Would relate to:** T-023
**Source units:** unit 30, unit 31, unit 32, unit 33

CRTO devotes substantial material to AD enumeration via PowerView (Get-DomainComputer, Get-DomainGPO, Find-DomainUserLocation) and ADSearch with custom LDAP filters. T-023 covers 'recon' generically but does not document AD-specific enumeration primitives, their OPSEC costs (Find-DomainUserLocation queries every machine), or how they integrate with the broader recon flow. The vault would benefit from surfacing AD recon as a first-class capability area.

---
Use `id: T-079`, canonical name above, and `member_notes: ['lgtm:domain-recon-standard-user', 'lgtm:active-directory-recon-coverage-gap']`.
Cross-reference `would_relate_to`: ['T-023'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.