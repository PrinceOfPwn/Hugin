---
id: T-212
title: "Domain and Active Directory Recon from Standard User Context"
category: patterns
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: domain-recon-standard-user-context
member_notes: ["lgtm:domain-recon-standard-user", "lgtm:active-directory-recon-coverage-gap"]
---

## Summary
This technique covers Domain and Active Directory Recon from Standard User Context, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
CRTO documents AD enumeration via PowerView (Get-DomainComputer, Get-DomainUser, Get-DomainGPO, Get-DomainController, Find-DomainUserLocation) and ADSearch with custom LDAP filters — all runnable from standard user context without elevation. Running domain recon from a high-integrity process is operationally detrimental because it conflates the recon footprint with the elevated token (token duplication context, EDR attention). The vault's T-023 covers 'recon' generically but does not document the standard-user AD enumeration layer that bridges initial access and lateral movement; the card should enumerate PowerView cmdlets, ADSearch LDAP filter syntax, and the operational guidance that recon must be performed in the initial standard-user context.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// PowerView Get-DomainComputer -LDAPFilter '(operatingSystem=*Server*)' invoking System.DirectoryServices.DirectorySearcher against LDAP://CN=Configuration,DC=... rootDSE
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:domain-recon-standard-user: Contributed insights into the specific mechanism.
- Note lgtm:active-directory-recon-coverage-gap: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-023: Relates conceptually based on evidence.

## References
- Internal vault documentation on Domain and Active Directory Recon from Standard User Context
