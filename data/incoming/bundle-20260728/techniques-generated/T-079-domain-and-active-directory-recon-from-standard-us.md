---
id: T-079
name: Domain and Active Directory Recon from Standard User
category: discovery
tier: A
crate: none
source_file: none
mitre: T1018
mitre_secondary: [T1087.002, T1069.002]
tags: [domain-recon, active-directory, powerview, adsearch, ldap, integrity-level, standard-user, lateral-movement, tradecraft]
origin: atlas-synthesis
member_notes: ['lgtm:domain-recon-standard-user', 'lgtm:active-directory-recon-coverage-gap']
---

# Domain and Active Directory Recon from Standard User — Standard-User AD Enumeration for Lateral Movement Planning

## Summary

Active Directory enumeration from a standard domain user context enables mapping of domain computers, users, groups, Group Policy Objects, domain controllers, and user session locations without requiring local elevation on the enumeration host. The technique leverages LDAP queries against domain controllers that default Active Directory ACLs permit for all authenticated domain users. CRTO material explicitly warns that running domain recon from a high-integrity process is operationally detrimental because it associates the recon footprint with an elevated token, increasing EDR scrutiny and conflating reconnaissance with post-exploitation activity. PowerView cmdlets (Get-DomainComputer, Get-DomainUser, Get-DomainGPO, Get-DomainController, Find-DomainUserLocation) and ADSearch with custom LDAP filters are the primary tooling vectors documented in the CRTO curriculum. The primary detection surface is LDAP query logging on domain controllers and PowerShell script block logging on the enumeration host.

## Mechanism

1. An implant operating as a standard domain user holds a Kerberos Ticket-Granting Ticket (TGT) obtained during initial authentication. This TGT permits LDAP binds to domain controllers using the user's standard-domain-user token, with no local elevation required on the enumeration host.

2. LDAP queries target the domain controller's Directory Information Tree (DIT) over TCP port 389 (LDAP) or 636 (LDAPS). Active Directory's default security descriptor on the domain partition grants "Authenticated Users" (well-known SID S-1-5-11) read access to most object attributes, including computer accounts, user accounts, group memberships, and GPO link information. No special privileges are required beyond domain membership.

3. PowerView cmdlets wrap System.DirectoryServices.DirectorySearcher or System.DirectoryServices.ActiveDirectory.Domain objects to construct LDAP filters and enumerate AD objects:
   - `Get-DomainComputer` — queries `objectCategory=computer`, returns DNS host names, operating system versions, SPNs, and last logon timestamps. Used for lateral movement target selection.
   - `Get-DomainUser` — queries `objectCategory=person` with optional filters for `samAccountType`, `memberOf`, or `userAccountControl` flags. Identifies privileged accounts, service accounts, and Kerberoastable targets.
   - `Get-DomainGPO` — queries `objectCategory=groupPolicyContainer`, returns GPO display names, GUIDs, and linked OUs. Maps policy enforcement boundaries.
   - `Get-DomainController` — queries `objectCategory=computer` with `(userAccountControl:1.2.840.113556.1.4.803:=8192)` to identify domain controllers. Determines LDAP bind targets and Kerberos KDC endpoints.
   - `Find-DomainUserLocation` — iterates every computer returned by Get-DomainComputer and queries active sessions via NetSessionEnum or remote WMI. This cmdlet is operationally expensive because it generates a network connection to every machine in the domain, producing high-volume share access and RPC traffic.

4. ADSearch provides a lightweight alternative to PowerView using direct LDAP filter syntax. Custom filters such as `(&(objectCategory=computer)(operatingSystem=*Server*))` or `(&(objectCategory=user)(servicePrincipalName=*))` allow targeted enumeration with minimal tooling footprint. ADSearch runs as a single compiled binary with no .NET framework dependency, reducing PowerShell-based telemetry exposure.

5. The integrity-level tradeoff is the core tradecraft decision: performing AD enumeration from the initial standard-user process context (Medium integrity level, IL=2) avoids associating the LDAP query traffic with an elevated or high-integrity token. If recon is performed from a high-integrity process — after UAC bypass or token theft — the EDR sees LDAP queries originating from a process with an anomalous integrity level, which may trigger detection rules that flag elevated processes performing network reconnaissance. The elevated token also carries additional groups or privileges that change the access check results and log details on the domain controller.

6. Enumeration results feed directly into lateral movement planning: computer accounts with recent `lastLogon` timestamps become targets for remote service deployment or WMI execution; user accounts with SPNs become Kerberoasting targets; GPO boundaries inform which machines share security configuration; domain controller locations determine where DCSync or NTDS.dit extraction would be attempted.

## OS Internals Context

Active Directory is implemented as an LDAP directory service backed by the Extensible Storage Engine (ESE) database (NTDS.dit) on domain controllers. The domain controller's lsass.exe process hosts the Active Directory Domain Services (AD DS) service, which services LDAP requests via the LDAP handler in lsass.exe.

Default ACLs on the Active Directory domain partition grant "Authenticated Users" (well-known SID S-1-5-11) read access to most object classes. This is a deliberate design choice: domain users need to query AD for logon script locations, GPO application, and service endpoint discovery during normal operation. The specific extended rights that require elevated permissions — such as replicating directory changes (DS-Replication-Get-Changes) — are controlled by separate ACLs on the domain root object and are not needed for enumeration.

From the Windows security token perspective, a standard domain user process holds a token with Integrity Level 2 (Medium). The token contains the user's SID, group SIDs (including Domain Users S-1-5-21-...-513), and privileges limited to SeChangeNotifyPrivilege and SeShutdownPrivilege (if interactive). When LDAP binds occur, the domain controller performs access checks against this token. The resulting security event log entries (Event ID 4662 — "An operation was performed on an object") contain the caller's subject SID and the object's security descriptor reference. If the caller's token includes elevated groups or higher integrity, the 4662 events carry that information, making the recon traffic distinguishable from normal domain user query patterns.

PowerView's LDAP queries flow through the System.DirectoryServices namespace, which internally uses the wldap32.dll LDAP client. The LDAP bind operation uses either GSS-SPNEGO (Kerberos) or NTLM authentication, depending on SPN resolution and security configuration. Each LDAP search operation generates one or more Event ID 4662 audit entries on the domain controller if Directory Service Access auditing is enabled via SACL on the domain partition.

Find-DomainUserLocation's session enumeration uses NetSessionEnum (netapi32.dll) or remote WMI queries against each target machine. NetSessionEnum hits the LanmanServer service via RPC, generating Event ID 5140 (network share access) and 5145 (detailed file share access) on each queried machine. This produces a high volume of network connections and log entries proportional to the domain size — a single run against a 500-machine domain generates 500 RPC connections and corresponding log entries.

## Key Implementation Details

**No current implementation in the HUGIN source.** The `byakugan.rs` module in the client_rust crate performs network reconnaissance including ARP scanning, TCP port scanning, and AD enumeration, and the `protocol.rs` file defines `MSG_BYAKUGAN_SCAN_RESULT` (0x40) for transmitting scan results, but the specific AD enumeration primitives documented in CRTO (PowerView cmdlet equivalents, ADSearch LDAP filters, the integrity-level tradeoff guidance) are not verified in the provided source. An implementation would consist of: (1) constructing LDAP filters as Rust string literals, (2) binding to a domain controller via the `ldap` crate or direct FFI to wldap32.dll, (3) issuing paged LDAP searches for computer, user, and GPO objects with the filters documented above, and (4) returning JSON-serialized results via the MSG_BYAKUGAN_SCAN_RESULT protocol message. The integrity-level guidance would manifest as a design constraint: the recon module must execute in the initial process context before any elevation is performed, with the operational framework ensuring that elevation occurs only after reconnaissance completes.

## Why It Matters

The integrity-level tradeoff is the central operational insight this card captures. Standard domain user AD enumeration is the bridge between initial access and lateral movement — it maps the attack surface without requiring exploitation or elevation. CRTO material explicitly flags that performing this enumeration from an elevated context is a tradecraft error because it associates reconnaissance traffic with an elevated token, creating a detectable anomaly. Documenting this as a distinct technique ensures operators understand that the timing and integrity context of AD recon is as important as the enumeration itself.

## Detection Considerations

- **Telemetry sources**: Domain controller Event ID 4662 (directory service access) captures LDAP queries when Directory Service Access auditing is enabled via SACL on the domain partition. Event ID 5140/5145 on target machines captures Find-DomainUserLocation's session enumeration via NetSessionEnum. PowerShell Script Block Logging (Event ID 4104) captures PowerView cmdlet execution and the full LDAP filter strings. Microsoft-Windows-PowerShell/Operational ETW provider logs cmdlet invocations.
- **Bypass options**: ADSearch avoids PowerShell telemetry entirely by using direct LDAP via wldap32.dll FFI or a native LDAP library, producing no PowerShell script block events. Running enumeration from the initial standard-user process avoids integrity-level anomalies that trigger elevated-process network activity rules. Targeted LDAP filters — querying specific OUs or object types — reduce the volume of 4662 events compared to broad wildcard queries.
- **Residual artifacts**: LDAP bind records in DC security logs contain the source IP and caller SID. PowerShell command history (if PowerView is used) stores cmdlet invocations. Network connections from the enumeration host to the DC on TCP 389/636 appear in firewall logs. Find-DomainUserLocation leaves connections to every queried machine in network logs and NetSessionEnum access records.

## Related Techniques

- **T-023 Client Capabilities** — byakugan.rs implements network reconnaissance including AD enumeration; this card documents the tradecraft layer and integrity-level guidance above the implementation
- **T-024 Host Survey and Situational Awareness** — host-level reconnaissance complements domain-level enumeration; together they form the full situational awareness picture from single host to domain scope

## References

- Atlas material: atlas-recon-part1.md, atlas-recon-part6.md
- MITRE ATT&CK: T1018 — https://attack.mitre.org/techniques/T1018/
- LGTM notes: lgtm:domain-recon-standard-user, lgtm:active-directory-recon-coverage-gap

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling (PowerView, ADSearch).