# Cluster Spec — T-089: WMI as Dual-Use Recon and Persistence Channel

- **T-NNN ID**: `T-089`
- **Canonical name**: WMI as Dual-Use Recon and Persistence Channel
- **Proposed category**: `discovery`
- **Proposed tier**: `A`
- **Priority**: high — Two member notes with cross-source convergence; surfaces WMI dual-use nature absent from both T-017 and T-023
- **would_relate_to**: ['T-023', 'T-017']

## Consolidated Description

SEC670 Book 4 (Persistence) and Book 2 (Recon) both use WMI — Book 4 for __EventFilter / __EventConsumer / __FilterToConsumerBinding persistence binding in root\subscription namespace, Book 2 for Win32_Process / Win32_Service / Win32_Registry enumeration via Get-WmiObject or IWbemServices::ExecQuery. CRTO also surfaces WMI via Get-Domain / Get-DomainController PowerShell cmdlets. The convergence point: WMI is the single Windows management substrate that supports both recon (read via ExecQuery on standard namespaces root\cimv2, root\default) and persistence (write via permanent event subscription in root\subscription) using the same COM interfaces (CoCreateInstance(CLSID_WbemLocator, IID_IWbemLocator) -> IWbemLocator::ConnectServer -> IWbemServices::ExecQuery / PutInstance). The vault's T-023 recon card and T-017 persistence card both miss the dual-use nature, which means the same COM channel can be used to enumerate the host and to establish persistence in a single IWbemServices session.


## Member LGTM Notes (2)

### Note 1: WMI Tradecraft Convergence Across SEC670 and CRTO
- id: `lgtm:cross-source-wmi-convergence`
- origin: atlas-recon-part3
- would_relate_to: ['T-023', 'T-017']
- tags: ['wmi', 'cross-source', 'convergence', 'recon', 'persistence']

**Kind:** cross-source-convergence
**Origin:** atlas-recon-part3
**Would relate to:** T-023, T-017
**Source units:** unit 20, unit 23, unit 39, unit 40

WMI enumeration (Win32_Process, Win32_Registry, Win32_Service via Get-WmiObject) appears in SEC670 units 19-24; WMI also surfaces in CRTO units via Get-Domain / Get-DomainController PowerShell cmdlets (which wrap WMI/CIM). Multiple courses converge on WMI as a recon and persistence substrate, indicating strong tradecraft consensus. The vault's T-023 and T-017 would benefit from explicit WMI surface documentation.

### Note 2: WMI as Dual-Use Recon and Persistence Channel
- id: `lgtm:cross-source-wmi-recon-persistence-convergence`
- origin: atlas-recon-part5
- would_relate_to: ['T-017', 'T-023']
- tags: ['wmi', 'recon', 'persistence', 'convergence']

**Kind:** cross-source-convergence
**Origin:** atlas-recon-part5
**Would relate to:** T-017, T-023
**Source units:** unit 15, unit 16, unit 17, unit 18

SEC670 Book 4 (Persistence) and Book 2 (Recon) both cover WMI Win32_ classes — Book 4 for __EventFilter/__EventConsumer persistence binding and Book 2 for Win32_Process/Win32_Service enumeration. The dual-use nature of WMI as both recon channel and persistence substrate is a cross-cutting insight the vault splits across T-017 and T-023. A graph edge or concept tying WMI recon to WMI persistence would surface the operational coupling.

---
Use `id: T-089`, canonical name above, and `member_notes: ['lgtm:cross-source-wmi-convergence', 'lgtm:cross-source-wmi-recon-persistence-convergence']`.
Cross-reference `would_relate_to`: ['T-023', 'T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.