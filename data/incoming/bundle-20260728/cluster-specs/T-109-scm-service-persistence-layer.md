# Cluster Spec — T-109: Windows Service (SCM) Persistence as Distinct Layer

- **T-NNN ID**: `T-109`
- **Canonical name**: Windows Service (SCM) Persistence as Distinct Layer
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: high — 4 member notes from different batches; flagship persistence card T-017 has explicit gap for this category.
- **would_relate_to**: ['T-017']

## Consolidated Description

SEC670 dedicates multiple units to the Windows Service Control Manager
programming model: ServiceMain entry point,
StartServiceControlDispatcher (binding SERVICE_TABLE_ENTRY array),
RegisterServiceCtrlHandlerEx (registering HandlerFunction callback),
SetServiceStatus (SERVICE_RUNNING/SERVICE_STOPPED state machine), and the
SCM-RPC protocol. Service persistence variants include: (1) classic —
register a binary at
HKLM\SYSTEM\CurrentControlSet\Services\{svc}\ImagePath, Start=2
(SERVICE_AUTO_START), Type=0x10 (SERVICE_WIN32_OWN_PROCESS); (2) shared
process — Type=0x20 (SERVICE_WIN32_SHARE_PROCESS) for blending with
svchost; (3) service-binary patching — modify an existing service's
ImagePath to point at attacker-controlled binary preserving the original
service name for cover. The vault's T-017 covers COM hijack, NTFS EA,
schtask, TLS callback, and PhantomPersist but omits services. Card should
document detection: Sysmon EID 1 + EID 3 + ImagePath mismatch against
signed service binary inventory.


## Member LGTM Notes (4)

### Note 1: Windows Service (SCM) Persistence as a Distinct Layer
- id: `lgtm:scm-service-persistence-layer`
- origin: atlas-exploit-dev-part9
- would_relate_to: ['T-017']
- tags: ['persistence', 'service', 'scm', 'coverage-gap', 'windows-internals']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part9
**Would relate to:** T-017
**Source units:** unit 27, unit 28, unit 29, unit 30, unit 31, unit 32

SEC670 dedicates multiple units to the Windows Service Control Manager programming model — ServiceMain, StartServiceControlDispatcher, RegisterServiceCtrlHandlerEx, SetServiceStatus, and the full CreateService parameter surface (lpBinaryPathName, lpServiceStartName, lpDependencies). The vault's T-017 lists schtask, COM hijack, NTFS EA, TLS callback, and PhantomPersist as its five persistence layers but does not document the classic CreateService persistence path, which is the most common boot-time persistence primitive in production Windows red team operations. The SCM contract is also more demanding than the other layers (the binary must implement a control handler or the SCM marks it failed), which makes it operationally distinct and worth its own treatment within T-017 or as a dedicated sub-card.

### Note 2: Service-Based Persistence Coverage Gap in T-017
- id: `lgtm:service-based-persistence-gap`
- origin: atlas-labs-part2
- would_relate_to: ['T-017']
- tags: ['persistence', 'service', 'wininit', 'coverage-gap', 'sec670']

**Kind:** coverage-gap
**Origin:** atlas-labs-part2
**Would relate to:** T-017
**Source units:** unit 4, unit 5

SEC670 Lab 4.4 'NotInService' and Lab 4.5 'InitToWinit' target service and WinInit-based persistence mechanisms. T-017 documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not cover service-image-path manipulation, service trigger configuration, or WinInit/RunOnce-style persistence. The vault's persistence card under-covers the service-vector space.

### Note 3: Service and Binary Patching Persistence Coverage Gap
- id: `lgtm:services-and-binary-patching-persistence-gap`
- origin: atlas-methodology-part4
- would_relate_to: ['T-017']
- tags: ['persistence', 'services', 'binary-patching', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-methodology-part4
**Would relate to:** T-017
**Source units:** unit 9, unit 10, unit 11, unit 13, unit 15, unit 24, unit 26

SEC670 Section 4 lists Services Revisited and Binary Patching as persistence mechanisms, both absent from the vault's T-017 Five-Layer Persistence card. Service persistence (registering a malicious service binary or hijacking an existing service path) is one of the most common persistence vectors in incident response data. Binary patching persistence modifies an existing on-disk binary to incorporate attacker code. The vault's persistence coverage is currently oriented toward fileless or filesystem-adjacent techniques (COM hijack, NTFS EA, schtask, TLS callback) and would benefit from explicit service and binary-patch technique documentation.

### Note 4: Windows Service Persistence Not in Vault
- id: `lgtm:services-persistence-gap`
- origin: atlas-methodology-part7
- would_relate_to: ['T-017']
- tags: ['persistence', 'services', 'scm', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-methodology-part7
**Would relate to:** T-017
**Source units:** unit 5, unit 6, unit 8, unit 10

SEC670 covers 'Services Revisited' and Lab 4.1 (PersistentService) as a primary persistence vector. The vault's T-017 suite does not include classic service-based persistence (svc.exe binary on disk + SCM registration with auto-start). Given that services remain one of the most common real-world persistence vectors, this is a notable gap versus the existing schtask layer in T-017.

---
Use `id: T-109`, canonical name above, and `member_notes: ['lgtm:scm-service-persistence-layer', 'lgtm:service-based-persistence-gap', 'lgtm:services-and-binary-patching-persistence-gap', 'lgtm:services-persistence-gap']`.
Cross-reference `would_relate_to`: ['T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.