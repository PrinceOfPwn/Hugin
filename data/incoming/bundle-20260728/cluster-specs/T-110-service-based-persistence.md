# Cluster Spec — T-110: Windows Service (SCM) Persistence via CreateService

- **T-NNN ID**: `T-110`
- **Canonical name**: Windows Service (SCM) Persistence via CreateService
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: high — 4 member notes from independent batches, most commonly deployed persistence vector in real intrusions
- **would_relate_to**: ['T-017']

## Consolidated Description

SEC670 Book 4 documents the full SCM persistence lifecycle: OpenSCManager() → CreateService(hSCManager, lpServiceName, NULL, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, lpBinaryPathName, ...) with Lab 4.1 'PersistentService' walking through a custom service binary. The service auto-restarts on boot via SERVICE_AUTO_START, and failure-action recovery can be configured via ChangeServiceConfig to restart on crash. This is the most commonly deployed persistence vector in real-world intrusions (SEC670 review material identifies Run key and services as the two most common), yet T-017 documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist without including the SCM layer.


## Member LGTM Notes (4)

### Note 1: T-017 Persistence Surface Under-Covered vs SEC670
- id: `lgtm:gap-persistence-surface-coverage`
- origin: atlas-misc-part1
- would_relate_to: ['T-017']
- tags: ['persistence', 'coverage-gap', 't-017']

**Kind:** coverage-gap
**Origin:** atlas-misc-part1
**Would relate to:** T-017
**Source units:** unit 1, unit 2, unit 7, unit 10, unit 11, unit 26

SEC670's 'Persistence: Die Another Day' module covers services, registry keys, AppInit_DLLs, IFEO, GlobalFlag/Silent Process Exit, port monitors, and WMI event subscriptions. The vault's T-017 documents only COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist — five layers that do not overlap with most of the SEC670 surface. Cross-cutting metadata on T-017 indicating which persistence surfaces the vault covers vs. which it omits would aid operator navigation.

### Note 2: Service-Based Persistence Coverage Gap
- id: `lgtm:service-based-persistence-card`
- origin: atlas-post-exploit-part10
- would_relate_to: ['T-017']
- tags: ['scm', 'services', 'persistence', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part10
**Would relate to:** T-017
**Source units:** unit 1, unit 5, unit 7, unit 10, unit 12, unit 13

SEC670 Book 4 covers SCM, CreateService, ChangeServiceConfig, and SERVICE_WIN32_OWN_PROCESS service lifecycle as a persistence mechanism, including failure-action auto-restart. T-017's five-layer persistence suite does not include service installation. Service persistence differs from schtask in that it requires a properly-formed ServiceMain implementation and exposes SCM handle-based detection surface (Sysmon 7045) — distinct operational considerations.

### Note 3: Service-Based Persistence (CreateService) Not Documented in T-017
- id: `lgtm:gap-service-based-persistence`
- origin: atlas-post-exploit-part14
- would_relate_to: ['T-017']
- tags: ['persistence', 'scm', 'services', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part14
**Would relate to:** T-017
**Source units:** unit 24, unit 36, unit 37, unit 38, unit 39, unit 40

T-017 documents five persistence layers (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) but does not include Windows service-based persistence via CreateService + SCM. SEC670 dedicates Section 4, Lab 4.1 PersistentService, and source code review to this technique. It is operationally distinct from schtask (uses SCM not Task Scheduler) and from PhantomPersist (does not require resilience monitor). Service persistence is foundational enough to merit either its own T-NNN card or explicit documentation in T-017.

### Note 4: SCM Service-Based Persistence Coverage in T-017
- id: `lgtm:scm-service-persistence-coverage-gap`
- origin: atlas-post-exploit-part16
- would_relate_to: ['T-017']
- tags: ['scm', 'create-service', 'persistence', 'coverage-gap', 'service']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part16
**Would relate to:** T-017
**Source units:** unit 19, unit 39, unit 40

SEC670 Book 3 documents the CreateService API signature in detail (hSCManager, lpServiceName, dwServiceType, dwStartType, lpBinaryPathName) and Book 4 Lab 4.1 PersistentService walks through creating a custom service for persistence. T-017's persistence suite does not list service creation as one of its five layers; the vault's BYOVD module uses SCM service registration (experimental/evasion/byovd/service.rs) but not for persistence. Service-based persistence is a documented, distinct tradecraft with its own detection surface (service creation events, Service Control Manager auditing) that the vault under-covers.

---
Use `id: T-110`, canonical name above, and `member_notes: ['lgtm:gap-persistence-surface-coverage', 'lgtm:service-based-persistence-card', 'lgtm:gap-service-based-persistence', 'lgtm:scm-service-persistence-coverage-gap']`.
Cross-reference `would_relate_to`: ['T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.