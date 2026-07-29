# Cluster Spec — T-106: Persistence Vector Catalog Gap (Run, AppInit, AppCert, IFEO, WMI, PortMon, Weak Svc ACL)

- **T-NNN ID**: `T-106`
- **Canonical name**: Persistence Vector Catalog Gap (Run, AppInit, AppCert, IFEO, WMI, PortMon, Weak Svc ACL)
- **Proposed category**: `persistence`
- **Proposed tier**: `S`
- **Priority**: high — Five member notes covering at least 7 distinct persistence vectors absent from T-017; cross-source convergence across SEC670 modules elevates priority
- **would_relate_to**: ['T-017']

## Consolidated Description

T-017 documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but lacks Run / RunOnce (HKLM and HKCU\Software\Microsoft\Windows\CurrentVersion\Run), AppInit_DLLs (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs loaded into every User32-linked process), AppCert (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls), IFEO Debugger values (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>\Debugger, plus SilentProcessExit monitor), WMI Event Subscriptions (__EventFilter + __EventConsumer + __FilterToConsumerBinding in root\subscription namespace), Port Monitors (HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver), and weak service ACL replacement via sc.exe sdset combined with binary path overwrite. The convergence pattern: each abuses an admin or debugging feature by redirecting a code path the OS executes on a scheduled or trigger-based event. The vault's T-017 currently lists only five layers and should be expanded to catalog at least seven more vectors with explicit trigger, detection surface, and required privilege per vector.


## Member LGTM Notes (5)

### Note 1: Run / RunOnce Registry Persistence Coverage Gap
- id: `lgtm:gap-run-key-persistence`
- origin: atlas-post-exploit-part6
- would_relate_to: ['T-017']
- tags: ['run-key', 'registry', 'persistence', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part6
**Would relate to:** T-017
**Source units:** unit 1, unit 2

SEC670 review material identifies the Run key as the most commonly used persistence key in Windows. The vault's T-017 enumerates five persistence layers (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) but does not document Run/RunOnce/RunTwice Registry persistence as a discrete technique. This is the canonical Windows persistence vector and its absence from the card leaves a gap relative to baseline red-team tradecraft.

### Note 2: AppInit/AppCert/IFEO/WMI Persistence Vectors Undocumented
- id: `lgtm:gap-appinit-appcert-ifeo-wmi-persistence`
- origin: atlas-post-exploit-part6
- would_relate_to: ['T-017']
- tags: ['appinit', 'appcert', 'ifeo', 'wmi', 'persistence', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part6
**Would relate to:** T-017
**Source units:** unit 5, unit 6, unit 9

SEC670 references AppInit_DLLs and AppCert as persistence techniques for User32-linked processes, IFEO Debugger values (Sauron IFEO and IFEOPersisto labs), and WMI Event Subscriptions as a persistence module. None of these appear in the vault's T-017 coverage. Each is a distinct Windows persistence surface with different Registry backing, trigger semantics, and detection footprints that would benefit from explicit graph presence.

### Note 3: T-017 Persistence Suite Layer Coverage Gap
- id: `lgtm:persistence-suite-coverage-gap`
- origin: atlas-post-exploit-part7
- would_relate_to: ['T-017']
- tags: ['persistence', 'coverage-gap', 't-017', 'port-monitor', 'ifeo', 'wmi', 'layer-expansion']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part7
**Would relate to:** T-017
**Source units:** unit 1, unit 9, unit 36

SEC670 covers three persistence mechanisms (port monitors, IFEO Debugger/SilentProcessExit, WMI event subscriptions) that are standard red team tradecraft but absent from the vault's T-017 five-layer suite. The current five layers (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) represent a subset of available Windows persistence surfaces. The vault would benefit from either expanding T-017 to a broader layer set or creating dedicated cards for each persistence mechanism class, as operators selecting persistence techniques from the vault currently lack these options.

### Note 4: Persistence Tradecraft Convergence Across SEC670 Modules
- id: `lgtm:cross-source-persistence-tradecraft-convergence`
- origin: atlas-post-exploit-part7
- would_relate_to: ['T-017']
- tags: ['persistence', 'tradecraft', 'convergence', 'target-selection', 'privilege-requirement', 'cleanup']

**Kind:** cross-source-convergence
**Origin:** atlas-post-exploit-part7
**Would relate to:** T-017
**Source units:** unit 6, unit 18, unit 21, unit 27, unit 36

SEC670's port monitor, IFEO, and WMI persistence modules all converge on the same operational pattern: abuse a Windows management/debugging feature intended for administrators by redirecting its execution path to an implant, requiring elevated privileges and careful target selection to ensure reliable triggering. The shared tradecraft — target processes that execute early or frequently, require Admin/SYSTEM for HKLM modification, and include cleanup logic to revert registry changes — applies across all three mechanisms and aligns with the persistence design philosophy already present in T-017's five layers.

### Note 5: Weak Service ACL Persistence Coverage Gap
- id: `lgtm:weak-service-acl-persistence`
- origin: atlas-recon-part7
- would_relate_to: ['T-017']
- tags: ['persistence', 'services', 'sddl', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-recon-part7
**Would relate to:** T-017
**Source units:** unit 17

The persistence suite (T-017) documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist layers but does not appear to cover service-binary-replacement or service-config-change persistence via weak service ACLs. SEC670 treats sc.exe sdshow as a primary recon primitive for surfacing weak service permissions. Operators running T-017 in environments where COM hijack is monitored but legacy weak-ACL services are present would benefit from a documented service-based persistence layer in the suite.

---
Use `id: T-106`, canonical name above, and `member_notes: ['lgtm:gap-run-key-persistence', 'lgtm:gap-appinit-appcert-ifeo-wmi-persistence', 'lgtm:persistence-suite-coverage-gap', 'lgtm:cross-source-persistence-tradecraft-convergence', 'lgtm:weak-service-acl-persistence']`.
Cross-reference `would_relate_to`: ['T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.