# Cluster Spec — T-112: AppInit_DLLs and AppCert DLL Registry Loading

- **T-NNN ID**: `T-112`
- **Canonical name**: AppInit_DLLs and AppCert DLL Registry Loading
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: medium — 2 member notes, distinct DLL-loading mechanism with historical APT usage, increasingly mitigated on modern systems
- **would_relate_to**: ['T-017']

## Consolidated Description

AppInit_DLLs (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs and RequireSignedAppInit_DLLs) causes user32.dll to load the specified DLL into any process that imports user32.dll, providing broad-scope persistence across GUI processes. AppCert DLLs (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls) similarly loads DLLs into processes that use the Win32 subsystem APIs via CreateProcess. SEC670 treats these as distinct from Run/RunOnce keys because they are DLL-loading mechanisms triggered by subsystem events rather than shell-launch values. AppInit_DLLs in particular is historically significant (Apt28/T9000 usage documented by SEC670) but has been progressively restricted by Microsoft (RequireSignedAppInit DLLs, Secure Boot mitigation disabling AppInit entirely on modern systems).


## Member LGTM Notes (2)

### Note 1: AppInit_DLLs and AppCert Persistence Vectors
- id: `lgtm:appinit-and-appcert-persistence`
- origin: atlas-post-exploit-part1
- would_relate_to: ['T-017']
- tags: ['persistence', 'appinit', 'appcert', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part1
**Would relate to:** T-017
**Source units:** unit 9, unit 11

SEC670's review question on persistence for processes linked against User32.dll identifies AppInit_DLLs as the correct technique, distinct from AppCert and RunOnce. The vault's T-017 does not include either AppInit_DLLs or AppCert as layers. AppInit_DLLs has a distinctive detection signature (registry value write at HKLM\...\Windows\AppInit_DLLs), a documented infinite-loop hazard when the loaded DLL re-loads User32.dll, and modern-Windows behavior differences (the feature is off by default). The vault should surface this coverage.

### Note 2: AppInit_DLLs and AppCert DLLs Registry-Driven Loading
- id: `lgtm:registry-dll-loading-mechanisms`
- origin: atlas-post-exploit-part11
- would_relate_to: ['T-017']
- tags: ['appinit', 'appcert', 'registry', 'dll-loading', 'persistence', 'autoruns-detectable']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part11
**Would relate to:** T-017
**Source units:** unit 8, unit 24, unit 25, unit 31, unit 32

T-017 enumerates persistence layers but does not separately document the AppInit_DLLs and AppCert registry-driven DLL loading mechanisms. SEC670 treats these as distinct from Run/RunOnce keys because they trigger on process linkage (User32 for AppInit) or process creation (CreateProcess family for AppCert) rather than at logon. They have unique operational constraints: AppInit risks infinite loading loops, AppCert requires admin and reboot. AutoRuns detects both. Worth separate documentation in T-017 or as a new card.

---
Use `id: T-112`, canonical name above, and `member_notes: ['lgtm:appinit-and-appcert-persistence', 'lgtm:registry-dll-loading-mechanisms']`.
Cross-reference `would_relate_to`: ['T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.