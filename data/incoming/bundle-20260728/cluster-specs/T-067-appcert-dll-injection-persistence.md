# Cluster Spec — T-067: AppCert DLL Injection Persistence

- **T-NNN ID**: `T-067`
- **Canonical name**: AppCert DLL Injection Persistence
- **Proposed category**: `persistence`
- **Proposed tier**: `B`
- **Priority**: low — Singleton, distinct from other T-017 persistence layers, narrow host-activity-triggered profile.
- **would_relate_to**: ['T-017']

## Consolidated Description

AppCertDlls registry persistence that injects DLL into any process calling CreateProcess-family APIs or WinExec. Registry key: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls. DLL loaded whenever process spawns via documented creation APIs; host-activity triggered persistence.

## Member LGTM Notes (1)

### Note 1: AppCert DLLs as a Persistence Layer
- id: `lgtm:appcert-dll-persistence`
- origin: atlas-edr-evasion-part2
- would_relate_to: ['T-017']
- tags: ['persistence', 'appcert', 'registry', 'dll-injection', 'proposed']

**Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part2
**Would relate to:** T-017
**Source units:** unit 2

SEC670 documents the AppCertDlls registry mechanism that injects a DLL into any process calling CreateProcess-family APIs or WinExec. This is a distinct persistence vector from COM hijack, schtask, NTFS EA, TLS callback, and PhantomPersist in T-017 — it triggers on host activity rather than on schedule or boot. It requires Admin + reboot to install. The vault currently has no card covering this, and it would complement the five-layer persistence stack.

---
Use `id: T-067`, canonical name above, and `member_notes: ['lgtm:appcert-dll-persistence']`.
Cross-reference `would_relate_to`: ['T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.