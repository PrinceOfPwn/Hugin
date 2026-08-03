---
id: T-224
title: "_KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking"
category: patterns
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: kprocess-forensic-anchor-peb-unlink-detection
member_notes: ["lgtm:kprocess-as-forensic-anchor"]
---

## Summary
This technique covers _KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents the forensic pivot that defeats the vault's T-016 PEB-unlink technique. A scanner that operated only on the PEB Ldr.InLoadOrderModuleList (PEB_LDR_DATA.InLoadOrderModuleList at PEB offset 0x10 on x64) can be defeated by unlinking the module entry. Forensic scanners pivot through EPROCESS.Pcb (the embedded _KPROCESS) → ThreadListHead to enumerate threads, then through KTHREAD.Process (back-pointer) to find processes whose PEB has been tampered with. They also compare the PEB module list against EPROCESS.Pcb.DirectoryTableBase walks of the VAD tree (MMVAD via MiQueryAddressTree). The vault's T-016 PEB unlink is therefore incomplete as a hiding technique; a fuller hide must also patch the VAD.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// EPROCESS.Pcb.ThreadListHead (offset 0x030) pivot → KTHREAD.Process (back-pointer to EPROCESS) → cross-check against PEB_LDR_DATA.InLoadOrderModuleList
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:kprocess-as-forensic-anchor: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-016: Relates conceptually based on evidence.

## References
- Internal vault documentation on _KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking
