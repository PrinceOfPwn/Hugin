---
id: T-210
title: "_KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking"
category: patterns
tier: B
tags: ['research-gap', 'kprocess-forensic-anchor-peb-unlink-detection']
mitre: []
origin: glm-expand-cluster
source_cluster: kprocess-forensic-anchor-peb-unlink-detection
member_notes: ['lgtm:kprocess-as-forensic-anchor']
---

## Summary

This technique card addresses the research gap identified in cluster `kprocess-forensic-anchor-peb-unlink-detection`.
Documents the forensic pivot that defeats the vault's T-016 PEB-unlink technique. A scanner that operated only on the PEB Ldr.InLoadOrderModuleList (PEB_LDR_DATA.InLoadOrderModuleList at PEB offset 0x10 on x64) can be defeated by unlinking the module entry. Forensic scanners pivot through EPROCESS.Pcb (the embedded _KPROCESS) → ThreadListHead to enumerate threads, then through KTHREAD.Process (back-pointer) to find processes whose PEB has been tampered with. They also compare the PEB module list against EPROCESS.Pcb.DirectoryTableBase walks of the VAD tree (MMVAD via MiQueryAddressTree). The vault's T-016 PEB unlink is therefore incomplete as a hiding technique; a fuller hide must also patch the VAD.


## Technical Deep Dive

Documents the forensic pivot that defeats the vault's T-016 PEB-unlink technique. A scanner that operated only on the PEB Ldr.InLoadOrderModuleList (PEB_LDR_DATA.InLoadOrderModuleList at PEB offset 0x10 on x64) can be defeated by unlinking the module entry. Forensic scanners pivot through EPROCESS.Pcb (the embedded _KPROCESS) → ThreadListHead to enumerate threads, then through KTHREAD.Process (back-pointer) to find processes whose PEB has been tampered with. They also compare the PEB module list against EPROCESS.Pcb.DirectoryTableBase walks of the VAD tree (MMVAD via MiQueryAddressTree). The vault's T-016 PEB unlink is therefore incomplete as a hiding technique; a fuller hide must also patch the VAD.


Technical anchor points:
```
EPROCESS.Pcb.ThreadListHead (offset 0x030) pivot → KTHREAD.Process (back-pointer to EPROCESS) → cross-check against PEB_LDR_DATA.InLoadOrderModuleList
```

## Evidence

- **lgtm:kprocess-as-forensic-anchor**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-016: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `kprocess-forensic-anchor-peb-unlink-detection`
- Generated as part of batch processing to fill identified research gaps.
