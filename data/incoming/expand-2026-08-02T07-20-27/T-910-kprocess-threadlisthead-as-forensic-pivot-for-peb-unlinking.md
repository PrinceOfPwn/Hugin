---
id: T-910
title: "_KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking"
category: patterns
tier: B
tags: [generated, manual]
mitre: []
origin: manual-expand-cluster
source_cluster: kprocess-forensic-anchor-peb-unlink-detection
member_notes: ['lgtm:kprocess-as-forensic-anchor']
---

## Summary
Documents the forensic pivot that defeats the vault's T-016 PEB-unlink technique. A scanner that operated only on the PEB Ldr.InLoadOrderModuleList...

## Technical Deep Dive
Documents the forensic pivot that defeats the vault's T-016 PEB-unlink technique. A scanner that operated only on the PEB Ldr.InLoadOrderModuleList (PEB_LDR_DATA.InLoadOrderModuleList at PEB offset 0x10 on x64) can be defeated by unlinking the module entry. Forensic scanners pivot through EPROCESS.Pcb (the embedded _KPROCESS) → ThreadListHead to enumerate threads, then through KTHREAD.Process (back-pointer) to find processes whose PEB has been tampered with. They also compare the PEB module list against EPROCESS.Pcb.DirectoryTableBase walks of the VAD tree (MMVAD via MiQueryAddressTree). The vault's T-016 PEB unlink is therefore incomplete as a hiding technique; a fuller hide must also patch the VAD.


## Evidence
- lgtm:kprocess-as-forensic-anchor

## Detection & Mitigation
- Standard monitoring and detection.

## Related Techniques
- N/A

## References
- N/A
