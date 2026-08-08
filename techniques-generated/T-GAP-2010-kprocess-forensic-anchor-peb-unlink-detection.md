---
id: T-GAP-2010
title: "_KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking"
category: "discovery"
tier: "B"
tags: [generated, gap, research]
mitre: []
origin: glm-expand-cluster
source_cluster: kprocess-forensic-anchor-peb-unlink-detection
member_notes: ['lgtm:kprocess-as-forensic-anchor']
---

## Summary
Documents the forensic pivot that defeats the vault's T-016 PEB-unlink technique. A scanner that operated only on the PEB Ldr.InLoadOrderModuleList (PEB_LDR_DATA.InLoadOrderModuleList at PEB offset 0x10 on x64) can be defeated by unlinking the module entry. Forensic scanners pivot through EPROCESS.Pcb (the embedded _KPROCESS) → ThreadListHead to enumerate threads, then through KTHREAD.Process (back-pointer) to find processes whose PEB has been tampered with. They also compare the PEB module list against EPROCESS.Pcb.DirectoryTableBase walks of the VAD tree (MMVAD via MiQueryAddressTree). The vault's T-016 PEB unlink is therefore incomplete as a hiding technique; a fuller hide must also patch the VAD.


## Technical Deep Dive
The cluster represents a gap identified during automated research analysis. Single coverage-gap note naming _KPROCESS.ThreadListHead as the forensic pivot that defeats PEB-based hiding; complements the EPROCESS/KPROCESS concept card.

## Evidence
- lgtm:kprocess-as-forensic-anchor: See original note for details.

## Detection & Mitigation
Monitor for the aforementioned behaviors using standard EDR hooks and ETW telemetry.

## Related Techniques
- Placeholder: related techniques to be discovered

## References
- Internal vault references
