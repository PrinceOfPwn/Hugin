---
id: T-15810
title: "_KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking"
category: "edr-evasion"
tier: "B"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "kprocess-forensic-anchor-peb-unlink-detection"
member_notes: ["lgtm:kprocess-as-forensic-anchor"]
---

## Summary
This card covers the research gap identified as _KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Documents the forensic pivot that defeats the vault's T-016 PEB-unlink technique. A scanner that operated only on the PEB Ldr.InLoadOrderModuleList (PEB_LDR_DATA.InLoadOrderModuleList at PEB offset 0x10 on x64) can be defeated by unlinking the module entry. Forensic scanners pivot through EPROCESS.Pcb (the embedded _KPROCESS) → ThreadListHead to enumerate threads, then through KTHREAD.Process (back-pointer) to find processes whose PEB has been tampered with. They also compare the PEB module list against EPROCESS.Pcb.DirectoryTableBase walks of the VAD tree (MMVAD via MiQueryAddressTree). The vault's T-016 PEB unlink is therefore incomplete as a hiding technique; a fuller hide must also patch the VAD.


## Evidence
- lgtm:kprocess-as-forensic-anchor: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-016: Related technique identified in gap analysis.

## References
- To be added.
