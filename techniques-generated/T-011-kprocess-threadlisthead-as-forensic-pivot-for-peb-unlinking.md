---
id: T-011
title: "_KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking"
category: discovery
tier: B
tags: ["gap", "research"]
mitre: []
origin: manual-gap-extraction
source_cluster: kprocess-forensic-anchor-peb-unlink-detection
member_notes: ["lgtm:kprocess-as-forensic-anchor"]
---

## Summary

Documents the forensic pivot that defeats the vault's T-016 PEB-unlink technique. A scanner that operated only on the PEB Ldr.InLoadOrderModuleList (PEB_LDR_DATA.InLoadOrderModuleList at PEB offset 0x10 on x64) can be defeated by unlinking the module entry. Forensic scanners pivot through EPROCESS.Pcb (the embedded _KPROCESS) → ThreadListHead to enumerate threads, then through KTHREAD.Process (back-pointer) to find processes whose PEB has been tampered with. They also compare the PEB module list against EPROCESS.Pcb.DirectoryTableBase walks of the VAD tree (MMVAD via MiQueryAddressTree). The vault's T-016 PEB unlink is therefore incomplete as a hiding technique; a fuller hide must also patch the VAD.


## Technical Deep Dive

Single coverage-gap note naming _KPROCESS.ThreadListHead as the forensic pivot that defeats PEB-based hiding; complements the EPROCESS/KPROCESS concept card.

Technical Anchor: EPROCESS.Pcb.ThreadListHead (offset 0x030) pivot → KTHREAD.Process (back-pointer to EPROCESS) → cross-check against PEB_LDR_DATA.InLoadOrderModuleList

## Evidence

- lgtm:kprocess-as-forensic-anchor

## Detection & Mitigation

To be documented.

## Related Techniques

- T-016

## References

- Internal research vault
