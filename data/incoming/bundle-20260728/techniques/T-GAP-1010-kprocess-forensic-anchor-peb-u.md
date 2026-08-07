---
id: T-GAP-1010
name: "_KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking"
category: discovery
tier: B
crate: none
source_file: none
mitre: T1082
mitre_secondary: []
tags: []
origin: lgtm-cluster
member_notes: ["lgtm:kprocess-as-forensic-anchor"]
---

# _KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking

## Summary

Documents the forensic pivot that defeats the vault's T-016 PEB-unlink technique. A scanner that operated only on the PEB Ldr.InLoadOrderModuleList (PEB_LDR_DATA.InLoadOrderModuleList at PEB offset 0x10 on x64) can be defeated by unlinking the module entry. Forensic scanners pivot through EPROCESS.Pcb (the embedded _KPROCESS) → ThreadListHead to enumerate threads, then through KTHREAD.Process (back-pointer) to find processes whose PEB has been tampered with. They also compare the PEB module list against EPROCESS.Pcb.DirectoryTableBase walks of the VAD tree (MMVAD via MiQueryAddressTree). The vault's T-016 PEB unlink is therefore incomplete as a hiding technique; a fuller hide must also patch the VAD.


## Mechanism

EPROCESS.Pcb.ThreadListHead (offset 0x030) pivot → KTHREAD.Process (back-pointer to EPROCESS) → cross-check against PEB_LDR_DATA.InLoadOrderModuleList

## Rationale

Single coverage-gap note naming _KPROCESS.ThreadListHead as the forensic pivot that defeats PEB-based hiding; complements the EPROCESS/KPROCESS concept card.

## Related To

T-016
