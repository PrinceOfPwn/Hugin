---
id: T-3010
title: "_KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking"
category: discovery
tier: B
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: kprocess-forensic-anchor-peb-unlink-detection
member_notes: ['lgtm:kprocess-as-forensic-anchor']
---
## Summary

This technique card covers _KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking. It details mechanisms required to implement or understand kprocess-forensic-anchor-peb-unlink-detection operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents the forensic pivot that defeats the vault's T-016 PEB-unlink technique. A scanner that operated only on the PEB Ldr.InLoadOrderModuleList (PEB_LDR_DATA.InLoadOrderModuleList at PEB offset 0x10 on x64) can be defeated by unlinking the module entry. Forensic scanners pivot through EPROCESS.Pcb (the embedded _KPROCESS) → ThreadListHead to enumerate threads, then through KTHREAD.Process (back-pointer) to find processes whose PEB has been tampered with. They also compare the PEB module list against EPROCESS.Pcb.DirectoryTableBase walks of the VAD tree (MMVAD via MiQueryAddressTree). The vault's T-016 PEB unlink is therefore incomplete as a hiding technique; a fuller hide must also patch the VAD.



```c
// Example for _KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking
// Implementation specific to kprocess-forensic-anchor-peb-unlink-detection
void execute_kprocess_forensic_anchor_peb_unlink_detection() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:kprocess-as-forensic-anchor`: Referenced in internal atlas batches as a core component of kprocess-forensic-anchor-peb-unlink-detection.

## Detection & Mitigation

Memory scanning (YARA) and runtime behavioral analysis focusing on manual memory traversal outside of typical OS loader behavior. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on _KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking
