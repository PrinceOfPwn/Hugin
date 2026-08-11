---
id: T-140
title: "_KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking"
category: discovery
tier: B
tags: ['kprocess-forensic-anchor-peb-unlink-detection']
mitre: ["T-016"]
origin: glm-expand-cluster
source_cluster: kprocess-forensic-anchor-peb-unlink-detection
member_notes: ["lgtm:kprocess-as-forensic-anchor"]
---
## Summary

This technique covers _KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking. It addresses a gap in knowledge for red-team operations related to discovery.

## Technical Deep Dive

Documents the forensic pivot that defeats the vault's T-016 PEB-unlink technique. A scanner that operated only on the PEB Ldr.InLoadOrderModuleList (PEB_LDR_DATA.InLoadOrderModuleList at PEB offset 0x10 on x64) can be defeated by unlinking the module entry. Forensic scanners pivot through EPROCESS.Pcb (the embedded _KPROCESS) → ThreadListHead to enumerate threads, then through KTHREAD.Process (back-pointer) to find processes whose PEB has been tampered with. They also compare the PEB module list against EPROCESS.Pcb.DirectoryTableBase walks of the VAD tree (MMVAD via MiQueryAddressTree). The vault's T-016 PEB unlink is therefore incomplete as a hiding technique; a fuller hide must also patch the VAD.


Technical anchor details:
```text
EPROCESS.Pcb.ThreadListHead (offset 0x030) pivot → KTHREAD.Process (back-pointer to EPROCESS) → cross-check against PEB_LDR_DATA.InLoadOrderModuleList
```

## Evidence

- lgtm:kprocess-as-forensic-anchor: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-016: Related technique for extended operations.

## References

- Internal Vault References
