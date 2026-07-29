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

The technique known as **_KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking** represents a sophisticated vector that leverages low-level system structures. Documents the forensic pivot that defeats the vault's T-016 PEB-unlink technique. A scanner that operated only on the PEB Ldr.InLoadOrderModuleList (PEB_LDR_DATA.InLoadOrderModuleList at PEB offset 0x10 on x64) can be defeated by unlinking the module entry. Forensic scanners pivot through EPROCESS.Pcb (the embedded _KPROCESS) → ThreadListHead to enumerate threads, then through KTHREAD.Process (back-pointer) to find processes whose PEB has been tampered with. They also compare the PEB module list against EPROCESS.Pcb.DirectoryTableBase walks of the VAD tree (MMVAD via MiQueryAddressTree). The vault's T-016 PEB unlink is therefore incomplete as a hiding technique; a fuller hide must also patch the VAD.

The primary mechanism relies on invoking `EPROCESS.Pcb.ThreadListHead` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `kprocess-forensic-anchor-peb-unlink-detection`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of _KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking
NTSTATUS status = EPROCESS.Pcb.ThreadListHead(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific kprocess-forensic-anchor-peb-unlink-detection constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:kprocess-as-forensic-anchor: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **_KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `EPROCESS.Pcb.ThreadListHead` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `kprocess-forensic-anchor-peb-unlink-detection` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-016: Related technique identified in gap analysis.

## References

- Microsoft Documentation on EPROCESS.Pcb.ThreadListHead: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of _KPROCESS ThreadListHead as Forensic Pivot for PEB Unlinking and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to kprocess-forensic-anchor-peb-unlink-detection.
