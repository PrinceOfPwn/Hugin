---
id: T-15814
title: "Binary Patching as Standalone Offensive Capability"
category: "edr-evasion"
tier: "B"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "binary-patching-memory-and-disk"
member_notes: ["lgtm:binary-patching-as-standalone-capability", "lgtm:binary-patching-as-distinct-technique"]
---

## Summary
This card covers the research gap identified as Binary Patching as Standalone Offensive Capability. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **Binary Patching as Standalone Offensive Capability** represents a sophisticated vector that leverages low-level system structures. Documents binary patching as a discrete operational concept: modifying binaries on disk or in memory to change execution behavior. Memory patching: NTDLL unhook (T-016 byte-level), AMSI patch (AmsiScanBuffer prologue → ret), ETW patch (NtTraceEvent prologue → ret). Disk patching: persisting a modified PE on disk (e.g., patching an Import Directory or adding an export to enable IAT hijack on next load), or modifying a signed-but-relaxed binary's checksum-adjusted bytes. SEC670 lists this as a discrete Red Team Tools capability; the vault references patching implicitly inside T-016 but does not document it as a unified capability with the byte-alignment, checksum, and signature-discipline considerations that distinguish memory from disk patching.

The primary mechanism relies on invoking `Memory:` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `binary-patching-memory-and-disk`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of Binary Patching as Standalone Offensive Capability
NTSTATUS status = Memory:(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific binary-patching-memory-and-disk constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:binary-patching-as-standalone-capability: Identified gap in the research corpus.
- lgtm:binary-patching-as-distinct-technique: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **Binary Patching as Standalone Offensive Capability** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `Memory:` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `binary-patching-memory-and-disk` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-016: Related technique identified in gap analysis.
- T-017: Related technique identified in gap analysis.
- T-020: Related technique identified in gap analysis.

## References

- Microsoft Documentation on Memory:: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of Binary Patching as Standalone Offensive Capability and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to binary-patching-memory-and-disk.
