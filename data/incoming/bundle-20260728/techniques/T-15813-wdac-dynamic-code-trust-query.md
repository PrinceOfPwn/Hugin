---
id: T-15813
title: "WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust"
category: "edr-evasion"
tier: "A"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "wdac-dynamic-code-trust-query"
member_notes: ["lgtm:coverage-gap-wdac-dynamic-code-trust-query"]
---

## Summary
This card covers the research gap identified as WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust** represents a sophisticated vector that leverages low-level system structures. Documents WldpQueryDynamicCodeTrust as the user-mode query for Windows Defender Application Control (WDAC) dynamic-code trust — the API an implant uses to check whether a candidate payload region (e.g., RWX memory about to be executed) would survive Code Integrity Guard (CIG) enforcement before committing the allocation. Without this check, an implant attempting module stomping or shellcode-to-PIC transition on a WDAC-enforced process triggers a CiInitializeSigned policy violation and process termination. The query takes the candidate base address and returns a trust verdict; pairs with WLDP API set wldp.dll. Distinct from WldpIsClassApproved / WldpQueryDynamicCodeTrust — the latter is the runtime check, the former is policy enumeration.

The primary mechanism relies on invoking `WldpQueryDynamicCodeTrust(base` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `wdac-dynamic-code-trust-query`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust
NTSTATUS status = WldpQueryDynamicCodeTrust(base(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific wdac-dynamic-code-trust-query constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:coverage-gap-wdac-dynamic-code-trust-query: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `WldpQueryDynamicCodeTrust(base` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `wdac-dynamic-code-trust-query` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-016: Related technique identified in gap analysis.

## References

- Microsoft Documentation on WldpQueryDynamicCodeTrust(base: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to wdac-dynamic-code-trust-query.
