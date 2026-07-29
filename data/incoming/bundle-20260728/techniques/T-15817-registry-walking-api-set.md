---
id: T-15817
title: "Registry Walking API Set for Persistence and Recon"
category: "edr-evasion"
tier: "C"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "registry-walking-api-set"
member_notes: ["lgtm:registry-api-enumeration-primitives"]
---

## Summary
This card covers the research gap identified as Registry Walking API Set for Persistence and Recon. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **Registry Walking API Set for Persistence and Recon** represents a sophisticated vector that leverages low-level system structures. Documents the complete registry-walking Win32 API set: RegOpenKeyExW(HKEY_LOCAL_MACHINE, subpath, 0, KEY_READ, &hKey), RegQueryValueExW(hKey, valueName, NULL, &type, buffer, &size), RegEnumValue(hKey, index, valueName, &nameLen, NULL, &type, data, &dataLen), RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, &values, &maxValueNameLen, &maxValueLen, NULL, NULL, NULL). The two-pass buffer-size pattern (call with NULL buffer → ERROR_MORE_DATA/ERROR_INSUFFICIENT_BUFFER → allocate → retry) underlies all registry enumeration. Pairs with T-017 persistence enumeration (walking Run keys, Image File Execution Options, AppInit_DLLs, AppCertDlls) and T-023 recon (registry-based discovery).

The primary mechanism relies on invoking `RegQueryInfoKey` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `registry-walking-api-set`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of Registry Walking API Set for Persistence and Recon
NTSTATUS status = RegQueryInfoKey(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific registry-walking-api-set constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:registry-api-enumeration-primitives: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **Registry Walking API Set for Persistence and Recon** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `RegQueryInfoKey` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `registry-walking-api-set` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-017: Related technique identified in gap analysis.
- T-023: Related technique identified in gap analysis.

## References

- Microsoft Documentation on RegQueryInfoKey: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of Registry Walking API Set for Persistence and Recon and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to registry-walking-api-set.
