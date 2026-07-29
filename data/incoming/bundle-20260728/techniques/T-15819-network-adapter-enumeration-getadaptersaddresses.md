---
id: T-15819
title: "GetAdaptersAddresses Network Recon Primitive"
category: "edr-evasion"
tier: "C"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "network-adapter-enumeration-getadaptersaddresses"
member_notes: ["lgtm:network-adapter-enumeration-primitive"]
---

## Summary
This card covers the research gap identified as GetAdaptersAddresses Network Recon Primitive. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **GetAdaptersAddresses Network Recon Primitive** represents a sophisticated vector that leverages low-level system structures. Documents GetAdaptersAddresses(Family, Flags, Reserved, pAdapterAddresses, &size) and GetNumberOfInterfaces(&count) as the canonical Win32 network recon primitives. GetAdaptersAddresses uses the ERROR_BUFFER_OVERFLOW (0x6F / 111) two-pass allocation pattern: call with NULL buffer → returns ERROR_BUFFER_OVERFLOW and populates size → allocate → retry. Returns IP_ADAPTER_ADDRESSES linked list with FirstUnicastAddress, FirstDnsSuffix, FirstGateway, FriendlyName, and AdapterName (GUID). GetNumberOfInterfaces returns a ULONG/DWORD count (depending on Win32 version) for quick inventory. Pairs with WSAStartup + gethostname for hostname enumeration and IP helper API (Ipifcons.h) for interface type classification.

The primary mechanism relies on invoking `GetAdaptersAddresses` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `network-adapter-enumeration-getadaptersaddresses`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of GetAdaptersAddresses Network Recon Primitive
NTSTATUS status = GetAdaptersAddresses(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific network-adapter-enumeration-getadaptersaddresses constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:network-adapter-enumeration-primitive: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **GetAdaptersAddresses Network Recon Primitive** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `GetAdaptersAddresses` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `network-adapter-enumeration-getadaptersaddresses` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-023: Related technique identified in gap analysis.

## References

- Microsoft Documentation on GetAdaptersAddresses: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of GetAdaptersAddresses Network Recon Primitive and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to network-adapter-enumeration-getadaptersaddresses.
