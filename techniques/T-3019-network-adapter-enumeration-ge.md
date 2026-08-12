---
id: T-3019
title: "GetAdaptersAddresses Network Recon Primitive"
category: discovery
tier: C
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: network-adapter-enumeration-getadaptersaddresses
member_notes: ['lgtm:network-adapter-enumeration-primitive']
---
## Summary

This technique card covers GetAdaptersAddresses Network Recon Primitive. It details mechanisms required to implement or understand network-adapter-enumeration-getadaptersaddresses operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents GetAdaptersAddresses(Family, Flags, Reserved, pAdapterAddresses, &size) and GetNumberOfInterfaces(&count) as the canonical Win32 network recon primitives. GetAdaptersAddresses uses the ERROR_BUFFER_OVERFLOW (0x6F / 111) two-pass allocation pattern: call with NULL buffer → returns ERROR_BUFFER_OVERFLOW and populates size → allocate → retry. Returns IP_ADAPTER_ADDRESSES linked list with FirstUnicastAddress, FirstDnsSuffix, FirstGateway, FriendlyName, and AdapterName (GUID). GetNumberOfInterfaces returns a ULONG/DWORD count (depending on Win32 version) for quick inventory. Pairs with WSAStartup + gethostname for hostname enumeration and IP helper API (Ipifcons.h) for interface type classification.



```c
// Example for GetAdaptersAddresses Network Recon Primitive
// Implementation specific to network-adapter-enumeration-getadaptersaddresses
void execute_network_adapter_enumeration_getadaptersaddresses() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:network-adapter-enumeration-primitive`: Referenced in internal atlas batches as a core component of network-adapter-enumeration-getadaptersaddresses.

## Detection & Mitigation

Detecting this behavior requires deep visibility into API calls. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on GetAdaptersAddresses Network Recon Primitive
