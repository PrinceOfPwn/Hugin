---
id: T-919
title: "GetAdaptersAddresses Network Recon Primitive"
category: patterns
tier: C
tags: [generated, manual]
mitre: []
origin: manual-expand-cluster
source_cluster: network-adapter-enumeration-getadaptersaddresses
member_notes: ['lgtm:network-adapter-enumeration-primitive']
---

## Summary
Documents GetAdaptersAddresses(Family, Flags, Reserved, pAdapterAddresses, &size) and GetNumberOfInterfaces(&count) as the canonical Win32 network recon primitives.

## Technical Deep Dive
Documents GetAdaptersAddresses(Family, Flags, Reserved, pAdapterAddresses, &size) and GetNumberOfInterfaces(&count) as the canonical Win32 network recon primitives. GetAdaptersAddresses uses the ERROR_BUFFER_OVERFLOW (0x6F / 111) two-pass allocation pattern: call with NULL buffer → returns ERROR_BUFFER_OVERFLOW and populates size → allocate → retry. Returns IP_ADAPTER_ADDRESSES linked list with FirstUnicastAddress, FirstDnsSuffix, FirstGateway, FriendlyName, and AdapterName (GUID). GetNumberOfInterfaces returns a ULONG/DWORD count (depending on Win32 version) for quick inventory. Pairs with WSAStartup + gethostname for hostname enumeration and IP helper API (Ipifcons.h) for interface type classification.


## Evidence
- lgtm:network-adapter-enumeration-primitive

## Detection & Mitigation
- Standard monitoring and detection.

## Related Techniques
- N/A

## References
- N/A
