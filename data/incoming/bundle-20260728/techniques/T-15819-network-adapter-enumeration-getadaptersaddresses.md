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
Documents GetAdaptersAddresses(Family, Flags, Reserved, pAdapterAddresses, &size) and GetNumberOfInterfaces(&count) as the canonical Win32 network recon primitives. GetAdaptersAddresses uses the ERROR_BUFFER_OVERFLOW (0x6F / 111) two-pass allocation pattern: call with NULL buffer → returns ERROR_BUFFER_OVERFLOW and populates size → allocate → retry. Returns IP_ADAPTER_ADDRESSES linked list with FirstUnicastAddress, FirstDnsSuffix, FirstGateway, FriendlyName, and AdapterName (GUID). GetNumberOfInterfaces returns a ULONG/DWORD count (depending on Win32 version) for quick inventory. Pairs with WSAStartup + gethostname for hostname enumeration and IP helper API (Ipifcons.h) for interface type classification.


## Evidence
- lgtm:network-adapter-enumeration-primitive: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-023: Related technique identified in gap analysis.

## References
- To be added.
