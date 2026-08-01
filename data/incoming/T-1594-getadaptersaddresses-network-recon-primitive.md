---
id: T-1594
title: "GetAdaptersAddresses Network Recon Primitive"
category: discovery
tier: C
tags: [network, adapter, enumeration, getadaptersaddresses]
mitre: []
origin: glm-expand-cluster
source_cluster: network-adapter-enumeration-getadaptersaddresses
member_notes: ['lgtm:network-adapter-enumeration-primitive']
---

## Summary
Documents GetAdaptersAddresses(Family, Flags, Reserved, pAdapterAddresses, &size) and GetNumberOfInterfaces(&count) as the canonical Win32 network recon primitives. GetAdaptersAddresses uses the ERROR_BUFFER_OVERFLOW (0x6F / 111) two-pass allocation pattern: call with NULL buffer → returns ERROR_BUFFER_OVERFLOW and populates size → allocate → retry. Returns IP_ADAPTER_ADDRESSES linked list with FirstUnicastAddress, FirstDnsSuffix, FirstGateway, FriendlyName, and AdapterName (GUID). GetNumberOfInterfaces returns a ULONG/DWORD count (depending on Win32 version) for quick inventory. Pairs with WSAStartup + gethostname for hostname enumeration and IP helper API (Ipifcons.h) for interface type classification.

## Technical Deep Dive
Single coverage-gap note documenting the canonical network adapter enumeration API underlying T-023 client recon.

Key technical anchor: GetAdaptersAddresses with ERROR_BUFFER_OVERFLOW (0x6F) two-pass allocation; IP_ADAPTER_ADDRESSES linked list via Next pointer

## Evidence
- lgtm:network-adapter-enumeration-primitive: Highlights the gap or observation related to this tradecraft.

## Detection & Mitigation
Detection of this technique relies heavily on endpoint telemetry (Sysmon, ETW). Mitigation requires a combination of strict ACLs and execution control policies.

## Related Techniques
- T-023 - related to GetAdaptersAddresses Network Recon Primitive

## References
- Refer to internal research note network-adapter-enumeration-getadaptersaddresses for preliminary data.
