---
id: T-919
title: "GetAdaptersAddresses Network Recon Primitive"
category: discovery
tier: C
tags: []
mitre: []
origin: manual-gap-extraction
source_cluster: network-adapter-enumeration-getadaptersaddresses
member_notes: ['lgtm:network-adapter-enumeration-primitive']
---

## Summary
Documents GetAdaptersAddresses(Family, Flags, Reserved, pAdapterAddresses, &size) and GetNumberOfInterfaces(&count) as the canonical Win32 network recon primitives. GetAdaptersAddresses uses the ERROR_BUFFER_OVERFLOW (0x6F / 111) two-pass allocation pattern: call with NULL buffer → returns ERROR_BUFFER_OVERFLOW and populates size → allocate → retry. Returns IP_ADAPTER_ADDRESSES linked list with FirstUnicastAddress, FirstDnsSuffix, FirstGateway, FriendlyName, and AdapterName (GUID). GetNumberOfInterfaces returns a ULONG/DWORD count (depending on Win32 version) for quick inventory. Pairs with WSAStartup + gethostname for hostname enumeration and IP helper API (Ipifcons.h) for interface type classification.


## Technical Deep Dive
Documents GetAdaptersAddresses(Family, Flags, Reserved, pAdapterAddresses, &size) and GetNumberOfInterfaces(&count) as the canonical Win32 network recon primitives. GetAdaptersAddresses uses the ERROR_BUFFER_OVERFLOW (0x6F / 111) two-pass allocation pattern: call with NULL buffer → returns ERROR_BUFFER_OVERFLOW and populates size → allocate → retry. Returns IP_ADAPTER_ADDRESSES linked list with FirstUnicastAddress, FirstDnsSuffix, FirstGateway, FriendlyName, and AdapterName (GUID). GetNumberOfInterfaces returns a ULONG/DWORD count (depending on Win32 version) for quick inventory. Pairs with WSAStartup + gethostname for hostname enumeration and IP helper API (Ipifcons.h) for interface type classification.


Technical anchor: GetAdaptersAddresses with ERROR_BUFFER_OVERFLOW (0x6F) two-pass allocation; IP_ADAPTER_ADDRESSES linked list via Next pointer

## Evidence
- lgtm:network-adapter-enumeration-primitive

## Detection & Mitigation
General mitigation strategies apply. Monitor API calls and anomalous behaviors.

## Related Techniques
- T-023

## References
- Internal knowledge base.
