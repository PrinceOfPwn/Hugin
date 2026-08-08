---
id: T-GAP-1019
title: "GetAdaptersAddresses Network Recon Primitive"
tier: "C"
category: "discovery"
---

# GetAdaptersAddresses Network Recon Primitive

## Description
Documents GetAdaptersAddresses(Family, Flags, Reserved, pAdapterAddresses, &size) and GetNumberOfInterfaces(&count) as the canonical Win32 network recon primitives. GetAdaptersAddresses uses the ERROR_BUFFER_OVERFLOW (0x6F / 111) two-pass allocation pattern: call with NULL buffer → returns ERROR_BUFFER_OVERFLOW and populates size → allocate → retry. Returns IP_ADAPTER_ADDRESSES linked list with FirstUnicastAddress, FirstDnsSuffix, FirstGateway, FriendlyName, and AdapterName (GUID). GetNumberOfInterfaces returns a ULONG/DWORD count (depending on Win32 version) for quick inventory. Pairs with WSAStartup + gethostname for hostname enumeration and IP helper API (Ipifcons.h) for interface type classification.


## Rationale
Single coverage-gap note documenting the canonical network adapter enumeration API underlying T-023 client recon.

## References
- lgtm:network-adapter-enumeration-primitive
