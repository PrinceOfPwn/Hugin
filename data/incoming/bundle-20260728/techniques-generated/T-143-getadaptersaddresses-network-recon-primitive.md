---
id: T-143
title: "GetAdaptersAddresses Network Recon Primitive"
category: discovery
tier: C
tags: ['network-adapter-enumeration-getadaptersaddresses']
mitre: ["T-023"]
origin: glm-expand-cluster
source_cluster: network-adapter-enumeration-getadaptersaddresses
member_notes: ["lgtm:network-adapter-enumeration-primitive"]
---
## Summary

This technique covers GetAdaptersAddresses Network Recon Primitive. It addresses a gap in knowledge for red-team operations related to discovery.

## Technical Deep Dive

Documents GetAdaptersAddresses(Family, Flags, Reserved, pAdapterAddresses, &size) and GetNumberOfInterfaces(&count) as the canonical Win32 network recon primitives. GetAdaptersAddresses uses the ERROR_BUFFER_OVERFLOW (0x6F / 111) two-pass allocation pattern: call with NULL buffer → returns ERROR_BUFFER_OVERFLOW and populates size → allocate → retry. Returns IP_ADAPTER_ADDRESSES linked list with FirstUnicastAddress, FirstDnsSuffix, FirstGateway, FriendlyName, and AdapterName (GUID). GetNumberOfInterfaces returns a ULONG/DWORD count (depending on Win32 version) for quick inventory. Pairs with WSAStartup + gethostname for hostname enumeration and IP helper API (Ipifcons.h) for interface type classification.


Technical anchor details:
```text
GetAdaptersAddresses with ERROR_BUFFER_OVERFLOW (0x6F) two-pass allocation; IP_ADAPTER_ADDRESSES linked list via Next pointer
```

## Evidence

- lgtm:network-adapter-enumeration-primitive: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-023: Related technique for extended operations.

## References

- Internal Vault References
