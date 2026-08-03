---
id: T-213
title: "Anti-VM Detection Primitive API Catalog"
category: anti-analysis
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: anti-vm-detection-primitive-catalog
member_notes: ["lgtm:gap-anti-vm-detection-primitives"]
---

## Summary
This technique covers Anti-VM Detection Primitive API Catalog, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
The vault's T-020 lists 10 anti-VM checks but does not document the recon API primitives that power them. SEC670 shows that the same APIs used for survey (Program Files directory walk via FindFirstFile / FindNextFile, WTSEnumerateProcessesEx, NtQuerySystemInformation, GetAdaptersAddresses via iphlpapi, RegOpenKeyEx on HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum for VM-aware driver names like VBOXBUS, pvscsi, vmci) also support anti-VM fingerprinting. The vault should document the API -> check mapping so an operator can construct custom anti-VM chains rather than hardcoded checks; the card should also cover the Hypervisor CPUID leaf 0x40000000 (returning 'MicrosoftHV' / 'KVMKVMKVM' / 'VMwareVMware' vendor signatures) and the RDTSC-based timing detection via __rdtsc / QueryPerformanceCounter.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// RegOpenKeyEx(HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum) returning Value '0' = 'PCI\VEN_80EE&DEV_BEEF...' (VirtualBox) or '_VMBUS' (Hyper-V); CPUID leaf 0x40000000 vendor signature
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:gap-anti-vm-detection-primitives: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-020: Relates conceptually based on evidence.
- T-023: Relates conceptually based on evidence.

## References
- Internal vault documentation on Anti-VM Detection Primitive API Catalog
