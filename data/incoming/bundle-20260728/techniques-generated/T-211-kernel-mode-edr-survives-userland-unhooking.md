---
id: T-211
title: "Kernel-Mode EDR Survives Userland Unhooking"
category: edr-evasion
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: kernel-mode-edr-survives-unhooking
member_notes: ["lgtm:unhooking-kernel-limitation-convergence"]
---

## Summary
This technique covers Kernel-Mode EDR Survives Userland Unhooking, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
SEC670 explicitly states that unhooking ntdll does not truly blind a security product because a kernel driver can still observe via PsSetCreateProcessNotifyRoutine (process create / exit callback), PsSetLoadImageNotifyRoutine (image load callback), PsSetCreateThreadNotifyRoutine (thread create callback), ObRegisterCallbacks (process / thread handle duplication callback), CmRegisterCallback (registry modification callback), and mini-filter FileFilter callbacks. T-016's clean-ntdll-unhook technique therefore only addresses userland-hook-based telemetry; it does not defeat EDRs that operate at the kernel boundary. The vault should make this operational constraint explicit on T-016 so operators understand that unhooking is necessary but not sufficient for evasion against modern EDRs, and that combining T-016 unhooking with callback blocking (kernel-driver-based) is required for full telemetry suppression.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// PsSetCreateProcessNotifyRoutine (kernel callback class ProcessCreate / ProcessExit) and PsSetLoadImageNotifyRoutine surviving ntdll userland unhook
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:unhooking-kernel-limitation-convergence: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-016: Relates conceptually based on evidence.

## References
- Internal vault documentation on Kernel-Mode EDR Survives Userland Unhooking
