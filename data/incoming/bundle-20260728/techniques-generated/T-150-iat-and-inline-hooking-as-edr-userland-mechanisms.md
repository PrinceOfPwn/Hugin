---
id: T-150
title: "IAT and Inline Hooking as EDR Userland Mechanisms"
category: edr-evasion
tier: B
tags: ['edr-hooking-mechanisms-background']
mitre: ["T-016"]
origin: glm-expand-cluster
source_cluster: edr-hooking-mechanisms-background
member_notes: ["lgtm:hooking-as-edr-mechanism-background"]
---
## Summary

This technique covers IAT and Inline Hooking as EDR Userland Mechanisms. It addresses a gap in knowledge for red-team operations related to edr-evasion.

## Technical Deep Dive

SEC670 units 35-40 document the two primary userland hooking mechanisms EDRs employ:
IAT pointer overwrite (flipping the IAT entry's memory protection to PAGE_READWRITE via
VirtualProtect, replacing the function pointer with a detour, restoring protection) and
inline prologue patching (overwriting the first 5-7 bytes of the function prologue with
a jmp to the detour, saving the original bytes for pass-through). The vault's T-016
(NTAPI Hook Evasion) evades these hooks by using direct syscalls but does not document
the hook mechanisms themselves as background. A prerequisite card should describe both
hook types, the VirtualProtect-based IAT flip, the inline prologue patch with trampoline
construction, the saved-byte restoration pattern, and how each hook type is detected
(scanning IAT for non-module-range pointers; scanning prologue for jmp opcodes). This
background makes T-016's evasion approach comprehensible to readers without prior EDR
internals knowledge.


Technical anchor details:
```text
IAT hook: VirtualProtect PAGE_READWRITE → overwrite function pointer → restore protection; Inline hook: prologue byte patch with jmp rel32 (0xE8/E9) + trampoline with saved original bytes
```

## Evidence

- lgtm:hooking-as-edr-mechanism-background: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-016: Related technique for extended operations.

## References

- Internal Vault References
