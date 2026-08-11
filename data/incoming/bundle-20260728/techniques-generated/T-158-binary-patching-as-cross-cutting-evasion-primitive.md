---
id: T-158
title: "Binary Patching as Cross-Cutting Evasion Primitive"
category: edr-evasion
tier: A
tags: ['binary-patching-as-evasion-primitive']
mitre: ["T-016"]
origin: glm-expand-cluster
source_cluster: binary-patching-as-evasion-primitive
member_notes: ["lgtm:gap-binary-patching-primitive-coverage"]
---
## Summary

This technique covers Binary Patching as Cross-Cutting Evasion Primitive. It addresses a gap in knowledge for red-team operations related to edr-evasion.

## Technical Deep Dive

SEC670 Unit 24 treats binary patching as its own evasion primitive distinct
from API hooking: in-place modification of instruction bytes at the function
prologue (jmp/call trampoline) or within a code cave (overwritten with NOPs +
ret 0x12 for AMSI). T-016 currently lists AMSI, ETW, stack spoofing, PEB unlink,
NTDLL unhook, and handle blocking but omits the underlying byte-patching
primitive. The card should distinguish patching (write to .text at VA) from
hooking (write a jmp indirection through Detours-style trampoline) — patching
is one-shot and persistent across process lifetime, while hooking requires
runtime indirection per call. Specific examples: AmsiScanBuffer prologue
patched with mov eax, AMSI_RESULT_CLEAN; ret; EtwEventWrite patched with ret
0x00 (NtTraceEvent returns STATUS_SUCCESS on 0).


Technical anchor details:
```text
In-place prologue patch of AmsiScanBuffer with mov eax, AMSI_RESULT_CLEAN; ret (or xor eax,eax; ret); EtwEventWrite patched to ret returning STATUS_SUCCESS
```

## Evidence

- lgtm:gap-binary-patching-primitive-coverage: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-016: Related technique for extended operations.

## References

- Internal Vault References
