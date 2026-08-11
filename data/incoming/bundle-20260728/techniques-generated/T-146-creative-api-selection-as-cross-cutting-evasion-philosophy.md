---
id: T-146
title: "Creative API Selection as Cross-Cutting Evasion Philosophy"
category: edr-evasion
tier: A
tags: ['creative-api-selection-evasion-philosophy']
mitre: ["T-001","T-004","T-014","T-016","T-022"]
origin: glm-expand-cluster
source_cluster: creative-api-selection-evasion-philosophy
member_notes: ["lgtm:creative-api-selection-as-evasion-philosophy"]
---
## Summary

This technique covers Creative API Selection as Cross-Cutting Evasion Philosophy. It addresses a gap in knowledge for red-team operations related to edr-evasion.

## Technical Deep Dive

SEC670 units 39-40 articulate the philosophy that 'using less common APIs can bypass
EDR detection by performing standard tasks in non-traditional ways,' citing x86matthew
as a reference for creative API usage. This is not a single technique but a cross-cutting
design principle that underpins the vault's T-001 (RecycledGate, which reuses an existing
hooked function's syscall stub rather than fabricating one), T-004 (PEB Walker, which
resolves modules via PEB traversal instead of GetModuleHandle), T-014/T-016 (direct NT
API usage vs. Win32 wrappers), and T-022 (WinHTTP transport selection). A concept card
should frame this as a decision pattern: for each standard task (memory allocation,
process enumeration, module resolution, network transport), identify the canonical Win32
API, the less-common alternative, and the detection-surface differential.


Technical anchor details:
```text
x86matthew creative API usage as reference — principle of performing standard tasks via non-traditional API paths to bypass EDR hooks
```

## Evidence

- lgtm:creative-api-selection-as-evasion-philosophy: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-001: Related technique for extended operations.
- T-004: Related technique for extended operations.
- T-014: Related technique for extended operations.
- T-016: Related technique for extended operations.
- T-022: Related technique for extended operations.

## References

- Internal Vault References
