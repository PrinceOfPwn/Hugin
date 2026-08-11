---
id: T-155
title: ".def File Ordinal-Based Export Control"
category: exploit-primitive
tier: B
tags: ['def-file-ordinal-export-control']
mitre: ["T-008","T-016"]
origin: glm-expand-cluster
source_cluster: def-file-ordinal-export-control
member_notes: ["lgtm:def-file-export-ordinal-control"]
---
## Summary

This technique covers .def File Ordinal-Based Export Control. It addresses a gap in knowledge for red-team operations related to exploit-primitive.

## Technical Deep Dive

SEC670 covers .def files as a way to declare DLL exports with explicit ordinals and
library/version metadata. The .def file syntax includes EXPORTS section with function
name, ordinal (@N suffix), NONAME attribute (export by ordinal only, hiding the name),
and PRIVATE attribute (not visible in the import library). Ordinal-based export
resolution is operationally distinct from name-based resolution: GetProcAddress(hModule,
MAKEINTRESOURCE(ordinal)) resolves by ordinal, which bypasses name-based EDR hooks on
GetProcAddress and produces no export-name string in the import table. The vault's
T-008 (Thread Hijacking) and T-016 (NTAPI Hook Evasion) could benefit from ordinal-based
resolution for stealthy function lookup. A card should document the .def file syntax,
the linker /DEF flag, the MAKEINTRESOURCE(ordinal) macro for GetProcAddress, the
NONAME/Private attributes, and the detection surface (ordinal-only exports are a known
DLL-cloaking IoC).


Technical anchor details:
```text
.def file EXPORTS section: FunctionName @Ordinal NONAME PRIVATE — resolved via GetProcAddress(hModule, MAKEINTRESOURCE(ordinal)) bypassing name-based hooks
```

## Evidence

- lgtm:def-file-export-ordinal-control: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-008: Related technique for extended operations.
- T-016: Related technique for extended operations.

## References

- Internal Vault References
