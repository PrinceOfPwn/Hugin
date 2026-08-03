---
id: T-221
title: "Native Subsystem (IMAGE_SUBSYSTEM_NATIVE) Implant Entry Points"
category: patterns
tier: S
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: native-subsystem-implant-entry-points
member_notes: ["lgtm:native-subsystem-implant-entry-point"]
---

## Summary
This technique covers Native Subsystem (IMAGE_SUBSYSTEM_NATIVE) Implant Entry Points, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Native-subsystem executables (IMAGE_SUBSYSTEM_NATIVE in
IMAGE_OPTIONAL_HEADER.Subsystem) receive the PEB pointer directly as
NtProcessStartup's first parameter — no CRT, no Win32 loader, no
kernel32!CreateProcess call path. Entry signature is
NTSTATUS NtProcessStartup(PPEB peb). This pattern lets implants skip the
standard Win32 module-load telemetry (Sysmon EID 1 with ImageLoad events
for kernel32/user32/gdi32), presenting as a standalone native image.
Trade-offs: must hand-resolve all imports via PEB->Ldr->InLoadOrderModuleList
walk (smss.exe / csrss.exe / wininit.exe are the only legitimate native
binaries, so process name selection matters). The card should document the
SUBSYSTEM field location at IMAGE_OPTIONAL_HEADER offset 0x44 (PE32) / 0x5C
(PE32+) and the /SUBSYSTEM:NATIVE linker flag equivalent.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// IMAGE_SUBSYSTEM_NATIVE (0x03) at IMAGE_OPTIONAL_HEADER.Subsystem; entry point NTSTATUS NtProcessStartup(PPEB peb) bypasses Win32 loader
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:native-subsystem-implant-entry-point: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-004: Relates conceptually based on evidence.
- T-022: Relates conceptually based on evidence.

## References
- Internal vault documentation on Native Subsystem (IMAGE_SUBSYSTEM_NATIVE) Implant Entry Points
