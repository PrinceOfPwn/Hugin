# Cluster Spec — T-055: Native Application Development: Bypassing Win32 Subsystem

- **T-NNN ID**: `T-055`
- **Canonical name**: Native Application Development: Bypassing Win32 Subsystem
- **Proposed category**: `discovery`
- **Proposed tier**: `B`
- **Priority**: low — Singleton, specialized process creation pattern, low operational differentiation.
- **would_relate_to**: ['T-014', 'T-004']

## Consolidated Description

Native application development for Win32-subsystem bypass. Native applications receive PEB directly via NtProcessStartup entry point rather than through Win32 initialization (CreateProcessA/W, main). Enables direct NT syscall usage without Win32 runtime overhead. NtCreateUserProcess can spawn native apps; native entry point provides direct kernel interaction and minimal detectable footprint.

## Member LGTM Notes (1)

### Note 1: Native Application Entry Point and Subsystem Bypass
- id: `lgtm:native-application-development`
- origin: atlas-post-exploit-part13
- would_relate_to: ['T-014', 'T-004']
- tags: ['native-application', 'nt-process-startup', 'peb', 'subsystem-bypass', 'minimal-footprint']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part13
**Would relate to:** T-014, T-004
**Source units:** unit 16, unit 17

SEC670 identifies NTSTATUS NtProcessStartup(PPEB peb) as the function signature for native applications — executables that bypass the Win32 subsystem entirely and receive the PEB directly. The vault's T-014 (NtCreateUserProcess) covers direct NT process creation but does not document the native application entry point convention as a distinct technique for minimal-footprint implant development. Native applications avoid the Win32 initialization path, reducing userland hook exposure and artifact generation. This would merit its own technique card or a dedicated section within T-014.

---
Use `id: T-055`, canonical name above, and `member_notes: ['lgtm:native-application-development']`.
Cross-reference `would_relate_to`: ['T-014', 'T-004'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.