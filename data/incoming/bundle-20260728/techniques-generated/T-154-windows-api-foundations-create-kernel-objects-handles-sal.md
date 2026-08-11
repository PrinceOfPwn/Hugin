---
id: T-154
title: "Windows API Foundations — Create* Kernel Objects, Handles, SAL"
category: discovery
tier: B
tags: ['windows-api-foundations']
mitre: ["T-014","T-015","T-016"]
origin: glm-expand-cluster
source_cluster: windows-api-foundations
member_notes: ["lgtm:windows-api-foundation-coverage-gap"]
---
## Summary

This technique covers Windows API Foundations — Create* Kernel Objects, Handles, SAL. It addresses a gap in knowledge for red-team operations related to discovery.

## Technical Deep Dive

SEC670 Book 1 dedicates substantial material to SAL annotations, the Create* kernel-
object/handle pattern (CreateFile/CreateProcess/CreateThread/CreateEvent returning a
HANDLE with ref-count semantics), the CloseHandle/GetLastError error model, and the
WaitFor* synchronization family (WaitForSingleObject, WaitForMultipleObjects). The
vault's T-014 (Module Stomping), T-015 (not specified), and T-016 (NTAPI Hook Evasion)
all assume familiarity with these patterns but do not document them as a shared
prerequisite. A concept card should document the handle table model (per-process handle
table, handle value encoding with audit/inherit bits), the Create/Close lifecycle, the
GetLastError/HRESULT/NTSTATUS error-code regimes (and how they differ), and the
WaitFor* family's relationship to signaled/non-signaled kernel objects. This card
would serve as a navigation hub for readers new to Windows internals approaching the
vault's technique cards.


Technical anchor details:
```text
Create* → HANDLE (per-process handle table with Entry containing Lock/Inheritable/Audit/Protect-from-close bits) + CloseHandle + GetLastError (Win32 error) vs HRESULT vs NTSTATUS (ntstatus.h) error regimes
```

## Evidence

- lgtm:windows-api-foundation-coverage-gap: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-014: Related technique for extended operations.
- T-015: Related technique for extended operations.
- T-016: Related technique for extended operations.

## References

- Internal Vault References
