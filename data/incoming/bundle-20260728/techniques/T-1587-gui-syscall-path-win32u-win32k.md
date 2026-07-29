---
id: T-1587
title: "GUI Syscall Path via win32u.dll and win32k.sys"
category: "edr-evasion"
tier: "A"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "gui-syscall-path-win32u-win32k"
member_notes: ["lgtm:win32u-gui-syscall-hook-coverage", "lgtm:gui-vs-native-syscall-path-awareness"]
---

## Summary
This card covers the research gap identified as GUI Syscall Path via win32u.dll and win32k.sys. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **GUI Syscall Path via win32u.dll and win32k.sys** represents a sophisticated vector that leverages low-level system structures. Documents that Windows splits syscall routing into native (ntdll.dll → ntoskrnl.exe / executive) and GUI (win32u.dll → win32k.sys) paths. EDRs hook both; GUI functions like NtUserOpenClipboard, NtUserFindWindowEx, NtUserMessageCall are dispatched through win32u, not ntdll, so a T-016 ntdll unhook does NOT restore clean access to GUI primitives. Thread type matters: a non-GUI thread (no Win32k attributed) issuing a win32k syscall will be rejected; this is enforced by the thread's Win32Thread (THREADINFO) field being NULL. Operators issuing clipboard, window, or input syscalls must ensure the calling thread is GUI-initialized (called User32!Win32InitializeThunk or otherwise have an associated W32THREAD).

The primary mechanism relies on invoking `win32u.dll` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `gui-syscall-path-win32u-win32k`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of GUI Syscall Path via win32u.dll and win32k.sys
NTSTATUS status = win32u.dll(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific gui-syscall-path-win32u-win32k constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:win32u-gui-syscall-hook-coverage: Identified gap in the research corpus.
- lgtm:gui-vs-native-syscall-path-awareness: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **GUI Syscall Path via win32u.dll and win32k.sys** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `win32u.dll` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `gui-syscall-path-win32u-win32k` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-001: Related technique identified in gap analysis.
- T-002: Related technique identified in gap analysis.
- T-016: Related technique identified in gap analysis.
- T-023: Related technique identified in gap analysis.

## References

- Microsoft Documentation on win32u.dll: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of GUI Syscall Path via win32u.dll and win32k.sys and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to gui-syscall-path-win32u-win32k.
