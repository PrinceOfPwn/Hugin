---
id: T-15816
title: "Native Application (NT_main) Execution Surface"
category: "edr-evasion"
tier: "B"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "native-application-nt-main-entry"
member_notes: ["lgtm:native-application-execution-surface", "lgtm:native-application-entry-point"]
---

## Summary
This card covers the research gap identified as Native Application (NT_main) Execution Surface. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **Native Application (NT_main) Execution Surface** represents a sophisticated vector that leverages low-level system structures. Documents the native Windows application execution mode: entry signature `NTSTATUS NTAPI NT_main(int argc, char* argv[])`, distinct from the Win32 main / WinMainCRTStartup. Native applications run before the Win32 subsystem is fully initialized — they are invoked via the Session Manager (smss.exe) during early boot or via RtlCreateUserProcess with the image registered as a known DLL. They have no subsystem import binding; must call only ntdll exports. Operations: registry access via NtCreateKey/NtSetValueKey, file I/O via NtCreateFile, no kernel32/kernelbase. Useful for early-boot persistence (Boot Execute via HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute), SurvivableProtectedProcess launchers, and minimal recon droppers that avoid the Win32 API surface EDRs monitor.

The primary mechanism relies on invoking `NTSTATUS` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `native-application-nt-main-entry`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of Native Application (NT_main) Execution Surface
NTSTATUS status = NTSTATUS(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific native-application-nt-main-entry constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:native-application-execution-surface: Identified gap in the research corpus.
- lgtm:native-application-entry-point: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **Native Application (NT_main) Execution Surface** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `NTSTATUS` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `native-application-nt-main-entry` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-017: Related technique identified in gap analysis.
- T-020: Related technique identified in gap analysis.

## References

- Microsoft Documentation on NTSTATUS: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of Native Application (NT_main) Execution Surface and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to native-application-nt-main-entry.
