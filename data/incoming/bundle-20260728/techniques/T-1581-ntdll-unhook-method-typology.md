---
id: T-1581
title: "NTDLL Unhook Method Typology and Restore Sequence"
category: "edr-evasion"
tier: "A"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "ntdll-unhook-method-typology"
member_notes: ["lgtm:coverage-gap-ntdll-restore-api-sequence", "lgtm:cross-source-ntdll-unhook-convergence", "lgtm:cross-source-unhook-method-typology"]
---

## Summary
This card covers the research gap identified as NTDLL Unhook Method Typology and Restore Sequence. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **NTDLL Unhook Method Typology and Restore Sequence** represents a sophisticated vector that leverages low-level system structures. Documents the three canonical NTDLL unhook variants and their concrete API sequences. (1) Byte-level prologue patch: per-function search-and-replace of the EDR's trampoline bytes with the original Nt* prologue (the inverse of the inline-hook byte forensics pattern). (2) Fresh-copy file mapping: CreateFileA(L"\\??\\C:\\Windows\\System32\\ntdll.dll") → CreateFileMapping(PAGE_READONLY | SEC_IMAGE) → MapViewOfFile → walk IMAGE_NT_HEADERS to locate .text section → memcpy the clean .text over the hooked .text in the loaded ntdll. (3) Per-function stub restore via RtlPcToFileHeader + the on-disk ntdll .text RVA. All three are partial: kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks, CmRegisterCallback) continue to observe operations after userland hooks are removed, so unhooking must be paired with operations that do not trigger callbacks. The fresh-copy variant is operationally preferred because it does not require per-function signature knowledge.

The primary mechanism relies on invoking `MapViewOfFile` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `ntdll-unhook-method-typology`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of NTDLL Unhook Method Typology and Restore Sequence
NTSTATUS status = MapViewOfFile(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific ntdll-unhook-method-typology constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:coverage-gap-ntdll-restore-api-sequence: Identified gap in the research corpus.
- lgtm:cross-source-ntdll-unhook-convergence: Identified gap in the research corpus.
- lgtm:cross-source-unhook-method-typology: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **NTDLL Unhook Method Typology and Restore Sequence** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `MapViewOfFile` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `ntdll-unhook-method-typology` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-016: Related technique identified in gap analysis.

## References

- Microsoft Documentation on MapViewOfFile: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of NTDLL Unhook Method Typology and Restore Sequence and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to ntdll-unhook-method-typology.
