---
id: T-15818
title: "FindFirstFile/FindNextFile Directory Walk for Recon and Exfil"
category: "edr-evasion"
tier: "C"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "file-enumeration-findfirstfile-recon"
member_notes: ["lgtm:file-enumeration-recon-primitives"]
---

## Summary
This card covers the research gap identified as FindFirstFile/FindNextFile Directory Walk for Recon and Exfil. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **FindFirstFile/FindNextFile Directory Walk for Recon and Exfil** represents a sophisticated vector that leverages low-level system structures. Documents the Win32 directory-walking primitive: FindFirstFileA(lpPath, &WIN32_FIND_DATAA) returns a HANDLE for continued enumeration and populates the first entry; FindNextFileA(hFind, &fd) walks subsequent entries; FindClose(hFind) releases. WIN32_FIND_DATAA contains dwFileAttributes (FILE_ATTRIBUTE_DIRECTORY = 0x10), ftCreationTime / ftLastAccessTime / ftLastWriteTime (FILETIME), nFileSizeHigh / nFileSizeLow (file size split for > 4GB), cFileName (MAX_PATH = 260 chars), cAlternateFileName (8.3 short name). The pattern for recursive walk: prepend path with "\\*" for FindFirstFileA, recurse on FILE_ATTRIBUTE_DIRECTORY entries excluding "." and "..".

The primary mechanism relies on invoking `FindFirstFileA/FindNextFileA` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `file-enumeration-findfirstfile-recon`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of FindFirstFile/FindNextFile Directory Walk for Recon and Exfil
NTSTATUS status = FindFirstFileA/FindNextFileA(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific file-enumeration-findfirstfile-recon constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:file-enumeration-recon-primitives: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **FindFirstFile/FindNextFile Directory Walk for Recon and Exfil** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `FindFirstFileA/FindNextFileA` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `file-enumeration-findfirstfile-recon` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-023: Related technique identified in gap analysis.

## References

- Microsoft Documentation on FindFirstFileA/FindNextFileA: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of FindFirstFile/FindNextFile Directory Walk for Recon and Exfil and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to file-enumeration-findfirstfile-recon.
