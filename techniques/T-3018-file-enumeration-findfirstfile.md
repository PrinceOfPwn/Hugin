---
id: T-3018
title: "FindFirstFile/FindNextFile Directory Walk for Recon and Exfil"
category: discovery
tier: C
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: file-enumeration-findfirstfile-recon
member_notes: ['lgtm:file-enumeration-recon-primitives']
---
## Summary

This technique card covers FindFirstFile/FindNextFile Directory Walk for Recon and Exfil. It details mechanisms required to implement or understand file-enumeration-findfirstfile-recon operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents the Win32 directory-walking primitive: FindFirstFileA(lpPath, &WIN32_FIND_DATAA) returns a HANDLE for continued enumeration and populates the first entry; FindNextFileA(hFind, &fd) walks subsequent entries; FindClose(hFind) releases. WIN32_FIND_DATAA contains dwFileAttributes (FILE_ATTRIBUTE_DIRECTORY = 0x10), ftCreationTime / ftLastAccessTime / ftLastWriteTime (FILETIME), nFileSizeHigh / nFileSizeLow (file size split for > 4GB), cFileName (MAX_PATH = 260 chars), cAlternateFileName (8.3 short name). The pattern for recursive walk: prepend path with "\\*" for FindFirstFileA, recurse on FILE_ATTRIBUTE_DIRECTORY entries excluding "." and "..".



```c
// Example for FindFirstFile/FindNextFile Directory Walk for Recon and Exfil
// Implementation specific to file-enumeration-findfirstfile-recon
void execute_file_enumeration_findfirstfile_recon() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:file-enumeration-recon-primitives`: Referenced in internal atlas batches as a core component of file-enumeration-findfirstfile-recon.

## Detection & Mitigation

Detecting this behavior requires deep visibility into API calls. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on FindFirstFile/FindNextFile Directory Walk for Recon and Exfil
