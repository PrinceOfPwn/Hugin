---
id: T-218
title: "FindFirstFile/FindNextFile Directory Walk for Recon and Exfil"
category: patterns
tier: C
tags: ['research-gap', 'file-enumeration-findfirstfile-recon']
mitre: []
origin: glm-expand-cluster
source_cluster: file-enumeration-findfirstfile-recon
member_notes: ['lgtm:file-enumeration-recon-primitives']
---

## Summary

This technique card addresses the research gap identified in cluster `file-enumeration-findfirstfile-recon`.
Documents the Win32 directory-walking primitive: FindFirstFileA(lpPath, &WIN32_FIND_DATAA) returns a HANDLE for continued enumeration and populates the first entry; FindNextFileA(hFind, &fd) walks subsequent entries; FindClose(hFind) releases. WIN32_FIND_DATAA contains dwFileAttributes (FILE_ATTRIBUTE_DIRECTORY = 0x10), ftCreationTime / ftLastAccessTime / ftLastWriteTime (FILETIME), nFileSizeHigh / nFileSizeLow (file size split for > 4GB), cFileName (MAX_PATH = 260 chars), cAlternateFileName (8.3 short name). The pattern for recursive walk: prepend path with "\\*" for FindFirstFileA, recurse on FILE_ATTRIBUTE_DIRECTORY entries excluding "." and "..".


## Technical Deep Dive

Documents the Win32 directory-walking primitive: FindFirstFileA(lpPath, &WIN32_FIND_DATAA) returns a HANDLE for continued enumeration and populates the first entry; FindNextFileA(hFind, &fd) walks subsequent entries; FindClose(hFind) releases. WIN32_FIND_DATAA contains dwFileAttributes (FILE_ATTRIBUTE_DIRECTORY = 0x10), ftCreationTime / ftLastAccessTime / ftLastWriteTime (FILETIME), nFileSizeHigh / nFileSizeLow (file size split for > 4GB), cFileName (MAX_PATH = 260 chars), cAlternateFileName (8.3 short name). The pattern for recursive walk: prepend path with "\\*" for FindFirstFileA, recurse on FILE_ATTRIBUTE_DIRECTORY entries excluding "." and "..".


Technical anchor points:
```
FindFirstFileA/FindNextFileA with WIN32_FIND_DATAA.dwFileAttributes FILE_ATTRIBUTE_DIRECTORY = 0x10
```

## Evidence

- **lgtm:file-enumeration-recon-primitives**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-023: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `file-enumeration-findfirstfile-recon`
- Generated as part of batch processing to fill identified research gaps.
