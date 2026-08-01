---
id: T-1593
title: "FindFirstFile/FindNextFile Directory Walk for Recon and Exfil"
category: discovery
tier: C
tags: [file, enumeration, findfirstfile, recon]
mitre: []
origin: glm-expand-cluster
source_cluster: file-enumeration-findfirstfile-recon
member_notes: ['lgtm:file-enumeration-recon-primitives']
---

## Summary
Documents the Win32 directory-walking primitive: FindFirstFileA(lpPath, &WIN32_FIND_DATAA) returns a HANDLE for continued enumeration and populates the first entry; FindNextFileA(hFind, &fd) walks subsequent entries; FindClose(hFind) releases. WIN32_FIND_DATAA contains dwFileAttributes (FILE_ATTRIBUTE_DIRECTORY = 0x10), ftCreationTime / ftLastAccessTime / ftLastWriteTime (FILETIME), nFileSizeHigh / nFileSizeLow (file size split for > 4GB), cFileName (MAX_PATH = 260 chars), cAlternateFileName (8.3 short name). The pattern for recursive walk: prepend path with "\\*" for FindFirstFileA, recurse on FILE_ATTRIBUTE_DIRECTORY entries excluding "." and "..".

## Technical Deep Dive
Single coverage-gap note documenting the foundational directory-walking API underlying T-023 client recon and exfil.

Key technical anchor: FindFirstFileA/FindNextFileA with WIN32_FIND_DATAA.dwFileAttributes FILE_ATTRIBUTE_DIRECTORY = 0x10

## Evidence
- lgtm:file-enumeration-recon-primitives: Highlights the gap or observation related to this tradecraft.

## Detection & Mitigation
Detection of this technique relies heavily on endpoint telemetry (Sysmon, ETW). Mitigation requires a combination of strict ACLs and execution control policies.

## Related Techniques
- T-023 - related to FindFirstFile/FindNextFile Directory Walk for Recon and Exfil

## References
- Refer to internal research note file-enumeration-findfirstfile-recon for preliminary data.
