---
id: T-1018
title: "FindFirstFile/FindNextFile Directory Walk for Recon and Exfil"
category: patterns
tier: C
tags: [research-gap, patterns]
mitre: []
origin: glm-expand-cluster
source_cluster: file-enumeration-findfirstfile-recon
member_notes: ['lgtm:file-enumeration-recon-primitives']
---

## Summary
Documents the Win32 directory-walking primitive: FindFirstFileA(lpPath, &WIN32_FIND_DATAA) returns a HANDLE for continued enumeration and populates the first entry; FindNextFileA(hFind, &fd) walks subsequent entries; FindClose(hFind) releases. WIN32_FIND_DATAA contains dwFileAttributes (FILE_ATTRIBUTE_DIRECTORY = 0x10), ftCreationTime / ftLastAccessTime / ftLastWriteTime (FILETIME), nFileSizeHigh / nFileSizeLow (file size split for > 4GB), cFileName (MAX_PATH = 260 chars), cAlternateFileName (8.3 short name).

## Technical Deep Dive
The pattern for recursive walk: prepend path with "\\*" for FindFirstFileA, recurse on FILE_ATTRIBUTE_DIRECTORY entries excluding "." and "..".

### Technical Anchor
FindFirstFileA/FindNextFileA with WIN32_FIND_DATAA.dwFileAttributes FILE_ATTRIBUTE_DIRECTORY = 0x10

## Evidence
- `lgtm:file-enumeration-recon-primitives`: Contributed evidence for this cluster.

## Detection & Mitigation
Detection strategies should focus on the technical anchors described above. Specifically, monitor for associated API calls, memory allocations, or specific thread creation behaviors as applicable.

## Related Techniques
- T-023: Related technique identified during clustering.

## References
- Internal cluster analysis
