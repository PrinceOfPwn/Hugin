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
Documents the Win32 directory-walking primitive: FindFirstFileA(lpPath, &WIN32_FIND_DATAA) returns a HANDLE for continued enumeration and populates the first entry; FindNextFileA(hFind, &fd) walks subsequent entries; FindClose(hFind) releases. WIN32_FIND_DATAA contains dwFileAttributes (FILE_ATTRIBUTE_DIRECTORY = 0x10), ftCreationTime / ftLastAccessTime / ftLastWriteTime (FILETIME), nFileSizeHigh / nFileSizeLow (file size split for > 4GB), cFileName (MAX_PATH = 260 chars), cAlternateFileName (8.3 short name). The pattern for recursive walk: prepend path with "\\*" for FindFirstFileA, recurse on FILE_ATTRIBUTE_DIRECTORY entries excluding "." and "..".


## Evidence
- lgtm:file-enumeration-recon-primitives: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-023: Related technique identified in gap analysis.

## References
- To be added.
