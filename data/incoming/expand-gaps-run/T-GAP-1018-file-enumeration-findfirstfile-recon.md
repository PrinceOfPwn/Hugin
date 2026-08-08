---
id: T-GAP-1018
title: "FindFirstFile/FindNextFile Directory Walk for Recon and Exfil"
tier: "C"
category: "discovery"
---

# FindFirstFile/FindNextFile Directory Walk for Recon and Exfil

## Description
Documents the Win32 directory-walking primitive: FindFirstFileA(lpPath, &WIN32_FIND_DATAA) returns a HANDLE for continued enumeration and populates the first entry; FindNextFileA(hFind, &fd) walks subsequent entries; FindClose(hFind) releases. WIN32_FIND_DATAA contains dwFileAttributes (FILE_ATTRIBUTE_DIRECTORY = 0x10), ftCreationTime / ftLastAccessTime / ftLastWriteTime (FILETIME), nFileSizeHigh / nFileSizeLow (file size split for > 4GB), cFileName (MAX_PATH = 260 chars), cAlternateFileName (8.3 short name). The pattern for recursive walk: prepend path with "\\*" for FindFirstFileA, recurse on FILE_ATTRIBUTE_DIRECTORY entries excluding "." and "..".


## Rationale
Single coverage-gap note documenting the foundational directory-walking API underlying T-023 client recon and exfil.

## References
- lgtm:file-enumeration-recon-primitives
