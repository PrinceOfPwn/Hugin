---
id: T-063
name: System32 Folder Blending as File-Based Hiding Technique
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1036.005
mitre_secondary: [T1070.006]
tags: [file-blending, system32, masquerading, timestomp, ntfs, filename-convention, anti-forensics]
origin: atlas-synthesis
member_notes: [lgtm:system32-blending-evasion]
---

# System32 Folder Blending as File-Based Hiding Technique — Statistical Obscuration Among Legitimate Files

## Summary

System32 folder blending hides a payload file inside C:\Windows\System32 by exploiting the directory's scale — 4,200 or more existing files — rather than any technical concealment mechanism. The operator selects an insertion point in the middle of the alphabetical listing, derives a filename that matches the naming conventions of surrounding legitimate entries, and aligns the file's timestamps with its neighbors so the artifact survives casual directory inspection. SEC670 documents this as tradecraft aimed at defender workflow: it defeats the human analyst scrolling a directory listing, not the security product scanning file contents. Because the file is fully present on disk and subject to signature checks, hash-set comparison, and content scanning, the technique is a complement to — never a substitute for — payload-level evasion. Its detection surface is everything the technique does not address: true creation timestamps in the NTFS journal, unsigned-code anomaly detection, and known-good hash sets.

## Mechanism

1. Enumerate the target directory with NtQueryDirectoryFile (FileBothDirectoryInformation) or FindFirstFileEx, collecting the complete filename set of System32 and confirming the file count is in the multi-thousand range that provides statistical cover.
2. Compute the insertion point in the lexicographic ordering — the middle of the listing. Human reviewers inspecting a sorted directory concentrate on the first and last screenfuls; an entry in the middle of 4,200 names is rarely eyeballed.
3. Derive the filename from the conventions of the entries adjacent to the insertion point: match length distribution, prefix morphology, and extension mix of the neighbors (for example, mimicking the shape of nearby DLL or EXE names) so the name does not stand out in a sorted view. Verify no collision with a genuine file.
4. Write the payload to the chosen path with NtCreateFile. Writing into System32 requires elevation, and Windows Resource Protection ACLs most System32 objects to TrustedInstaller; the write path must account for this (unprotected location or appropriate privilege).
5. Align timestamps. Open a legitimate neighbor file, read its FILE_BASIC_INFORMATION, and apply its CreationTime, LastWriteTime, and ChangeTime to the payload with NtSetInformationFile (FileBasicInformation) or SetFileTime, so a date-sorted or date-filtered review shows the payload blending into the same install-era window as its neighbors.
6. Match remaining surface attributes: file attributes (archive flag, not hidden — hidden files in System32 draw attention), and, when the payload is a PE, version-resource strings that resemble the neighboring binaries' vendor and description fields.

## OS Internals Context

NTFS stores directory contents in the $I30 index attribute of the directory's $MFT record, organized as a B-tree keyed on filename under case-insensitive Unicode collation. Enumeration therefore returns names in a deterministic lexicographic order, and both the raw API and Explorer's default sort reflect it — which is what makes a "middle of the listing" position computable and stable across tools.

The timestamp-alignment step interacts with a dual-timestamp reality. NTFS maintains two timestamp sets per file: $STANDARD_INFORMATION ($SI), which SetFileTime and NtSetInformationFile modify, and $FILE_NAME ($FN), which the filesystem updates on rename and attribute operations and which user-mode APIs cannot set directly. A file whose $SI creation time claims 2019 but whose $FN timestamps reflect the true write time is a classic timestomp indicator under raw $MFT analysis. The USN journal additionally records the file-creation record with the genuine timestamp at the moment of the write, independent of any later $SI rewrite — timestamp alignment defeats the listing view, not the forensic view.

Code-signing posture is the statistical wall the technique cannot climb. The overwhelming majority of PE files in System32 are Authenticode- or catalog-signed by Microsoft; an unsigned or differently signed binary in that directory is an outlier to any tool that sweeps signatures (Get-AuthenticodeSignature, sigcheck) regardless of filename or position. Similarly, known-good hash sets (NSRL-style, or a golden-image diff) flag the file instantly. The material's framing is explicit on this point: blending is behavioral obscuration against manual inspection, and it composes with persistence and content-level evasion rather than replacing them.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would be a placement module called by the persistence or dropper path: enumerate the directory through the existing RecycledGate NT wrappers, select the mid-listing insertion point, synthesize the filename from neighbor morphology, write the payload, then copy a neighbor's FILE_BASIC_INFORMATION onto it via NtSetInformationFile. The vault's existing self-deletion module represents the counter-forensic complement for when blending fails and the artifact must be removed.

## Why It Matters

Persistence cards cover where implants anchor; this card covers how the anchored file survives the first five minutes of a human triage session. Analysts working from Autoruns output, Explorer listings, or EDR file trees make keep-or-kill decisions on name, location, and date plausibility before ever opening the file. A payload positioned, named, and dated to match 4,200 legitimate neighbors passes that review at zero technical cost, buying the dwell time that technical controls alone would not.

## Detection Considerations

- **Telemetry sources**: Sysmon event ID 11 (FileCreate) logs the write with the true timestamp regardless of subsequent timestomping. The USN journal and $MFT preserve authentic creation records. Signature-verification sweeps and known-good hash comparisons detect the content anomaly that naming cannot fix.
- **Bypass options**: Aligning $SI timestamps removes the date-sort anomaly; matching name morphology defeats visual scans; placing the file mid-listing defeats positional review. Signing the payload or proxying execution through a signed host addresses the signature outlier, which is a separate technique.
- **Residual artifacts**: The file on disk in a WRP-protected tree (the write itself may have generated privileged file-operation telemetry), $SI/$FN timestamp divergence under forensic review, and the USN journal entry.

## Related Techniques

- **T-017 Five-Layer Persistence** — blending is the placement tradecraft for file-backed persistence layers anchoring on disk.
- **T-020 Anti-Analysis Suite** — self-deletion is the counter-forensic complement when a blended artifact is discovered, and IAT camouflage is the static-analysis analog of blending applied at the import level.

## References

- Atlas material: atlas-edr-evasion-part1.md
- MITRE ATT&CK: T1036.005 (https://attack.mitre.org/techniques/T1036/005/)
- LGTM notes: lgtm:system32-blending-evasion

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.