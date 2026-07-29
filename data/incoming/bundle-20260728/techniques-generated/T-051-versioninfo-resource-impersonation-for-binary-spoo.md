---
id: T-051
name: VERSIONINFO Resource Impersonation for Binary Spoofing
category: anti-analysis
tier: B
crate: none
source_file: none
mitre: T1036
tags: [versioninfo, metadata-spoofing, resource-section, masquerading, rsrc, static-analysis-evasion, pe-resources, vendor-impersonation]
origin: atlas-synthesis
member_notes: [lgtm:binary-versioninfo-impersonation]
---

# VERSIONINFO Resource Impersonation for Binary Spoofing — Forge Vendor Metadata in the PE Resource Section

## Summary

VERSIONINFO resource impersonation embeds forged vendor metadata — CompanyName, FileDescription, OriginalFilename, ProductVersion — into the PE `.rsrc` section so that static analysis tooling attributes the binary to a legitimate application such as Google Chrome or a Windows component. The technique exploits the fact that VS_VERSION_INFO is purely informational: the Windows loader never reads it, while Explorer, Task Manager, Sysmon, sigcheck, and triage tooling surface it as authoritative provenance. Operators use it to defeat human triage and metadata-based heuristics that compare binary provenance against known-good vendor signatures before any behavioral analysis begins. The MalDev Academy metadata.src unit demonstrates the pattern by impersonating Google Chrome with CompanyName=Google LLC, FileDescription=Google Chrome, OriginalFilename=chrome.exe, and ProductVersion=112.0.5615.86. The primary detection surface is the mismatch between the claimed vendor and everything else about the binary — missing Authenticode signature, inconsistent file path, inconsistent filename.

## Mechanism

1. Author a `.rc` resource script containing a VS_VERSION_INFO root block with two payloads: a fixed numeric header and a string table.
2. Populate the StringFileInfo entries with the impersonation target's values: CompanyName, FileDescription, FileVersion, InternalName, LegalCopyright, OriginalFilename, ProductName, ProductVersion — for the Chrome example, Google LLC / Google Chrome / chrome.exe / 112.0.5615.86.
3. Populate the fixed file info to match the strings numerically: FILEVERSION and PRODUCTVERSION as the same 112.0.5615.86 quad, file OS VOS_NT_WINDOWS32, file type VFT_APP, flags zero. Keeping the numeric and string forms consistent prevents trivial string-versus-number cross-checks.
4. Compile the `.rc` into a `.res` (rc.exe, llvm-rc, or windres) and link it; the linker emits a `.rsrc` section containing the version resource under resource type RT_VERSION (16).
5. On disk, any consumer calling GetFileVersionInfoSize / GetFileVersionInfo / VerQueryValue, or walking the resource directory tree directly, receives the forged strings and presents them as attribution.
6. Execution is unaffected — the loader, memory manager, and loader snaps ignore RT_VERSION entirely — so the impersonation is pure data. Because it lives in the resource section rather than in code, it survives compilation choices, packing, and in-memory loading unchanged; the same bytes are read whether the binary is inspected on disk or dumped from memory.

## OS Internals Context

The `.rsrc` section is organized as a three-level IMAGE_RESOURCE_DIRECTORY tree: Type level (RT_VERSION = 16 for version resources), Name/ID level, Language level, terminating in an IMAGE_RESOURCE_DATA_ENTRY whose OffsetToData and Size locate the VS_VERSION_INFO blob. That blob opens with VS_FIXEDFILEINFO — signature 0xFEEF04BD, dwFileVersionMS/dwFileVersionLS carrying the numeric version consumed by installer and version-comparison APIs — followed by StringFileInfo containing one or more StringTable blocks keyed by an 8-hex-digit language-plus-codepage identifier ("040904b0" for en-US Unicode), each holding the human-readable strings, and finally VarFileInfo with a Translation value listing the same language/codepage pairs. Two consumer paths diverge: VerQueryValue resolves the localized strings through the language table, while version-comparison logic reads only the fixed numeric quad; forging both keeps the two representations coherent.

Consumers of this data are numerous and none of them validate it: Explorer's file Properties → Details tab, Task Manager's process list, PowerShell's Get-AuthenticodeSignature-adjacent version cmdlets, WMI CIM_DataFile version queries, sigcheck, and Sysmon Event ID 1, which extracts Description, Product, Company, and OriginalFileName from the image at process-create time and forwards them to the SIEM. The forged metadata therefore propagates automatically into defender telemetry pipelines under the attacker's chosen vendor identity.

Authenticode interacts with the resource section in a way that bounds the technique: the image digest computed by ImageGetDigestStream hashes the `.rsrc` contents, so editing VERSIONINFO on a signed binary invalidates its signature. Impersonation is consequently applied to unsigned implants, and the resulting gap — a binary claiming CompanyName "Google LLC" with no signature — is itself the standard analyst catch. Machine-learning classifiers also consume metadata as static features (presence of a company string, OriginalFilename-to-filename agreement, version-string entropy), which is the heuristic class the technique targets: an implant carrying plausible, internally consistent vendor metadata scores closer to the benign distribution than one with empty or garbage version fields.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. An implementation would add a build-time step to the dark_crystal pipeline: a `.rc` script with the VS_VERSION_INFO block compiled via the `embed-resource` crate in `build.rs`, parameterized by a builder profile that selects the impersonation target (chrome.exe, Microsoft component strings, or a verbatim copy extracted from a genuine binary on disk). A post-build variant would open the compiled binary with BeginUpdateResourceW, write the RT_VERSION payload with UpdateResourceW, and commit with EndUpdateResourceW, allowing per-build metadata rotation without recompiling the implant.

## Why It Matters

The vault's T-020 anti-analysis suite manipulates import tables (IAT camouflage) and on-disk presence (self-deletion) but does not surface provenance metadata, which is the first artifact an analyst reads during triage and a field that flows unmodified into Sysmon Event ID 1. VERSIONINFO impersonation is a compile-time control with zero runtime cost and zero additional API surface that shapes both human judgment and static heuristics before behavioral analysis ever runs. It composes directly with filename and path masquerading: the Chrome strings are maximally effective when the binary actually presents as chrome.exe in a plausible directory, making the resource the load-bearing half of a coherent disguise.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 1 logs Company, Description, Product, and OriginalFileName extracted from the image at process creation; EDR consoles surface the same fields as attribution; static scanners (peframe, YARA with the pe module, sigcheck) read the `.rsrc` section directly.
- **Bypass options**: copy metadata verbatim from a genuine binary of the impersonated product so both string and numeric version forms match a real release; align OriginalFilename with the actual on-disk filename and directory; select impersonation targets whose legitimate distribution is unsigned or whose signature absence is unremarkable in the environment; keep resource-section size and language-table structure plausible (a single 040904b0 table matches most en-US binaries).
- **Residual artifacts**: the forged resource is a permanent static artifact embedded in the deliverable. Mismatch heuristics are the primary catch — CompanyName "Google LLC" with no Authenticode signature, OriginalFilename disagreeing with the actual path, version strings inconsistent with PE compile timestamps, or vendor strings on binaries with high-entropy sections. Public YARA rules match known-vendor version strings appearing on unsigned executables.

## Related Techniques

- **T-020 Anti-Analysis Suite** — T-020 covers IAT camouflage, anti-VM, API hammering, and self-deletion; VERSIONINFO impersonation is the static-provenance complement that the suite does not document, operating on the analyst-facing metadata layer rather than imports or disk artifacts.

## References

- Atlas material: atlas-binary-analysis-part8.md (unit 39, metadata.src)
- MITRE ATT&CK: T1036 — Masquerading (https://attack.mitre.org/techniques/T1036/)
- LGTM notes: lgtm:binary-versioninfo-impersonation
- Public references: MalDev Academy (metadata.src unit)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.