# Cluster Spec — T-077: Native Application (NT_main) Execution Surface

- **T-NNN ID**: `T-077`
- **Canonical name**: Native Application (NT_main) Execution Surface
- **Proposed category**: `anti-analysis`
- **Proposed tier**: `B`
- **Priority**: medium — Two notes flag this as emerging tradecraft; minimal but distinct execution mode not in existing cards.
- **would_relate_to**: ['T-017', 'T-020']

## Consolidated Description

Documents the native Windows application execution mode: entry signature `NTSTATUS NTAPI NT_main(int argc, char* argv[])`, distinct from the Win32 main / WinMainCRTStartup. Native applications run before the Win32 subsystem is fully initialized — they are invoked via the Session Manager (smss.exe) during early boot or via RtlCreateUserProcess with the image registered as a known DLL. They have no subsystem import binding; must call only ntdll exports. Operations: registry access via NtCreateKey/NtSetValueKey, file I/O via NtCreateFile, no kernel32/kernelbase. Useful for early-boot persistence (Boot Execute via HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute), SurvivableProtectedProcess launchers, and minimal recon droppers that avoid the Win32 API surface EDRs monitor.


## Member LGTM Notes (2)

### Note 1: Native Application (NT_main) Execution Surface
- id: `lgtm:native-application-execution-surface`
- origin: atlas-binary-analysis-part5
- would_relate_to: []
- tags: ['native-application', 'nt-main', 'early-boot', 'orphan', 'emerging']

**Kind:** emerging-tradecraft
**Origin:** atlas-binary-analysis-part5
**Would relate to:** (new territory)
**Source units:** unit 32

SEC670 unit 32 documents the NTSTATUS NT_main(int argc, const char* argv[]) entry signature used by native Windows applications that run before the Win32 subsystem is fully initialized. Native applications can be invoked by smss during early boot or by WinDbg-style native tooling and present an execution surface distinct from conventional Win32 EXEs. The vault does not currently document native-application execution as a technique; it would relate to early-boot persistence and to evasion contexts where avoiding the Win32 subsystem is operationally valuable.

### Note 2: Native Application Entry Point Signature
- id: `lgtm:native-application-entry-point`
- origin: atlas-binary-analysis-part8
- would_relate_to: ['T-020']
- tags: ['native-application', 'entry-point', 'ntapi', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-binary-analysis-part8
**Would relate to:** T-020
**Source units:** unit 30

SEC670 unit 30 asks about the function signature for a native application (the NTSTATUS NTAPI entry form vs standard C main). The vault's dark_crystal dropper is a Windows implant that interacts with NT APIs but does not document native-application entry-point conventions or the choice between standard subsystem and native subsystem builds. This is a build-time tradecraft decision that affects loader visibility and would merit a note under T-022 architecture or a dedicated section.

---
Use `id: T-077`, canonical name above, and `member_notes: ['lgtm:native-application-execution-surface', 'lgtm:native-application-entry-point']`.
Cross-reference `would_relate_to`: ['T-017', 'T-020'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.