---
id: T-156
title: "UACMe Project as Canonical UAC Bypass Corpus"
category: privesc
tier: B
tags: ['uacme-corpus-uac-bypass']
mitre: ["T-021","T-017"]
origin: glm-expand-cluster
source_cluster: uacme-corpus-uac-bypass
member_notes: ["lgtm:uacme-corpus-coverage"]
---
## Summary

This technique covers UACMe Project as Canonical UAC Bypass Corpus. It addresses a gap in knowledge for red-team operations related to privesc.

## Technical Deep Dive

SEC670 Unit 39 explicitly references the UACMe project's FusionScanFiles routine,
identifying UACMe as the canonical UAC bypass research corpus. The vault's T-021 covers
UAC bypass via CMSTP (Microsoft Connection Manager Profile Installer) and slui.exe
(Windows Activation executable) registry manipulation. UACMe documents 80+ UAC bypass
methods organized by auto-elevation mechanism (ICMLuaUtil, IColorDataProxy,
IEditionUpgradeManager, IFwCplUser), each exploiting a different auto-elevated COM
interface or binary. A card should document the UACMe corpus structure, the auto-
elevation criteria (requestedExecutionLevel=RequireAdministrator in manifest +
autoElevate=true), the COM-interface-based bypass pattern (instantiating an
elevated COM object and calling its methods to execute arbitrary actions), and the
FusionScanFiles routine specifically (which uses IFileOperation via elevated COM to
copy/replace files in protected locations).


Technical anchor details:
```text
UACMe FusionScanFiles: elevated COM interface IFileOperation (CLSID {3ad00546-1E8F-4C95-A33A-9C9B20BEE633}) via ICMLuaUtil::ShellExec — bypass via autoElevate=true manifest + CoCreateInstance with elevated token
```

## Evidence

- lgtm:uacme-corpus-coverage: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-021: Related technique for extended operations.
- T-017: Related technique for extended operations.

## References

- Internal Vault References
