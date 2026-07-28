---
id: T-057
name: Registry Enumeration Pattern for Target Discovery
category: discovery
tier: B
crate: none
source_file: none
mitre: T1012
mitre_secondary: [T1546.015, T1547.001]
tags: [registry, enumeration, recon, com-hijack, autostart, regenumvalue, discovery, fingerprint]
origin: atlas-synthesis
member_notes: [lgtm:registry-enumeration-fingerprint]
---

# Registry Enumeration Pattern — COM Hijack Discovery and Autostart Targeting

## Summary

The canonical Advapi32 registry enumeration pattern — RegOpenKeyExW to open a parent key, RegQueryInfoKeyW to size buffers from key metadata, then an index-based RegEnumKeyExW / RegEnumValueW loop terminating on ERROR_NO_MORE_ITEMS — is the reusable primitive behind COM-hijack candidate discovery, autostart location inventory, and registry-based reconnaissance. It exploits nothing; it exercises the documented Win32 registry API contract, which the Configuration Manager services through NT native calls. An operator uses it to locate CLSID registrations whose InprocServer32 binaries are missing or shadowable, and to inventory Run-key and policy autostart values for both targeting and change detection. The primary detection surface is not Sysmon, which logs no registry reads by default, but kernel registry callbacks (CmRegisterCallbackEx) and behavioral heuristics that flag high-volume sequential key opens from a process that is not a registry tool.

## Mechanism

1. Open the parent key with RegOpenKeyExW — for example `HKEY_CLASSES_ROOT\CLSID`, `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`, or a machine-hive equivalent — requesting KEY_READ (decomposed as STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY). The return is LSTATUS; only ERROR_SUCCESS (0) yields a valid handle in phkResult.
2. Call RegQueryInfoKeyW on the handle. The call returns the subkey count (lpcSubKeys), the longest subkey name (lpcbMaxSubKeyLen), the value count (lpcValues), the longest value name (lpcbMaxValueNameLen), the largest value payload (lpcbMaxValueDataLen), and the key's last-write time as a FILETIME.
3. Allocate the value-name buffer as lpcbMaxValueNameLen + 1 wide characters — the returned maximum excludes the null terminator — and a data buffer of lpcbMaxValueDataLen bytes. The last-write FILETIME is retained; it feeds timestomping-aware baselining.
4. Enumerate subkeys with RegEnumKeyExW starting at dwIndex 0, incrementing per call. Each successful call fills the subkey name and its last-write time. Terminate the loop on ERROR_NO_MORE_ITEMS (259). Handle ERROR_MORE_DATA (234) by growing the buffer and retrying the same index — key contents can change between steps 2 and 4, invalidating the sizing.
5. For each subkey of interest — a CLSID GUID, a TreatAs target, a ProgID — open it with a fresh RegOpenKeyExW and enumerate its values with RegEnumValueW from dwIndex 0. The (Default) value arrives with an empty name string. Terminate on ERROR_NO_MORE_ITEMS; treat ERROR_ACCESS_DENIED on the re-open as a skippable entry, not a fatal error.
6. Dispatch on lpType: REG_SZ and REG_EXPAND_SZ yield path strings (expand REG_EXPAND_SZ with ExpandEnvironmentStringsW before filesystem testing); REG_DWORD yields a numeric flag; REG_BINARY and REG_MULTI_SZ are captured raw.
7. Close every handle with RegCloseKey. Per-user hive handles must not be cached across logoff, because hive unload invalidates them.
8. COM-hijack application: for each CLSID containing an InprocServer32 subkey, record the (Default) path and ThreadingModel. Test the referenced binary for existence on disk. Check whether a corresponding HKLM\Software\Classes\CLSID entry exists — a per-user-only registration or a registration pointing at a deleted binary is a hijack candidate. Cross-reference CLSIDs consumed by scheduled task XML (ComHandler actions) and autorun entries.
9. Autostart application: enumerate Run, RunOnce, RunOnceEx, and Policies\Explorer\Run under both HKLM and HKCU, plus the Wow6432Node variants, capturing value name, data, and parent-key last-write time to build a change-detection baseline.

## OS Internals Context

The Advapi32 Reg* functions are thunks over NT native registry APIs. RegOpenKeyExW becomes NtOpenKeyEx against the Object Manager namespace rooted at `\Registry\Machine` and `\Registry\User`. RegEnumKeyExW maps to NtEnumerateKey with KeyBasicInformation (name only) or KeyNodeInformation (name plus class); RegEnumValueW maps to NtEnumerateValueKey with KeyValueBasicInformation or KeyValueFullInformation. RegQueryInfoKeyW maps to NtQueryKey with KeyFullInformation plus KeyCachedInformation.

Enumeration is index-based, not cursor-based. The Configuration Manager stores a key's subkeys as cell indexes in hash lists (lf/lh/ri cells) hanging off the parent key node (nk cell) inside the hive. Index order follows hash-bucket layout, so enumeration order is not alphabetical and is unstable across subkey addition and deletion; an operator enumerating while another thread mutates the key can see duplicates or misses. This is why the pattern re-queries metadata rather than assuming stability.

The hive itself is a file (SAM, SECURITY, SOFTWARE, SYSTEM under System32\config; NTUSER.DAT and UsrClass.dat per user) mapped into kernel memory and organized into 4096-byte-aligned bins (HBIN) containing variable-length cells. Key nodes carry the signature "nk", value cells "vk"; small value data is stored inline in the value cell when the size field's high bit is set.

WOW64 redirection intersects enumeration: a 32-bit process sees the redirected view under Wow6432Node unless it passes KEY_WOW64_64KEY (0x0100) or KEY_WOW64_32KEY (0x0200) in samDesired. Reconnaissance that must cover both views opens the key twice with explicit flags rather than relying on the default reflection behavior.

LSTATUS values are Win32 error codes, not NTSTATUS; advapi32 performs the translation. The two codes that define the loop contract are ERROR_NO_MORE_ITEMS (259) for termination and ERROR_MORE_DATA (234) for buffer resize. Treating any non-zero code as fatal is the most common implementation bug in this pattern.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would live in a recon module using `windows-sys` Win32::System::Registry bindings: a generic enumerator parameterized on root handle, subkey path, and desired access, returning a vector of (name, type, data, last-write) tuples. Two consumers would sit on top: a COM-hijack scanner that walks HKCR\CLSID (or the per-user classes hive directly), filters to entries with InprocServer32, and tests binary existence plus HKLM-shadowability; and an autostart auditor that walks the Run-key family across both hives and both WOW64 views, emitting a baseline for diffing on subsequent runs. Buffer sizing should call RegQueryInfoKeyW per key rather than using fixed buffers, and the loop must treat ERROR_MORE_DATA as a resize signal.

## Why It Matters

Single-key lookups answer questions an operator already knows to ask; enumeration answers questions the operator has not yet formed. Consolidating the three-call contract, its error semantics, and its detection fingerprint into one card prevents re-derivation of the same loop across COM-hijack targeting, autostart inventory, and installed-software reconnaissance, and it makes the behavioral signature — bulk sequential key opens — an explicit, weighable cost rather than an accident.

## Detection Considerations

- **Telemetry sources**: Sysmon event IDs 12, 13, and 14 cover registry create, value-set, and rename operations but log no reads, so pure enumeration is invisible to default Sysmon configs. Visibility comes from the ETW provider Microsoft-Windows-Kernel-Registry (rarely enabled at scale due to volume), from EDR kernel callbacks registered via CmRegisterCallbackEx observing RegNtPreEnumerateKey, RegNtPreEnumerateValueKey, and RegNtPreQueryKey operations, and from behavioral rules: a non-registry-editor process opening thousands of distinct CLSID subkeys within seconds matches the profile of autorun auditors and hijack scanners.
- **Bypass options**: Replace broad enumeration with targeted RegQueryValueExW calls against candidate keys derived from other sources — scheduled task XML, service configurations, known CLSID lists. Spread enumeration across time to stay under rate-based heuristics. Call the NT native enumeration APIs directly to bypass user-mode hooks on the advapi32 thunks.
- **Residual artifacts**: None on disk; the registry tracks last-write but not last-read. Residue is purely behavioral — timing correlation between enumeration bursts and subsequent persistence writes (Sysmon 13 on HKCU classes keys) is the strongest retroactive indicator.

## Related Techniques

- **T-017 Five-Layer Persistence** — the COM hijack layer consumes exactly this enumeration output to locate shadowable per-user CLSID registrations.
- **T-023 Client Capabilities** — recon and sysinfo collection reuse the same loop contract for installed-software and configuration inventory.
- **T-020 Anti-Analysis Suite** — environment checks such as installed security-product discovery and LotL binary inventory enumerate registry keys with this pattern.
- **T-059 Registry Merged Views and Link Semantics** — the structural rules that determine which keys the enumeration actually sees and where a given registration physically lives.

## References

- Atlas material: atlas-binary-analysis-part6.md
- MITRE ATT&CK: T1012 (https://attack.mitre.org/techniques/T1012/), T1546.015 (https://attack.mitre.org/techniques/T1546/015/), T1547.001 (https://attack.mitre.org/techniques/T1547/001/)
- LGTM notes: lgtm:registry-enumeration-fingerprint

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.