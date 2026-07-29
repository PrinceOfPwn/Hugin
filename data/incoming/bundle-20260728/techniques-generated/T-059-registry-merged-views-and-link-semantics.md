---
id: T-059
name: Registry Merged Views and Link Semantics
category: discovery
tier: C
crate: none
source_file: none
mitre: T1546.015
mitre_secondary: [T1012]
tags: [registry, hkcr, hkcc, merged-view, com-hijack, windows-internals, registry-links, per-user-persistence]
origin: atlas-synthesis
member_notes: [lgtm:windows-registry-internals-deep-dive]
---

# Registry Merged Views and Link Semantics — Structural Basis for Per-User Persistence

## Summary

The registry's predefined root handles are not independent stores: HKEY_CLASSES_ROOT is a merged view over machine-wide and per-user class registrations, HKEY_CURRENT_USER is an alias into HKEY_USERS, and HKEY_CURRENT_CONFIG is entirely a link into the HKLM subtree with no storage of its own. Merge precedence — per-user classes override machine-wide ones for the querying session — is the structural fact that makes per-user COM hijack persistence work without administrative rights. An operator implementing persistence or interpreting reconnaissance output must understand which hive a registration physically lands in and which view a consumer resolves against. The detection surface concentrates on writes to the per-user classes hive (UsrClass.dat), visible as Sysmon Event 13 against `HKU\<SID>_Classes` paths, and on merged-view discrepancies detectable by diffing HKCR against HKLM alone.

## Mechanism

1. At boot and logon, the Configuration Manager loads hives: machine hives (SAM, SECURITY, SOFTWARE, SYSTEM) from `%SystemRoot%\System32\config`, and per-user hives — NTUSER.DAT and UsrClass.dat — for each interactive profile. The hive inventory is exposed at `HKLM\SYSTEM\CurrentControlSet\Control\hivelist`.
2. The Object Manager namespaces the registry under `\Registry\Machine` and `\Registry\User`. HKEY_LOCAL_MACHINE opens the former; HKEY_USERS opens the latter.
3. HKEY_CURRENT_USER is an alias to `\Registry\User\<SID>` — the caller's loaded profile hive. No HKCU storage exists independently; a HKCU write is an HKU\<SID> write through a convenience handle.
4. HKEY_CLASSES_ROOT is a merged view composed of `HKLM\Software\Classes` (machine-wide registration) and `HKCU\Software\Classes` (per-user registration, physically resident in UsrClass.dat since Vista). Reads and enumerations return the union; on name collision the per-user entry wins.
5. Writes to HKCR follow the caller's privilege: a standard user writing `HKCR\CLSID\{...}\InprocServer32` silently lands in HKCU\Software\Classes; an elevated caller can write the machine-wide portion. This write redirection is the documented behavior that enables per-user COM registration without admin.
6. Deletes on a merged key remove the per-user copy first; if a machine-wide copy exists underneath, it resurfaces in subsequent reads once the shadowing per-user key is gone. Cleanup logic must delete both copies to fully remove a registration.
7. HKEY_CURRENT_CONFIG is a pure link to `HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current` — every HKCC read is an HKLM read through a symbolic link. It holds the active hardware profile and has no per-user dimension.
8. Link resolution recurses: CurrentControlSet itself is a link to ControlSet00x, selected by the Select\Current value. The Configuration Manager resolves REG_LINK symbolic links at parse time during object lookup.
9. COM activation consumes the merged view: CoCreateInstance resolves the CLSID through HKCR, so a per-user InprocServer32 registration shadows the machine-wide server for that user's session only, redirecting activation to an operator-controlled binary without touching HKLM.

## OS Internals Context

A hive is a file-backed memory image organized into 4096-byte-aligned bins (HBIN), each containing variable-length cells addressed by cell index. Key nodes carry the "nk" signature and hold the parent cell index, subkey list, value list, security descriptor cell reference, and class name; value cells carry "vk" and store small payloads inline when the data-size high bit is set. Subkey lists are hash structures (lf/lh/ri cells), which is why enumeration order is hash-determined rather than lexical. Loaded hives are tracked per key control block in a hash table the CM maintains for fast name lookup, and modified cells are flushed to the hive file by the lazy writer on a periodic schedule, so a crash can strand very recent writes.

Merged-view behavior is implemented in the CM's key lookup: when a key participates in the classes merge, queries consult both the machine and per-user branches and apply precedence. The operational consequences that matter to an operator are the documented ones — per-user wins on collision, enumeration returns the union, unprivileged writes redirect to the per-user hive, and deletes peel the per-user layer first.

Registry symbolic links (REG_LINK) are a distinct mechanism from the merged view. HKCC and CurrentControlSet are links; creating new links is effectively restricted to kernel-mode callers, so operators consume links rather than mint them. Link resolution happens transparently in the namespace parse path, meaning a handle opened against HKCC\...\Current is indistinguishable from one opened against the HKLM target.

WOW64 intersects both mechanisms: the registry redirector splits portions of the classes hive for 32-bit processes (the Wow6432Node\CLSID view), so a 32-bit consumer of HKCR sees a different merged view than a 64-bit consumer on the same machine. Persistence aimed at 32-bit COM servers must account for the redirected branch. Per-user classes under HKU\<SID>_Classes follow the same shadowing rules, and because UsrClass.dat roams with the profile, per-user registrations can follow a domain user across machines — a persistence property with no machine-hive equivalent.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation drawing on this knowledge would not be a standalone module but a set of structural rules baked into registry-writing code: the COM-hijack persistence layer should write per-user registrations to HKCU\Software\Classes directly (rather than HKCR, to make the physical landing explicit), should treat enumeration of HKCR as a merged-view read when auditing for shadow conflicts, and should delete both the per-user and machine copies during cleanup. Verification tooling should resolve HKCR and HKLM\Software\Classes separately to expose shadowing.

## Why It Matters

Merged-view and link semantics explain, at the structure level, why per-user persistence requires no elevation and why cleanup so often fails — the machine registration resurfaces after a per-user delete. They also prevent operator error: writing to HKCR while assuming an HKLM write, or auditing HKCR and mis-attributing a per-user shadow to the machine hive. Surfacing this as a dedicated concept card gives the persistence and reconnaissance cards a fixed reference for the behavior they depend on.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 13 captures value writes under `HKU\<SID>_Classes\CLSID`, exposing per-user registrations; Event 12 covers key creation. ETW's Microsoft-Windows-Kernel-Registry provider and CmRegisterCallbackEx callbacks give EDRs the same visibility. Autorun-style hunting tools diff the HKCR merged view against the HKLM-only view to surface shadow registrations.
- **Bypass options**: There is no way to make a functional per-user registration invisible to the merged view — the shadow must exist to work. Operators reduce noise by writing only the minimal key set (CLSID plus InprocServer32, skipping ProgID where possible) and by shadowing CLSIDs already consumed by a legitimate, frequently activated component so the registration blends with expected activation traffic.
- **Residual artifacts**: UsrClass.dat entries persist across reboot and roam with the profile; the shadow survives until the per-user key is explicitly deleted. Forensic acquisition of UsrClass.dat reveals the full per-user registration set.

## Related Techniques

- **T-017 Five-Layer Persistence** — the COM hijack layer depends directly on per-user classes shadowing machine registrations in the HKCR merged view.
- **T-057 Registry Enumeration Pattern** — the enumeration primitive operates over the merged view; precedence and redirection rules determine what its reads return and where its consumers' writes land.

## References

- Atlas material: atlas-recon-part6.md
- MITRE ATT&CK: T1546.015 (https://attack.mitre.org/techniques/T1546/015/), T1012 (https://attack.mitre.org/techniques/T1012/)
- LGTM notes: lgtm:windows-registry-internals-deep-dive

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.