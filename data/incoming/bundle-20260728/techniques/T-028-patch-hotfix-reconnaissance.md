---
id: T-028
name: Patch and Hotfix Status Enumeration
category: discovery
tier: B
crate: none
source_file: none
mitre: T1082
mitre_secondary: [T1518]
tags: [patch-enumeration, hotfix, qfe, win32-quickfixengineering, wmi, wua, get-hotfix, wmic-qfe, exploit-selection, service-pack]
origin: atlas-synthesis
member_notes: ['lgtm:patch-recon-for-exploit-selection', 'lgtm:patch-status-inventory-card']
---

# Patch and Hotfix Status Enumeration — QFE/WMI/WUA Recon to Gate Exploit Selection

## Summary

Patch and Hotfix Status Enumeration inventories the hotfixes, Quick Fix Engineering (QFE) updates, and service packs applied to a Windows host so an operator can determine which privilege-escalation and kernel exploits remain viable against that specific build. SEC670 frames this as a precondition for exploit selection rather than general host survey: the course presents three collection paths — the `Get-HotFix` PowerShell cmdlet, the `wmic qfe list` command, and the Windows Update Agent (WUA) COM APIs — and notes that the first two are backed by the same WMI `Win32_QuickFixEngineering` class. The output directly drives operational planning: applied KBs rule out candidate exploits, missing KBs confirm attack surface, and the service-pack/kernel baseline determines whether a payload will even run without crashing the target. Because every collection path uses built-in administrative tooling designed for users and system administrators, the enumeration rides on legitimate Windows management interfaces rather than custom instrumentation.

## Mechanism

1. Establish the servicing baseline: OS version, architecture (x86 vs x86_64), service pack level, and kernel build via the `ntoskrnl.exe` file version under `C:\Windows\System32`. The material treats this as the first recon step because payload compatibility and API availability differ across versions — some API families only exist on newer Windows releases, and an architecture mismatch risks crashing the target.
2. Collection path A — `Get-HotFix`: invoke the PowerShell cmdlet, which lists updates seen by the Quick Fix Engineering class. The cmdlet surfaces the standard `Win32_QuickFixEngineering` properties (HotFixID, Description, InstalledOn, InstalledBy) for each applied update.
3. Collection path B — `wmic qfe list`: invoke the WMIC command-line utility with the `qfe` alias. The material states that both `Get-HotFix` and `wmic qfe list` query the same `Win32_QuickFixEngineering` WMI class and that this class may not provide a full view of all updates on the system.
4. Collection path C — custom WMI query: from C/C++, construct a direct WQL query (`SELECT * FROM Win32_QuickFixEngineering`) against the local WMI service, bypassing the cmdlet and WMIC wrappers while reading the same underlying QFE store.
5. Collection path D — WUA COM APIs: instantiate the WUA object chain. Per the material's code sequence: create an `IUpdateSession`, call `upSsn->CreateUpdateSearcher(&upSearch)` to obtain an `IUpdateSearcher`, execute `upSearch->Search(criteria, &results)` to obtain an `ISearchResult`, then walk `results->get_Updates(&upList)` for the `IUpdateCollection` and `upList->get_Count(&upSize)` for its size. The material identifies `UpdateSearcher` as the WUA object used to find updates on a system.
6. Normalize results into an effective patch state: service packs are cumulative bundles — each service pack targeting an OS version carries all hotfixes from prior service packs, so a host can jump to the latest without sequential installs (material, Service Packs unit). Effective patch state = service pack level + standalone hotfixes applied on top.
7. Gate exploit selection on the result: the material notes that differing service pack levels affect exploit compatibility and that implant and local-privilege-escalation developers must account for target OS versions. Missing KBs confirm unpatched vulnerabilities; present KBs discard candidates before they are attempted. The member notes extend this to kernel-touching technique viability (BYOVD, kernel-callback-dependent evasion) and to reasoning about ETW and callback differences across builds.

## OS Internals Context

The `Win32_QuickFixEngineering` class is a view into the Windows servicing stack, not a complete update ledger. Since Windows Vista, OS servicing is component-based: updates are installed and tracked by Component-Based Servicing (CBS) against the component store in `%WinDir%\WinSxS`, and per MSDN remarks on the class, `Win32_QuickFixEngineering` reports only updates installed through CBS — updates installed via Microsoft Installer (MSI) packages or other channels are not returned. This is the technical reason behind the material's warning that `Get-HotFix` and `wmic qfe list` may not show the full picture, and it is why the WUA path exists as the authoritative alternative.

The WUA APIs were introduced with Windows XP and are designed for system administrators and developers (material, WUA unit). They are exposed as COM interfaces declared in the WUA SDK headers, and they can determine which updates are available to install, which have been installed, or remove installed updates — including queries against a Windows Server Update Services (WSUS) backend in managed fleets. The standard search contract takes a criteria string (per MSDN, expressions such as `IsInstalled=1`) that the searcher evaluates against the agent's update metadata. All of this executes entirely in user mode: no driver, no privileged kernel interface, and no raw servicing-store parsing is required for any of the three paths.

The operational semantics of "hot" matter for timing. The material explains that the term "hot fix" traditionally meant a patch applicable while the system was still running, and that hosts with automatic updates enabled download hotfixes without user intervention — the only exception being a reboot. A fleet therefore drifts toward a patched state over time, so the patch inventory is a point-in-time measurement whose value decays between enumeration and exploitation.

The kernel build remains the ground truth for exploit compatibility. `ntoskrnl.exe` under `C:\Windows\System32` is the kernel image itself (material, OS Information unit); its file version, combined with the service-pack level, pins the exact code an exploit or LPE must target. The material ties this directly to implant development: kernel-touching payloads that assume one build's structures or callback layouts can crash a differently patched host, which is why patch enumeration precedes technique selection rather than following it.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in PowerShell, WMIC, and C/C++ COM. The keyword-matched files supplied with this cluster (`browser_hook.rs`, `browser_session.rs`, `pe_loader.rs`) were reviewed and do not implement patch or hotfix enumeration; they cover browser extension sideloading, CDP session launch, and reflective PE loading respectively.

An implementation would live in `client_rust` alongside `sysinfo_collect.rs` as a recon module invoked during initial survey. The primary backend would instantiate the WUA chain through the `windows` crate: `CoCreateInstance` of the `UpdateSession` coclass for `IUpdateSession`, `CreateUpdateSearcher` for `IUpdateSearcher`, a synchronous `Search` with an installed-updates criteria string, then iteration over the returned `IUpdateCollection` reading each `IUpdate`'s title and KB article IDs into a `Vec<HotfixRecord { kb_id, title, installed_on }>`. A fallback backend would spawn `wmic qfe list` or `powershell -Command Get-HotFix` and parse stdout when COM instantiation fails. Results would serialize to JSON and merge into the HELLO/sysinfo payload described in T-023.

## Why It Matters

T-023's system-info collection gathers hostname, OS, CPU, RAM, disk, and network adapters, and T-020's Kaguya inventories LOtL binaries and security products — neither surfaces the applied-update set. Patch status is the gating input for exploit selection: it determines whether kernel-touching capabilities are viable on the target build and prevents burning exploits or crashing hosts against patched vulnerabilities. Both member notes independently flag this as a coverage gap, which is why it earns a standalone card rather than a line under general host survey.

## Detection Considerations

Training material does not discuss detection for this technique.

## Related Techniques

- **T-020 Anti-Analysis Suite** — Kaguya's LOtL-binary and EDR inventory is the adjacent host-survey capability; T-028 adds the servicing-state dimension that determines whether the evasion and kernel-touching techniques in that suite remain viable on the enumerated build.
- **T-023 Client Capabilities Suite** — `sysinfo_collect.rs` populates the HELLO message with OS/hardware data but includes no patch inventory; T-028 defines the recon primitive that would extend that survey with applied-update data and feed exploit selection downstream.

## References

- Atlas material: atlas-methodology-part2.md, atlas-recon-part1.md
- MITRE ATT&CK: T1082 System Information Discovery (https://attack.mitre.org/techniques/T1082/)
- LGTM notes: lgtm:patch-recon-for-exploit-selection, lgtm:patch-status-inventory-card
- Public references: SANS SEC670 "Service Packs/Hotfixes/Patches" module (named in atlas material); Microsoft documentation for the Windows Update Agent API and the `Win32_QuickFixEngineering` WMI class (discussed in the material)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.