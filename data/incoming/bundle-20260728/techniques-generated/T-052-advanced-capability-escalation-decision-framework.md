---
id: T-052
name: Advanced Capability Escalation Decision Framework
category: discovery
tier: B
crate: none
source_file: none
mitre: T1518.001
tags: [operational, trigger-framework, technique-selection, tradecraft, escalation, edr-detection, capability-tiers, methodology]
origin: atlas-synthesis
member_notes: [lgtm:advanced-capability-selection-framework]
---

# Advanced Capability Escalation Decision Framework — Trigger-Based Selection of Implant Capabilities

## Summary

The Advanced Capability Escalation Decision Framework is a SEC670 methodology for deciding when an implant must move from basic to advanced capabilities, driven by four explicit triggers and four escalation options. It is an operator-side decision process rather than endpoint code: it maps observed defender posture to the minimum sufficient technique tier so that advanced tradecraft is only exposed when the environment demands it. Operators use it to avoid two failure modes — under-matching, where a hooked-API technique is deployed against an EDR that instruments exactly that API, and over-matching, where direct syscalls or manual loaders are burned on a target that LoadLibrary would have serviced, exposing premium capability to telemetry and reverse engineering. The framework itself emits no endpoint telemetry; its inputs (defender discovery actions) and outputs (the deployed techniques) carry the entire detection surface.

## Mechanism

1. Deploy a baseline capability tier chosen for a default-assumed environment — standard Win32 APIs, conventional module loading, established C2.
2. Enumerate defender posture: installed security products, running services and kernel drivers, EDR DLLs present in processes, monitoring and hunting tooling.
3. Evaluate the four triggers against the observations: (1) **defender match** — a specific EDR is identified whose instrumentation covers the technique currently in use; (2) **tech-savvy admin** — indicators of competent active defense such as hunting scripts, Sysmon deployment, or rapid incident response; (3) **stealth requirement** — a mission constraint that demands minimal telemetry regardless of what defense is observed; (4) **basic technique failure** — an API call is blocked, an alert fires, or a payload terminates in a way that indicates interception.
4. Map the fired triggers to escalation options: **manual image loading** to replace LoadLibrary-based module introduction; **API hook reimplementation** to supply own implementations instead of calling hooked APIs; **C2 callbacks** to shift execution into the communication channel; **shellcode execution** to abandon PE artifacts in favor of position-independent payloads. The consolidated cluster description records the same option set in broader terms as manual image loading, hook reimplementation, direct syscalls, and custom tooling.
5. Validate the selected technique against a lab replica of the observed defender stack before it touches the target again.
6. Deploy, monitor for the failure trigger, and re-enter the loop at step 3 if interception recurs — escalation is iterative, not one-shot.

## OS Internals Context

Each escalation option changes which OS boundary the implant crosses, and therefore which instrumentation layer observes it. LoadLibrary crosses the user-mode loader: LdrLoadDll inside ntdll walks the module dependency graph, snaps the PEB loader lists (InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList), fires ImageLoad ETW events, and passes through any EDR hooks on the loader path. A manual image loader performs its own section mapping, relocation, and import resolution, skipping loader bookkeeping and its ETW surface — at the cost of absent LDR entries that become their own anomaly under memory analysis. Calling Win32 APIs crosses kernelbase and ntdll stubs, which is precisely where EDR inline hooks and ETW user-mode providers sit; reimplementing the functionality locally, or descending to the syscall instruction directly, removes the hooked entry points from the call path and leaves kernel callbacks and ETW Threat-Intelligence as the remaining observers. C2 callbacks shift work off the endpoint entirely, reducing local API volume at the price of network-layer telemetry — the trade documented in the networking cards. Shellcode execution removes PE structure from memory and defeats image-based scanning, but encounters RWX-page heuristics, thread start-address analysis, and the absence of a backing module. The framework is the disciplined act of choosing which boundary to cross after learning which boundaries are watched, rather than defaulting to the most exotic primitive available.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. The nearest existing analog is the static phase pipeline in `src/dark_crystal/crates/core/src/runner.rs`, where technique selection is fixed at build time through `selection_config` constants — anti-VM on or off, injection type, syscall mode, hammering — and where `dispatch_injection` cascades through module overloading, ghosting, threadless, reflection, and fiber injection in a predetermined order. A framework implementation would make that pipeline conditional on runtime posture: a posture-assessment phase enumerating EDR processes, drivers, and injected DLLs whose results gate which later phases activate, plus failure-feedback handling that re-selects the injection path when a phase returns an interception-indicating error, converting the current fixed fallback ordering into trigger-driven selection.

## Why It Matters

The vault documents more than eighty techniques as isolated cards, but nothing previously recorded the selection logic that SEC670 teaches for navigating among them. The framework fills the operational gap between "technique exists" and "technique is appropriate," protecting high-tier capabilities — RecycledGate, VEH Gate, Early Cascade — from premature exposure against targets that basic tradecraft would have handled. It also gives engagement teams a shared vocabulary for escalation decisions when defender posture shifts mid-operation, and it defines when to stop escalating: the stealth-requirement trigger caps exposure rather than rewarding maximal sophistication.

## Detection Considerations

- **Telemetry sources**: the framework is operator-side and emits nothing itself. Its posture-enumeration inputs — process, service, driver, and loaded-module inventory — can touch ETW Threat-Intelligence when privileged handles are opened, and its outputs inherit the full detection surface of whichever technique card is selected.
- **Bypass options**: derive defender posture from passive sources where possible, such as file-system artifacts of EDR installations and service registry keys, rather than broad live enumeration; validate escalations against a lab replica so the target never observes the probing that would confirm defender presence.
- **Residual artifacts**: none from the framework itself; each escalated technique leaves the artifacts documented on its own card.
- The training material documents the triggers and escalation options but does not discuss detection of the framework itself.

## Related Techniques

- **T-007 Pool Party and Process Injection Methods** — the injection catalog is the primary escalation target when the basic-technique-failure trigger fires on module introduction or shellcode execution.
- **T-016 EDR Evasion Suite** — the capability pool selected when the defender-match trigger identifies specific instrumentation such as AMSI, ETW, or user-mode hooks.
- **T-022 Network Suite** — the C2-callback escalation option shifts execution into the networking and transport layer documented here.

## References

- Atlas material: atlas-exploit-dev-part15.md (unit 38)
- MITRE ATT&CK: T1518.001 — Software Discovery: Security Software Discovery (https://attack.mitre.org/techniques/T1518/001/)
- LGTM notes: lgtm:advanced-capability-selection-framework
- Public references: SEC670 (trigger framework unit)

## Source Reference

No current implementation. The static selection pipeline in src/dark_crystal/crates/core/src/runner.rs and dark_crystal/crowd/src/payload_cfg.rs is the nearest analog; see atlas material for the methodology.