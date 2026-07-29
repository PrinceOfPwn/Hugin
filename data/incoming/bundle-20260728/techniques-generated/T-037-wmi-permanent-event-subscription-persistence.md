---
id: T-037
name: WMI Permanent Event Subscription Persistence
category: persistence
tier: A
crate: none
source_file: none
mitre: T1546.003
tags: [persistence, wmi, event-subscription, cim-repository, filter-to-consumer-binding, command-line-event-consumer, wql, wmiprvse, sysmon-wmi, root-subscription]
origin: atlas-synthesis
member_notes: ['lgtm:wmi-event-subscription-persistence', 'lgtm:wmi-permanent-subscription-persistence-card', 'lgtm:wmi-event-subscription-persistence-card', 'lgtm:proposed-wmi-event-subscription-persistence', 'lgtm:proposed-wmi-persistence-suite', 'lgtm:wmi-permanent-subscription-card', 'lgtm:wmi-permanent-subscription-persistence']
---

# WMI Permanent Event Subscription Persistence — Event-Driven Execution from the CIM Repository

## Summary

WMI permanent event subscriptions persist attacker logic inside the Windows Management Instrumentation repository as a three-object triad — an `__EventFilter` instance holding a WQL trigger query, an event consumer (the training material focuses on `CommandLineEventConsumer`) holding the action to run, and a `__FilterToConsumerBinding` instance associating the two — and WMI executes the consumer inside the WmiPrvSE.exe provider host whenever the filter's event fires. The mechanism abuses WMI's legitimate event subscription infrastructure: the subscription objects live in the CIM repository rather than in a Run key, scheduled task, service entry, or PE modification, so they survive reboot without touching the locations that persistence scanners and Autoruns-style tooling enumerate. Operators use it for event-driven re-execution on arbitrary system conditions (process creation, system uptime, drive insertion, failed logon) and, because consumers execute as SYSTEM, for Admin-to-SYSTEM elevation. The primary detection surface is Sysmon's dedicated WMI event class (EID 19/20/21) plus process telemetry showing unexpected children of WmiPrvSE.exe.

## Mechanism

1. Obtain the privileges needed to write the subscription namespace. Creating instances under `root\subscription` requires administrative access; the material frames the technique as combining persistence with elevation from Admin to SYSTEM.
2. Prototype the trigger query interactively. Lab 4.6 (OhMyWMI) directs the operator to use PowerShell to test WQL queries first, then implement the finalized query programmatically. Installation paths discussed across the material are C++ via COM interfaces, PowerShell scripting, and wmic.exe against the subscription namespace.
3. Connect to the WMI service on the target namespace (`root\subscription`, referenced directly in the HUGIN LOtL catalog template `wmic.exe /NAMESPACE:\\root\subscription ...`).
4. Create an `__EventFilter` instance. Its properties carry the event definition: a `Name`, the `EventNamespace` the query evaluates against, `QueryLanguage` set to `WQL`, and the `Query` string itself.
5. Select the event class. The material splits WMI events into intrinsic events — changes within the "standard WMI model" such as `__InstanceCreationEvent`, for objects that reside in the WMI repository — and extrinsic events, which are not tied directly to a change in the WMI model, such as `RegistryKeyChangeEvent`. The two classes have different delivery profiles, covered in the OS Internals section.
6. Create a `CommandLineEventConsumer` instance. Its properties carry the action: a `Name` and the command line to execute when the bound filter fires.
7. Create a `__FilterToConsumerBinding` instance. This is the class that "holds together the event filter and the event consumer" — a point the course review section repeats across multiple units. Its `Filter` and `Consumer` properties are object references to the instances created in steps 4 and 6.
8. All three objects are written into the CIM repository. Because repository data persists across reboots, the subscription reactivates when the WMI service restarts after boot, with no filesystem script, registry value, or scheduled task re-registration required.
9. On each event delivery, the WMI event subsystem evaluates active filters; when the WQL query matches, the bound consumer fires. A `CommandLineEventConsumer` launches its command line within the WmiPrvSE.exe provider host context, which runs as SYSTEM.
10. Trigger variants enumerated by the material: system uptime (the Lab 4.6 OhMyWMI requirement — "create a permanent subscription based on system uptime; the trigger should execute your persistence tool"), process creation (the course's worked example filters for notepad.exe launching), a new logical drive being loaded, a failed logon attempt, and registry changes via the extrinsic `RegistryKeyChangeEvent`.

## OS Internals Context

WMI is Microsoft's implementation of the Common Information Model (CIM), an industry standard for representing systems, processes, devices, and related data in a uniform, object-oriented way that "gives the look and feel of a C++ class." CIM defines three levels of classes — Core, Common, and Extended — moving from most general to most technology-specific. Classes group into schemas: the CIM schema (prefix `CIM_`) provides the Core and Common definitions, and the Win32 schema (prefix `Win32_`) provides the Extended classes specific to the Win32 environment. Developers can define custom classes in either schema, which is the property that makes the subscription object model extensible rather than fixed.

The WMI architecture, as the material walks it from the MSDN diagram, has three stages. Area 1 is providers and objects: WMI providers supply data that can be stored in the WMI repository — the Win32 provider, for example, hands consumers a list of processes. Area 2 is the WMI infrastructure, which includes the repository and the object manager that routes requests. Area 3 is consumers: C++ programs, PowerShell scripts, or anything driving the COM interfaces, using WQL to filter events of interest. The repository is the load-bearing element for this technique: the material notes that its data is persistent across reboots, which is exactly what converts an event subscription into a persistence mechanism. On disk the repository is backed by files under `%SystemRoot%\System32\wbem\Repository`, so the subscription does have a physical footprint even though no standalone script or binary exists.

The event model determines triggering behavior. Intrinsic events (`__InstanceCreationEvent` and siblings) fire on changes to objects in the standard WMI data model; extrinsic events (`RegistryKeyChangeEvent` and similar) originate outside that model. The material distinguishes the two by delivery profile — characterizing intrinsic events as firing immediately and extrinsic events as requiring polling at an interval — and drills the distinction in its review section ("What types of events must be polled at some interval?"). Polled event queries in WQL carry a `WITHIN` clause specifying the polling interval, which the operator tunes to trade trigger latency against query overhead.

The system classes that implement subscriptions live in the `root\subscription` namespace: `__EventFilter`, the `__EventConsumer` hierarchy (from which `CommandLineEventConsumer` derives), and `__FilterToConsumerBinding`. Execution context is the final internal that matters: consumers run inside WmiPrvSE.exe, the WMI provider host, which operates as SYSTEM. This is why the material describes WMI subscriptions as delivering both "persistence and elevation" — an operator with administrative access installs the subscription, and the resulting execution lands in a SYSTEM process without a token manipulation step.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for the course's reference workflow (PowerShell prototyping, then programmatic installation) in SEC670 Book 4, Lab 4.6 OhMyWMI.

Verification of grep-matched files: `dark_crystal/crowd/src/kaguya.rs` catalogs `wmic.exe` as a LOtL binary with `persist_method: Some("event_consumer")`, `persist_template: "wmic.exe /NAMESPACE:\\\\root\\subscription ..."`, and `mitre_persist: "T1546.003"`, but no function in the file instantiates the filter/consumer/binding triad — `execute_chain()` acts only on a chain's execution stage via PPID-spoofed process creation, and the persistence template string is never invoked. `client_rust/src/browser_hook.rs` and `client_rust/src/commands.rs` implement browser-extension persistence and command dispatch respectively; neither touches WMI.

An implementation would follow the mechanism directly: resolve COM (or spawn wmic.exe per the Kaguya catalog template), connect an `IWbemServices` pointer to `root\subscription`, and `PutInstance` three objects — the `__EventFilter` (embedding the WQL query and chosen event class), the `CommandLineEventConsumer` (embedding the payload command line), and the `__FilterToConsumerBinding` (referencing the first two). In the HUGIN architecture this would sit as an additional module under `crowd/src/persist/`, feature-gated like the existing five layers, with install, verify (query for the three instances), and remove entry points so the resilience monitor can re-establish a deleted triad.

## Why It Matters

T-017's five layers anchor in COM registration, an NTFS extended attribute, the Task Scheduler COM interface, a patched PE TLS directory, and the application-restart API — every one of them boot/logon-triggered and stored in a location persistence tooling knows to scan. WMI subscriptions occupy a different substrate entirely: the CIM repository, with event-driven triggers (process creation, uptime thresholds, registry changes) that no boot-time scanner models, and a detection surface (Sysmon EID 19/20/21) that many default Sysmon configurations do not enable. The mechanism also doubles as an elevation primitive, executing as SYSTEM from an admin install, which none of T-017's layers provide on their own.

## Detection Considerations

- **Telemetry sources**: The material identifies Sysmon as the primary tool — "Sysmon can be configured to detect WMI attacks," with the configuration catching the Event Filters and the Event Consumers. The LGTM notes pin the dedicated event class: Sysmon EID 19 (WMI event filter activity), EID 20 (WMI event consumer registration), and EID 21 (filter-to-consumer binding). Process telemetry showing command lines spawned as children of WmiPrvSE.exe is a second signal, since `CommandLineEventConsumer` execution always lands in that provider host. ETW provider coverage for WMI subscription writes is not documented in the material.
- **Bypass options**: Training material does not discuss bypass options for this telemetry.
- **Residual artifacts**: The three CIM instances (filter, consumer, binding) persist in the repository until explicitly deleted — cleanup has distinct requirements from file- or registry-based persistence because all three objects must be removed and the binding dereferenced. The repository's physical backing lives under `%SystemRoot%\System32\wbem\Repository`. Each consumer execution leaves a WmiPrvSE.exe child process record in process-creation telemetry.

## Related Techniques

- **T-017 Five-Layer Persistence with Resilience Monitor** — WMI subscription is the event-driven persistence layer the five-layer suite does not contain; T-017's resilience-monitor model (periodic reinstallation of removed layers) applies equally to re-establishing a deleted filter/consumer/binding triad.
- **T-018 Edo Tensei (Polymorphic Resurrection Engine)** — Edo Tensei rotates one persistence layer per generation via its `EDO_PERSIST_METHOD` array; a WMI subscription layer would slot into that rotation as a generation fingerprint distinct from com_hijack, ntfs_ea, and schtask.

## References

- Atlas material: atlas-methodology-part4.md, atlas-methodology-part9.md, atlas-misc-part1.md, atlas-post-exploit-part1.md, atlas-post-exploit-part8.md, atlas-post-exploit-part15.md, atlas-post-exploit-part16.md
- MITRE ATT&CK: T1546.003 — Event Triggered Execution: Windows Management Instrumentation Event Subscription (https://attack.mitre.org/techniques/T1546/003/)
- LGTM notes: lgtm:wmi-event-subscription-persistence, lgtm:wmi-permanent-subscription-persistence-card, lgtm:wmi-event-subscription-persistence-card, lgtm:proposed-wmi-event-subscription-persistence, lgtm:proposed-wmi-persistence-suite, lgtm:wmi-permanent-subscription-card, lgtm:wmi-permanent-subscription-persistence
- Public references: SANS SEC670 Book 4 "Persistence: Die Another Day," WMI Event Subscriptions module and Lab 4.6 OhMyWMI (named in the atlas material)

## Source Reference

No current implementation. `dark_crystal/crowd/src/kaguya.rs` references the technique as a catalog entry (`wmic.exe` / `event_consumer` / T1546.003) but does not implement it. See atlas material and MITRE reference for public tooling.