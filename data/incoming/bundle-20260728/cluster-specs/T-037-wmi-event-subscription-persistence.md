# Cluster Spec — T-037: WMI Permanent Event Subscription Persistence

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-037`
- **Canonical name**: WMI Permanent Event Subscription Persistence
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: high — 9 member notes (strongest signal), distinct CIM-repository mechanism, multiple event-trigger variants.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-017', 'T-018']

## Consolidated Description (from clustering)

WMI permanent event subscriptions via __EventFilter (event definition), CommandLineEventConsumer, and __FilterToConsumerBinding (association). Subscriptions survive reboots and execute within WmiPrvSE.exe context. Extrinsic events (polling) vs. intrinsic events (fire immediately) provide different triggering profiles.

## Member LGTM Notes (7)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: WMI Permanent Event Subscription Persistence
- **id**: `lgtm:wmi-event-subscription-persistence`
- **origin**: atlas-methodology-part4
- **source_units**: ['unit 27', 'unit 28', 'unit 29', 'unit 30', 'unit 31']
- **would_relate_to**: ['T-017', 'T-023']
- **tags**: ['persistence', 'wmi', 'cim', 'event-subscription', 'sysmon-19-20-21', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-methodology-part4
**Would relate to:** T-017, T-023
**Source units:** unit 27, unit 28, unit 29, unit 30, unit 31

SEC670 Section 4 lists WMI Event Subscriptions as a distinct persistence mechanism, and units 27-30 provide the CIM/WMI schema background (Core/Common/Extended classes, CIM_ and Win32_ prefixes) that the technique operates on. The vault's T-017 card does not document WMI permanent subscriptions (the __EventFilter / __EventConsumer / __FilterToConsumerBinding triad). T-023 includes WMI execution as a client capability, but not the permanent subscription persistence layer. This deserves a separate persistence T-NNN given the distinct object model, installation path, and Sysmon 19/20/21 detection surface.

### Note 2: WMI Permanent Subscription as a Standalone Persistence Technique
- **id**: `lgtm:wmi-permanent-subscription-persistence-card`
- **origin**: atlas-post-exploit-part16
- **source_units**: ['unit 27', 'unit 28', 'unit 29', 'unit 30', 'unit 31', 'unit 32', 'unit 33']
- **would_relate_to**: ['T-017']
- **tags**: ['wmi', 'persistence', 'filter-to-consumer-binding', 'coverage-gap', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part16
**Would relate to:** T-017
**Source units:** unit 27, unit 28, unit 29, unit 30, unit 31, unit 32, unit 33

SEC670 Book 4 devotes a module to WMI permanent subscriptions (EventFilter + EventConsumer + FilterToConsumerBinding) for persistence and elevation, including a dedicated lab (OhMyWMI) and explicit discussion of extrinsic vs intrinsic event types and their polling requirements. T-017 currently lists COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist — WMI subscription is absent. It deserves graph presence as a distinct persistence layer because it executes from the WMI repository without a scheduled-task or registry entry, has different detection surface (Sysmon WMI config), and survives reboot differently from schtask.

### Note 3: WMI Event Subscription Persistence as Standalone Card
- **id**: `lgtm:wmi-event-subscription-persistence-card`
- **origin**: atlas-methodology-part9
- **source_units**: ['unit 19', 'unit 20', 'unit 21']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'wmi', 'event-subscription', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-methodology-part9
**Would relate to:** T-017
**Source units:** unit 19, unit 20, unit 21

SEC670 Section 4 dedicates a persistence module to WMI Event Subscriptions (EventFilter + EventConsumer + FilterToConsumerBinding). T-017 currently covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not list WMI Event Subscription as a documented persistence layer. WMI Event Subscription is operationally distinct from these — it requires WMI namespace write access, has unique detection surface (Sysmon EID 19/20/21), and supports event-triggered execution rather than boot/logon-triggered. Deserves standalone treatment within or alongside T-017.

### Note 4: WMI Event Subscription Persistence
- **id**: `lgtm:proposed-wmi-event-subscription-persistence`
- **origin**: atlas-misc-part1
- **source_units**: ['unit 1', 'unit 2', 'unit 7', 'unit 26']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'wmi', 'event-subscription', 'proposed']

**Kind:** proposed-technique
**Origin:** atlas-misc-part1
**Would relate to:** T-017
**Source units:** unit 1, unit 2, unit 7, unit 26

SEC670 Book 4 roadmap lists WMI Event Subscriptions as a persistence module. WMI event subscriptions execute attacker actions on system events (process creation, logon, timed) within WmiPrvSE.exe context, surviving reboots without typical filesystem or registry persistence-scan coverage. The vault's T-017 does not document WMI persistence. Would extend T-017's persistence surface.

### Note 5: WMI Permanent Event Subscription Persistence
- **id**: `lgtm:proposed-wmi-persistence-suite`
- **origin**: atlas-post-exploit-part15
- **source_units**: ['unit 16', 'unit 17', 'unit 18', 'unit 19', 'unit 20', 'unit 21', 'unit 22', 'unit 23']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'wmi', 'event-subscription', 'filter-to-consumer-binding', 'cim-repository']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part15
**Would relate to:** T-017
**Source units:** unit 16, unit 17, unit 18, unit 19, unit 20, unit 21, unit 22, unit 23

SEC670 covers WMI persistence via the EventFilter / EventConsumer / FilterToConsumerBinding trio, distinguishing extrinsic events (require polling) from intrinsic events (fire immediately). The vault's T-017 does not include WMI permanent subscriptions. This deserves its own card because WMI persistence is file-less (lives in the CIM repository), survives reboot, supports arbitrary trigger conditions, and has its own Sysmon event class (EID 19/20/21) for detection.

### Note 6: WMI Permanent Event Subscription as a Standalone Technique
- **id**: `lgtm:wmi-permanent-subscription-card`
- **origin**: atlas-post-exploit-part1
- **source_units**: ['unit 7', 'unit 36', 'unit 37']
- **would_relate_to**: ['T-017', 'T-018']
- **tags**: ['persistence', 'wmi', 'event-subscription', 'proposed-card']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part1
**Would relate to:** T-017, T-018
**Source units:** unit 7, unit 36, unit 37

SEC670 Book 4 dedicates a full module and Lab 4.6 OhMyWMI to permanent WMI subscriptions as a persistence vector combining __EventFilter, __EventConsumer, and __FilterToConsumerBinding in the CIM repository. The vault's T-017 covers schtask, COM hijack, NTFS EA, TLS callback, and PhantomPersist but does not surface WMI subscription as its own technique card. Because the mechanism has distinct detection surface (Sysmon EID 19/20/21), distinct persistence properties (survives reboot, not on disk as a script file), and distinct cleanup requirements, it merits its own T-NNN card rather than remaining implicit under T-017.

### Note 7: WMI Permanent Event Subscription Persistence
- **id**: `lgtm:wmi-permanent-subscription-persistence`
- **origin**: atlas-post-exploit-part8
- **source_units**: ['unit 1', 'unit 2', 'unit 3', 'unit 5', 'unit 6', 'unit 9', 'unit 11', 'unit 12', 'unit 15', 'unit 16']
- **would_relate_to**: ['T-017']
- **tags**: ['wmi', 'persistence', 'event-subscription', 'filter-to-consumer-binding', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part8
**Would relate to:** T-017
**Source units:** unit 1, unit 2, unit 3, unit 5, unit 6, unit 9, unit 11, unit 12, unit 15, unit 16

SEC670 dedicates extensive material to WMI permanent event subscriptions as a persistence mechanism using __EventFilter, CommandLineEventConsumer, and FilterToConsumerBinding. The vault's T-017 covers five persistence layers (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) but does not include WMI subscription persistence. This would merit addition to T-017 or a standalone card because WMI subscriptions persist across reboots via the WMI repository and support event-driven triggering (process creation, system uptime, registry changes).

---

## Your Task

Produce the technique card for **T-037** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-037` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-017', 'T-018'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:wmi-event-subscription-persistence', 'lgtm:wmi-permanent-subscription-persistence-card', 'lgtm:wmi-event-subscription-persistence-card', 'lgtm:proposed-wmi-event-subscription-persistence', 'lgtm:proposed-wmi-persistence-suite', 'lgtm:wmi-permanent-subscription-card', 'lgtm:wmi-permanent-subscription-persistence']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.