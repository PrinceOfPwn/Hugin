# Cluster Spec — T-061: Registry Watchdog for Situational Awareness and AV Detection

- **T-NNN ID**: `T-061`
- **Canonical name**: Registry Watchdog for Situational Awareness and AV Detection
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `B`
- **Priority**: low — Singleton situational-awareness technique; narrow applicability (AV/EDR detection).
- **would_relate_to**: ['T-017', 'T-020']

## Consolidated Description

Registry watchdog via RegNotifyChangeKey to monitor HKLM\SOFTWARE\Microsoft for AV product installation in real time. REG_NOTIFY_THREAD_AGNOSTIC enables thread-persistent notifications. Operators detect AV/EDR product installation without polling, informing technique escalation decisions.

## Member LGTM Notes (1)

### Note 1: Registry Watchdog for Situational Awareness
- id: `lgtm:registry-watchdog-situational-awareness`
- origin: atlas-edr-evasion-part1
- would_relate_to: ['T-017', 'T-020']
- tags: ['registry', 'situational-awareness', 'regnotifychangekey', 'watchdog']

**Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part1
**Would relate to:** T-017, T-020
**Source units:** unit 26, unit 27

SEC670 dedicates material to RegNotifyChangeKey and the REG_NOTIFY_CHANGE_* filter set as a watchdog primitive — detecting AV product installation in real time without polling, with REG_NOTIFY_THREAD_AGNOSTIC enabling thread-persistent notifications. The vault has no technique card for registry-driven situational awareness; this would fit as a distinct T-NNN since it is a reusable primitive across persistence, evasion, and self-deletion chains.

---
Use `id: T-061`, canonical name above, and `member_notes: ['lgtm:registry-watchdog-situational-awareness']`.
Cross-reference `would_relate_to`: ['T-017', 'T-020'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.