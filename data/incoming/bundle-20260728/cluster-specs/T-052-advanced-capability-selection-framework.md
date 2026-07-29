# Cluster Spec — T-052: Advanced Capability Escalation Decision Framework

- **T-NNN ID**: `T-052`
- **Canonical name**: Advanced Capability Escalation Decision Framework
- **Proposed category**: `discovery`
- **Proposed tier**: `B`
- **Priority**: low — Singleton operational framework, conceptual rather than discrete technique.
- **would_relate_to**: ['T-007', 'T-016', 'T-022']

## Consolidated Description

Operational decision framework for technique escalation: triggers include (1) defender match (EDR detected), (2) tech-savvy admin (strong defenses), (3) stealth requirement (mission constraint), (4) basic technique failure. Escalation options include manual image loading, API hook reimplementation, direct syscalls, custom tooling. Provides structured methodology for technique selection based on operational context. Methodological rather than discrete technique.

## Member LGTM Notes (1)

### Note 1: Trigger-Based Selection Framework for Advanced Implant Techniques
- id: `lgtm:advanced-capability-selection-framework`
- origin: atlas-exploit-dev-part15
- would_relate_to: ['T-007', 'T-016', 'T-022']
- tags: ['operational', 'trigger-framework', 'technique-selection', 'tradecraft', 'escalation']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part15
**Would relate to:** T-007, T-016, T-022
**Source units:** unit 38

SEC670 provides a structured framework for when to escalate from basic to advanced capabilities: four explicit triggers (defender match, tech-savvy admin, stealth requirement, basic technique failure) and four escalation options (manual image loading, API hook reimplementation, C2 callbacks, shellcode execution). The vault has no card documenting this selection logic — each T-NNN exists in isolation without operational guidance on when to prefer one over another. A trigger-to-technique mapping card would help operators navigate the vault when planning an engagement where the defender posture is unknown or shifts mid-engagement.

---
Use `id: T-052`, canonical name above, and `member_notes: ['lgtm:advanced-capability-selection-framework']`.
Cross-reference `would_relate_to`: ['T-007', 'T-016', 'T-022'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.