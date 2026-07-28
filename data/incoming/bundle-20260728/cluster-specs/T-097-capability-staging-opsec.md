# Cluster Spec — T-097: Capability Staging OPSEC — Reflective vs Disk

- **T-NNN ID**: `T-097`
- **Canonical name**: Capability Staging OPSEC — Reflective vs Disk
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `A`
- **Priority**: medium — 2 member notes with cross-source convergence across SEC670/MalDev/CRTO, documents an OPSEC decision framework
- **would_relate_to**: ['T-009', 'T-010', 'T-013', 'T-016', 'T-020']

## Consolidated Description

SEC670 frames dropping a capability to disk as risking both detection (file-system minifilter, Windows Defender real-time protection) and loss of capability (the staged binary is a recoverable artifact for defenders). The convergence across SEC670, MalDev Academy, and CRTO is that capabilities should prefer reflective loading (RtlImageNtHeader + manual PE mapping in-process) over disk staging on systems with unknown security products. The vault documents file-less execution techniques (T-013 in-memory, T-016 evasion) and artifact management (T-009, T-010) but does not frame the staging decision as an explicit OPSEC tradeoff with dual failure modes. SEC670's framing — detection AND capability loss as equivalent failures — changes the operator's risk calculus: a staged capability that is detected is not merely burned, it is actively counterproductive because it provides the defender with a recoverable sample.


## Member LGTM Notes (2)

### Note 1: Capability Staging to Disk — OPSEC Reasoning
- id: `lgtm:coverage-gap-payload-staging-opsec`
- origin: atlas-post-exploit-part15
- would_relate_to: ['T-009', 'T-010', 'T-013', 'T-016']
- tags: ['coverage-gap', 'opsec', 'disk-write-avoidance', 'payload-staging']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part15
**Would relate to:** T-009, T-010, T-013, T-016
**Source units:** unit 32, unit 33, unit 34

SEC670 frames dropping a capability to disk as risking both detection and loss of capability, framing them as equivalent operational failures. The vault documents file-less execution techniques (T-009 Ghosting, T-010 Herpaderping, T-013 reflective loader) but does not currently surface the explicit OPSEC rationale — why these techniques exist — in cross-cutting metadata. A graph edge or annotation documenting 'disk-write avoidance' as a unifying motivation across T-009, T-010, T-013, and T-016 would help operators select techniques by OPSEC intent rather than mechanism.

### Note 2: Capability Staging OpSec — Reflective vs Disk
- id: `lgtm:capability-staging-opsec-convergence`
- origin: atlas-post-exploit-part17
- would_relate_to: ['T-013', 'T-016', 'T-020']
- tags: ['opsec', 'reflective-loading', 'capability-staging', 'anti-analysis']

**Kind:** cross-source-convergence
**Origin:** atlas-post-exploit-part17
**Would relate to:** T-013, T-016, T-020
**Source units:** unit 9, unit 12, unit 13, unit 14, unit 15

SEC670 converges with MalDev Academy and CRTO tradecraft on the principle that capabilities should not be dropped to disk on systems with unknown security products, preferring in-memory reflective loading. The vault's T-020 Anti-Analysis card and T-013 reflective PE loader touch this principle but the operational decision tree — when reflective loading is required versus optional, what detection surface is traded — is not surfaced as a navigable concept.

---
Use `id: T-097`, canonical name above, and `member_notes: ['lgtm:coverage-gap-payload-staging-opsec', 'lgtm:capability-staging-opsec-convergence']`.
Cross-reference `would_relate_to`: ['T-009', 'T-010', 'T-013', 'T-016', 'T-020'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.