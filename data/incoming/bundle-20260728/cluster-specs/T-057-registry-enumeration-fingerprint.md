# Cluster Spec — T-057: Registry Enumeration Pattern: COM Hijack Discovery and Autostart Targeting

- **T-NNN ID**: `T-057`
- **Canonical name**: Registry Enumeration Pattern: COM Hijack Discovery and Autostart Targeting
- **Proposed category**: `discovery`
- **Proposed tier**: `B`
- **Priority**: low — Singleton pattern, foundational but not standalone offensive capability.
- **would_relate_to**: ['T-017', 'T-023', 'T-020']

## Consolidated Description

Standard registry enumeration pattern for vulnerability discovery: RegOpenKeyExW opens key, RegQueryInfoKey retrieves metadata, RegEnumValue iterates through values with LSTATUS checking and ERROR_NO_MORE_ITEMS termination. Pattern foundational for COM-hijack target discovery (T-017), autostart location enumeration, and registry-based inventory. Distinct from single-key lookups.

## Member LGTM Notes (1)

### Note 1: RegOpenKeyExW + RegQueryInfoKey + RegEnumValue Fingerprint
- id: `lgtm:registry-enumeration-fingerprint`
- origin: atlas-binary-analysis-part6
- would_relate_to: ['T-017', 'T-023', 'T-020']
- tags: ['registry', 'regopenkeyex', 'regenumvalue', 'recon', 'fingerprint', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part6
**Would relate to:** T-017, T-023, T-020
**Source units:** unit 21, unit 35, unit 36, unit 37

The unit documents the canonical three-call registry enumeration pattern with LSTATUS return checking and ERROR_NO_MORE_ITEMS loop termination. This pattern is the operational basis for COM-hijack target discovery (T-017), autostart enumeration (T-017), and recon collection (T-023). The vault does not have a card documenting the pattern itself as a reusable recon primitive; a proposed card would consolidate the call sequence, error-handling contract, and detection fingerprint.

---
Use `id: T-057`, canonical name above, and `member_notes: ['lgtm:registry-enumeration-fingerprint']`.
Cross-reference `would_relate_to`: ['T-017', 'T-023', 'T-020'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.