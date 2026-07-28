# Cluster Spec — T-076: AV/EDR Cloud Sample Submission OPSEC Discipline

- **T-NNN ID**: `T-076`
- **Canonical name**: AV/EDR Cloud Sample Submission OPSEC Discipline
- **Proposed category**: `anti-analysis`
- **Proposed tier**: `B`
- **Priority**: medium — Two convergence notes; operational discipline rather than a discrete technique but cross-cuts evasion category.
- **would_relate_to**: ['T-016', 'T-020', 'T-021']

## Consolidated Description

Documents the cloud-sample-submission OPSEC risk: some AV/EDR vendors (notably Defender SmartScreen, CrowdStrike Falcon, SentinelOne) automatically submit unique binaries (those that match no known signature and trigger a behavioral alert) to vendor cloud analysis, potentially exposing "all tool capabilities or trade secrets" to the vendor. The operational response is egress discipline: cutting the implant off from internet except for the C2 channel, blocking the vendor's submission endpoints (defender-smartscreen-endpoint-*.cloud.app, falon-.crowdstrike.com) at the host firewall, and using only known-signed payload containers when possible. The vault has no card or cross-cutting metadata documenting this risk; should be referenced from T-016 (after bypass) and T-020 (pre-flight hygiene).


## Member LGTM Notes (2)

### Note 1: AV Cloud Sample Submission OPSEC
- id: `lgtm:av-cloud-sample-submission-opsec`
- origin: atlas-edr-evasion-part1
- would_relate_to: ['T-020', 'T-021']
- tags: ['opsec', 'av', 'cloud-submission', 'build-features', 'minimal-access']

**Kind:** coverage-gap
**Origin:** atlas-edr-evasion-part1
**Would relate to:** T-020, T-021
**Source units:** unit 11, unit 35, unit 36, unit 37

SEC670 covers the OPSEC risk that 'some AV solutions require' cloud submission of unique binaries, potentially exposing 'all tool capabilities' or 'trade secrets' to the vendor. The vault does not currently document the OPSEC tradeoff between full-featured and minimal-access builds against cloud-submission risk. This would merit cross-cutting metadata on build-feature gating decisions.

### Note 2: Cloud Sample Submission Risk as an Operational Discipline
- id: `lgtm:cloud-sample-submission-egress-discipline`
- origin: atlas-edr-evasion-part6
- would_relate_to: ['T-016', 'T-020']
- tags: ['cloud-submission', 'egress', 'evasion-tradeoff', 'signature-generation']

**Kind:** coverage-gap
**Origin:** atlas-edr-evasion-part6
**Would relate to:** T-016, T-020
**Source units:** unit 7

SEC670 unit 7 explicitly lists sample submission to AV/EDR cloud engines as the principal downside of operating custom bypasses, and frames cutting the implant off from internet as the precondition. The vault has no card or cross-cutting note on egress discipline for evasion R&D — when an operator iterates a custom bypass against a real EDR, network egress must be cut or the sample is uploaded and reverse-engineered into a new signature. This is operational tradecraft that exists between T-016 (evasion) and T-020 (anti-analysis) but neither card surfaces it.

---
Use `id: T-076`, canonical name above, and `member_notes: ['lgtm:av-cloud-sample-submission-opsec', 'lgtm:cloud-sample-submission-egress-discipline']`.
Cross-reference `would_relate_to`: ['T-016', 'T-020', 'T-021'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.