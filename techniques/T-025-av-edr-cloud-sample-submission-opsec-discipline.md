---
id: T-025
title: "AV/EDR Cloud Sample Submission OPSEC Discipline"
category: anti-analysis
tier: B
tags: [gap-card]
mitre: []
origin: manual-script
source_cluster: av-cloud-sample-submission-opsec
member_notes: ["lgtm:av-cloud-sample-submission-opsec","lgtm:cloud-sample-submission-egress-discipline"]
---

## Summary

Documents the cloud-sample-submission OPSEC risk: some AV/EDR vendors (notably Defender SmartScreen, CrowdStrike Falcon, SentinelOne) automatically submit unique binaries (those that match no known signature and trigger a behavioral alert) to vendor cloud analysis, potentially exposing "all tool capabilities or trade secrets" to the vendor. The operational response is egress discipline: cutting the implant off from internet except for the C2 channel, blocking the vendor's submission endpoints (defender-smartscreen-endpoint-*.cloud.app, falon-.crowdstrike.com) at the host firewall, and using only known-signed payload containers when possible. The vault has no card or cross-cutting metadata documenting this risk; should be referenced from T-016 (after bypass) and T-020 (pre-flight hygiene).


## Technical Deep Dive

Two coverage-gap notes both surface the cloud-submission risk for unique binaries; cross-cutting operational discipline currently undocumented.

## Evidence

- lgtm:av-cloud-sample-submission-opsec
- lgtm:cloud-sample-submission-egress-discipline

## Detection & Mitigation

N/A

## Related Techniques

N/A

## References

N/A
