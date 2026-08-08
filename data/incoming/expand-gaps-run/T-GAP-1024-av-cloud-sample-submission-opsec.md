---
id: T-GAP-1024
title: "AV/EDR Cloud Sample Submission OPSEC Discipline"
tier: "B"
category: "anti-analysis"
---

# AV/EDR Cloud Sample Submission OPSEC Discipline

## Description
Documents the cloud-sample-submission OPSEC risk: some AV/EDR vendors (notably Defender SmartScreen, CrowdStrike Falcon, SentinelOne) automatically submit unique binaries (those that match no known signature and trigger a behavioral alert) to vendor cloud analysis, potentially exposing "all tool capabilities or trade secrets" to the vendor. The operational response is egress discipline: cutting the implant off from internet except for the C2 channel, blocking the vendor's submission endpoints (defender-smartscreen-endpoint-*.cloud.app, falon-.crowdstrike.com) at the host firewall, and using only known-signed payload containers when possible. The vault has no card or cross-cutting metadata documenting this risk; should be referenced from T-016 (after bypass) and T-020 (pre-flight hygiene).


## Rationale
Two coverage-gap notes both surface the cloud-submission risk for unique binaries; cross-cutting operational discipline currently undocumented.

## References
- lgtm:av-cloud-sample-submission-opsec
- lgtm:cloud-sample-submission-egress-discipline
