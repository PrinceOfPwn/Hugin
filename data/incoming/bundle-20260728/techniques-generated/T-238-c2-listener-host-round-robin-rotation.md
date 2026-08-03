---
id: T-238
title: "C2 Listener Host Round-Robin Rotation"
category: networking
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: c2-listener-host-rotation
member_notes: ["lgtm:host-rotation-strategy-c2"]
---

## Summary
This technique covers C2 Listener Host Round-Robin Rotation, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
CRTO documents Cobalt Strike HTTP listener configuration with round-robin host rotation across multiple HTTP hosts on port 80, providing C2 infrastructure resilience against sinkhole, domain takedown, or single-host seizure. The listener definition accepts a comma-separated Host field and cycles through hosts at the HTTP transport layer, with the teamserver distributing Beacons across the listed hosts during profile generation. The vault's T-022 networking suite does not document this operational pattern for infrastructure redundancy; a card should cover listener HA configuration, the C2-Profile Malleable C2 host rotation syntax, and the operator-side Beacon retry logic that handles per-host failure.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// Cobalt Strike listener 'Host' field accepting comma-separated HTTP[S] hosts for round-robin rotation on port 80 / 443, plus Malleable C2 profile http-get / http-post uri-append syntax
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:host-rotation-strategy-c2: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-022: Relates conceptually based on evidence.

## References
- Internal vault documentation on C2 Listener Host Round-Robin Rotation
