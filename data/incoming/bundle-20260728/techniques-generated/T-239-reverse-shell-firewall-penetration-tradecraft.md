---
id: T-239
title: "Reverse Shell Firewall Penetration Tradecraft"
category: networking
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: reverse-shell-firewall-penetration
member_notes: ["lgtm:reverse-shell-vs-bind-shell-firewall-penetration"]
---

## Summary
This technique covers Reverse Shell Firewall Penetration Tradecraft, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
SEC670 states that reverse shells are mostly preferred over bind shells because they can poke through outbound-permissive firewalls and connect back to the C2 listener. The trade-off: bind shells require inbound port exposure on the target (often blocked by host firewall or egress filtering), while reverse shells originate from inside the network and only need outbound 80 / 443 / 53 (HTTP / HTTPS / DNS). This foundational tradecraft informs the design of T-022's networking stack and the operator's choice between connect-back and bind-listener code paths in an implant; the vault should document the trade-off matrix on T-022 and explicitly call out the Windows Firewall (netsh advfirewall) inbound block behavior that makes reverse shells operationally preferred.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// Outbound-only TCP connect-back from implant to C2 listener on port 80 / 443 / 53 (HTTP/S/DNS) vs bind-listen on arbitrary port requiring netsh advfirewall firewall add rule inbound ACL
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:reverse-shell-vs-bind-shell-firewall-penetration: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-019: Relates conceptually based on evidence.
- T-022: Relates conceptually based on evidence.

## References
- Internal vault documentation on Reverse Shell Firewall Penetration Tradecraft
