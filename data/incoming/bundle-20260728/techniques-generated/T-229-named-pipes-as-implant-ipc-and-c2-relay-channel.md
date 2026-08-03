---
id: T-229
title: "Named Pipes as Implant IPC and C2 Relay Channel"
category: networking
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: named-pipe-ipc-channel
member_notes: ["lgtm:named-pipe-ipc-channel"]
---

## Summary
This technique covers Named Pipes as Implant IPC and C2 Relay Channel, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, bufSize, bufSize, 0, NULL) and ConnectNamedPipe(hPipe, &overlapped) as the canonical implant-IPC channel. Operationally valuable for relay chains: an implant on Host A can expose a named pipe `\\.\pipe\<name>` that a forwarder on Host B reads via a S4U/piggy-backed handle; the pipe impersonates the connecting client's token via ImpersonateNamedPipeClient (the pivot for many potato-class privilege escalations). Pairs with T-022 (NT sockets) for SMB relay tunnels and T-023 (peer relay) for implant-to-implant communication across a pivot host.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// CreateNamedPipeW(PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE) + ImpersonateNamedPipeClient for token capture
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:named-pipe-ipc-channel: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-022: Relates conceptually based on evidence.
- T-023: Relates conceptually based on evidence.

## References
- Internal vault documentation on Named Pipes as Implant IPC and C2 Relay Channel
