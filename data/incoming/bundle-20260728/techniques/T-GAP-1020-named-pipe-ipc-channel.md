---
id: T-GAP-1020
name: "Named Pipes as Implant IPC and C2 Relay Channel"
category: networking
tier: B
crate: none
source_file: none
mitre: T1082
mitre_secondary: []
tags: []
origin: lgtm-cluster
member_notes: ["lgtm:named-pipe-ipc-channel"]
---

# Named Pipes as Implant IPC and C2 Relay Channel

## Summary

Documents CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, bufSize, bufSize, 0, NULL) and ConnectNamedPipe(hPipe, &overlapped) as the canonical implant-IPC channel. Operationally valuable for relay chains: an implant on Host A can expose a named pipe `\\.\pipe\<name>` that a forwarder on Host B reads via a S4U/piggy-backed handle; the pipe impersonates the connecting client's token via ImpersonateNamedPipeClient (the pivot for many potato-class privilege escalations). Pairs with T-022 (NT sockets) for SMB relay tunnels and T-023 (peer relay) for implant-to-implant communication across a pivot host.


## Mechanism

CreateNamedPipeW(PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE) + ImpersonateNamedPipeClient for token capture

## Rationale

Single coverage-gap note naming named pipes as a distinct IPC/C2-relay channel currently absent from the vault despite touching T-022 and T-023.

## Related To

T-022, T-023
