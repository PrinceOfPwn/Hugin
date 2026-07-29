---
id: T-104
name: Malleable C2 Profile and P2P Listener Convergence
category: networking
tier: A
crate: client_rust
source_file: none
mitre: T1071.001
tags: [malleable-c2, p2p, cobalt-strike, beacon, smb, tcp, c2-matrix, traffic-shaping, profile, peer-relay]
origin: atlas-synthesis
member_notes: ['lgtm:cross-source-malleable-c2-convergence', 'lgtm:cross-source-c2-protocol-convergence']
---

# Malleable C2 Profile and P2P Listener Convergence — Traffic Shaping and Peer-to-Peer C2 Chaining

## Summary

Malleable C2 profiles are configuration files that shape HTTP beacon traffic to blend with legitimate web application patterns, controlling User-Agent, URI paths, HTTP headers, GET/POST staging, and jitter timing. The CRTO curriculum documents Cobalt Strike's `.profile` files as the canonical implementation, and the HUGIN vault implements a malleable C2 profile engine in `client_rust/src/henge.rs`. CRTO also documents P2P listener chaining where Beacons communicate over TCP listeners and SMB named pipe listeners, allowing an isolated beacon without direct HTTP egress to chain through an intermediate beacon that has network access. The HUGIN vault implements peer relay networking in `juubi.rs`, multi-chain vault in `rikudo.rs`, and SOCKS5 proxy in `kamui.rs`. The convergence between CRTO's operational framing and the vault's implementation confirms malleable profiles and P2P chaining as the standard multi-protocol C2 architecture.

## Mechanism

1. **Malleable C2 profile configuration**: A malleable profile defines HTTP transaction properties for each beacon communication type. The profile syntax controls:
   - **User-Agent**: The `User-Agent` header value, typically set to match a common browser string (e.g., `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`).
   - **URI structure**: The request URI and any sub-URI paths for staging, task retrieval, and result posting. URIs are designed to match the target environment's expected web application paths (e.g., `/api/v2/reports`, `/images/thumbnails`).
   - **HTTP headers**: Custom headers that carry beacon data. The profile can specify that the beacon ID is encoded in a `Cookie` header, `X-Forwarded-For` header, or custom header name.
   - **GET/POST staging**: Whether the initial beacon stage download uses GET (metadata in URI) or POST (metadata in body). The profile specifies the `http-get` and `http-post` blocks with distinct URI, header, and body parameter configurations.
   - **Jitter**: Random variation in beacon check-in interval (e.g., 10% jitter on a 60-second cycle means check-ins occur between 54 and 66 seconds apart) to avoid fixed-interval detection by network behavioral analytics.
   - **Data transformation**: The profile can specify Base64, XOR, or custom encoding for beacon payloads embedded in HTTP traffic.

2. **HTTP beacon egress**: The beacon polls its C2 server at the configured interval with jitter. Each poll is an HTTP(S) request whose appearance is fully controlled by the malleable profile. The server responds with tasking (commands to execute) or an empty response (no tasks).

3. **TCP P2P listener**: A beacon that has established HTTP egress can open a TCP listener on a port. Other beacons on the same internal network that cannot reach the internet connect to this TCP listener. The TCP listener beacon acts as a relay: it receives tasking from the HTTP C2 server and forwards it over the TCP connection to the chained beacon. Results flow back in reverse.

4. **SMB named pipe P2P listener**: An alternative to TCP, the SMB listener creates a named pipe (e.g., `\\.\pipe\msagent_011`). Beacons connect to this pipe via `CreateFile("\\\\target\\pipe\\msagent_011")` and exchange data over the pipe. SMB P2P is useful in environments where TCP connections between hosts are blocked by host-based firewalls but SMB (port 445) is allowed for file sharing.

5. **C2 Matrix**: The full set of transport options forms a matrix:
   - **HTTP(S)**: Direct egress via HTTP or HTTPS to a C2 server. Subject to network proxy, IDS, and web filtering.
   - **DNS**: Beaconing via DNS queries (A, TXT, AAAA records). Slow bandwidth but effective in environments where only DNS is allowed outbound.
   - **TCP**: P2P relay between beacons on the internal network.
   - **SMB**: P2P relay via named pipes over the SMB protocol.

6. **P2P chain topology**: In a segmented network, the topology might be: Internet-facing beacon (HTTP egress) ← TCP listener → Internal beacon A ← SMB listener → Isolated beacon B. Tasking flows: C2 server → HTTP → Internet beacon → TCP → Internal beacon A → SMB → Isolated beacon B. Results flow in reverse. Each hop must support the beacon protocol.

## OS Internals Context

Named pipes in Windows are implemented by theNamed Pipe File System driver (`npfs.sys`). A named pipe server creates a pipe via `CreateNamedPipeW` (which calls `NtCreateNamedPipeFile`), and a client connects via `CreateFileW` with the pipe path format `\\server\pipe\pipename`. The SMB redirector (`mrxsmb.sys` / `mrxsmb20.sys`) transparently routes named pipe access to remote hosts over SMB (port 445). When a beacon connects to `\\target\pipe\msagent_011`, the SMB redirector establishes an SMB session with the target host and opens the named pipe. Data written to the pipe via `WriteFile` / `NtWriteFile` is transmitted over the SMB session, and data read via `ReadFile` / `NtReadFile` is received from the SMB session.

TCP listeners use the Winsock API (`WSASocket` / `bind` / `listen` / `accept`). The underlying kernel transport is the TCP/IP driver (`tcpip.sys`). TCP connections between hosts on the same subnet do not traverse a proxy or gateway — they are direct Layer 3 connections subject only to host-based firewall rules (Windows Filtering Platform, `netsh advfirewall`).

The HUGIN vault's `henge.rs` (listed in the file manifest as the malleable C2 profile engine under T-022) implements the profile parsing and HTTP traffic shaping. The `juubi.rs` peer relay module and `rikudo.rs` multi-chain vault implement the P2P chaining topology. The `kamui.rs` SOCKS5 proxy provides additional transport flexibility for relayed connections. These source files were not provided for verification in this batch — the file manifest listing serves as the reference.

## Key Implementation Details

The HUGIN vault file manifest references the following implementation files under `client_rust/`:
- `src/henge.rs` — listed as "Malleable C2 profile engine" mapped to T-022 (Network Suite). This file was not provided for source verification in this batch. The implementation is expected to parse malleable profile configuration (User-Agent, URI, headers, jitter) and shape HTTP request/response cycles accordingly.
- `src/juubi.rs` — listed as "Peer relay network" mapped to T-022. Implements the P2P relay topology.
- `src/juubi_chain.rs` — listed as "Peer relay chain management" mapped to T-022. Manages multi-hop relay chains.
- `src/rikudo.rs` — listed as "Multi-chain vault" mapped to T-022. Implements the multi-protocol C2 matrix (HTTP, TCP, SMB).
- `src/kamui.rs` — listed as "SOCKS5 proxy" mapped to T-022. Provides SOCKS5 proxy capability for relayed traffic.
- `src/http_poll_transport.rs` — listed as "HTTP long-poll transport" mapped to T-022. Implements HTTP long-polling for beacon check-in.

These files were not provided for verification. The cluster spec confirms convergence between CRTO's operational framing (malleable profiles, P2P listeners, C2 matrix) and the vault's implementation architecture.

## Why It Matters

The convergence between CRTO operational tradecraft and the HUGIN vault implementation confirms that malleable C2 profiles and P2P listener chaining are the standard C2 architecture for multi-protocol command and control. The P2P chaining capability is operationally significant because it allows a beacon that cannot egress directly (e.g., on an isolated subnet behind network segmentation) to chain through an intermediate beacon that has HTTP egress, using the SMB or TCP listener as the transport. Without P2P chaining, operators would need to establish independent C2 channels for every beacon, increasing the network footprint and detection surface. The malleable profile capability is the baseline for HTTP C2 traffic shaping — without it, beacon HTTP traffic has fixed URIs and headers that are trivially detected by network IDS signatures.

## Detection Considerations

- **Telemetry sources**: HTTP C2 traffic is monitored by network IDS/IPS (Snort, Suricata, Zeek), web proxies (Zscaler, BlueCoat), and EDR network inspection modules. DNS-based C2 is monitored by DNS analytics (RSA NetWitness, Cisco Umbrella). SMB named pipe connections are logged by Sysmon Event ID 17 (NamedPipeCreated) and Event ID 18 (NamedPipeConnected). TCP P2P connections between internal hosts may be detected by network flow analysis (fixed-interval connections, unusual port usage).
- **Bypass options**: Malleable profiles shape HTTP traffic to match legitimate web application patterns, defeating signature-based IDS. Jitter randomization defeats fixed-interval beaconing detection. SMB named pipe P2P uses the standard SMB protocol on port 445, which is expected traffic in enterprise environments. TCP P2P can use standard ports (80, 443, 8080) to blend with HTTP traffic.
- **Residual artifacts**: HTTP C2 leaves server-side access logs and proxy cache entries. SMB named pipe P2P leaves named pipe handles (visible via `GetNamedPipeInfo` / `NtQueryInformationFile` with `FilePipeInformation`). TCP connections leave socket entries visible in `netstat` and `GetExtendedTcpTable`.

## Related Techniques

- **T-022 Network Suite** — vault networking card implementing malleable C2 (henge.rs), peer relay (juubi.rs), multi-chain vault (rikudo.rs), and SOCKS5 proxy (kamui.rs)
- **T-033 Named Pipes for C2 Communication** — named pipe IPC mechanism used by SMB P2P listeners

## References

- Atlas material: atlas-post-exploit-part15 (unit 37), atlas-post-exploit-part16 (units 2, 6, 8)
- MITRE ATT&CK: T1071.001 (Web Protocols) — https://attack.mitre.org/techniques/T1071/001
- LGTM notes: lgtm:cross-source-malleable-c2-convergence, lgtm:cross-source-c2-protocol-convergence

## Source Reference

`client_rust/src/henge.rs` (malleable C2 engine), `client_rust/src/juubi.rs` (peer relay), `client_rust/src/rikudo.rs` (multi-chain vault), `client_rust/src/kamui.rs` (SOCKS5 proxy) — listed in vault file manifest mapped to T-022 but not provided for source verification in this batch.