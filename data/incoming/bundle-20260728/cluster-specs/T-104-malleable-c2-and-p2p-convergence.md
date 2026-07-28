# Cluster Spec — T-104: Malleable C2 Profile and P2P Listener Convergence

- **T-NNN ID**: `T-104`
- **Canonical name**: Malleable C2 Profile and P2P Listener Convergence
- **Proposed category**: `networking`
- **Proposed tier**: `A`
- **Priority**: medium — 2 member notes with cross-source convergence, confirms T-022 architecture against CRTO operational framing
- **would_relate_to**: ['T-022']

## Consolidated Description

CRTO describes malleable C2 profiles as the canonical HTTP-beacon traffic-shaping mechanism (Cobalt Strike's .profile files controlling User-Agent, URI, headers, jitter, GET/POST staging) and the vault's T-022 implements a malleable C2 profile engine (henge.rs). CRTO also documents P2P listeners chaining Beacons over TCP (tcp listener) and SMB named pipes (smb listener), plus a C2 Matrix spanning HTTP(S), DNS, TCP, and SMB transports. The convergence between CRTO's operational framing and the vault's T-022 implementation confirms malleable profiles and P2P chaining as the standard C2 architecture. The P2P chaining is operationally significant because it allows a beacon that cannot egress directly (e.g., isolated subnet) to chain through an intermediate beacon that has HTTP egress, using the SMB or TCP listener as the transport.


## Member LGTM Notes (2)

### Note 1: Malleable C2 Profile Cross-Source Convergence
- id: `lgtm:cross-source-malleable-c2-convergence`
- origin: atlas-post-exploit-part15
- would_relate_to: ['T-022']
- tags: ['malleable-c2', 'convergence', 'beacon', 'http-listener', 'tradecraft']

**Kind:** cross-source-convergence
**Origin:** atlas-post-exploit-part15
**Would relate to:** T-022
**Source units:** unit 37

CRTO describes malleable C2 profiles as the canonical HTTP-beacon traffic-shaping mechanism, and the vault's T-022 implements a malleable C2 profile engine (henge.rs). The convergence between CRTO operational framing and vault implementation indicates strong tradecraft consensus on profile-based C2 traffic shaping as a baseline capability. The vault could document the CRTO profile syntax lineage so operators familiar with Cobalt Strike profiles can map directly to henge configuration.

### Note 2: C2 Protocol and P2P Listener Convergence Across CRTO and SEC670
- id: `lgtm:cross-source-c2-protocol-convergence`
- origin: atlas-post-exploit-part16
- would_relate_to: ['T-022']
- tags: ['c2', 'p2p', 'cobalt-strike', 'convergence', 'networking', 'smb', 'tcp']

**Kind:** cross-source-convergence
**Origin:** atlas-post-exploit-part16
**Would relate to:** T-022
**Source units:** unit 2, unit 6, unit 8

CRTO documents Cobalt Strike P2P listeners chaining Beacons over TCP and SMB, plus a C2 Matrix spanning HTTP(S), DNS, TCP, and SMB. SEC670's course title explicitly covers Command and Control development. T-022 (Network Suite) implements SOCKS5, peer relay, HTTP poll, malleable C2, and multi-chain vault, which align with the same protocol and P2P topology space CRTO describes. The convergence indicates strong tradecraft consensus around multi-protocol C2 with P2P chaining that the vault captures partially but could expand with explicit TCP/SMB P2P listener equivalents.

---
Use `id: T-104`, canonical name above, and `member_notes: ['lgtm:cross-source-malleable-c2-convergence', 'lgtm:cross-source-c2-protocol-convergence']`.
Cross-reference `would_relate_to`: ['T-022'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.