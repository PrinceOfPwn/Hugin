# Cluster Spec — T-033: Named Pipes for C2 Communication and Implant IPC

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-033`
- **Canonical name**: Named Pipes for C2 Communication and Implant IPC
- **Proposed category**: `networking`
- **Proposed tier**: `A`
- **Priority**: medium — 3 member notes, distinct duplex transport mechanism, clear operational value.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-022', 'T-007']

## Consolidated Description (from clustering)

Windows named pipes as duplex IPC and C2 transport using CreateNamedPipe, ConnectNamedPipe, CreateFile, CallNamedPipe. Supports network accessibility via Server service (\\ComputerName\pipe\PipeName). Named pipes offer duplex, network-capable communication vs. anonymous pipes (local-only, one-way). Provides kernel-mode transport with implicit buffering.

## Member LGTM Notes (3)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Anonymous and Named Pipes as Implant IPC Transports
- **id**: `lgtm:pipe-ipc-for-staged-implant-communication`
- **origin**: atlas-exploit-dev-part9
- **source_units**: ['unit 36', 'unit 37', 'unit 38', 'unit 39', 'unit 40']
- **would_relate_to**: ['T-022', 'T-007']
- **tags**: ['ipc', 'pipes', 'networking', 'coverage-gap', 'c2-transport']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part9
**Would relate to:** T-022, T-007
**Source units:** unit 36, unit 37, unit 38, unit 39, unit 40

Units 36–40 cover CreatePipe, anonymous pipe semantics (local-only, one-way, parent/child), and named pipe semantics (duplex, network-capable). The vault's T-022 documents SOCKS5, HVNC, VNC/RFB, malleable C2, peer relay, HTTP poll, NT sockets, and BYOVD but does not document pipes as a local C2 transport between an injected implant and a host process, or as a parent/child communication channel for staged payloads. Pipes are a distinct capability — anonymous pipes specifically support parent/child shellcode handoff without named-pipe overhead, and named pipes support inter-host implant communication without a full networking stack. This deserves its own card or an explicit sub-section in T-022.

### Note 2: Named Pipe C2 Transport as Proposed Networking Layer
- **id**: `lgtm:named-pipe-c2-transport`
- **origin**: atlas-post-exploit-part10
- **source_units**: ['unit 15', 'unit 16', 'unit 17', 'unit 18', 'unit 19']
- **would_relate_to**: ['T-022']
- **tags**: ['named-pipes', 'c2-transport', 'networking', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part10
**Would relate to:** T-022
**Source units:** unit 15, unit 16, unit 17, unit 18, unit 19

SEC670 covers named pipes with duplex communication, network accessibility via the Server service, and \ComputerName\pipe\PipeName addressing. T-022's networking suite lists SOCKS5, HVNC, VNC/RFB, malleable C2, peer relay, HTTP poll, and NT sockets but does not include named pipe transport. Named pipes offer a legitimate-looking IPC channel that blends with Windows administrative traffic and is a documented C2 transport in operational red team tradecraft.

### Note 3: Named Pipe Duplex IPC Tradecraft
- **id**: `lgtm:named-pipe-ipc`
- **origin**: atlas-post-exploit-part5
- **source_units**: ['unit 1', 'unit 2', 'unit 3']
- **would_relate_to**: ['T-022']
- **tags**: ['ipc', 'named-pipe', 'networking', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part5
**Would relate to:** T-022
**Source units:** unit 1, unit 2, unit 3

SEC670 covers Windows named pipes as a duplex, network-capable IPC mechanism between unrelated processes, with CreateNamedPipe, ConnectNamedPipe, CreateFile, and CallNamedPipe as the API surface. The vault's T-022 Network Suite documents NT Sockets via the AFD driver but does not document named pipes as an alternative local or remote C2 channel. Named pipes are widely used by SMB-based lateral movement and C2 frameworks and would merit their own technique card or expansion of T-022.

---

## Your Task

Produce the technique card for **T-033** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-033` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-022', 'T-007'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:pipe-ipc-for-staged-implant-communication', 'lgtm:named-pipe-c2-transport', 'lgtm:named-pipe-ipc']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.