# Cluster Spec — T-103: WinINet vs WinHTTP for C2 Transport

- **T-NNN ID**: `T-103`
- **Canonical name**: WinINet vs WinHTTP for C2 Transport
- **Proposed category**: `networking`
- **Proposed tier**: `A`
- **Priority**: high — Two member notes from different batches; documents an alternative C2 transport API family with distinct detection surface.
- **would_relate_to**: ['T-022']

## Consolidated Description

SEC670 documents InternetConnect + HttpOpenRequest (WinINet, wininet.dll) as the
canonical HTTP C2 session API sequence, covering InternetOpen (session handle),
InternetConnect (server handle with port), HttpOpenRequest (request handle with method
and path), HttpSendRequest (transmit), and InternetReadFile (response body). The vault's
T-022 networking suite currently lists WinHTTP-based download (winhttp_dl.rs using
WinHttpOpen/WinHttpConnect/WinHttpOpenRequest/WinHttpSendRequest) as the staged download
mechanism. WinINet and WinHTTP are distinct API families: WinINet (wininet.dll) is the
higher-level API with built-in IE cache, cookie, and proxy support, historically used
by web browsers; WinHTTP (winhttp.dll) is the lighter API designed for server-side and
non-interactive HTTP. A card should document both API sequences side-by-side, the
detection-surface differential (WinINet hooks are common in EDRs; WinHTTP hooks less
so but increasing), and the operational tradeoffs (cache artifacts vs. stealth, cookie
persistence vs. statelessness, proxy behavior).


## Member LGTM Notes (2)

### Note 1: WinINet vs. WinHTTP for C2 Transport
- id: `lgtm:wininet-vs-winhttp-c2`
- origin: atlas-exploit-dev-part12
- would_relate_to: ['T-022']
- tags: ['wininet', 'winhttp', 'c2-transport', 'http', 'ftp', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part12
**Would relate to:** T-022
**Source units:** unit 39, unit 40

Units 39-40 cover the WinINet API family (InternetOpen/InternetConnect) for HTTP and FTP session management. The vault's T-022 networking card uses WinHTTP (winhttp_dl.rs) for staged download. WinINet and WinHTTP are distinct API surfaces with different monitoring profiles, dependency footprints, and capability sets (WinINet supports FTP and IE-compatible cookie/caching; WinHTTP is leaner). The vault does not currently document the WinINet alternative or the trade-offs between the two for C2 transport.

### Note 2: WinINet (InternetConnect/HttpOpenRequest) as C2 Transport
- id: `lgtm:wininet-vs-winhttp-transport-choice`
- origin: atlas-exploit-dev-part20
- would_relate_to: ['T-022']
- tags: ['wininet', 'winhttp', 'http-c2', 'transport', 'proxy']

**Kind:** cross-source-convergence
**Origin:** atlas-exploit-dev-part20
**Would relate to:** T-022
**Source units:** unit 22, unit 23

SEC670 documents InternetConnect + HttpOpenRequest as the canonical HTTP C2 session API sequence. The vault's T-022 networking suite currently lists WinHTTP-based download (winhttp_dl.rs) as the staged download mechanism but does not surface WinINet as an alternative transport with its own operational properties (automatic credential caching, IE proxy inheritance, user-agent pooling). WinINet and WinHTTP have divergent telemetry profiles and proxy handling behavior; surfacing this distinction in the graph would help operators select transports based on environment.

---
Use `id: T-103`, canonical name above, and `member_notes: ['lgtm:wininet-vs-winhttp-c2', 'lgtm:wininet-vs-winhttp-transport-choice']`.
Cross-reference `would_relate_to`: ['T-022'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.