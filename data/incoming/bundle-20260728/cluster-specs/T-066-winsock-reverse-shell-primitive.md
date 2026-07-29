# Cluster Spec — T-066: Winsock Reverse Shell via Handle Redirection

- **T-NNN ID**: `T-066`
- **Canonical name**: Winsock Reverse Shell via Handle Redirection
- **Proposed category**: `networking`
- **Proposed tier**: `B`
- **Priority**: low — Singleton, well-known pattern, basic tradecraft component.
- **would_relate_to**: ['T-022', 'T-023']

## Consolidated Description

Winsock reverse shell via WSAStartup(MAKEWORD(2,2)), socket creation, STARTUPINFOA population with hStdInput/hStdOutput/hStdError set to socket HANDLE, dwFlags=STARTF_USESTDHANDLES, and CreateProcessA execution. Standard pattern for early-stage interactive shell establishing persistent socket-based I/O stream.

## Member LGTM Notes (1)

### Note 1: Winsock + STARTUPINFOA Handle-Redirected Reverse Shell
- id: `lgtm:winsock-reverse-shell-primitive`
- origin: atlas-exploit-dev-part1
- would_relate_to: ['T-022', 'T-023']
- tags: ['reverse-shell', 'winsock', 'startupinfo', 'createprocess', 'initial-access']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part1
**Would relate to:** T-022, T-023
**Source units:** unit 14, unit 15

Units 14 and 15 together describe the canonical Winsock reverse shell: WSAStartup(MAKEWORD(2,2)) initializes Winsock, a socket is created, STARTUPINFOA is populated with hStdInput/hStdOutput/hStdError set to the socket HANDLE, dwFlags=STARTF_USESTDHANDLES, and CreateProcessA launches cmd.exe with bInheritHandles=TRUE. The vault's client_rust has TCP transport and a hidden VNC desktop but does not document this minimal reverse-shell primitive as a fallback or initial-access technique. Operators needing a tiny initial beacon before staging the full client could use this pattern; it would merit a small T-NNN entry or a note on the T-022 networking card.

---
Use `id: T-066`, canonical name above, and `member_notes: ['lgtm:winsock-reverse-shell-primitive']`.
Cross-reference `would_relate_to`: ['T-022', 'T-023'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.