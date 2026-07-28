---
id: T-103
name: WinINet vs WinHTTP for C2 Transport
category: networking
tier: A
crate: dark_crystal
source_file: dark_crystal/crowd/src/winhttp_dl.rs
mitre: T1071.001
tags: [wininet, winhttp, c2-transport, http, proxy, cookie, cache, api-selection, ie-cache, user-agent]
origin: atlas-synthesis
member_notes: ['lgtm:wininet-vs-winhttp-c2', 'lgtm:wininet-vs-winhttp-transport-choice']
---

# WinINet vs WinHTTP for C2 Transport — API Family Selection for HTTP C2 Channels

## Summary

WinINet (`wininet.dll`) and WinHTTP (`winhttp.dll`) are two distinct Windows API families for HTTP communication, each with different monitoring profiles, dependency footprints, and capability sets. WinINet is the higher-level API with built-in IE cache, cookie persistence, and proxy inheritance from the system's Internet Explorer settings; WinHTTP is the lighter API designed for server-side and non-interactive HTTP with explicit proxy configuration. The HUGIN source implements WinHTTP in `winhttp_dl.rs` for staged payload download, dynamically loading `winhttp.dll` via `LoadLibraryA` to avoid static IAT detection. The selection between the two API families determines the EDR telemetry surface (WinINet hooks are common, WinHTTP hooks less so but increasing), proxy handling behavior, and whether cache artifacts are left on disk.

## Mechanism

1. **WinINet API sequence** (documented in SEC670 as the canonical HTTP C2 session pattern):
   - `InternetOpen(lpszAgent, dwAccessType, lpszProxyName, lpszProxyBypass, dwFlags)` — creates a session handle. The `lpszAgent` parameter sets the User-Agent string. `dwAccessType` determines proxy behavior: `INTERNET_OPEN_TYPE_PRECONFIG` inherits IE proxy settings, `INTERNET_OPEN_TYPE_DIRECT` bypasses proxies.
   - `InternetConnect(hSession, lpszServerName, nServerPort, lpszUsername, lpszPassword, dwService, dwFlags, dwContext)` — creates a server connection handle. `dwService` is set to `INTERNET_SERVICE_HTTP` for HTTP or `INTERNET_SERVICE_FTP` for FTP.
   - `HttpOpenRequest(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext)` — creates a request handle. `lpszVerb` is "GET" or "POST". `dwFlags` can include `INTERNET_FLAG_SECURE` for HTTPS, `INTERNET_FLAG_NO_CACHE_WRITE` to suppress caching.
   - `HttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)` — transmits the request. Headers and body are sent here.
   - `InternetReadFile(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead)` — reads the response body in chunks.

2. **WinHTTP API sequence** (implemented in HUGIN's `winhttp_dl.rs`):
   - `WinHttpOpen(pszUserAgent, dwAccessType, pszProxyName, pszProxyBypass, dwFlags)` — creates a session handle. The HUGIN implementation uses User-Agent `"Microsoft-CryptoAPI/10.0"` to masquerade as Windows Update traffic.
   - `WinHttpConnect(hSession, pszServerName, nServerPort, dwReserved)` — creates a connection handle.
   - `WinHttpOpenRequest(hConnect, pszVerb, pszObjectName, pszVersion, pszReferrer, ppwszAcceptTypes, dwFlags)` — creates a request handle. The HUGIN implementation uses `WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE`.
   - `WinHttpSendRequest(hRequest, pszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext)` — sends the request.
   - `WinHttpReceiveResponse(hRequest, lpReserved)` — waits for the response headers.
   - `WinHttpQueryDataAvailable(hRequest, lpdwBytesAvailable)` — checks how much response data is available.
   - `WinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwBytesRead)` — reads response body in chunks.

3. The HUGIN `winhttp_dl.rs` implementation dynamically resolves all WinHTTP function pointers at runtime via `LoadLibraryA("winhttp.dll")` and `GetProcAddress`. This avoids static IAT entries for WinHTTP functions, defeating IAT-based detection that flags processes importing `winhttp.dll`.

4. The implementation validates each downloaded chunk's SHA-256 hash against a pre-computed manifest, aborting on mismatch. Downloaded data is assembled into an `NtVecBuf` that attempts large-page allocation via `NtAllocateVirtualMemory` with `MEM_LARGE_PAGES` when `SeLockMemoryPrivilege` is available, falling back to a standard `Vec<u8>`.

## OS Internals Context

WinINet (`wininet.dll`) is implemented on top of WinHTTP internally but adds a caching layer, cookie management, and proxy auto-configuration (PAC) script evaluation. The IE cache is stored in the `%LOCALAPPDATA%\Microsoft\Windows\INetCache` directory structure, with cache entries indexed by URL hash in the `index.dat` file. When `InternetReadFile` reads a response, WinINet may serve cached content if the cache entry has not expired (controlled by HTTP `Cache-Control` and `Expires` headers). This caching behavior can cause a C2 implant to receive stale responses if the cache is not explicitly bypassed with `INTERNET_FLAG_NO_CACHE_WRITE` or `INTERNET_FLAG_RELOAD` flags.

WinHTTP (`winhttp.dll`) does not implement a cache. Every request goes to the network (or proxy). WinHTTP's proxy configuration is set via `WinHttpOpen` parameters or `WinHttpSetOption` with `WINHTTP_OPTION_PROXY` — it does not inherit IE proxy settings unless the application explicitly queries IE configuration via `WinHttpGetIEProxyConfigurationForCurrentUser` (available on Windows 8.1+). WinHTTP is used by Windows Update (`wuaueng.dll`), Windows Defender (`MsMpEng.exe`), and other system services — traffic using the `Microsoft-CryptoAPI/10.0` User-Agent blends with legitimate Windows Update client traffic.

Both APIs ultimately use `Winsock` (via `ws2_32.dll`) for TCP transport. The kernel-level network stack (AFD driver, TCP/IP driver) is shared. ETW providers for HTTP traffic include `Microsoft-Windows-WinINet` (WinINet) and `Microsoft-Windows-WinHTTP` (WinHTTP) — these providers emit events for request/response cycles including URL, status code, and byte counts. An EDR that subscribes to either ETW provider can monitor all HTTP traffic through that API family.

## Key Implementation Details

The HUGIN source file `dark_crystal/crowd/src/winhttp_dl.rs` implements the WinHTTP transport. Key implementation choices:

- **Dynamic loading**: The `load_winhttp()` function uses `LoadLibraryA("winhttp.dll")` and `GetProcAddress` to resolve all WinHTTP function pointers at runtime. The `WinHttpFns` struct holds 8 function pointers (`open`, `connect`, `open_request`, `send`, `recv_response`, `query_avail`, `read`, `close`). This avoids static IAT entries for WinHTTP.
- **User-Agent camouflage**: `pszUserAgent` is set to `"Microsoft-CryptoAPI/10.0"`, matching the User-Agent used by Windows Update client. This blends C2 traffic with legitimate Windows Update polling.
- **HTTPS enforcement**: `WinHttpOpenRequest` is called with `WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE`, enforcing TLS and disabling proxy caching.
- **Chunked download with hash validation**: Data is read in 1MB chunks (`CHUNK_SIZE = 1024 * 1024`). Each chunk's SHA-256 is validated against a pre-computed hash manifest. Mismatch causes silent abort.
- **Large-page allocation**: The `try_large_page_alloc_and_copy` function attempts `NtAllocateVirtualMemory` with `MEM_LARGE_PAGES` to store the downloaded payload in a large-page region, falling back to a standard `Vec<u8>` if `SeLockMemoryPrivilege` is not available or large pages are unsupported.

No WinINet implementation exists in the HUGIN source. The vault's `winhttp_dl.rs` comment explicitly notes "no WinINet — menor footprint" as a design choice.

## Why It Matters

The vault's T-022 networking suite documents WinHTTP-based download but does not surface WinINet as an alternative or document the operational trade-offs between the two API families. The distinction matters operationally: WinINet's IE proxy inheritance simplifies C2 in environments where the target uses a corporate proxy (no manual proxy configuration needed), but WinINet's cache artifacts leave forensic evidence in `INetCache`. WinHTTP's explicit proxy configuration requires the operator to discover and configure proxy settings, but produces no cache artifacts. EDRs that hook WinINet (common — most EDRs monitor browser-relevant APIs) will intercept WinINet C2 traffic; WinHTTP hooks are less common but increasing as EDR vendors recognize WinHTTP's use in non-interactive HTTP C2.

## Detection Considerations

- **Telemetry sources**: ETW provider `Microsoft-Windows-WinINet` emits events for WinINet HTTP traffic. ETW provider `Microsoft-Windows-WinHTTP` emits events for WinHTTP traffic. Sysmon Event ID 22 (DNS) and network connection events capture the underlying TCP connections regardless of API family. EDR products may hook `WinHttpSendRequest` / `InternetConnect` / `HttpSendRequest` via inline hooks in the respective DLL's export table.
- **Bypass options**: Dynamic loading via `LoadLibraryA` + `GetProcAddress` avoids static IAT detection. Using a User-Agent matching legitimate system traffic (e.g., `"Microsoft-CryptoAPI/10.0"`) blends with Windows Update. HTTPS enforcement prevents plaintext network inspection. Domain fronting or CDN-backed C2 infrastructure makes the TCP destination appear legitimate.
- **Residual artifacts**: WinINet leaves cache entries in `%LOCALAPPDATA%\Microsoft\Windows\INetCache\` and cookie files. WinHTTP leaves no filesystem artifacts. Both APIs generate TCP connection records in the system's network stack. Proxy configuration changes (if `WinHttpSetOption` is used) may be logged by proxy-aware EDRs.

## Related Techniques

- **T-022 Network Suite** — networking card that documents WinHTTP download, SOCKS5, HVNC, malleable C2, and multi-chain vault
- **T-065 Certificate Pinning for C2 TLS Transport** — TLS certificate validation for the HTTPS transport layer

## References

- Atlas material: atlas-exploit-dev-part12 (units 39, 40), atlas-exploit-dev-part20 (units 22, 23)
- MITRE ATT&CK: T1071.001 (Web Protocols) — https://attack.mitre.org/techniques/T1071/001
- LGTM notes: lgtm:wininet-vs-winhttp-c2, lgtm:wininet-vs-winhttp-transport-choice

## Source Reference

`dark_crystal/crowd/src/winhttp_dl.rs` — `winhttp_download()` function (full WinHTTP API sequence: `WinHttpOpen` → `WinHttpConnect` → `WinHttpOpenRequest` → `WinHttpSendRequest` → `WinHttpReceiveResponse` → `WinHttpQueryDataAvailable` → `WinHttpReadData`). Dynamic loading via `load_winhttp()` using `LoadLibraryA` + `GetProcAddress`.