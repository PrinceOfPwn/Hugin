---
id: T-078
name: CNG over Legacy CryptoAPI Migration
category: crypto
tier: A
crate: none
source_file: none
mitre: T1027
tags: [cng, bcrypt, cryptoapi, aes-gcm, api-migration, authenticated-encryption, cryptoapi-deprecated, bcrypt-provider, symmetric-encryption, windows-crypto]
origin: atlas-synthesis
member_notes: [lgtm:cng-vs-cryptoapi-modernization-signal, lgtm:cryptoapi-to-cng-migration-guidance, lgtm:cng-api-crypto-coverage]
---

# CNG over Legacy CryptoAPI Migration — Windows-Native Authenticated Encryption via BCrypt*

## Summary

SEC670 explicitly frames the deprecated CryptoAPI (Crypt*) family versus the recommended CNG (Cryptography Next Generation, BCrypt*) family as a tradecraft decision for Windows-native cryptographic operations. CryptoAPI uses CryptAcquireContextA with PROV_RSA_AES, CryptDeriveKey, and CryptEncrypt — an API surface that lacks support for authenticated encryption modes (AEAD) such as GCM and CCM. CNG uses BCryptOpenAlgorithmProvider, BCryptSetProperty, BCryptGenerateSymmetricKey, and BCryptEncrypt, providing AES-GCM and AES-CCM support via the BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure. The HUGIN dark_crystal crate uses Rust's aes-gcm crate rather than either Windows API family, which avoids the bcrypt.dll import dependency but introduces a third implementation path. This card documents the CNG API sequence for AES-GCM encryption and the operational tradeoffs between CNG, CryptoAPI, and language-native crypto crates.

## Mechanism

1. (Legacy CryptoAPI path) CryptAcquireContextA is called with the PROV_RSA_AES provider type (value 24) to obtain a cryptographic provider handle (HCRYPTPROV). This provider type maps to the Microsoft Enhanced RSA and AES Cryptographic Provider and supports RSA and AES algorithms, but the CSP (Cryptographic Service Provider) interface does not expose authenticated encryption modes.
2. CryptDeriveKey derives a symmetric key from the provider handle using a hash of the input key material. The key algorithm is specified via the ALG_ID parameter (e.g., CALG_AES_256 for 256-bit AES).
3. CryptEncrypt performs encryption using the derived key. For AES-CBC, the caller sets the cipher mode via CryptSetKeyParam with KP_MODE set to CRYPT_MODE_CBC. No GCM or CCM mode is available through the CryptoAPI CSP interface, making it unsuitable for modern authenticated encryption requirements.
4. (CNG path) BCryptOpenAlgorithmProvider is called with the algorithm identifier BCRYPT_AES_ALGORITHM (L"AES") and an optional provider name (NULL for the default Microsoft Primitive Provider). This returns a BCRYPT_ALG_HANDLE representing the AES algorithm provider.
5. BCryptSetProperty sets the chaining mode on the algorithm provider handle before key generation. The property name is BCRYPT_CHAINING_MODE (L"ChainingMode") and the value is BCRYPT_CHAIN_MODE_GCM (L"ChainingModeGCM"). For CBC mode, the value would be BCRYPT_CHAIN_MODE_CBC.
6. BCryptGenerateSymmetricKey creates a BCRYPT_KEY_HANDLE from the algorithm provider handle and the raw key material buffer (32 bytes for AES-256). The key material is passed directly as a byte array — CNG does not require key derivation through a separate CSP step, unlike CryptoAPI.
7. BCryptEncrypt performs authenticated encryption using the key handle. The caller provides a BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure as the pPaddingInfo parameter. This structure contains:
   - pbNonce: pointer to the nonce/IV buffer (12 bytes for GCM per NIST SP 800-38D)
   - cbNonce: size of the nonce (12)
   - pbAuthData: pointer to optional additional authenticated data (AAD)
   - cbAuthData: size of the AAD
   - pbTag: pointer to the output authentication tag buffer (16 bytes for GCM)
   - cbTag: size of the tag (16)
   - dwVersion and cbSize: structure version and size fields (initialized via the BCRYPT_INIT_AUTH_MODE_INFO macro)
8. BCryptEncrypt returns the ciphertext in the output buffer and writes the authentication tag to pbTag. The tag is stored alongside the ciphertext for transmission. On the receiving end, BCryptDecrypt uses the same BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure with the received tag — if the tag does not match the computed GMAC over the ciphertext and AAD, BCryptDecrypt returns STATUS_AUTH_TAG_MISMATCH (0xC000A002).
9. BCryptDestroyKey releases the key handle, and BCryptCloseAlgorithmProvider releases the algorithm provider handle. The bcrypt.dll module remains loaded in the process's module list for the lifetime of the process once any BCrypt* function is called.

## OS Internals Context

CNG was introduced in Windows Vista as the replacement for the legacy CryptoAPI (also known as Wincrypt or CryptoAPI 1.0). CryptoAPI uses a CSP (Cryptographic Service Provider) architecture where cryptographic operations are delegated to pluggable provider DLLs loaded via the CryptLoadCSP function. The PROV_RSA_AES provider type (24) maps to the Microsoft Enhanced RSA and AES Cryptographic Provider (rsaenh.dll). The CSP interface was designed in the Windows NT 4.0 era and predates the standardization of authenticated encryption modes (GCM was specified in NIST SP 800-38D in 2007). CryptoAPI's lack of AEAD support is a structural limitation of the CSP architecture, not a missing feature.

CNG uses a different architecture: algorithm providers are loaded by the CNG configuration subsystem (configured under HKLM\SOFTWARE\Microsoft\Cryptography\Defaults\Providers) and exposed through the BCrypt* function surface implemented in bcrypt.dll (user mode) and ksecdd.sys (kernel mode). The Microsoft Primitive Provider (Microsoft Primitive Provider, loaded by default when no provider name is specified) implements AES, SHA-2, RSA, and ECDSA primitives directly in the CNG framework without requiring an external provider DLL.

The BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure (defined in bcrypt.h) is approximately 100 bytes on x64. It contains version fields (dwVersion must be set to BCRYPT_INIT_AUTH_MODE_INFO_VERSION, cbSize to sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)), the nonce (pbNonce/cbNonce), additional authenticated data (pbAuthData/cbAuthData), the tag (pbTag/cbTag), and MAC context fields (pbMacContext/cbMacContext) used for multi-part authenticated encryption via BCryptEncrypt with the BCRYPT_BLOCK_PADDING flag and multiple calls.

For AES-GCM, the nonce should be 12 bytes (96 bits) per NIST SP 800-38D, and the tag is 16 bytes (128 bits). AES-GCM processes the plaintext in counter mode (AES-CTR) and computes a Galois MAC (GMAC) over the ciphertext and AAD using GHASH polynomial evaluation over GF(2^128). The CNG provider performs both the AES-CTR and GHASH operations internally when BCryptEncrypt is called with the BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure.

The deprecation of CryptoAPI is implicit in Microsoft's documentation: the Crypt* functions are marked as "superseded" by CNG equivalents, and new cryptographic algorithms are only available through CNG providers. The Windows CNG framework is the only way to use AES-GCM or AES-CCM through Windows-native APIs. The legacy CryptoAPI remains present for backward compatibility but should not be used for new development.

## Key Implementation Details

**No current implementation in the HUGIN source.** The dark_crystal crate's crypto module (dark_crystal/crates/core/src/crypto.rs, mapped to T-021) implements AES-256-GCM encryption using the Rust aes-gcm crate (the Aes256Gcm type from the aes-gcm crate), not CNG. The crypto module uses a 12-byte nonce and 16-byte tag matching the GCM standard. The client_rust crate's protocol.rs defines binary protocol message types but does not implement cryptographic operations — it defines message type constants (MSG_FRAME, MSG_HELLO, etc.) and build_message/parse_message functions for the wire format.

The dark_crystal crate's wrappers.rs module uses windows_targets::link! for ntdll API bindings, and the crowd crate's resolve.rs implements PEB walking and DJB2 hash resolution for dynamic API loading. An implementation using CNG would replace the aes-gcm crate dependency with FFI bindings to bcrypt.dll, resolved either via the static import table or dynamically via the PEB walker (T-004) and manual GetProcAddress (T-050) to avoid a static bcrypt.dll import. The sequence would be: BCryptOpenAlgorithmProvider(BCRYPT_AES_ALGORITHM) → BCryptSetProperty(BCRYPT_CHAINING_MODE_GCM) → BCryptGenerateSymmetricKey(key_material) → BCryptEncrypt with BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO. This approach produces no Rust crypto code in the binary but adds a bcrypt.dll dependency.

## Why It Matters

The choice of cryptographic API family affects the implant's import table, binary size, and detection surface. CNG adds a bcrypt.dll import that may appear anomalous in an implant binary that does not otherwise require Windows crypto services — a static import of bcrypt.dll in a dropper or loader is a signal that cryptographic operations are performed, which narrows the analyst's search. The Rust aes-gcm crate produces self-contained crypto code with no external DLL dependency, compiled directly into the binary, but increases binary size by approximately 50-100 KB due to the embedded AES and GHASH implementations. SEC670's explicit recommendation of CNG over CryptoAPI reflects the industry shift toward authenticated encryption — CryptoAPI's lack of GCM and CCM support makes it unsuitable for modern C2 protocols that require AEAD for message integrity and confidentiality. Operators working in C/C++ must use CNG; operators in Rust can choose either CNG via FFI or the native aes-gcm crate.

## Detection Considerations

- **Telemetry sources**: BCryptOpenAlgorithmProvider and BCryptEncrypt are exported by bcrypt.dll and may be hooked by EDR products that monitor cryptographic API calls. Import table analysis (via dumpbin /imports or similar) reveals bcrypt.dll as a static dependency, which is a static indicator of cryptographic operations. The Rust aes-gcm crate does not appear in the import table — its code is compiled into the binary as pure Rust with no Windows API calls.
- **Bypass options**: Dynamic resolution of bcrypt.dll functions via the PEB walker (T-004) and manual GetProcAddress (T-050) avoids the static bcrypt.dll import in the import table. The Rust aes-gcm crate avoids the bcrypt.dll dependency entirely. API calls to bcrypt.dll through dynamically resolved function pointers may still be monitored by EDR products that hook at the function level, but the aes-gcm crate's in-process computation produces no observable API calls to bcrypt.dll.
- **Residual artifacts**: CNG usage via static imports produces bcrypt.dll in the import table. CNG usage via dynamic resolution creates a loaded module entry for bcrypt.dll visible in the PEB's InLoadOrderModuleList (detectable by PE-sieve and Volatility). The Rust aes-gcm crate produces no file system, module list, or import table artifacts but adds compiled AES and GHASH code to the binary's .text section, increasing the code size footprint.

## Related Techniques

- **T-021 Crypto & Obfuscation** — The existing crypto card documents AES-256-GCM with zstd compression using the Rust aes-gcm crate; this card documents the Windows-native CNG API alternative and the deprecated CryptoAPI path that the Rust approach replaces

## References

- Atlas material: atlas-exploit-dev-part13.md (units 18, 19, 40), atlas-exploit-dev-part14.md (units 1, 2, 3), atlas-exploit-dev-part19.md (units 28, 39)
- MITRE ATT&CK: T1027 — https://attack.mitre.org/techniques/T1027/
- LGTM notes: lgtm:cng-vs-cryptoapi-modernization-signal, lgtm:cryptoapi-to-cng-migration-guidance, lgtm:cng-api-crypto-coverage

## Source Reference

No current implementation. The dark_crystal crate uses the Rust aes-gcm crate (dark_crystal/crates/core/src/crypto.rs) as an alternative to both CNG and CryptoAPI. See atlas material for SEC670 coverage of the CNG vs CryptoAPI tradecraft decision.