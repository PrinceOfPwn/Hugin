# Cluster Spec — T-078: CNG (BCrypt*) over Legacy CryptoAPI (Crypt*) Migration

- **T-NNN ID**: `T-078`
- **Canonical name**: CNG (BCrypt*) over Legacy CryptoAPI (Crypt*) Migration
- **Proposed category**: `crypto`
- **Proposed tier**: `A`
- **Priority**: high — Three member notes from three atlas batches; cross-source convergence on CNG as the recommended Windows-native crypto API.
- **would_relate_to**: ['T-021']

## Consolidated Description

SEC670 explicitly frames the deprecated Crypt* family (CryptAcquireContextA with
PROV_RSA_AES, CryptDeriveKey, CryptEncrypt) versus the recommended CNG BCrypt* family
(bcrypt.h: BCryptOpenAlgorithmProvider, BCryptSetProperty, BCryptGenerateSymmetricKey,
BCryptEncrypt) as a tradecraft decision. CNG is positioned as 'more advanced and
extensible' than CryptoAPI, with support for authenticated encryption modes (GCM,
CCM) that the legacy API lacks. The vault's T-021 uses Rust's aes-gcm crate rather
than either Windows API family, which is appropriate for the Rust-based dark_crystal
crate but leaves CNG and CryptoAPI paths undocumented for operators working in C/C++.
A card should document the CNG API sequence for AES-GCM (BCryptOpenAlgorithmProvider
with BCRYPT_AES_ALGORITHM → BCryptSetProperty with BCRYPT_CHAINING_MODE_GCM →
BCryptGenerateSymmetricKey → BCryptEncrypt with BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO),
the deprecation timeline of CryptoAPI, and the operational tradeoff versus using a
language-native crypto crate.


## Member LGTM Notes (3)

### Note 1: CNG over CryptoAPI Modernization Signal
- id: `lgtm:cng-vs-cryptoapi-modernization-signal`
- origin: atlas-exploit-dev-part13
- would_relate_to: ['T-021']
- tags: ['cng', 'cryptoapi', 'aes-gcm', 'modernization', 'bcrypt', 'deprecated']

**Kind:** cross-source-convergence
**Origin:** atlas-exploit-dev-part13
**Would relate to:** T-021
**Source units:** unit 18, unit 19, unit 40

SEC670 units 18 and 40 explicitly mark the legacy CryptoAPI AES sequence (CryptAcquireContextA with PROV_RSA_AES) as deprecated and recommend CNG (bcrypt.h) with BCryptOpenAlgorithmProvider/BCryptSetProperty/BCryptGenerateSymmetricKey/BCryptEncrypt. The vault's T-021 uses AES-GCM+zstd but does not document which Win32 crypto stack backs it. This convergence across SEC670 and MalDev Academy material indicates CNG is the current tradecraft standard and the vault should annotate its crypto implementation choice.

### Note 2: CryptoAPI to CNG Migration as Tradecraft Guidance
- id: `lgtm:cryptoapi-to-cng-migration-guidance`
- origin: atlas-exploit-dev-part14
- would_relate_to: ['T-021']
- tags: ['crypto', 'cng', 'cryptoapi', 'api-selection', 'tradecraft']

**Kind:** cross-source-convergence
**Origin:** atlas-exploit-dev-part14
**Would relate to:** T-021
**Source units:** unit 1, unit 2, unit 3

SEC670 explicitly frames the deprecated Crypt* family versus the recommended CNG BCrypt* family as a tradecraft decision. The vault's T-021 uses Rust's aes-gcm crate rather than either Windows API family, which is a third path the training material does not address. A graph node documenting the API-family choice and its detection implications would help operators understand when to use Windows-native crypto versus Rust-native crypto.

### Note 3: CNG API Cryptography Approach
- id: `lgtm:cng-api-crypto-coverage`
- origin: atlas-exploit-dev-part19
- would_relate_to: ['T-021']
- tags: ['crypto', 'cng', 'bcrypt', 'aes', 'cross-source-convergence']

**Kind:** cross-source-convergence
**Origin:** atlas-exploit-dev-part19
**Would relate to:** T-021
**Source units:** unit 28, unit 39

SEC670 covers CNG (Cryptography Next Generation) BCrypt* APIs as the Windows-native approach to AES shellcode encryption, positioning it as 'more advanced and extensible' than alternatives. The vault's T-021 documents AES-256-GCM with zstd but does not specify whether the implementation uses CNG, a Rust crypto crate, or a custom implementation. Documenting the CNG API approach alongside the existing Rust-based crypto would clarify the tradeoff between Windows-native (CNG, no external dependency, but links to bcrypt.dll) and portable (Rust crate, self-contained, but larger binary) approaches.

---
Use `id: T-078`, canonical name above, and `member_notes: ['lgtm:cng-vs-cryptoapi-modernization-signal', 'lgtm:cryptoapi-to-cng-migration-guidance', 'lgtm:cng-api-crypto-coverage']`.
Cross-reference `would_relate_to`: ['T-021'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.