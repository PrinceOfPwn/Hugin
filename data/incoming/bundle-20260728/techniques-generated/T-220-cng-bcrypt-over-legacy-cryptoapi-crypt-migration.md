---
id: T-220
title: "CNG (BCrypt*) over Legacy CryptoAPI (Crypt*) Migration"
category: crypto
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: cng-cryptography-migration
member_notes: ["lgtm:cng-vs-cryptoapi-modernization-signal", "lgtm:cryptoapi-to-cng-migration-guidance", "lgtm:cng-api-crypto-coverage"]
---

## Summary
This technique covers CNG (BCrypt*) over Legacy CryptoAPI (Crypt*) Migration, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
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


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// CNG AES-GCM: BCryptOpenAlgorithmProvider(BCRYPT_AES_ALGORITHM) → BCryptSetProperty(BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_GCM) → BCryptGenerateSymmetricKey → BCryptEncrypt with BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO — vs. deprecated CryptAcquireContextA(PROV_RSA_AES)
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:cng-vs-cryptoapi-modernization-signal: Contributed insights into the specific mechanism.
- Note lgtm:cryptoapi-to-cng-migration-guidance: Contributed insights into the specific mechanism.
- Note lgtm:cng-api-crypto-coverage: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-021: Relates conceptually based on evidence.

## References
- Internal vault documentation on CNG (BCrypt*) over Legacy CryptoAPI (Crypt*) Migration
