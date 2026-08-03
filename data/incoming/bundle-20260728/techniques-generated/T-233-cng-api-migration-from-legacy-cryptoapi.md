---
id: T-233
title: "CNG API Migration from Legacy CryptoAPI"
category: crypto
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: cng-cryptoapi-modernization
member_notes: ["lgtm:cng-vs-legacy-cryptoapi-modernization"]
---

## Summary
This technique covers CNG API Migration from Legacy CryptoAPI, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents the deprecation of legacy CryptoAPI (CAPI) and the recommended CNG (Cryptography API: Next Generation) replacements. Legacy API sequence: CryptAcquireContextA(&hProv, container, provider, PROV_RSA_AES, 0) → CryptCreateHash → CryptHashData → CryptDeriveKey → CryptDecrypt. CNG replacement: BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) → BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC) → BCryptGenerateSymmetricKey(hAlg, &hKey, ...) → BCryptDecrypt(hKey, ciphertext, ..., &iv, plaintext, ...). CNG provides FIPS-validated algorithm providers, better key isolation (asymmetric keys stored in KSP), and AES-GCM authenticated encryption modes that legacy CAPI lacks. Pairs with T-021 client capability for payload decryption and C2 frame crypto.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// BCryptOpenAlgorithmProvider(BCRYPT_AES_ALGORITHM) + BCryptSetProperty(BCRYPT_CHAINING_MODE = BCRYPT_CHAIN_MODE_CBC) replacing CryptAcquireContextA(PROV_RSA_AES)
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:cng-vs-legacy-cryptoapi-modernization: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-021: Relates conceptually based on evidence.

## References
- Internal vault documentation on CNG API Migration from Legacy CryptoAPI
