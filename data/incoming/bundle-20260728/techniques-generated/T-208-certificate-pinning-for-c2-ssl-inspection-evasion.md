---
id: T-208
title: "Certificate Pinning for C2 SSL Inspection Evasion"
category: networking
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: certificate-pinning-c2-ssl-inspection-evasion
member_notes: ["lgtm:certificate-pinning-c2-tradecraft"]
---

## Summary
This technique covers Certificate Pinning for C2 SSL Inspection Evasion, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents certificate pinning as a technique to prevent MITM inspection of C2 traffic by SSL proxy appliances (F5 BIG-IP, Blue Coat, Netscaler). The Win32 implementation uses InternetQueryOption(hRequest, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &certChainCtx, &size) to retrieve the server's certificate chain, CertGetNameString(CERT_NAME_SIMPLE_DISPLAY_TYPE) to extract the subject CN, and a byte-level comparison of the certificate's SHA-256 fingerprint (computed via CryptHashCertificate) against a pre-pinned list. Pairs with WinHTTP's WINHTTP_OPTION_SERVER_CERT_CONTEXT for transport-agnostic implementation. The vault's T-022 documents NT sockets and transport-level framing but does not document the application-layer certificate validation that defeats SSL inspection.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// InternetQueryOption(INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT) + CertGetNameString + SHA-256 fingerprint byte-comparison
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:certificate-pinning-c2-tradecraft: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-022: Relates conceptually based on evidence.

## References
- Internal vault documentation on Certificate Pinning for C2 SSL Inspection Evasion
