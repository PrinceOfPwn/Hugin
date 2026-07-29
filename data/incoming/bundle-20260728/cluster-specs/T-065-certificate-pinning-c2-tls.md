# Cluster Spec — T-065: Certificate Pinning for C2 TLS Transport Validation

- **T-NNN ID**: `T-065`
- **Canonical name**: Certificate Pinning for C2 TLS Transport Validation
- **Proposed category**: `networking`
- **Proposed tier**: `B`
- **Priority**: low — Singleton, well-documented pattern; standard transport hardening.
- **would_relate_to**: ['T-022']

## Consolidated Description

Certificate pinning for C2 TLS transports using InternetQueryOption with INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, CertGetNameString, CertGetCertificateContextProperty with CERT_HASH_PROP_ID, hex-string comparison. Implants validate server certificate chain offline to prevent MITM attacks and network-level redirection.

## Member LGTM Notes (1)

### Note 1: Certificate Pinning for C2 TLS Transports
- id: `lgtm:certificate-pinning-for-c2-transports`
- origin: atlas-exploit-dev-part13
- would_relate_to: ['T-022']
- tags: ['certificate-pinning', 'tls', 'mitm-resistance', 'c2', 'tradecraft']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part13
**Would relate to:** T-022
**Source units:** unit 21

SEC670 unit 21 documents a full certificate pinning workflow (InternetQueryOption with INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, CertGetNameString, CertGetCertificateContextProperty with CERT_HASH_PROP_ID, hex conversion for comparison). The vault's T-022 network suite covers HTTP poll, malleable C2, peer relay, and NT sockets but does not document a certificate pinning capability to resist MITM proxies. This would merit its own sub-technique under T-022 since it composes with any TLS-based transport.

---
Use `id: T-065`, canonical name above, and `member_notes: ['lgtm:certificate-pinning-for-c2-transports']`.
Cross-reference `would_relate_to`: ['T-022'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.