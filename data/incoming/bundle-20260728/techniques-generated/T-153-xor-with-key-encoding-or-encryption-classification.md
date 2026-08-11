---
id: T-153
title: "XOR with Key — Encoding or Encryption Classification"
category: crypto
tier: C
tags: ['xor-encoding-vs-encryption-classification']
mitre: ["T-021"]
origin: glm-expand-cluster
source_cluster: xor-encoding-vs-encryption-classification
member_notes: ["lgtm:xor-encoding-vs-encryption-semantic-debate"]
---
## Summary

This technique covers XOR with Key — Encoding or Encryption Classification. It addresses a gap in knowledge for red-team operations related to crypto.

## Technical Deep Dive

SEC670 surfaces the long-standing debate over whether XOR with a key constitutes
encoding or encryption, noting that the presence of a key supports the encryption
classification. The vault's T-021 treats shellcode encoding formats (IPv4/IPv6/MAC/
UUID/words) as encoding — which is correct for format-only transforms — but does not
address the XOR-with-key semantic boundary. The distinction matters operationally
because some EDR/AV vendors classify XOR-with-key as encryption (triggering
entropy-based detection) while others classify it as encoding (triggering no
detection). A concept card should document the XOR operation (plaintext[i] ^ key[i %
key_len]), the entropy profile of XOR output (preserves byte-frequency distribution of
the key, not the plaintext), the detection differential (high-entropy keys produce
high-entropy output detectable by Shannon entropy analysis), and the classification
rationale (presence of a key → encryption; absence of a key → encoding).


Technical anchor details:
```text
XOR operation: plaintext[i] ^ key[i % key_len] — Shannon entropy of output depends on key entropy, not plaintext entropy; presence of key → encryption classification per some EDR vendors
```

## Evidence

- lgtm:xor-encoding-vs-encryption-semantic-debate: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-021: Related technique for extended operations.

## References

- Internal Vault References
