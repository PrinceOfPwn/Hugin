---
id: T-145
title: "AV Static/Dynamic Detection Engine Bypass Lifecycle"
category: edr-evasion
tier: B
tags: ['av-detection-engine-lifecycle-bypass']
mitre: ["T-016","T-020"]
origin: glm-expand-cluster
source_cluster: av-detection-engine-lifecycle-bypass
member_notes: ["lgtm:av-detection-engine-lifecycle-convergence"]
---
## Summary

This technique covers AV Static/Dynamic Detection Engine Bypass Lifecycle. It addresses a gap in knowledge for red-team operations related to edr-evasion.

## Technical Deep Dive

SEC670 and MalDev Academy converge on the same lifecycle decomposition of AV detection
engines: static engines (signature/YARA-based, bypassable by changing the code base via
encoding, encryption, or metamorphism) versus dynamic engines (sandboxed execution,
bypassable by delaying execution, encrypting payloads, or triggering environment-gated
behavior). The vault's T-016 (NTAPI Hook Evasion) and T-020 (Anti-Analysis) implicitly
target these two layers but do not explicitly frame the dual-engine model as a
prerequisite concept. Documenting the lifecycle enables operators to map each evasion
primitive to the specific engine stage it defeats, producing a decision tree rather than
a flat technique list.


Technical anchor details:
```text
Static signature engine (YARA rule matching) vs. dynamic sandbox execution engine — bypassed by code-base mutation vs. execution delay/encryption respectively
```

## Evidence

- lgtm:av-detection-engine-lifecycle-convergence: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-016: Related technique for extended operations.
- T-020: Related technique for extended operations.

## References

- Internal Vault References
