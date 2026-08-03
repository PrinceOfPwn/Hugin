---
id: T-205
title: "Memory Forensics Tooling Awareness (Volatility, PE-sieve, Moneta)"
category: anti-analysis
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: memory-forensics-tooling-awareness
member_notes: ["lgtm:memory-forensics-tooling-coverage-gap", "lgtm:memory-forensics-defense-landscape"]
---

## Summary
This technique covers Memory Forensics Tooling Awareness (Volatility, PE-sieve, Moneta), focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents the three memory forensics tools an operator must assume are in use: Volatility (vol.py, the reference framework — scans for DTB, walks EPROCESS list, PEB module lists, VAD tree, handles), PE-sieve (hashes the .text section of every loaded module and compares against on-disk counterparts to find hooked/hollowed DLLs), and Moneta (scans for PAGE_EXECUTE_READWRITE pages with no corresponding mapped file in the VAD — catches PIC shellcode and module stomping). The operational consequence: "being in memory is not a get out of jail free card" — T-007 injection and T-016 unhook must consider detection by these scanners, not just by EDR hooks. Specific evasion responses: hash-mismatch hiding via T-016 fresh-copy unhook (defeats PE-sieve), VAD-backed allocation via NtMapViewOfSection of a legitimate DLL (defeats Moneta).


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// PE-sieve hashes ntdll.dll .text and compares against on-disk counterpart; Moneta scans for PAGE_EXECUTE_READWRITE with no VAD backing
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:memory-forensics-tooling-coverage-gap: Contributed insights into the specific mechanism.
- Note lgtm:memory-forensics-defense-landscape: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-007: Relates conceptually based on evidence.
- T-013: Relates conceptually based on evidence.
- T-016: Relates conceptually based on evidence.

## References
- Internal vault documentation on Memory Forensics Tooling Awareness (Volatility, PE-sieve, Moneta)
