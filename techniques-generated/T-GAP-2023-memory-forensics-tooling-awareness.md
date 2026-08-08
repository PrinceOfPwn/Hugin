---
id: T-GAP-2023
title: "Memory Forensics Tooling Awareness (Volatility, PE-sieve, Moneta)"
category: "anti-analysis"
tier: "A"
tags: [generated, gap, research]
mitre: []
origin: glm-expand-cluster
source_cluster: memory-forensics-tooling-awareness
member_notes: ['lgtm:memory-forensics-tooling-coverage-gap', 'lgtm:memory-forensics-defense-landscape']
---

## Summary
Documents the three memory forensics tools an operator must assume are in use: Volatility (vol.py, the reference framework — scans for DTB, walks EPROCESS list, PEB module lists, VAD tree, handles), PE-sieve (hashes the .text section of every loaded module and compares against on-disk counterparts to find hooked/hollowed DLLs), and Moneta (scans for PAGE_EXECUTE_READWRITE pages with no corresponding mapped file in the VAD — catches PIC shellcode and module stomping). The operational consequence: "being in memory is not a get out of jail free card" — T-007 injection and T-016 unhook must consider detection by these scanners, not just by EDR hooks. Specific evasion responses: hash-mismatch hiding via T-016 fresh-copy unhook (defeats PE-sieve), VAD-backed allocation via NtMapViewOfSection of a legitimate DLL (defeats Moneta).


## Technical Deep Dive
The cluster represents a gap identified during automated research analysis. Two coverage-gap notes both name Volatility, PE-sieve, and Moneta as the defensive memory-forensics stack an operator must assume is in use; cross-cutting awareness metadata.

## Evidence
- lgtm:memory-forensics-tooling-coverage-gap: See original note for details.
- lgtm:memory-forensics-defense-landscape: See original note for details.

## Detection & Mitigation
Monitor for the aforementioned behaviors using standard EDR hooks and ETW telemetry.

## Related Techniques
- Placeholder: related techniques to be discovered

## References
- Internal vault references
