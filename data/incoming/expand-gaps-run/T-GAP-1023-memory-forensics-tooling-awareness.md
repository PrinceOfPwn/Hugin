---
id: T-GAP-1023
title: "Memory Forensics Tooling Awareness (Volatility, PE-sieve, Moneta)"
tier: "A"
category: "anti-analysis"
---

# Memory Forensics Tooling Awareness (Volatility, PE-sieve, Moneta)

## Description
Documents the three memory forensics tools an operator must assume are in use: Volatility (vol.py, the reference framework — scans for DTB, walks EPROCESS list, PEB module lists, VAD tree, handles), PE-sieve (hashes the .text section of every loaded module and compares against on-disk counterparts to find hooked/hollowed DLLs), and Moneta (scans for PAGE_EXECUTE_READWRITE pages with no corresponding mapped file in the VAD — catches PIC shellcode and module stomping). The operational consequence: "being in memory is not a get out of jail free card" — T-007 injection and T-016 unhook must consider detection by these scanners, not just by EDR hooks. Specific evasion responses: hash-mismatch hiding via T-016 fresh-copy unhook (defeats PE-sieve), VAD-backed allocation via NtMapViewOfSection of a legitimate DLL (defeats Moneta).


## Rationale
Two coverage-gap notes both name Volatility, PE-sieve, and Moneta as the defensive memory-forensics stack an operator must assume is in use; cross-cutting awareness metadata.

## References
- lgtm:memory-forensics-tooling-coverage-gap
- lgtm:memory-forensics-defense-landscape
