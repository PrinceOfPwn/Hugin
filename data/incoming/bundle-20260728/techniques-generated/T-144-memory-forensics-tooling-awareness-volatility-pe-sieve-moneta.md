---
id: T-144
title: "Memory Forensics Tooling Awareness (Volatility, PE-sieve, Moneta)"
category: anti-analysis
tier: A
tags: ['memory-forensics-tooling-awareness']
mitre: ["T-007","T-013","T-016"]
origin: glm-expand-cluster
source_cluster: memory-forensics-tooling-awareness
member_notes: ["lgtm:memory-forensics-tooling-coverage-gap","lgtm:memory-forensics-defense-landscape"]
---
## Summary

This technique covers Memory Forensics Tooling Awareness (Volatility, PE-sieve, Moneta). It addresses a gap in knowledge for red-team operations related to anti-analysis.

## Technical Deep Dive

Documents the three memory forensics tools an operator must assume are in use: Volatility (vol.py, the reference framework — scans for DTB, walks EPROCESS list, PEB module lists, VAD tree, handles), PE-sieve (hashes the .text section of every loaded module and compares against on-disk counterparts to find hooked/hollowed DLLs), and Moneta (scans for PAGE_EXECUTE_READWRITE pages with no corresponding mapped file in the VAD — catches PIC shellcode and module stomping). The operational consequence: "being in memory is not a get out of jail free card" — T-007 injection and T-016 unhook must consider detection by these scanners, not just by EDR hooks. Specific evasion responses: hash-mismatch hiding via T-016 fresh-copy unhook (defeats PE-sieve), VAD-backed allocation via NtMapViewOfSection of a legitimate DLL (defeats Moneta).


Technical anchor details:
```text
PE-sieve hashes ntdll.dll .text and compares against on-disk counterpart; Moneta scans for PAGE_EXECUTE_READWRITE with no VAD backing
```

## Evidence

- lgtm:memory-forensics-tooling-coverage-gap: Member note detailing operations.
- lgtm:memory-forensics-defense-landscape: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-007: Related technique for extended operations.
- T-013: Related technique for extended operations.
- T-016: Related technique for extended operations.

## References

- Internal Vault References
