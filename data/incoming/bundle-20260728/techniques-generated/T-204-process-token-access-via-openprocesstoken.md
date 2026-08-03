---
id: T-204
title: "Process Token Access via OpenProcessToken"
category: patterns
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: token-manipulation-openprocesstoken
member_notes: ["lgtm:token-manipulation-via-openprocesstoken"]
---

## Summary
This technique covers Process Token Access via OpenProcessToken, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents OpenProcessToken(GetCurrentProcess() | OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION), TOKEN_ALL_ACCESS, &hToken) as the foundational primitive for all token manipulation. Pairs with GetTokenInformation(hToken, TokenStatistics / TokenUser / TokenGroups / TokenPrivileges, ...) to enumerate the token's user SID, group memberships, and privilege bitmap. The SANS TokenThief lab demonstrates duplicating a SYSTEM token from a higher-privilege process via OpenProcessToken + DuplicateTokenEx(MAXIMUM_ALLOWED, SecurityImpersonation, TokenPrimary) and replacing the calling thread's token via ImpersonateLoggedOnUser or SetThreadToken. Required by T-015 (token impersonation chains) and T-017 (privilege escalation persistence).


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken) → GetTokenInformation(TokenPrivileges) → DuplicateTokenEx + SetThreadToken
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:token-manipulation-via-openprocesstoken: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-015: Relates conceptually based on evidence.
- T-017: Relates conceptually based on evidence.

## References
- Internal vault documentation on Process Token Access via OpenProcessToken
