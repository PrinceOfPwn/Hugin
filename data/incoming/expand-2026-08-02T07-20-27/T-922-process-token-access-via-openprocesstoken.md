---
id: T-922
title: "Process Token Access via OpenProcessToken"
category: patterns
tier: A
tags: [generated, manual]
mitre: []
origin: manual-expand-cluster
source_cluster: token-manipulation-openprocesstoken
member_notes: ['lgtm:token-manipulation-via-openprocesstoken']
---

## Summary
Documents OpenProcessToken(GetCurrentProcess() | OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION), TOKEN_ALL_ACCESS, &hToken) as the foundational primitive for all token manipulation.

## Technical Deep Dive
Documents OpenProcessToken(GetCurrentProcess() | OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION), TOKEN_ALL_ACCESS, &hToken) as the foundational primitive for all token manipulation. Pairs with GetTokenInformation(hToken, TokenStatistics / TokenUser / TokenGroups / TokenPrivileges, ...) to enumerate the token's user SID, group memberships, and privilege bitmap. The SANS TokenThief lab demonstrates duplicating a SYSTEM token from a higher-privilege process via OpenProcessToken + DuplicateTokenEx(MAXIMUM_ALLOWED, SecurityImpersonation, TokenPrimary) and replacing the calling thread's token via ImpersonateLoggedOnUser or SetThreadToken. Required by T-015 (token impersonation chains) and T-017 (privilege escalation persistence).


## Evidence
- lgtm:token-manipulation-via-openprocesstoken

## Detection & Mitigation
- Standard monitoring and detection.

## Related Techniques
- N/A

## References
- N/A
