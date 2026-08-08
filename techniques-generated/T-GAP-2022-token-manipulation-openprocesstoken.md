---
id: T-GAP-2022
title: "Process Token Access via OpenProcessToken"
category: "privesc"
tier: "A"
tags: [generated, gap, research]
mitre: []
origin: glm-expand-cluster
source_cluster: token-manipulation-openprocesstoken
member_notes: ['lgtm:token-manipulation-via-openprocesstoken']
---

## Summary
Documents OpenProcessToken(GetCurrentProcess() | OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION), TOKEN_ALL_ACCESS, &hToken) as the foundational primitive for all token manipulation. Pairs with GetTokenInformation(hToken, TokenStatistics / TokenUser / TokenGroups / TokenPrivileges, ...) to enumerate the token's user SID, group memberships, and privilege bitmap. The SANS TokenThief lab demonstrates duplicating a SYSTEM token from a higher-privilege process via OpenProcessToken + DuplicateTokenEx(MAXIMUM_ALLOWED, SecurityImpersonation, TokenPrimary) and replacing the calling thread's token via ImpersonateLoggedOnUser or SetThreadToken. Required by T-015 (token impersonation chains) and T-017 (privilege escalation persistence).


## Technical Deep Dive
The cluster represents a gap identified during automated research analysis. Single coverage-gap note documenting OpenProcessToken as the foundational token-manipulation primitive; the vault lacks a dedicated card for this despite T-015/T-017 touching it.

## Evidence
- lgtm:token-manipulation-via-openprocesstoken: See original note for details.

## Detection & Mitigation
Monitor for the aforementioned behaviors using standard EDR hooks and ETW telemetry.

## Related Techniques
- Placeholder: related techniques to be discovered

## References
- Internal vault references
