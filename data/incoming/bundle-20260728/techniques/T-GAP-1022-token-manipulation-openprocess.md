---
id: T-GAP-1022
name: "Process Token Access via OpenProcessToken"
category: privesc
tier: A
crate: none
source_file: none
mitre: T1082
mitre_secondary: []
tags: []
origin: lgtm-cluster
member_notes: ["lgtm:token-manipulation-via-openprocesstoken"]
---

# Process Token Access via OpenProcessToken

## Summary

Documents OpenProcessToken(GetCurrentProcess() | OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION), TOKEN_ALL_ACCESS, &hToken) as the foundational primitive for all token manipulation. Pairs with GetTokenInformation(hToken, TokenStatistics / TokenUser / TokenGroups / TokenPrivileges, ...) to enumerate the token's user SID, group memberships, and privilege bitmap. The SANS TokenThief lab demonstrates duplicating a SYSTEM token from a higher-privilege process via OpenProcessToken + DuplicateTokenEx(MAXIMUM_ALLOWED, SecurityImpersonation, TokenPrimary) and replacing the calling thread's token via ImpersonateLoggedOnUser or SetThreadToken. Required by T-015 (token impersonation chains) and T-017 (privilege escalation persistence).


## Mechanism

OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken) → GetTokenInformation(TokenPrivileges) → DuplicateTokenEx + SetThreadToken

## Rationale

Single coverage-gap note documenting OpenProcessToken as the foundational token-manipulation primitive; the vault lacks a dedicated card for this despite T-015/T-017 touching it.

## Related To

T-015, T-017
