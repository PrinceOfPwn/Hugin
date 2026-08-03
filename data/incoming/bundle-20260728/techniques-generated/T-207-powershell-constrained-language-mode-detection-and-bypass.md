---
id: T-207
title: "PowerShell Constrained Language Mode Detection and Bypass"
category: edr-evasion
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: powershell-clm-detection-and-bypass
member_notes: ["lgtm:clm-detection-and-bypass-coverage"]
---

## Summary
This technique covers PowerShell Constrained Language Mode Detection and Bypass, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents PowerShell Constrained Language Mode (CLM) detection and bypass. Detection primitive: query `$ExecutionContext.SessionState.LanguageMode` — returns "ConstrainedLanguage" under CLM, "FullLanguage" otherwise. Secondary probe: `[Math]::Pow(2, 10)` — succeeds in FullLanguage, throws in ConstrainedLanguage. CLM is enforced when WDAC/CIG policies are present, AppLocker is in enforce mode, or a Device Guard policy is active; it is distinct from and far more restrictive than ExecutionPolicy (which is bypassable via `-ExecutionPolicy Bypass` flag). Bypass requires either disabling the triggering policy (registry HKLM\System\CurrentControlSet\Control\CI\Config), running outside the constrained process (custom Runspace via CreateDefaultApplicationRunspace), or invoking COM objects through the default installer.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// $ExecutionContext.SessionState.LanguageMode == 'ConstrainedLanguage'; [Math]::Pow(2,10) probe; triggered by HKLM\System\CurrentControlSet\Control\CI\Config
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:clm-detection-and-bypass-coverage: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-016: Relates conceptually based on evidence.
- T-023: Relates conceptually based on evidence.

## References
- Internal vault documentation on PowerShell Constrained Language Mode Detection and Bypass
