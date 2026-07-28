---
id: T-108
name: Registry Run/RunOnce Key Persistence
category: persistence
tier: A
crate: none
source_file: none
mitre: T1547.001
tags: [persistence, registry, run-key, runonce, hklm, hkcu, autostart, logon, shell-launch]
origin: atlas-synthesis
member_notes: ['lgtm:gap-registry-run-key-persistence', 'lgtm:registry-run-key-persistence-coverage-gap', 'lgtm:registry-persistence-coverage-gap']
---

# Registry Run/RunOnce Key Persistence — Logon-Triggered Execution via Registry Autostart

## Summary

The Run and RunOnce registry keys under HKLM and HKCU provide the most commonly used Windows persistence mechanism, executing a specified command or binary at user logon. SEC670 identifies the Run key as the single most prevalent registry persistence vector in real-world intrusions, citing APT28, Emotet, and APT39 as operators that leverage it. HKLM Run keys require administrator privileges and execute for all users at logon, while HKCU Run keys provide per-user persistence accessible from medium integrity without elevation. The RunOnce variant executes its entries a single time and then deletes the registry value, providing single-shot persistence for first-stage payloads. T-017's five-layer persistence suite documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but omits Run/RunOnce despite their prevalence.

## Mechanism

1. The operator selects the target registry key based on the desired scope and privilege context. HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run executes for all users at logon but requires administrator privileges to modify. HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run executes only for the current user but requires no elevation, making it accessible from a medium-IL implant.
2. The operator creates a registry value under the selected key using RegSetValueExW. The value name is an arbitrary string (often mimicking a legitimate application name), and the value data is a REG_SZ or REG_EXPAND_SZ string containing the command to execute — a binary path, optionally with arguments.
3. At the next user logon, the Windows shell (explorer.exe) enumerates the Run keys in a specific order: HKLM\...\Run first, then HKCU\...\Run. Each value's command string is parsed and executed via CreateProcess.
4. For RunOnce keys (HKLM\...\RunOnce and HKCU\...\RunOnce), the shell executes the command and then deletes the registry value immediately after execution. This provides single-shot persistence useful for first-stage droppers that establish a more durable mechanism on first run.
5. The HKLM\...\RunOnce key supports the optional RunOnceEx mechanism, which uses a structured registry layout under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx to execute multiple commands in sequence with dependency ordering. RunOnceEx processes entries via the rundll32 shim iernonce.dll, providing a different execution path from standard RunOnce.
6. The executed binary runs in the user's logon session context, inheriting the user's token, environment variables, and integrity level. HKLM-launched processes run in the first logging user's context.
7. Persistence persists across reboots for standard Run keys, as the registry values remain until manually deleted. RunOnce values are self-deleting after a single execution.

## OS Internals Context

The Windows shell (explorer.exe) processes Run and RunOnce keys during its initialization sequence at user logon. The shell reads HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run first, then HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run, executing each value's command string via CreateProcess. The command string is passed as the lpCommandLine parameter, which means it is subject to the same parsing rules as any CreateProcess call — the first token is treated as the executable path, and the shell resolves unqualified paths against the system PATH.

The registry key hierarchy for Run/RunOnce persistence spans both per-machine (HKLM) and per-user (HKCU) scopes. HKLM keys require SeTakeOwnershipPrivilege or administrator access to modify, and they execute for every user who logs on. HKCU keys are writable by the current user without elevation and execute only for that user's sessions. This distinction makes HKCU\...\Run the primary persistence vector for medium-IL implants that have not achieved elevation.

The RunOnce key's self-deleting behavior is implemented by the shell: after executing the command, the shell calls RegDeleteValue on the registry entry. If the command fails to execute (e.g., the binary path is invalid), the shell still deletes the value, meaning a failed RunOnce entry provides no persistence benefit. This contrasts with the standard Run key, which retries on every logon regardless of execution success.

The RunOnceEx mechanism uses a different execution path. Instead of direct CreateProcess by the shell, RunOnceEx entries are processed by iernonce.dll (loaded via rundll32), which reads a structured registry layout with subkeys for each command, supporting dependency ordering and status logging. RunOnceEx entries are also self-deleting.

On 64-bit Windows, the registry's WOW64 redirection affects Run key access. A 32-bit process reading HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run is redirected to HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run. An operator writing a Run key from a 32-bit process must account for this redirection or use KEY_WOW64_64KEY to access the native 64-bit view.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. An implementation would call RegCreateKeyExW to open the target Run key, then RegSetValueExW to write the command string. For HKCU scope, no elevation is required. For HKLM scope, the implementation would need to either run elevated or adjust the process token to include SeTakeOwnershipPrivilege and take ownership of the key before modifying its DACL. The command string should use a fully qualified path to avoid PATH-based execution ambiguity, and the value name should mimic a legitimate startup application to reduce visual anomaly in Autoruns output.

## Why It Matters

Run/RunOnce registry persistence is the most prevalent autostart mechanism in real-world intrusions per SEC670 material, predating and exceeding in frequency the five persistence layers documented in T-017. HKCU\...\Run provides medium-IL persistence without elevation, making it accessible from standard user-context implants. The technique's prevalence in APT operations — SEC670 cites APT28, Emotet, APT39, CherryPicker, and T9000 — demonstrates its operational utility and detection surface tradeoffs.

## Detection Considerations

- **Telemetry sources**: Sysmon EID 12 (registry value set) and EID 13 (registry value renamed) with a target path filter on Run/RunOnce keys. Autoruns detects all Run/RunOnce entries in its Logon category. Windows Security event log EID 4657 (registry value modified) if registry auditing is enabled on the Run keys. EDR products typically monitor Run key modifications as a high-priority persistence indicator.
- **Bypass options**: Using a legitimate-looking binary name and path (e.g., placing the payload in a Program Files subdirectory) reduces anomaly scoring. Setting the value name to mimic a known startup application (e.g., "OneDrive" or "SecurityHealthService") blends with legitimate entries. Using REG_EXPAND_SZ with environment variables obscures the full path in casual inspection.
- **Residual artifacts**: The registry value under Run/RunOnce persists until manually deleted. The referenced binary file on disk remains. Autoruns and similar persistence enumeration tools flag entries with unsigned binaries, unusual paths, or suspicious command-line patterns.

## Related Techniques

- **T-017 Five-Layer Persistence** — T-108 fills the registry Run-key gap absent from T-017's persistence suite
- **T-034 IFEO GlobalFlag and SilentProcessExit Registry Persistence** — distinct registry persistence mechanism using Image File Execution Options rather than Run keys
- **T-038 AppInit_DLLs Registry Persistence** — distinct registry DLL-loading mechanism triggered by user32 import rather than shell logon

## References

- Atlas material: atlas-post-exploit-part5.md, atlas-post-exploit-part14.md, atlas-post-exploit-part16.md
- MITRE ATT&CK: T1547.001 — https://attack.mitre.org/techniques/T1547/001/
- LGTM notes: lgtm:gap-registry-run-key-persistence, lgtm:registry-run-key-persistence-coverage-gap, lgtm:registry-persistence-coverage-gap

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.