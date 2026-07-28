---
id: T-076
name: AV/EDR Cloud Sample Submission OPSEC
category: anti-analysis
tier: B
crate: none
source_file: none
mitre: T1027
tags: [cloud-submission, opsec, egress-discipline, sample-submission, defender-maps, crowdstrike-falcon, sentinelone, signature-generation, vendor-endpoints, behavioral-alert]
origin: atlas-synthesis
member_notes: [lgtm:av-cloud-sample-submission-opsec, lgtm:cloud-sample-submission-egress-discipline]
---

# AV/EDR Cloud Sample Submission OPSEC — Egress Discipline for Sample Submission Prevention

## Summary

SEC670 documents the operational risk that modern AV/EDR products — notably Microsoft Defender SmartScreen, CrowdStrike Falcon, and SentinelOne — automatically upload binaries that trigger behavioral alerts but match no known signature to vendor cloud analysis environments. The cloud sandbox detonates the submitted sample, extracts indicators of compromise, and generates new detection signatures that are distributed to all deployed agents. This process can expose the full capability set and implementation details of a custom implant to the vendor. The operational response is egress discipline: restricting the implant's network access to only the C2 channel, blocking known vendor submission endpoints at the host firewall, and using signed or known-good payload containers where possible to reduce the likelihood of behavioral alerts that trigger submission.

## Mechanism

1. The AV/EDR client monitors process behavior via kernel callbacks (ObRegisterCallbacks for handle operations, PsSetCreateProcessNotifyRoutine for process creation, PsSetCreateThreadNotifyRoutine for thread creation), ETW providers (Microsoft-Windows-Threat-Intelligence for memory operations), and user-mode hooks on ntdll/kernel32 functions. When a process exhibits behavior that matches a heuristic rule — for example, VirtualAllocEx followed by WriteProcessMemory followed by CreateRemoteThread — the client generates a behavioral alert.
2. If the binary that performed the suspicious behavior matches no existing signature in the local signature database, the client packages the executable file (or a memory dump of the loaded image) for cloud submission. The submission includes the binary, the behavioral context (which heuristic rule fired, what API call sequence was observed), and metadata about the process execution context.
3. The submission occurs over HTTPS to a vendor-specific endpoint. Microsoft Defender uses MAPS (Microsoft Active Protection Service) endpoints under *.cloud.app or SmartScreen reputation endpoints. CrowdStrike Falcon sensors submit to falcon-*.crowdstrike.com cloud endpoints. SentinelOne agents submit to management console endpoints under *.sentinelone.net or vendor-specific cloud domains.
4. The vendor's cloud sandbox executes the submitted sample in an instrumented environment with API monitoring, file system change tracking, registry modification logging, and network traffic capture. The sandbox extracts file system, registry, and network IOCs from the execution and generates a detection signature or YARA rule based on the observed behavior and static artifacts.
5. The new signature is distributed to all deployed agents via the vendor's cloud management platform. Retroactive scanning applies the new signature to all endpoints, detecting the implant across the entire fleet — not just the single host where the behavioral alert originally fired.
6. The operational countermeasure is egress isolation: the implant must be prevented from reaching any endpoint other than the C2 server. The operator configures the Windows Filtering Platform (WFP) or the host firewall (netsh advfirewall) to block outbound connections to known vendor submission domains and IP ranges before executing any evasion research or payload testing.
7. Vendor submission endpoints are enumerated via DNS resolution and network traffic analysis during pre-deployment testing. The operator resolves the vendor's cloud domains, identifies the resulting IP ranges, and adds host firewall rules blocking outbound TCP 443 to those ranges.
8. For payload containers, using binaries signed by a trusted certificate authority reduces the likelihood of behavioral alerts, as some AV/EDR products apply reduced scrutiny to signed binaries. However, signing does not guarantee immunity from cloud submission — behavioral anomalies still trigger submission regardless of signature status.

## OS Internals Context

The cloud submission pipeline operates through several Windows subsystems. The AV/EDR client typically runs as a service registered with the Service Control Manager (SCM) under the LocalSystem account or as a protected process (PS_PROTECTED type), with a kernel-mode network filter driver that inspects outbound traffic. When a behavioral alert triggers, the client uses WinHTTP or WinINet to upload the sample binary to the vendor's cloud endpoint over TLS 1.2+.

Microsoft Defender's cloud submission is governed by the MAPS (Microsoft Active Protection Service) configuration. The registry key HKLM\Software\Microsoft\Windows Defender\Spynet contains the SpynetReporting value (0 = disabled, 1 = basic metadata, 2 = advanced with file samples) and the SubmitSamplesConsent value (0 = always prompt, 1 = send safe samples automatically, 3 = send all samples automatically, 7 = never send). In enterprise environments, these settings are controlled via Group Policy under Administrative Templates → Windows Components → Microsoft Defender Antivirus → MAPS.

CrowdStrike Falcon's sensor operates through a kernel-mode driver (typically CSFalconService.sys or similar) with a user-mode service component (CSFalconService.exe) that communicates with the CrowdStrike cloud. The sensor's cloud submission behavior is controlled by sensor policy in the Falcon management console and cannot be disabled from the host without detection — the sensor itself monitors for tampering attempts against its configuration.

Windows Filtering Platform (WFP) provides the kernel infrastructure for network filtering. An operator can add WFP filter rules using the FwpmFilterAdd0 API with the FWPM_LAYER_ALE_AUTH_CONNECT_V4 layer identifier (for outbound IPv4 TCP connections) to block connections to specific remote IP ranges. The netsh advfirewall firewall add rule interface provides a user-mode wrapper around WFP for adding outbound blocking rules targeting specific remote addresses or IP subnets.

The relationship between behavioral alerts and cloud submission is critical: an implant that bypasses EDR hooks (T-016) may still trigger behavioral alerts through kernel callbacks that monitor memory operations (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks) or through ETW Threat Intelligence providers that operate at the kernel level. These kernel-level detection mechanisms are not bypassed by user-mode unhooking, creating a scenario where the implant successfully evades EDR hooks but its behavior still triggers a behavioral alert that leads to cloud submission.

## Key Implementation Details

**No current implementation in the HUGIN source.** The dark_crystal crate does not implement cloud-submission endpoint blocking or egress filtering. The client_rust crate's discovery module (src/discovery.rs) handles C2 endpoint discovery via rentry.co and Sepolia contract lookup but does not implement egress filtering or vendor endpoint blocking. An implementation would consist of: (1) a DNS-based enumeration module that resolves known vendor submission endpoints (Microsoft Defender MAPS endpoints, CrowdStrike cloud endpoints, SentinelOne management endpoints) to IP ranges; (2) a WFP filter injection module or netsh advfirewall rule generator that blocks outbound connections to these IP ranges; (3) a pre-deployment verification check that confirms the C2 channel is the only permitted egress path before executing payloads or evasion research.

## Why It Matters

Cloud sample submission is the highest-impact detection risk for custom implants. A single submission can compromise an entire tool family by exposing implementation details — API call sequences, crypto routines, C2 protocol structure — that vendors use to generate signatures distributed to all endpoints. SEC670 frames this as the principal downside of iterating custom bypasses against real EDR: each iteration risks uploading the sample if the bypass itself triggers a behavioral alert. This discipline sits between T-016 (evasion) and T-020 (anti-analysis) because it governs the operational environment in which evasion techniques are developed and deployed.

## Detection Considerations

- **Telemetry sources**: The AV/EDR client's cloud submission generates outbound TLS connections to vendor domains. Network monitoring (IDS/IPS, proxy logs, DNS query logs) can detect these connections. From the implant's perspective, the submission is passive — the operator does not control or observe the upload, making it a silent detection risk.
- **Bypass options**: Egress isolation is the primary countermeasure. Block vendor submission endpoints at the host firewall before executing any payload. For Microsoft Defender, disable MAPS via registry (HKLM\Software\Policies\Microsoft\Windows Defender\Spynet, set SpynetReporting=0 and SubmitSamplesConsent=7) in environments where Group Policy permits. For CrowdStrike and SentinelOne, the sensor's cloud submission behavior is controlled by vendor-side policy and cannot be disabled from the host without triggering tamper alerts.
- **Residual artifacts**: Host firewall rules blocking vendor endpoints are visible in netsh advfirewall firewall show rule output. Registry changes to MAPS settings are logged in the Microsoft-Windows-Windows Defender/Operational ETW channel. Network connections to vendor endpoints during pre-deployment testing may be logged by network monitoring infrastructure.

## Related Techniques

- **T-016 EDR Evasion Suite** — After bypassing EDR hooks, the implant must prevent cloud submission of its binary; the bypass itself may trigger behavioral alerts via kernel callbacks
- **T-020 Anti-Analysis Suite** — Pre-flight hygiene includes verifying egress isolation before executing evasion research or payload testing
- **T-021 Crypto & Obfuscation** — Build-time feature gating decisions affect the implant's behavioral fingerprint; minimal-feature builds reduce behavioral alert surface and thus reduce cloud submission risk

## References

- Atlas material: atlas-edr-evasion-part1.md (units 11, 35, 36, 37), atlas-edr-evasion-part6.md (unit 7)
- MITRE ATT&CK: T1027 — https://attack.mitre.org/techniques/T1027/
- LGTM notes: lgtm:av-cloud-sample-submission-opsec, lgtm:cloud-sample-submission-egress-discipline

## Source Reference

No current implementation. See atlas material for SEC670 coverage of cloud submission OPSEC discipline.