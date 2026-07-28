---
id: T-041
name: Service Hiding from SCM Enumeration
category: persistence
tier: B
crate: none
source_file: none
mitre: T1564
mitre_secondary: [T1543.003]
tags: [service-hiding, sddl, security-descriptor, dacl, scm, enumeration-evasion, acl-tampering, persistence-stealth]
origin: atlas-synthesis
member_notes: [lgtm:sddl-service-hiding-tradecraft, lgtm:hidden-service-technique, lgtm:service-hiding-coverage-gap]
---

# Service Hiding from SCM Enumeration — DACL-Based Suppression of Service Visibility

## Summary

Service hiding replaces the default security descriptor on an installed Windows service with a custom DACL that denies `SERVICE_QUERY_STATUS` and related rights to interactive users, service accounts, and built-in administrators while preserving full operational access for SYSTEM. The OS primitive exploited is the Service Control Manager's per-service access check: the SCM silently omits any service the caller cannot query from enumeration results, so the service disappears from `sc.exe query`, services.msc, and `Get-Service` while continuing to start and run normally. An operator uses this after registering a service-based persistence mechanism to remove the most common discovery path for that persistence — a plain service listing. The primary detection surface is the non-default security descriptor itself, persisted in the registry under the service's `Security` subkey, plus any Security-log object-access auditing the operator's own SACL generates.

## Mechanism

1. Register the payload service through the normal path — `CreateService` or `sc.exe create` — which creates the service key under `HKLM\SYSTEM\CurrentControlSet\Services\<name>` and assigns the SCM's default security descriptor. SEC670 Lab 4.4 ("NotInService") structures the exercise as three deliverables: the service application, the installation code, and the hiding code.

2. Craft the replacement security descriptor as an SDDL string. The reference string documented in SEC670 was built by SANS instructor Joshua Wright during a live engagement:

   ```
   D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)
     (A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
     (A;;CCLCSWRPWPDTLOCRRC;;;SY)
     (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
   S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
   ```

3. The `D:` section is the DACL. Its first three ACEs are deny ACEs placed ahead of all allows (canonical deny-first ordering) targeting Interactive Users (`IU`), Service logon sessions (`SU`), and Built-in Administrators (`BA`). Each denies the right set `DCLCWPDTSD`: `DC` = SERVICE_CHANGE_CONFIG, `LC` = SERVICE_QUERY_STATUS, `SW` = SERVICE_ENUMERATE_DEPENDENTS, `WP` = SERVICE_STOP, `DT` = SERVICE_PAUSE_CONTINUE, `SD` = DELETE.

4. The subsequent allow ACEs grant constrained rights back. `IU` and `SU` receive `CCLCSWLOCRRC` (SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_ENUMERATE_DEPENDENTS, SERVICE_INTERROGATE, SERVICE_USER_DEFINED_CONTROL, READ_CONTROL). Because deny ACEs are evaluated first, the grants of `LC` and `SW` in these allows are dead letters — the deny has already removed them. `SY` (LocalSystem) receives `CCLCSWRPWPDTLOCRRC`, which adds SERVICE_START and SERVICE_STOP: everything the SCM needs for routine lifecycle management. `BA` receives an ostensibly full allow (`CCDCLCSWRPWPDTLOCRSDRCWDWO`), but the earlier deny strips status query, stop, pause, reconfigure, and delete; administrators retain SERVICE_START, READ_CONTROL, WRITE_DAC, and WRITE_OWNER.

5. The `S:` section is a SACL with a single audit ACE: `(AU;FA;<all rights>;;;WD)` audits failed access attempts by Everyone against every service right.

6. Apply the descriptor. Manual path: `sc.exe sdset <service> "<SDDL>"`. Programmatic path (the route Lab 4.4 steers students toward): convert the SDDL string to a `SECURITY_DESCRIPTOR` with `ConvertStringSecurityDescriptorToSecurityDescriptorW`, then call `SetServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, pSD)` on a service handle opened with the corresponding access. The material also documents the pure-API alternative using `securitybaseapi.h` (`SetSecurityDescriptorControl` to manipulate descriptor control bits such as DACL protection) and `aclapi.h` (`SetNamedSecurityInfo` with the `SE_SERVICE` object type), which builds and applies the ACE list without hand-authoring SDDL.

7. The SCM persists the resulting self-relative security descriptor to the registry at `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Security`, value `Security` (REG_BINARY). The hiding therefore survives reboot along with the service itself.

8. From this point, enumeration suppresses the service. `sc.exe query`, services.msc, `Get-Service`, and any tool riding `EnumServicesStatus`/`EnumServicesStatusEx` omit the service from their output for any caller in the denied groups. The service still starts at boot, because the SCM host process (services.exe) runs as SYSTEM, and the `SY` ACE retains query, start, stop, and pause rights.

## OS Internals Context

Service objects are not kernel objects. The SCM (services.exe) is a user-mode RPC server implementing the MS-SCMR interface over the `\pipe\ntsvcs` named pipe / ncalrpc, and it maintains its own database of service records in memory, backed by the registry. Access control on services is therefore enforced inside services.exe via `AccessCheck` against the stored security descriptor — the kernel object manager, `ObRegisterCallbacks`, and process/thread object callbacks never see a "service" as such. This placement matters for detection: hiding a service produces no kernel-observable event; visibility comes only from RPC-layer telemetry, registry monitoring of the service key, and Security-log auditing driven by the SACL.

The documented enumeration contract is what makes the technique function: `EnumServicesStatusEx` silently omits any service for which the caller lacks `SERVICE_QUERY_STATUS`. There is no error and no placeholder row — the service simply is not in the returned buffer. The deny of `LC` to `IU`, `SU`, and `BA` in the reference DACL is precisely targeted at this contract. Note the asymmetry the string encodes: the service is hidden from administrators, yet administrators hold WRITE_DAC and WRITE_OWNER on it. A responder who suspects the anomaly (for example, by diffing a service list obtained as SYSTEM against one obtained as admin) can open the service with WRITE_DAC, strip the deny ACEs, and re-enumerate. The string is a concealment layer against routine enumeration, not a hard authorization boundary; SYSTEM retains full visibility throughout, which is also why `sc.exe sdshow <service>` executed as SYSTEM discloses the entire custom DACL.

The two-letter SDDL right codes map to service-specific access masks that exist only in the SCM's object model: `CC` SERVICE_QUERY_CONFIG (0x0001), `DC` SERVICE_CHANGE_CONFIG (0x0002), `LC` SERVICE_QUERY_STATUS (0x0004), `SW` SERVICE_ENUMERATE_DEPENDENTS (0x0008), `RP` SERVICE_START (0x0010), `WP` SERVICE_STOP (0x0020), `DT` SERVICE_PAUSE_CONTINUE (0x0040), `LO` SERVICE_INTERROGATE (0x0080), `CR` SERVICE_USER_DEFINED_CONTROL (0x0100), alongside standard rights `RC` READ_CONTROL, `SD` DELETE, `WD` WRITE_DAC, `WO` WRITE_OWNER. Because `CreateService`'s `lpSecurityDescriptor` parameter is usually NULL, nearly every service on a stock system carries the SCM default descriptor; any service whose persisted `Security` value contains deny ACEs against `BA` deviates from baseline in a way that is rare enough to function as a signature on its own. Applying the descriptor requires WRITE_DAC on the service object, which in practice means the installer already runs elevated — consistent with the material's placement of this tradecraft alongside other admin/SYSTEM persistence items in SEC670 Book 4.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C/Win32. The files matched by keyword grep (`client_rust/src/byakugan.rs`, `crates/core/src/experimental/api_hammering.rs`, `crowd/src/kaguya.rs`) were verified and do not implement this technique: `byakugan.rs` is network reconnaissance whose `guess_service()` maps port numbers to service names; `api_hammering.rs` enumerates `SYSTEM\CurrentControlSet\Services` registry keys purely as an anti-sandbox time sink; `kaguya.rs` inventories LOtL binaries and EDR processes. None touch service security descriptors.

An implementation would slot into `dark_crystal/crowd/src/persist/` beside the existing five layers: after the persistence service is created and its handle obtained, convert the reference SDDL with `ConvertStringSecurityDescriptorToSecurityDescriptorW` (windows crate, `Win32_Security`), apply it with `SetServiceObjectSecurity` passing `DACL_SECURITY_INFORMATION`, and free the converted descriptor with `LocalFree` in a drop guard matching the vault's RAII patterns. Setting the SACL component additionally requires `SeSecurityPrivilege`. The builder-side alternative — composing the ACL with `SetEntriesInAclW` and pushing it via `SetNamedSecurityInfo` with `SE_SERVICE` — avoids embedding a telltale SDDL string in the binary at the cost of more code.

## Why It Matters

T-017 establishes that the implant survives; nothing in that suite addresses whether the survival mechanism is visible. A service registered for persistence is one `sc query` away from discovery, and the five-layer suite contains no service-visibility control. This technique occupies a distinct axis — enumeration suppression via object ACLs rather than concealment via filesystem tricks (NTFS EA) or timing (TLS callback) — which is why it earns its own card rather than a footnote under T-017. It is also categorically different from T-020: anti-analysis gates whether the implant runs at all, while service hiding conceals an artifact that is already installed and running. All three member notes flag this as an uncovered gap between the persistence and evasion suites.

## Detection Considerations

Training material does not discuss defender-side detection for this technique beyond what is embedded in the reference string itself. Observable surface, stated conservatively:

- **Telemetry sources**: the reference SDDL carries its own tripwire — the SACL ACE `(AU;FA;<all rights>;;;WD)` audits failed access attempts by any principal against the service. When object-access auditing policy is enabled, probes against the hidden service generate Security-log object-access events with the Service Control Manager as the object server. The material documents no ETW providers or Sysmon event IDs for this technique.
- **Bypass options**: the material presents no bypass discussion for this technique; the tradecraft as taught is itself the evasion measure.
- **Residual artifacts**: the self-relative security descriptor persists at `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Security` (REG_BINARY), readable by SYSTEM. `sc.exe sdshow <service>` executed as SYSTEM returns the full SDDL, exposing the deny ACEs against `IU`/`SU`/`BA`. A service whose DACL denies administrators `SERVICE_QUERY_STATUS` is a baseline anomaly, and a differential enumeration — services visible as SYSTEM versus services visible as an administrator — reveals the hidden entry without parsing any descriptors. Administrators retain WRITE_DAC and WRITE_OWNER under the reference string, so the hiding is reversible without taking ownership through the filesystem.

## Related Techniques

- **T-017 Five-Layer Persistence with Resilience Monitor** — the concealment target. T-041 hides the service-execution layer that service-based persistence registers; the resilience monitor reinstalls mechanisms, this technique keeps a reinstalled service out of listings.
- **T-020 Anti-Analysis Suite** — complementary concealment axis. T-020 suppresses execution in hostile analysis environments pre-install; T-041 suppresses visibility of an installed artifact during post-hoc host review.

## References

- Atlas material: atlas-edr-evasion-part2.md (units 3, 4, 5 — SDDL exercise and programmatic hiding APIs), atlas-post-exploit-part17.md (unit 1 — "What Else? Hiding a service," Book 4 persistence module), atlas-post-exploit-part8.md (unit 13 — Lab 4.4 NotInService)
- MITRE ATT&CK: T1564 Hide Artifacts (https://attack.mitre.org/techniques/T1564/); secondary T1543.003 Create or Modify System Process: Windows Service (https://attack.mitre.org/techniques/T1543/003/)
- LGTM notes: lgtm:sddl-service-hiding-tradecraft, lgtm:hidden-service-technique, lgtm:service-hiding-coverage-gap
- Public references: reference SDDL string crafted by Joshua Wright (SANS SEC670 instructor/author) during an engagement, as documented in the SEC670 courseware

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling; the material documents the technique via `sc.exe sdset` for manual application and `securitybaseapi.h`/`aclapi.h` (`SetSecurityDescriptorControl`, `SetNamedSecurityInfo`) for programmatic application in C.