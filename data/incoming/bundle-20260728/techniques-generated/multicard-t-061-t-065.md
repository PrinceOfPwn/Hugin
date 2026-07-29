<!-- BEGIN CARD T-061 -->
---
id: T-061
name: Registry Watchdog for Situational Awareness and AV Detection
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1518.001
mitre_secondary: [T1012]
tags: [registry-watchdog, regnotifychangekeyvalue, situational-awareness, av-detection, event-driven, configuration-manager, edr-detection]
origin: atlas-synthesis
member_notes: [lgtm:registry-watchdog-situational-awareness]
---

# Registry Watchdog for Situational Awareness and AV Detection — Event-Driven Registry Change Monitoring

## Summary

Registry watchdog monitoring uses RegNotifyChangeKeyValue to receive event-driven notifications when targeted registry keys change, allowing an implant to detect AV and EDR product installation in real time without polling. The technique exploits the Windows Configuration Manager's notify-block mechanism, which signals a caller-supplied event object whenever a change matching a REG_NOTIFY_CHANGE_* filter occurs on a watched key or its subtree. SEC670 frames this as a situational-awareness primitive pointed at HKLM\SOFTWARE\Microsoft, where vendor product keys and Defender state changes surface during security-product installation. Because the watcher blocks on an event rather than enumerating the registry on a timer, its telemetry footprint is a fraction of any polling loop. The primary detection surface is the subsequent re-enumeration performed when the event fires, plus kernel registry callbacks that can observe the notification registration itself.

## Mechanism

1. Build a baseline. Enumerate the watch target — HKLM\SOFTWARE\Microsoft for AV vendor product keys and Defender state, and optionally HKLM\SYSTEM\CurrentControlSet\Services for EDR service and driver registrations — recording the known-good subkey set into an in-memory structure.
2. Open the target key with RegOpenKeyEx, requesting KEY_NOTIFY in addition to KEY_READ. KEY_NOTIFY (0x0010) is the access right that authorizes change-notification registration on the key handle.
3. Create a synchronization event via CreateEvent. Manual-reset versus auto-reset determines whether multiple waiters can observe a single signal.
4. Register the notification with RegNotifyChangeKeyValue, passing the key handle, bWatchSubtree set to TRUE to cover descendant keys, a filter mask composed of REG_NOTIFY_CHANGE_NAME (0x1, subkey addition or deletion), REG_NOTIFY_CHANGE_LAST_SET (0x4, value writes), and REG_NOTIFY_CHANGE_SECURITY (0x8, security-descriptor changes), the event handle, and fAsynchronous set to TRUE.
5. Block a dedicated watcher thread on the event with WaitForSingleObject. The thread consumes no CPU while waiting; no timer or polling loop exists.
6. On signal, re-enumerate the watched key and diff the result against the baseline. Classify newly appeared subkeys against a vendor list (AV and EDR product keys, uninstall entries) and feed the verdict to decision logic — suspend injection, trigger self-deletion, or activate an alternate persistence layer.
7. Re-register RegNotifyChangeKeyValue immediately after handling. Each registration is single-shot; failing to re-arm leaves the watcher blind to subsequent changes.
8. OR REG_NOTIFY_THREAD_AGNOSTIC (0x10000000) into the filter mask when the notification must survive the registering thread's lifetime, so any thread can wait on the event even after the original registrant exits.

## OS Internals Context

The registry is managed in kernel space by the Configuration Manager (Cm). Each open key is represented by a CM_KEY_BODY, and calls to NtNotifyChangeKey (the syscall behind RegNotifyChangeKeyValue) attach a notify block to that body describing the event to signal and the filter mask. When a modifying operation lands on the key — subkey creation, value write, security-descriptor change — Cm walks the attached notify blocks, matches the operation against each filter, and signals the associated event objects. The watch-subtree flag causes Cm to evaluate the filter against descendant key operations as well, which is what makes a single registration on HKLM\SOFTWARE\Microsoft sufficient to observe an entire vendor installation.

The REG_NOTIFY_CHANGE_* filter semantics are precise: REG_NOTIFY_CHANGE_NAME fires on subkey add or delete, REG_NOTIFY_CHANGE_ATTRIBUTES on key attribute changes, REG_NOTIFY_CHANGE_LAST_SET on any value write (the last-write timestamp on the key updates), and REG_NOTIFY_CHANGE_SECURITY on DACL/SACL modification. An AV installer writing its product key and configuration values trips NAME and LAST_SET filters; a service-installing EDR trips NAME on the Services key.

Thread affinity is the subtle contract. By default, a notification registration is bound to the calling thread: if that thread terminates, the Configuration Manager discards its pending notify blocks and the event never fires. REG_NOTIFY_THREAD_AGNOSTIC, available since Windows Vista, severs this binding — the notify block persists independently of any thread, and the event signals whenever the change occurs. For an implant whose worker threads are short-lived or whose watchdog thread might be torn down by a sleep-obfuscation cycle, the thread-agnostic flag is what makes the watcher durable.

The asynchronous mode contract also matters: with fAsynchronous TRUE and an event handle, the call returns immediately and the caller waits on the event. With fAsynchronous FALSE and a NULL event, RegNotifyChangeKeyValue itself blocks the calling thread until a matching change — usable but inflexible, and it occupies the thread for the entire watch duration.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would follow the existing codebase conventions: resolve NtOpenKey, NtNotifyChangeKey, NtEnumerateKey, and NtWaitForSingleObject through the DJB2-hash PEB walker and dispatch them via RecycledGate, avoiding the advapi32 registry thunks entirely. A dedicated watcher thread would own the event handle, maintain the baseline key set in a HashSet, and on each signal re-enumerate, diff, re-arm the notification, and publish a status word (e.g., an AtomicU32 product-detected flag) that other modules — persistence, injection dispatch, self-delete — consult before acting.

## Why It Matters

Every other AV/EDR detection approach in the vault is point-in-time: the implant checks for security products at startup and never learns about a product installed mid-operation. The registry watchdog converts security-product detection into a continuous signal with near-zero cost — one open key handle, one event, one blocked thread. That signal gates operational decisions: whether to proceed with a noisy injection, whether a persistence layer is likely to be quarantined on write, or whether the implant should self-delete before a newly installed EDR finishes initializing its kernel sensor.

## Detection Considerations

- **Telemetry sources**: The Microsoft-Windows-Kernel-Registry ETW provider logs registry operations at high volume and is rarely collected at scale; the watcher's registration and reads are a handful of events against it. Kernel sensors using CmRegisterCallbackEx can observe NtNotifyChangeKey registration itself, including the watched key path. Sysmon event IDs 12, 13, and 14 capture the installer's registry writes — the changes that trip the filter — but not the watch.
- **Bypass options**: Watching a parent key with subtree scope (one registration) generates less telemetry than per-vendor-key registrations. Performing the post-signal diff with direct NT enumeration avoids Win32 registry API hooks.
- **Residual artifacts**: No files or registry writes by the watcher itself. The open key handle and event handle exist for the watcher's lifetime and are visible in handle-table enumeration of the process.

## Related Techniques

- **T-017 Five-Layer Persistence** — the watchdog's install-detection signal gates persistence-layer decisions, such as holding off writes likely to be quarantined.
- **T-020 Anti-Analysis Suite** — Kaguya performs a one-shot EDR/AV inventory at startup; the registry watchdog supplies the continuous complement to that point-in-time check.

## References

- Atlas material: atlas-edr-evasion-part1.md
- MITRE ATT&CK: T1518.001 (https://attack.mitre.org/techniques/T1518/001/)
- LGTM notes: lgtm:registry-watchdog-situational-awareness

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-061 -->

<!-- BEGIN CARD T-062 -->
---
id: T-062
name: Security Descriptor Manipulation for Object Access Control
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1222
tags: [sddl, security-descriptor, dacl, null-sid, ace, setnamedsecurityinfo, access-control, object-loosening]
origin: atlas-synthesis
member_notes: [lgtm:sddl-security-descriptor-manipulation]
---

# Security Descriptor Manipulation for Object Access Control — SDDL-Driven DACL Loosening

## Summary

Security descriptor manipulation rewrites the DACL on Windows securable objects — files, services, named pipes, kernel objects — to grant access that the object's original access-control policy denied. The SEC670 material walks through constructing an SDDL string that grants GENERIC_ALL to the NULL SID (S-1-0-0), demonstrating the primitive of loosening an object's DACL so that anonymous or low-privilege access succeeds against a protected object. The technique is the inverse of handle blocking: rather than restricting access to the implant's own objects, it strips access-control barriers from objects the implant needs to reach. Conversion from SDDL text to a binary security descriptor via ConvertStringSecurityDescriptorToSecurityDescriptor, followed by application through SetNamedSecurityInfo or SetSecurityInfo, is the documented entry point. Detection surfaces are permission-change auditing and post-hoc DACL review.

## Mechanism

1. Identify the target object and its object type: a file path (SE_FILE_OBJECT), a service name (SE_SERVICE), a named pipe or other named kernel object (SE_KERNEL_OBJECT). The type determines which SetNamedSecurityInfo object-type constant applies.
2. Construct the SDDL string encoding the desired DACL. The material's Example #1 builds a DACL containing a single ACCESS_ALLOWED ACE granting GENERIC_ALL to S-1-0-0: in SDDL syntax, `D:(A;;GA;;;S-1-0-0)`, where `D:` introduces the DACL, `A` marks an access-allowed ACE, `GA` is the GENERIC_ALL rights alias, and S-1-0-0 is the NULL SID.
3. Convert the SDDL text into a self-relative PSECURITY_DESCRIPTOR with ConvertStringSecurityDescriptorToSecurityDescriptorW. The returned buffer is LocalAlloc-owned and freed with LocalFree.
4. Apply the descriptor with SetNamedSecurityInfoW, passing the object name, the object type, DACL_SECURITY_INFORMATION in the SecurityInfo mask, and the converted descriptor as the new DACL. For an already-open handle, SetSecurityInfo performs the same operation without reopening the object.
5. For services specifically, this is the programmatic equivalent of `sc.exe sdset <service> <SDDL>`; the SCM stores the descriptor and enforces it on subsequent OpenService access checks.
6. Verify by reopening the object from the low-privilege context that was previously denied, or by reading the descriptor back with GetNamedSecurityInfo and confirming the ACE landed.
7. Alternatively, bypass the SDDL layer entirely: build the SECURITY_DESCRIPTOR, ACL, ACE, and SID structures manually in a byte buffer and apply with NtSetSecurityObject — the pattern already used elsewhere in the vault for the inverse operation.

## OS Internals Context

A self-relative security descriptor is a contiguous buffer: a SECURITY_DESCRIPTOR header (Revision, Control, and four offsets to Owner, Group, Sacl, and Dacl), followed by the referenced structures. The Dacl offset points to an ACL — an 8-byte header (AclRevision, AclSize, AceCount) followed by ACEs. Each ACCESS_ALLOWED_ACE is an ACE_HEADER (AceType 0x00, AceFlags, AceSize), a 4-byte ACCESS_MASK, and a variable-length SID. GENERIC_ALL (0x10000000) is a generic right that the access check expands through the object type's GENERIC_MAPPING table into the type's specific rights — for a service, SERVICE_ALL_ACCESS; for a file, FILE_ALL_ACCESS.

The access check (AccessCheck in user mode, SeAccessCheck in the kernel) walks the DACL in order, comparing each ACE's SID against the SIDs present in the caller's access token and accumulating granted rights on match. S-1-0-0 is the NULL SID: authority SECURITY_NULL_SID_AUTHORITY (0), RID 0, conventionally the "Nobody" identifier. The SEC670 example uses it as the grantee to demonstrate the anonymous-access construction, illustrating that the operator controls the full ACE tuple — type, rights, and trustee — with nothing more than a text string.

The right to rewrite a DACL is itself access-controlled: the caller needs WRITE_DAC against the object, which owners hold implicitly (READ_CONTROL and WRITE_DAC are granted to owners via the owner-lookup path), and modifying the SACL additionally demands SE_SECURITY_NAME. For service objects, the descriptor lives in the SCM's database; for kernel objects such as named pipes, it is attached to the object in the Object Manager namespace and persists until the object is destroyed — a transient weakening that vanishes on reboot for pipes but survives for services and files.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

The vault contains the inverse primitive, verified in dark_crystal/crowd/src/block_handle.rs: block_external_handles() hand-builds a self-relative SECURITY_DESCRIPTOR in a byte buffer — Revision 1, Control 0x8004 (SE_SELF_RELATIVE | SE_DACL_PRESENT), a Dacl offset of 20, then an ACL with a DENY Everyone (S-1-1-0) ACE followed by an ALLOW SYSTEM (S-1-5-18) ACE, each carrying PROCESS_ALL_ACCESS — and applies it to a child-process handle through NtSetSecurityObject dispatched via RecycledGate. A loosening implementation would reuse that buffer-construction skeleton verbatim, substituting an ACCESS_ALLOWED ACE whose SID and mask grant the required access, and would target the external object (service, pipe, file) rather than the implant's own process handle.

## Why It Matters

Handle blocking (T-016) hardens the implant; descriptor loosening opens the target. Named pipes hardened against non-admin callers, services whose DACLs block SERVICE_START or SERVICE_CHANGE_CONFIG for the current user, and files ACL'd to SYSTEM-only all become reachable once their DACLs are rewritten. Because the change is an access-control edit rather than a payload, it leaves no code artifacts — the object simply becomes usable, which makes the technique composable with any follow-on capability that needs the object open.

## Detection Considerations

- **Telemetry sources**: Windows Security event 4670 (Permissions changed) fires only when a SACL with audit policy is present on the target object — absent on most objects by default. EDR products that snapshot service DACLs or monitor SCM descriptor writes alert on SE_SERVICE changes; sc.exe sdset equivalence makes service-descriptor edits a known-hunted behavior.
- **Bypass options**: Applying the descriptor via NtSetSecurityObject skips advapi32 and any user-mode hooks on SetNamedSecurityInfo. Targeting transient kernel objects (pipes) leaves no durable artifact after reboot.
- **Residual artifacts**: The modified DACL itself is the artifact. Get-Acl, AccessChk, and sc.exe sdshow reveal it immediately, and a DACL granting broad rights to an unusual trustee on a hardened object is a high-signal forensic find.

## Related Techniques

- **T-016 EDR Evasion Suite** — Block External Handles applies identical SDDL and security-descriptor mechanics in the inverse direction, restricting access to the implant rather than loosening access to target objects.

## References

- Atlas material: atlas-methodology-part7.md
- MITRE ATT&CK: T1222 (https://attack.mitre.org/techniques/T1222/)
- LGTM notes: lgtm:sddl-security-descriptor-manipulation

## Source Reference

No current implementation. Adjacent verified pattern: dark_crystal/crowd/src/block_handle.rs (manual self-relative SECURITY_DESCRIPTOR construction and NtSetSecurityObject application — the inverse, restrictive direction of this primitive).
<!-- END CARD T-062 -->

<!-- BEGIN CARD T-063 -->
---
id: T-063
name: System32 Folder Blending as File-Based Hiding Technique
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1036.005
mitre_secondary: [T1070.006]
tags: [file-blending, system32, masquerading, timestomp, ntfs, filename-convention, anti-forensics]
origin: atlas-synthesis
member_notes: [lgtm:system32-blending-evasion]
---

# System32 Folder Blending as File-Based Hiding Technique — Statistical Obscuration Among Legitimate Files

## Summary

System32 folder blending hides a payload file inside C:\Windows\System32 by exploiting the directory's scale — 4,200 or more existing files — rather than any technical concealment mechanism. The operator selects an insertion point in the middle of the alphabetical listing, derives a filename that matches the naming conventions of surrounding legitimate entries, and aligns the file's timestamps with its neighbors so the artifact survives casual directory inspection. SEC670 documents this as tradecraft aimed at defender workflow: it defeats the human analyst scrolling a directory listing, not the security product scanning file contents. Because the file is fully present on disk and subject to signature checks, hash-set comparison, and content scanning, the technique is a complement to — never a substitute for — payload-level evasion. Its detection surface is everything the technique does not address: true creation timestamps in the NTFS journal, unsigned-code anomaly detection, and known-good hash sets.

## Mechanism

1. Enumerate the target directory with NtQueryDirectoryFile (FileBothDirectoryInformation) or FindFirstFileEx, collecting the complete filename set of System32 and confirming the file count is in the multi-thousand range that provides statistical cover.
2. Compute the insertion point in the lexicographic ordering — the middle of the listing. Human reviewers inspecting a sorted directory concentrate on the first and last screenfuls; an entry in the middle of 4,200 names is rarely eyeballed.
3. Derive the filename from the conventions of the entries adjacent to the insertion point: match length distribution, prefix morphology, and extension mix of the neighbors (for example, mimicking the shape of nearby DLL or EXE names) so the name does not stand out in a sorted view. Verify no collision with a genuine file.
4. Write the payload to the chosen path with NtCreateFile. Writing into System32 requires elevation, and Windows Resource Protection ACLs most System32 objects to TrustedInstaller; the write path must account for this (unprotected location or appropriate privilege).
5. Align timestamps. Open a legitimate neighbor file, read its FILE_BASIC_INFORMATION, and apply its CreationTime, LastWriteTime, and ChangeTime to the payload with NtSetInformationFile (FileBasicInformation) or SetFileTime, so a date-sorted or date-filtered review shows the payload blending into the same install-era window as its neighbors.
6. Match remaining surface attributes: file attributes (archive flag, not hidden — hidden files in System32 draw attention), and, when the payload is a PE, version-resource strings that resemble the neighboring binaries' vendor and description fields.

## OS Internals Context

NTFS stores directory contents in the $I30 index attribute of the directory's $MFT record, organized as a B-tree keyed on filename under case-insensitive Unicode collation. Enumeration therefore returns names in a deterministic lexicographic order, and both the raw API and Explorer's default sort reflect it — which is what makes a "middle of the listing" position computable and stable across tools.

The timestamp-alignment step interacts with a dual-timestamp reality. NTFS maintains two timestamp sets per file: $STANDARD_INFORMATION ($SI), which SetFileTime and NtSetInformationFile modify, and $FILE_NAME ($FN), which the filesystem updates on rename and attribute operations and which user-mode APIs cannot set directly. A file whose $SI creation time claims 2019 but whose $FN timestamps reflect the true write time is a classic timestomp indicator under raw $MFT analysis. The USN journal additionally records the file-creation record with the genuine timestamp at the moment of the write, independent of any later $SI rewrite — timestamp alignment defeats the listing view, not the forensic view.

Code-signing posture is the statistical wall the technique cannot climb. The overwhelming majority of PE files in System32 are Authenticode- or catalog-signed by Microsoft; an unsigned or differently signed binary in that directory is an outlier to any tool that sweeps signatures (Get-AuthenticodeSignature, sigcheck) regardless of filename or position. Similarly, known-good hash sets (NSRL-style, or a golden-image diff) flag the file instantly. The material's framing is explicit on this point: blending is behavioral obscuration against manual inspection, and it composes with persistence and content-level evasion rather than replacing them.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would be a placement module called by the persistence or dropper path: enumerate the directory through the existing RecycledGate NT wrappers, select the mid-listing insertion point, synthesize the filename from neighbor morphology, write the payload, then copy a neighbor's FILE_BASIC_INFORMATION onto it via NtSetInformationFile. The vault's existing self-deletion module represents the counter-forensic complement for when blending fails and the artifact must be removed.

## Why It Matters

Persistence cards cover where implants anchor; this card covers how the anchored file survives the first five minutes of a human triage session. Analysts working from Autoruns output, Explorer listings, or EDR file trees make keep-or-kill decisions on name, location, and date plausibility before ever opening the file. A payload positioned, named, and dated to match 4,200 legitimate neighbors passes that review at zero technical cost, buying the dwell time that technical controls alone would not.

## Detection Considerations

- **Telemetry sources**: Sysmon event ID 11 (FileCreate) logs the write with the true timestamp regardless of subsequent timestomping. The USN journal and $MFT preserve authentic creation records. Signature-verification sweeps and known-good hash comparisons detect the content anomaly that naming cannot fix.
- **Bypass options**: Aligning $SI timestamps removes the date-sort anomaly; matching name morphology defeats visual scans; placing the file mid-listing defeats positional review. Signing the payload or proxying execution through a signed host addresses the signature outlier, which is a separate technique.
- **Residual artifacts**: The file on disk in a WRP-protected tree (the write itself may have generated privileged file-operation telemetry), $SI/$FN timestamp divergence under forensic review, and the USN journal entry.

## Related Techniques

- **T-017 Five-Layer Persistence** — blending is the placement tradecraft for file-backed persistence layers anchoring on disk.
- **T-020 Anti-Analysis Suite** — self-deletion is the counter-forensic complement when a blended artifact is discovered, and IAT camouflage is the static-analysis analog of blending applied at the import level.

## References

- Atlas material: atlas-edr-evasion-part1.md
- MITRE ATT&CK: T1036.005 (https://attack.mitre.org/techniques/T1036/005/)
- LGTM notes: lgtm:system32-blending-evasion

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-063 -->

<!-- BEGIN CARD T-064 -->
---
id: T-064
name: Undocumented NT Enumeration as Syscall-Level Evasion Primitive
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1057
mitre_secondary: [T1106]
tags: [ntquerysysteminformation, native-api, process-enumeration, hook-bypass, undocumented-api, direct-syscall, recon]
origin: atlas-synthesis
member_notes: [lgtm:undocumented-nt-enum-evasion-primitive]
---

# Undocumented NT Enumeration as Syscall-Level Evasion Primitive — NtQuerySystemInformation Reconnaissance

## Summary

Undocumented NT enumeration replaces documented Win32 discovery APIs with direct calls to native system services — principally NtQuerySystemInformation — so that reconnaissance traffic never crosses the user-mode API surface where EDR hooks and API-monitoring ETW providers concentrate. SEC670 explicitly frames NtQuerySystemInformation as the undocumented alternative to EnumProcesses, WTSEnumerateProcessesEx, and CreateToolhelp32Snapshot for process enumeration, returning the same process inventory without touching psapi, kernel32, or WTS API entry points. The trade is implementation complexity: the caller must manage buffer sizing against STATUS_INFO_LENGTH_MISMATCH and parse the linked SYSTEM_PROCESS_INFORMATION structures directly. On modern hosts where EDR also hooks ntdll, the primitive composes with direct or indirect syscall dispatch to remain effective. The detection surface shifts from Win32 API telemetry to ntdll hook coverage and syscall-origin analysis.

## Mechanism

1. Resolve NtQuerySystemInformation without a static import — walk the PEB and ntdll export table by hash rather than calling GetProcAddress, keeping the IAT clean of enumeration-related entries.
2. Allocate a growable buffer with NtAllocateVirtualMemory. NtQuerySystemInformation has no size-query contract for most classes; the caller guesses, checks the status, and retries.
3. Call NtQuerySystemInformation with SystemInformationClass set to SystemProcessInformation (class 5). On STATUS_INFO_LENGTH_MISMATCH (0xC0000004), double the buffer and retry until STATUS_SUCCESS.
4. Walk the returned chain: each SYSTEM_PROCESS_INFORMATION begins with NextEntryOffset (ULONG at offset 0), which links to the next entry; a value of zero terminates the list. Per entry, read UniqueProcessId, InheritedFromUniqueProcessId, SessionId, HandleCount, NumberOfThreads, CreateTime, and the ImageName UNICODE_STRING, whose Buffer pointer references the process-name string stored inline after the fixed fields.
5. For thread-level detail, parse the Threads array of SYSTEM_THREAD_INFORMATION structures that follows each entry's fixed fields — NumberOfThreads gives the count — exposing per-thread create time, start address, state, and wait reason without opening any thread handle.
6. Extend to adjacent classes as the mission requires: SystemModuleInformation (class 11) for the kernel driver list — the EDR driver inventory — SystemHandleInformation (class 16) for the system-wide handle table, and SystemCodeIntegrityInformation for CI policy state.
7. Where ntdll itself is hooked, dispatch the call as a direct or indirect syscall with the SSN resolved independently, bypassing the ntdll stub entirely.

## OS Internals Context

NtQuerySystemInformation is the kernel's general-purpose system-state query interface: (SystemInformationClass, SystemInformation buffer, SystemInformationLength, ReturnLength). The kernel copies class-specific data into the caller's buffer with no capability check for the basic classes, and — operationally decisive — the call returns global state without opening a single process or thread handle. Every documented enumeration API eventually funnels here: EnumProcesses in psapi is a wrapper over this syscall, and the Toolhelp32 snapshot path captures the same underlying process list. The Win32 layer adds nothing but convenience and a hooking surface.

The SYSTEM_PROCESS_INFORMATION layout is a forward-linked array rather than a true array: entries are variable-length because the thread array trails the fixed fields, so navigation is by NextEntryOffset arithmetic only. Fixed fields include CreateTime, UserTime, and KernelTime as LARGE_INTEGERs, the ImageName UNICODE_STRING, BasePriority, UniqueProcessId, InheritedFromUniqueProcessId, HandleCount, and SessionId. Because no handles are opened, the enumeration generates no ObRegisterCallbacks telemetry — the kernel object-manager callbacks that fire on OpenProcess are how many sensors detect process reconnaissance, and this path produces none of it.

The evasion delta is real but bounded. Hooking at the psapi or kernel32 layer misses the direct ntdll call entirely, which is why the material positions the primitive as an evasion technique. However, the standard modern EDR posture hooks ntdll exports as well, so NtQuerySystemInformation called through the ntdll stub is still visible to that class of sensor. The primitive's full strength appears only when combined with the vault's syscall-dispatch capabilities — SSN resolution plus an indirect-syscall gadget — at which point the enumeration never traverses any user-mode stub at all. The remaining observability is kernel-side: syscall-origin heuristics that flag system calls issued from non-ntdll memory.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

The codebase already demonstrates the adjacent pattern: per T-020, the Kaguya module (dark_crystal/crowd/src/kaguya.rs) performs security-product detection via NtQuerySystemInformation, resolved and dispatched without Win32 API calls. A dedicated implementation of this card's primitive would generalize that into a standalone enumeration module: resolve the native function through the existing PEB-walker and DJB2-hash resolution, grow the query buffer on STATUS_INFO_LENGTH_MISMATCH, and expose parsed process, module, and handle inventories to the recon, injection-target-selection, and security-product-detection consumers.

## Why It Matters

Discovery is the first thing an implant does and one of the first places defenders instrument. Replacing the documented enumeration APIs with direct NT queries removes the recon phase from the most heavily hooked API layer, and doing it without opening process handles removes object-manager callback telemetry as well. As a composable primitive, it upgrades every consumer — LOtL inventory, injection target selection, EDR product detection — without changing their logic.

## Detection Considerations

- **Telemetry sources**: Inline ntdll hooks on NtQuerySystemInformation (standard modern EDR coverage) see the call unless dispatched as a direct syscall. Kernel ETW threat-intelligence feeds and syscall-origin analysis flag syscalls issued from memory outside ntdll. Documented-API ETW providers and psapi-layer hooks see nothing.
- **Bypass options**: Direct or indirect syscall dispatch with independently resolved SSNs defeats ntdll hooks; NTDLL unhooking restores a clean stub for the indirect path. Rate-limiting repeated queries avoids behavioral correlation.
- **Residual artifacts**: None on disk and no handles opened. The query buffer exists only in process memory for the duration of the parse.

## Related Techniques

- **T-004 PEB Walker** — provides the import-free resolution of NtQuerySystemInformation that keeps the IAT clean.
- **T-016 EDR Evasion Suite** — NTDLL unhooking and indirect-syscall composition are what keep this primitive effective against sensors that hook ntdll itself.
- **T-023 Client Capabilities Suite** — client reconnaissance features are the consumers of enumeration data produced through this path.

## References

- Atlas material: atlas-enumeration-part1.md
- MITRE ATT&CK: T1057 (https://attack.mitre.org/techniques/T1057/)
- LGTM notes: lgtm:undocumented-nt-enum-evasion-primitive

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-064 -->

<!-- BEGIN CARD T-065 -->
---
id: T-065
name: Certificate Pinning for C2 TLS Transport Validation
category: networking
tier: B
crate: none
source_file: none
mitre: T1071.001
mitre_secondary: [T1573.002]
tags: [certificate-pinning, tls, wininet, mitm-resistance, c2-transport, cert-chain, thumbprint-validation]
origin: atlas-synthesis
member_notes: [lgtm:certificate-pinning-for-c2-transports]
---

# Certificate Pinning for C2 TLS Transport Validation — Offline Server Identity Verification

## Summary

Certificate pinning hardens a C2 TLS transport by validating the server's certificate chain against an expected identity embedded in the implant, independent of the host's trust store. The SEC670 workflow retrieves the negotiated chain from a live connection with InternetQueryOption and INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, walks the chain for display names with CertGetNameString, extracts the certificate hash with CertGetCertificateContextProperty and CERT_HASH_PROP_ID, and compares a hex-encoded thumbprint against the compiled-in pin. The purpose is MITM resistance: TLS-inspecting corporate proxies, researcher interception tooling, and network-level redirection all rely on certificate substitution that the system trust store accepts but a pin rejects. When validation fails, the implant aborts the connection rather than speaking to an interceptor. The detection surface is the abort behavior itself — a handshake that succeeds and then dies — plus the static pin embedded in the binary.

## Mechanism

1. Establish the HTTPS session through the WinINet stack: InternetOpen for the session handle, InternetConnect for the server connection, HttpOpenRequest with INTERNET_FLAG_SECURE, and HttpSendRequest to complete the TLS handshake and submit the request.
2. After the handshake, retrieve the negotiated server chain with InternetQueryOption on the request handle, passing INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT. The call yields a PCCERT_CHAIN_CONTEXT produced by the Schannel and crypt32 chain engine during the handshake.
3. Walk the CERT_CHAIN_CONTEXT: descend rgpChain to the simple chain, iterate its rgpElement array, and pull each CERT_CHAIN_ELEMENT's pCertContext — element zero of chain zero is the leaf (server) certificate; subsequent elements are intermediates and the root.
4. Optionally extract human-readable identity for diagnostics with CertGetNameString on each CERT_CONTEXT, using CERT_NAME_SIMPLE_DISPLAY_TYPE to obtain subject display names.
5. Extract the certificate thumbprint with CertGetCertificateContextProperty on the leaf's CERT_CONTEXT, passing CERT_HASH_PROP_ID. The property is the SHA-1 hash of the encoded certificate blob, returned as 20 bytes.
6. Hex-encode the thumbprint and compare it, case-insensitively, against the pin embedded at build time. A mismatch means the peer is not the expected C2 endpoint.
7. On mismatch, fail closed: tear down the handle stack with InternetCloseHandle, refuse to transmit, and either sleep, switch to an alternate channel, or retry later. On match, release the chain with CertFreeCertificateChain and proceed with the session.

## OS Internals Context

Default Windows TLS validation is a chain build, not an identity check. During the handshake, Schannel hands the server's certificate list to the crypt32 chain engine, which constructs a chain to a root present in the machine or user root store and reports validity. Enterprise TLS inspection exploits exactly this: an inspection root CA deployed through group policy sits in the trusted root store, the proxy re-signs every site on the fly, and chain validation passes for every connection. The same mechanism serves researcher interception — Burp-style tooling works by installing its CA. Pinning operates above the trust store: no matter whose root signed the presented certificate, the connection proceeds only if the presented certificate's hash matches the expected value, so a substituted certificate fails validation even though the operating system considers it fully trusted.

The data structures are crypt32's. A CERT_CONTEXT wraps the encoded certificate (pbCertEncoded, cbCertEncoded, dwCertEncodingType) plus a parsed CERT_INFO. CERT_CHAIN_CONTEXT aggregates the simple and quality chains the engine built; the rgpChain → rgpElement → pCertContext walk is the canonical navigation. CERT_HASH_PROP_ID returns the SHA-1 thumbprint of the encoded blob — the same value displayed in the certificate dialog — which is why the material's comparison converts it to a hex string before matching.

Pin granularity is the design decision the workflow leaves to the operator. Pinning the leaf thumbprint is the strictest identity check but breaks on every certificate reissuance, forcing implant rebuilds on rotation. Pinning an intermediate or root in the chain tolerates leaf rotation but extends trust to every certificate that CA issues. Public-key (SPKI) hashing survives reissuance with the same key pair, but the material documents the CERT_HASH_PROP_ID thumbprint approach; operators accepting its rotation cost get the simplest comparison.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

The verified current state is the antipattern this technique corrects: client_rust/src/tcp_transport.rs defines DangerousVerifier, a rustls ServerCertVerifier whose verify_server_cert unconditionally returns ServerCertVerified::assertion(), and whose TLS 1.2 and 1.3 signature verifiers likewise accept everything. The TLS session path installs this verifier via ClientConfig::builder().dangerous().with_custom_certificate_verifier(...), so the TCP-over-TLS transport performs no peer identity check at all and will speak to any interceptor presenting any certificate. A pinning implementation would replace DangerousVerifier with a verifier that hashes the end-entity CertificateDer presented by the peer and compares it against a compile-time embedded pin, rejecting the handshake on mismatch — or, for WinINet/WinHTTP-based transports such as the staged downloader, implement the material's InternetQueryOption workflow after each request.

## Why It Matters

C2 infrastructure is attacked at the network layer before it is attacked anywhere else: redirected DNS, sinkholed domains, TLS-terminating proxies in front of analysis sandboxes, and corporate egress inspection all present substituted certificates to the implant. Without pinning, every one of these paths yields readable C2 traffic and a controllable session. With it, the implant recognizes the substitution and refuses to speak, preserving both traffic confidentiality and channel integrity. The technique composes with any TLS transport in the network suite, which is why it stands alone as a card rather than living inside a single transport.

## Detection Considerations

- **Telemetry sources**: A TLS-inspecting proxy observes a handshake that completes and then an immediate teardown or alert — repeated refusals from one host are a behavioral signature of a pinned client. Schannel logs handshake errors to the Windows event log under its channel.
- **Bypass options**: Pinning an issuing CA rather than the leaf reduces abort frequency during legitimate rotation, at the cost of broader trust. Falling back to an alternate transport on pin failure avoids a repetitive refusal pattern against the same proxy.
- **Residual artifacts**: No disk artifacts. The embedded pin is a static indicator recoverable by string and hex-pattern scanning of the binary, and it binds the sample to its C2 certificate for cluster analysis.

## Related Techniques

- **T-022 Network and Protocol Suite** — pinning is the transport-hardening layer for the suite's TLS-bearing channels (HTTP long-poll, TCP/TLS, malleable C2); the suite's TCP transport currently accepts all certificates and is the integration point.

## References

- Atlas material: atlas-exploit-dev-part13.md
- MITRE ATT&CK: T1071.001 (https://attack.mitre.org/techniques/T1071/001/)
- LGTM notes: lgtm:certificate-pinning-for-c2-transports

## Source Reference

No current implementation. Integration point verified: client_rust/src/tcp_transport.rs (DangerousVerifier implementation near the top of the file — the accept-all verifier a pinning implementation would replace).
<!-- END CARD T-065 -->