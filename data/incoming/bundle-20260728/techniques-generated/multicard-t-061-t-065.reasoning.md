Let me analyze each cluster spec and produce the five cards.

**T-061: Registry Watchdog for Situational Awareness and AV Detection**
- Category: edr-evasion
- Tier: B
- MITRE: This is about monitoring registry for AV product installation. Best fit... T1082 (System Information Discovery)? Or T1518.001 (Security Software Discovery)? The technique detects AV product installation — T1518.001 Software Discovery: Security Software. That's the best fit.
- Crate: none (no source implements this — I checked the file manifest; no registry watchdog file exists)
- member_notes: ['lgtm:registry-watchdog-situational-awareness']
- would_relate_to: T-017, T-020
- Material details: RegNotifyChangeKey, HKLM\SOFTWARE\Microsoft, REG_NOTIFY_THREAD_AGNOSTIC, REG_NOTIFY_CHANGE_* filter set, event-driven not polling.

Key APIs to document: RegOpenKeyEx, RegNotifyChangeKeyValue (the actual API name — material says "RegNotifyChangeKey" but the real Windows API is RegNotifyChangeKeyValue; I should note the material's name vs. actual). The filter flags: REG_NOTIFY_CHANGE_NAME (0x1), REG_NOTIFY_CHANGE_ATTRIBUTES (0x2), REG_NOTIFY_CHANGE_LAST_SET (0x4), REG_NOTIFY_CHANGE_SECURITY (0x8), REG_NOTIFY_THREAD_AGNOSTIC (0x10000000). Uses CreateEvent + WaitForSingleObject pattern. When signaled, re-enumerate subkeys (e.g., HKLM\SOFTWARE\Microsoft\Windows Defender, or AV product keys) and re-register notification.

OS internals: The registry Configuration Manager maintains notify blocks per key; when a change matching the filter occurs, the event is signaled. REG_NOTIFY_THREAD_AGNOSTIC means the notification isn't tied to the registering thread's lifetime — normally if the thread exits, notifications stop. Watch subtree flag (bWatchSubtree = TRUE) monitors subkeys too.

Detection: ETW provider Microsoft-Windows-Kernel-Registry, Sysmon Event ID 12/13/14 (registry object create/delete, value set, rename). RegNotifyChangeKeyValue itself is low-noise. Monitoring HKLM\SOFTWARE is read-only so low telemetry. The callback behavior (subsequent enumeration) generates the telemetry.

**T-062: Security Descriptor Manipulation for Object Access Control**
- Category: edr-evasion
- Tier: B
- MITRE: Best fit... T1222 (File and Directory Permissions Modification)? The material is about loosening DACLs on objects (services, named pipes, kernel objects). T1222.001 or T1078? Actually MITRE T1222 covers permission modification. For named pipes and services, could be T1074? No. The best single fit: T1222 (File and Directory Permissions Modification). Although for generic objects... The LGTM note says it relates to T-016 (handle blocking). I'll use T1222 with secondary T1134? Hmm. Actually manipulating security descriptors on objects to permit access — T1222 fits. Could also use T1098 (Account Manipulation) — no. I'll go with T1222.001 (Windows File and Directory Permissions Modification) as primary... but the material mentions services/named pipes/kernel objects, not just files. Plain T1222 is safer. Actually let me think — SDDL manipulation to grant GENERIC_ALL to NULL SID. This is defense evasion through weakening access controls. T1562 (Impair Defenses)? Not quite. T1222 is the standard mapping for ACL modification. I'll use T1222 with secondary [T1078]? No — keep it simple: T1222, secondary maybe T1554? No. Just T1222.
- Crate: dark_crystal? There's block_handle.rs which does the INVERSE (restricting). The cluster spec's material explicitly says "The vault's T-016 covers handle blocking (restricting access to the implant) but does not cover the inverse primitive: loosening security descriptors." So block_handle.rs does NOT implement this technique — it's the inverse. Rule 8: block_handle.rs restricts access (deny Everyone), whereas T-062 loosens DACLs (grant GENERIC_ALL to NULL SID). So no current implementation. But I can reference block_handle.rs as demonstrating the SDDL/SECURITY_DESCRIPTOR buffer mechanics pattern in Related/Implementation — actually I should say no current implementation, and describe what implementation would look like, noting block_handle.rs shows the manual buffer-construction pattern that would be reused. That's legitimate and verified since block_handle.rs is provided in inputs.
- Source file: none. Crate: none? The pattern would live in dark_crystal but since no implementation, crate: none per rules? The template says crate: dark_crystal|client_rust|none and source_file: verified path or "none". Since no implementation: crate: none, source_file: none. Hmm, but related existing cards like T-030 etc. — I don't have them, but the vault context shows source_file: none cards exist (T-024 etc. presumably). I'll use crate: none, source_file: none.
- member_notes: ['lgtm:sddl-security-descriptor-manipulation']
- would_relate_to: T-016

Material details: SDDL Example #1 from SEC670: granting GENERIC_ALL to NULL SID S-1-0-0. SDDL string like "D:(A;;GA;;;S-1-0-0)". Entry points: ConvertStringSecurityDescriptorToSecurityDescriptor, SetNamedSecurityInfo (or SetSecurityInfo for handles). NULL SID S-1-0-0 — note: S-1-0-0 is the "Nobody" SID (SECURITY_NULL_SID_AUTHORITY, SECURITY_NULL_RID). Granting access to NULL SID is interesting because no token contains it... Actually the LGTM note says "permits anonymous access". Hmm, in the actual SEC670 material, the classic example is a NullDacl or granting to Everyone. The material says S-1-0-0 NULL SID. Actually — there's a subtlety: granting GENERIC_ALL to the NULL SID. Some documentation notes that the NULL SID (S-1-0-0) ACE effectively... The access check compares ACE SIDs against SIDs in the access token; S-1-0-0 appears in no token, so it would grant nobody access. BUT the material frames it as anonymous access. Material wins (Rule 4) — but I should be careful not to fabricate. The consolidated description says "granting GENERIC_ALL to S-1-0-0 permits anonymous access to protected objects." Hmm. Actually, I recall in real Windows: ACEs with the NULL SID are special-cased? Let me think... Actually yes — there's documented behavior where an ACE with the NULL SID grants access to everyone (this is a known quirk; e.g., "Null SID" ACEs match any token in some access check paths). Actually I believe the relevant behavior: the Everyone SID is S-1-1-0; NULL SID S-1-0-0 ACEs... I remember reading that setting a DACL with an ACE for S-1-0-0 effectively behaves like granting Everyone because access check treats the NULL SID ACE specially? I'm not 100% certain. The material asserts it permits anonymous access; I'll present it as the material presents it, describing the SDDL construction, and can note the mechanics of access check (token SIDs compared against ACE SIDs) — with the NULL SID ACE as the wildcard in this example. To stay safe, I'll describe what the material documents without over-claiming internals beyond standard: ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW with SE_OBJECT_TYPE (SE_FILE_OBJECT, SE_SERVICE, SE_KERNEL_OBJECT), DACL_SECURITY_INFORMATION flag. Also SetSecurityInfo for handles. And the inverse use in HUGIN block_handle.rs (manual buffer + NtSetSecurityObject).

Detection: Sysmon doesn't log security descriptor changes directly; SACL-based auditing Event 4670 (permissions changed), ETW Microsoft-Windows-Security-Auditing. Handle-based changes require WRITE_DAC access which itself is logged with 4663 if SACLs set. Residual: modified DACL persists on object; tools like AccessChk, Get-Acl reveal it.

**T-063: System32 Folder Blending**
- Category: edr-evasion
- Tier: B
- MITRE: T1036 (Masquerading) — best fit, maybe T1036.005 (Match Legitimate Name or Location). Yes! T1036.005 "Masquerading: Match Legitimate Name or Location" is exactly this. Primary: T1036.005. Secondary: T1070.006 (Timestomp) for timestamp alignment.
- Crate: none, source_file: none.
- member_notes: ['lgtm:system32-blending-evasion']
- would_relate_to: T-017, T-020

Material: System32 has 4,200+ files; place payload among them; choose middle-listing position (not first/last — humans scan top and bottom); match filename conventions of neighbors; align timestamps (timestomp to match directory median or a legitimate neighbor). Evasion via visual/statistical obscuration targeting manual inspection workflows rather than technical controls.

Mechanism steps: 1) Enumerate target directory (NtQueryDirectoryFile / FindFirstFile) to gather filename distribution stats. 2) Select insertion position — middle of alphabetical listing. 3) Derive filename matching conventions (prefix patterns, length distribution, e.g., mimicking adjacent dll/exe names). 4) Write payload. 5) Align timestamps — read neighbor's FILE_BASIC_INFORMATION (CreationTime, LastWriteTime) and apply via NtSetInformationFile FileBasicInformation. 6) Optionally match version info resources.

OS internals: directory enumeration ordering on NTFS is alphabetical via $I30 index (b-tree), so insertion point is deterministic-ish; humans use Explorer sorted views. NTFS timestamps from $STANDARD_INFORMATION vs $FILENAME (two timestamp sets; usn journal / raw disk parsing reveals discrepancies). SetFileTime/NtSetInformationFile changes $SI times; $FN times require different approach. Detection: file creation Sysmon 11, USN journal, $MFT analysis, Authenticode signature checks (unsigned binaries in System32 are anomalous — most System32 binaries are signed), known-folders hash sets (NSRL). Defender scans regardless of position — this only evades human triage.

**T-064: Undocumented NT Enumeration as Syscall-Level Evasion Primitive**
- Category: edr-evasion
- Tier: B
- MITRE: T1057 (Process Discovery) — material specifically frames NtQuerySystemInformation as alternative to EnumProcesses/WTSEnumerateProcessesEx/CreateToolhelp32Snapshot for process enumeration. Primary: T1057. Secondary: T1082? No — keep T1057, maybe secondary T1106 (Native API). Actually T1106 is "Native API" execution — fitting as secondary. Primary T1057.
- Crate: none? Wait — does any HUGIN source implement this? T-020's Kaguya "Detects security products (EDR/AV) via NtQuerySystemInformation" per T-020 card. kaguya.rs is in the file manifest: "src/kaguya.rs": role "LOtL binary inventory + EDR detection". The T-020 card says "Detects security products (EDR/AV) via NtQuerySystemInformation. All checks via NtOpenFile (RecycledGate) — zero Win32 API". So kaguya.rs uses NtQuerySystemInformation for security product detection. But is that the primary mechanism of T-064 (process enumeration via NT API as evasion)? The card describes enumeration primitives bypassing Win32 hooks. kaguya.rs uses it for EDR detection (process enumeration presumably). Hmm. Rule 8: at least ONE function must implement the primary mechanism the card describes. The primary mechanism: direct NT enumeration (NtQuerySystemInformation with SystemProcessInformation) as an evasion alternative to documented Win32 enumeration APIs. Kaguya detecting security products via NtQuerySystemInformation is close — it likely enumerates processes via SystemProcessInformation. But kaguya.rs is NOT in my provided inputs (I only have tcp_transport.rs, runner.rs, block_handle.rs, schtask.rs). Rule: "If a .rs file is in your inputs" — only these four are in inputs. I cannot verify kaguya.rs's actual code. The T-020 card (provided) states it detects security products via NtQuerySystemInformation. That's a provided related card, so I can reference it as grounding. But for source_file attribution, I should be conservative: the primary mechanism (general NT enumeration primitive as evasion) is documented for future implementation; kaguya's use is adjacent. I'll write: "No current implementation in the HUGIN source" for the standalone primitive, but mention in implementation details that crowd/src/kaguya.rs uses NtQuerySystemInformation for security-product detection per T-020, demonstrating the resolution pattern. Actually to be careful: source_file should be "none" since the standalone technique isn't implemented, and I can't verify kaguya's functions. I'll note in Key Implementation Details the adjacent usage in kaguya.rs as documented by T-020.

Also sysinfo: NtQuerySystemInformation classes: SystemProcessInformation (5) returns SYSTEM_PROCESS_INFORMATION array with NextEntryOffset, ProcessName (UNICODE_STRING from ImageName), UniqueProcessId, handle counts, thread counts, SYSTEM_THREAD_INFORMATION array. Since Windows 10 1809-ish, ProcessName available; also SystemModuleInformation (11) for drivers, SystemHandleInformation (16) for handles. The evasion angle: Win32 EnumProcesses → OpenProcess+EnumProcesses internally calls NtQuerySystemInformation; EDR hooks at kernel32/psapi layer miss direct calls. Caveat: modern EDRs hook ntdll NtQuerySystemInformation too — hence pair with direct/indirect syscalls (T-001, T-002). Material notes: "mostly legacy (modern EDR hooks syscalls)" per priority note — I should reflect that modern EDR hooks ntdll too, so the primitive composes with SSN resolution/indirect syscalls.

**T-065: Certificate Pinning for C2 TLS Transport Validation**
- Category: networking
- Tier: B
- MITRE: Best fit... T1071.001 (Web Protocols)? Or T1573 (Encrypted Channel)? Pinning is about validating C2 server cert to resist MITM — defensive hardening of the implant's comms. ATT&CK doesn't have a pinning technique per se. T1573.002 (Asymmetric Cryptography)? Hmm. The technique is transport validation. I'd go T1573 (Encrypted Channel) primary — no wait, pinning isn't encryption itself. Material-wise it's C2 over TLS with validation. T1071.001 (Web Protocols) is the standard mapping for HTTPS C2. I think T1573.002 or T1071.001. Given T-032 (beaconing) uses T1071.001 and T-022 covers transports, I'll use T1573 (Encrypted Channel) as primary since the essence is TLS channel validation. Hmm, but pinning is specifically certificate validation to prevent MITM/redirection — closest is T1573.002? That's about use of asymmetric crypto. Honestly T1573.002 fits "TLS uses asymmetric crypto" loosely. Many offensive pinning write-ups map to T1071.001. I'll go primary T1071.001 (Web Protocols) secondary T1573.002. That seems defensible.

- Crate: client_rust? Source: tcp_transport.rs is provided — and it implements the OPPOSITE: DangerousVerifier accepts ALL certs (verify_server_cert returns assertion success unconditionally). Rule 8: tcp_transport.rs does NOT implement certificate pinning; it implements cert-validation bypass. So no current implementation of pinning. But this is highly relevant to mention: the provided source actively disables validation, and a pinning implementation would replace DangerousVerifier with a verifier that compares the peer cert hash against a compile-time pinned value. That's a legitimate, verified observation from the provided source. I'll state: no current implementation of pinning; note tcp_transport.rs currently uses a permissive verifier (accept-all), which is the antipattern pinning addresses, and describe implementation: WinHTTP path per material (InternetQueryOption INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, CertGetCertificateContextProperty CERT_HASH_PROP_ID, hex compare) or rustls custom ServerCertVerifier performing SPKI/SHA-256 pin comparison.

Material: SEC670 unit 21 workflow: after HTTPS request via WinHTTP (material says InternetQueryOption — that's WinINet actually; INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT is a WinINet option). Both WinINet supports it. Steps: send request via HttpSendRequest; call InternetQueryOption(hRequest, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &chain_context) to get CERT_CHAIN_CONTEXT; walk chain (cChain, rgpChain, cLowerQualityChainContext etc.); CertGetNameString for display name; CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID,...) to get SHA-1 thumbprint; convert to hex string; compare against hardcoded pin (case-insensitive hex compare); abort connection on mismatch. Modern variant pins SHA-256 of SPKI. Purpose: resist MITM proxies (defensive blue team proxies, TLS-inspecting gateways, researchers with caido/burp) — detect redirection to analysis infrastructure, refuse to talk.

OS internals: WinINet maintains per-request HINTERNET handles; CERT_CHAIN_CONTEXT built by schannel during handshake; chain engine (crypt32) verifies against root CA store; pinning performs validation independent of system trust store — works even if attacker/defender installs rogue root CA on host (common in corp TLS inspection: enterprise root deployed via GPO). Detection: cert validation failures cause connection aborts observable at proxy; consistent pinned-cert refusal looks like... The implant fingerprint: JA3/JA3S of schannel vs custom. Residual: none on disk; pin embedded in binary is a static signature/YARA opportunity; config extraction.

Now format. Frontmatter fields per template:
- id, name (4-8 words), category, tier, crate, source_file, mitre, mitre_secondary (optional), tags (5-10 kebab-case), origin: atlas-synthesis, member_notes.

Length: 800+ words body each, target 1200-1800. Five cards — that's a lot of output but required. Let me draft each efficiently but with depth.

Card T-061 details:

Mechanism steps:
1. Open target key (HKLM\SOFTWARE\Microsoft or vendor-specific) with RegOpenKeyEx / NtOpenKey with KEY_NOTIFY access.
2. Create manual-reset event via CreateEvent/NtCreateEvent.
3. Register notification: RegNotifyChangeKeyValue(hKey, bWatchSubtree=TRUE, dwNotifyFilter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY, hEvent, fAsynchronous=TRUE).
4. Wait on event (WaitForSingleObject / NtWaitForSingleObject) in dedicated thread — no polling loop.
5. On signal: re-enumerate subkeys (RegEnumKeyEx / NtEnumerateKey) and diff against known baseline; check for AV/EDR product keys.
6. Re-register RegNotifyChangeKeyValue to continue monitoring (notification is one-shot per registration).
7. With REG_NOTIFY_THREAD_AGNOSTIC (0x10000000) in filter, notification persists even if registering thread exits — signals go to the event regardless of thread lifetime.

OS internals: Configuration Manager (Cm) notify blocks: each open key object (CM_KEY_BODY) can have attached notify blocks; Cm signals the event when a matching change occurs on the key or (if watching subtree) descendants. Filter semantics: NAME = subkey add/delete; ATTRIBUTES; LAST_SET = value set/write (last write time change); SECURITY = security descriptor change. Asynchronous mode requires an event handle; synchronous mode (hEvent NULL, fAsynchronous FALSE) blocks the calling thread. Default behavior: notifications are tied to the registering thread — when thread terminates, pending notifications are canceled; REG_NOTIFY_THREAD_AGNOSTIC (Vista+) decouples this. AV install detection: installers write to HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, vendor keys under HKLM\SOFTWARE, service registrations under HKLM\SYSTEM\CurrentControlSet\Services. Watching HKLM\SOFTWARE\Microsoft subtree catches Windows Defender signature/AV related changes; watching Services key catches EDR service/driver registration (Microsoft-Windows-Kernel-Registry ETW sees the writes but the watcher's reads are minimal).

Detection: The watcher itself performs one RegNotifyChangeKeyValue + wait — near-zero telemetry footprint vs polling loops that generate repeated registry open/enum ETW events. ETW Microsoft-Windows-Kernel-Registry logs registry operations (high-volume, often not collected). Sysmon 12/13/14 log create/delete/value-set — the installer's writes, not the watch. Kernel registry callbacks (CmRegisterCallbackEx) see the notify registration. Residual: open key handle + event handle.

Why it matters: event-driven situational awareness; operator learns of AV/EDR install mid-operation and can adjust (escalate to self-delete, suspend injection, switch chains) without polling.

Related: T-017 (persistence — watchdog informs persistence decisions), T-020 (anti-analysis — Kaguya does one-shot EDR detection; watchdog is continuous).

Card T-062:

Mechanism:
1. Construct SDDL string: "D:(A;;GA;;;S-1-0-0)" — D: DACL, ACE (A = ACCESS_ALLOWED, GA = GENERIC_ALL, S-1-0-0 NULL SID).
2. ConvertStringSecurityDescriptorToSecurityDescriptorW → PSECURITY_DESCRIPTOR self-relative.
3. Apply: SetNamedSecurityInfoW(objectName, SE_OBJECT_TYPE (SE_FILE_OBJECT / SE_SERVICE / SE_KERNEL_OBJECT), DACL_SECURITY_INFORMATION, ...) or SetSecurityInfo on open handle. Service targets: use SE_SERVICE on service name — equivalent to sc.exe sdset.
4. Verify: GetNamedSecurityInfo / access test from low-priv context.
5. Alternative: manual buffer construction + NtSetSecurityObject (as in HUGIN's block_handle.rs, which does the inverse).

OS internals: Security descriptor layout (self-relative): header (Revision, Control, offsets to Owner/Group/Sacl/Dacl). ACL header + ACEs; ACCESS_ALLOWED_ACE structure; SID S-1-0-0 (SECURITY_NULL_SID_AUTHORITY=0, RID 0). Access check algorithm (AccessCheck / SeAccessCheck): token SIDs vs ACE SIDs in order; first-match semantics with deny-first ordering. GENERIC_ALL maps via GENERIC_MAPPING per object type. WRITE_DAC required to change DACL; SE_SECURITY_NAME needed for SACL. The NULL SID ACE quirk as documented in the material (grants anonymous access). Named pipe hardening inverse: default named pipe DACLs grant Everyone read; tightening uses same API. Service DACLs: sc.exe sdshow/sdset uses SDDL. 

Detection: Event 4670 (Permissions changed) requires SACL auditing on object; ETW-TI? Sysmon doesn't capture ACL changes. Defender for Endpoint may alert on service DACL tampering. Residual: modified DACL persists; visible via AccessChk/Get-Acl/sc sdshow.

Related: T-016 (Block External Handles uses same SDDL mechanics to restrict — inverse primitive).

Card T-063:

Mechanism:
1. Enumerate System32 directory listing (NtQueryDirectoryFile FileBothDirectoryInformation or FindFirstFileEx) collecting filename set, count (~4,200+).
2. Compute insertion point: middle of alphabetical ordering — avoid first/last N entries which human analysts inspect; NTFS directory index returns names in lexicographic order.
3. Select filename: match conventions of neighbors at insertion point (length, prefix morphology, e.g., "mfcm140u.dll"-style or "Windows.*" patterns), ensure no collision with genuine file.
4. Drop payload via NtCreateFile to chosen path.
5. Timestamp alignment: open neighbor file, read FILE_BASIC_INFORMATION, apply its CreationTime/LastWriteTime/ChangeTime to payload via NtSetInformationFile(FileBasicInformation) or SetFileTime; aligns $STANDARD_INFORMATION timestamps with surrounding legit files.
6. Optionally set file attributes (hidden off, archive) to match neighbors; optionally forge version resource.

OS internals: NTFS $I30 index (B-tree) in $MFT directory entry — enumeration order deterministic lexicographic (case-insensitive Unicode collation); Explorer default sort matches. Two timestamp sets: $STANDARD_INFORMATION (settable via API) and $FILE_NAME ($FN, updated on rename/attr ops, not directly settable) — timestomp tools leave $SI/$FN divergence detectable via raw $MFT parsing. USN journal records file creation with true timestamps. Authenticode: most System32 PEs are signed + catalog-signed; unsigned/differently-signed file is statistical outlier regardless of name. System File Protection / WRP (Windows Resource Protection) owns ACLs on System32 — writes require admin + TrustedInstaller ACL bypass or unprotected subpath; write attempts may generate 4663/MpFilter telemetry.

Detection: Sysmon 11 (FileCreate) with true timestamp; USN journal/$MFT forensics; signature-verification sweeps (Get-AuthenticodeSignature over System32 flags unsigned); hash-set comparison vs NSRL/known-good; Defender scans by content not position — technique only defeats manual human review (Autoruns-style listing triage, Explorer eyeballing).

Related: T-017 (persistence placement), T-020 (self-delete is the counter-forensic complement; IAT camouflage is the static-analysis analog — blending at import level).

Hmm, T-020 relation justification: T-020 includes self-deletion and IAT camouflage — complementary anti-forensics. Justify as "complementary file-level anti-forensics."

Card T-064:

Mechanism:
1. Resolve NtQuerySystemInformation via PEB walk + export hash (T-004/T-050 patterns) — no static import.
2. Allocate growable buffer (NtAllocateVirtualMemory); call with SystemProcessInformation (class 5), loop on STATUS_INFO_LENGTH_MISMATCH doubling buffer.
3. Walk returned SYSTEM_PROCESS_INFORMATION chain via NextEntryOffset until 0; per entry read UniqueProcessId, ImageName (UNICODE_STRING buffer at entry+offset), NumberOfThreads, HandleCount, InheritedFromUniqueProcessId, SessionId, CreateTime.
4. Parse embedded SYSTEM_THREAD_INFORMATION array for per-thread detail (start address, state, wait reason) if needed.
5. Optionally direct-syscall the call (SSN from T-002 cascade + gadget from T-001) to bypass ntdll hooks too.
6. Alternative classes: SystemModuleInformation (11) kernel drivers for EDR driver inventory, SystemHandleInformation (16) handles, SystemCodeIntegrityInformation (103).

OS internals: NtQuerySystemInformation contract (SystemInformationClass, buffer, length, ReturnLength); SYSTEM_PROCESS_INFORMATION layout: NextEntryOffset at 0x0, NumberOfThreads 0x4, ... UniqueProcessId at 0x50 (x64), ImageName UNICODE_STRING at 0x60 — I should be careful with exact offsets; better to describe fields without asserting every offset. Actually I can state: NextEntryOffset (ULONG) links entries; fields include CreateTime, UserTime, KernelTime (LARGE_INTEGER), ImageName UNICODE_STRING, BasePriority, UniqueProcessId, InheritedFromUniqueProcessId, HandleCount, SessionId, followed by Threads[] array of SYSTEM_THREAD_INFORMATION. Win32 EnumProcesses in psapi/kernel32 is a thin wrapper over this syscall; WTSEnumerateProcessesEx similar; Toolhelp32 snapshot (NtQuerySystemInformation SystemProcessInformation under the hood too via PssCaptureSnapshot... actually CreateToolhelp32Snapshot uses NtQuerySystemInformation internally as well). The evasion delta: hooks placed by EDR on psapi!EnumProcesses / kernel32 wrappers / ETW on documented APIs miss direct ntdll calls; but ntdll hooking (the common case) still sees it — hence indirect syscall composition. ETW-TI kernel provider logs some NtQuerySystemInformation classes? There's THREAT_INTELLIGENCE... ETW-TI (Microsoft-Windows-Threat-Intelligence) can log process enumeration via NtQuerySystemInformation from PPL-protected sensor — actually ETW-TI logs things like process create, image load, handle operations; I shouldn't overclaim. I'll note kernel callbacks (ObRegisterCallbacks for handles) not relevant since no handles opened — a key advantage: query returns global state without OpenProcess calls, so no ObRegisterCallbacks telemetry, no handle table entries.

Detection: ntdll inline hooks on NtQuerySystemInformation (modern EDR) — bypass via T-001/T-002; Sysmon doesn't log process enumeration; ETW-TI may capture syscall usage; direct syscalls from non-ntdll memory flagged by call-stack analysis. Residual: none (no handles, no files).

Related: T-016 (EDR evasion suite — unhooking makes ntdll path safe), T-023 (client recon capabilities), T-004 (PEB walker — resolution mechanism feeding the call).

Card T-065:

Mechanism (per material, WinINet-based workflow):
1. Establish HTTPS session: InternetOpen → InternetConnect → HttpOpenRequest → HttpSendRequest over INTERNET_FLAG_SECURE.
2. After response headers received (or after send), query chain: InternetQueryOption(hRequest, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &pChainCtx, &size) → PCCERT_CHAIN_CONTEXT.
3. Walk chain context: rgpChain[0]->rgpElement[0]->pCertContext for leaf; iterate cElement for intermediates/root.
4. CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE) for subject/SAN display names (diagnostics/validation).
5. CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, hashBuf, &cb) → SHA-1 thumbprint of cert blob.
6. Hex-encode thumbprint; constant-time-ish case-insensitive compare against embedded pin; on mismatch: InternetCloseHandle cascade, abort, optionally fail-closed sleep/switch C2 channel.
7. CertFreeCertificateChain(pChainCtx) cleanup.

OS internals: schannel performs handshake + chain build via crypt32 chain engine (CertGetCertificateChain) against machine/user root store; enterprise TLS inspection works by installing a root CA — schannel accepts it, so default validation passes; pinning is validation layered above the trust store, keyed to expected cert hash, defeating rogue-root MITM. CERT_CONTEXT fields: dwCertEncodingType, pbCertEncoded, pCertInfo. Pin granularity choices: leaf (rotates), intermediate/CA (stable but broader trust), SPKI hash (survives reissuance) — material covers CERT_HASH_PROP_ID (SHA-1 blob hash). 

Key Implementation Details: no current pinning implementation. Provided source tcp_transport.rs implements rustls DangerousVerifier that unconditionally accepts any cert (verify_server_cert returns ServerCertVerified::assertion()) — the antipattern; pinning implementation replaces it with a verifier hashing pki_types::CertificateDer end-entity and comparing to compile-time embedded pin, or the WinINet workflow from the material for winhttp_dl-style transports. This is a verified observation (the file is in my inputs).

Detection: refusal-to-connect on TLS-inspected networks is itself observable to the inspecting proxy (handshake succeeds then abrupt close / TLS alert); static pin in binary → YARA/config extraction; JA3 fingerprinting of schannel vs rustls. Residual: none on disk; event log schannel errors possible.

Related: T-022 (network suite — composes with HTTP poll, malleable C2, TCP transport).

Now MITRE choices:
- T-061: T1518.001 (Security Software Discovery). Secondary: maybe T1012 (Query Registry)? The mechanism queries registry. I'll do mitre: T1518.001, secondary [T1012].
- T-062: mitre: T1222.001? T1222.001 is "Windows File and Directory Permissions Modification". Objects include services/pipes — broader. I'll use T1222 with secondary [T1562.001]? Impair Defenses isn't quite. Keep T1222 primary, secondary T1078? No. Actually "Indicator Removal"? No. I'll just do T1222 primary without secondary, or secondary T1562.009? No. Keep simple: T1222, mitre_secondary omitted... but template allows omit. Hmm — for named pipes/services, MITRE doesn't have perfect fit. Some map service DACL abuse to T1543.003 (that's service creation). DACL tampering → T1222 is standard. Fine: T1222.
- T-063: T1036.005 primary, secondary T1070.006 (Timestomp).
- T-064: T1057 primary, secondary T1106 (Native API).
- T-065: T1071.001 primary, secondary T1573.002.

Tier B for all per specs. Category: edr-evasion for 061-064, networking for 065.

Crates: all "none" with source_file "none"? Check specs: no matching source files provided for these clusters. The provided source files (tcp_transport.rs, runner.rs, block_handle.rs, schtask.rs) are contextual. For T-065, crate would be client_rust conceptually but no pinning implementation exists — per template "crate: dark_crystal|client_rust|none" — I'll use client_rust? Hmm. Rule 5 says crate from enum. If no implementation, "none" is the honest value since source_file must be "none". I'll use crate: none for all five, source_file: none. Wait — but for T-065 I discuss tcp_transport.rs's DangerousVerifier. The file doesn't implement the technique, so source_file: none is correct per Rule 8. Similarly block_handle.rs for T-062 — inverse primitive, not this technique.

Tags (5-10 kebab-case each):
- T-061: [registry-watchdog, regnotifychangekeyvalue, situational-awareness, av-detection, event-driven, config-manager, edr-detection]
- T-062: [sddl, security-descriptor, dacl, null-sid, ace, setnamedsecurityinfo, access-control, object-hardening]
- T-063: [file-blending, system32, masquerading, timestomp, ntfs, filename-convention, anti-forensics]
- T-064: [ntquerysysteminformation, native-api, process-enumeration, hook-bypass, undocumented-api, direct-syscall, recon]
- T-065: [certificate-pinning, tls, wininet, mitm-resistance, c2-transport, cert-chain, thumbprint]

References sections: Atlas material: atlas-edr-evasion-part1 (T-061, T-063), atlas-methodology-part7 (T-062), atlas-enumeration-part1 (T-064), atlas-exploit-dev-part13 (T-065). MITRE URLs: https://attack.mitre.org/techniques/T1518/001/ etc. LGTM notes as given. Public references: only if in material — none explicitly; maybe omit or state none. For T-061 material mentions SEC670; SEC670 is the training course — the atlas files ARE the SEC670 material, so "Atlas material" line suffices. I'll omit public references line or leave it out entirely? Template says "Public references: <optional — only names explicitly in the atlas material>". I'll omit it.

Word counts: aim ~1000-1400 words body per card. Let me write.

For T-061 Summary first sentence standalone: "Registry watchdog monitoring uses RegNotifyChangeKeyValue to receive event-driven notifications when specific registry keys change, enabling an implant to detect AV/EDR product installation in real time without polling."

Careful about the name: material says "RegNotifyChangeKey" — actual API is RegNotifyChangeKeyValue. I'll use the full correct name and can note it. Rule 4 — material authority but API name correction is fine (well-established Windows documentation).

Now write each card fully.

T-061 Mechanism (numbered):
1. Baseline enumeration of watch target (HKLM\SOFTWARE\Microsoft subtree, HKLM\SYSTEM\CurrentControlSet\Services) building a known-good key set.
2. Open the key with RegOpenKeyEx requesting KEY_NOTIFY (plus KEY_READ).
3. Create an auto/manual-reset event (CreateEvent).
4. Register: RegNotifyChangeKeyValue(hKey, TRUE for subtree watch, filter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY, hEvent, TRUE async). Registration is single-shot.
5. Dedicated thread waits on the event with WaitForSingleObject — blocked, zero CPU, no polling.
6. On signal: diff enumeration against baseline (RegEnumKeyEx / direct NtEnumerateKey), classify new subkeys against AV/EDR vendor list; feed result to decision logic (halt injection, trigger self-delete, switch persistence layer).
7. Re-register the notification immediately after handling to catch subsequent changes.
8. REG_NOTIFY_THREAD_AGNOSTIC (0x10000000) OR'd into filter: notification survives registering-thread exit, allowing the event to be waited on by any thread.

OS internals: CM notify blocks, filter flags meaning, thread-agnostic semantics, KEY_NOTIFY access right (0x10), synchronous vs async mode. Also note the material's target: HKLM\SOFTWARE\Microsoft — vendor/AV keys and Defender under Microsoft subtree. Services key for driver/service installs.

Detection considerations: low telemetry vs polling; ETW Microsoft-Windows-Kernel-Registry; Sysmon 12/13/14 see installer's writes not watch; CmRegisterCallbackEx sees notify registration (kernel sensors); residual artifacts: open handles only.

Word budget check as I go. Let me now compose all five cards carefully. I'll aim for depth but manage total length — 5 cards × ~1200 words is long but required.

Also remember: no banned words (elegant, clever, robust, notable, etc.), no first person, no "worth noting", no rhetorical questions. Careful with "notable" — avoid. Avoid "important". 

For T-064 offsets: I'll describe SYSTEM_PROCESS_INFORMATION fields without fabricating exact byte offsets, or state only NextEntryOffset at offset 0 which is certain. Safe.

For T-062: mention WRITE_DAC, SE_SECURITY_NAME for SACL, SE_OBJECT_TYPE enumeration values (SE_FILE_OBJECT, SE_SERVICE, SE_KERNEL_OBJECT, SE_REGISTRY_KEY...), sc.exe sdset equivalence, the HUGIN block_handle.rs manual buffer construction as the in-vault adjacent pattern (verified from provided source: builds self-relative SECURITY_DESCRIPTOR manually, DENY Everyone + ALLOW SYSTEM, applies via NtSetSecurityObject through RecycledGate).

T-063: mention that System32 writes need elevation; middle-listing position rationale (analysts inspect top/bottom of alphabetical listing, and newly-created files sort by name not date in default views); filename convention matching; timestamp alignment via SetFileTime/NtSetInformationFile FileBasicInformation; $SI vs $FN divergence forensics; WRP/TrustedInstaller; unsigned binary outlier.

T-065: INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT constant; CERT_CHAIN_CONTEXT structure navigation; CERT_HASH_PROP_ID returns SHA-1 thumbprint (20 bytes); hex compare; abort behavior; mention material workflow end-to-end; plus current source antipattern.

Alright, writing final output now. Ensure delimiters exact, frontmatter complete, sections in exact order, Related Techniques with justified entries only.

For T-061 Related Techniques: T-017 Five-Layer Persistence — watchdog output drives persistence-layer install/removal decisions; T-020 Anti-Analysis Suite — Kaguya performs one-shot EDR inventory; the watchdog provides the continuous complement. Justified from would_relate_to.

T-062 Related: T-016 EDR Evasion Suite — Block External Handles applies the same SDDL mechanics in the inverse direction (restricting access to the implant). That's the only justified one; maybe add T-042 (SeBackup/SeRestore ACL bypass)? Not in would_relate_to. Keep to T-016 only... 2 entries preferred? Only T-016 is justified. Fine.

T-063 Related: T-017 (placement for persistence artifacts), T-020 (self-deletion/anti-forensics complement). Both in would_relate_to.

T-064 Related: T-004 (PEB walker resolves the NT function), T-016 (NTDLL unhooking makes the call path safe), T-023 (client recon capabilities consume enumeration data). All in would_relate_to.

T-065 Related: T-022 Network Suite — pinning composes with the TCP/HTTP transports; the current tcp_transport.rs verifier accepts all certs. Justify via would_relate_to + verified source. Maybe only T-022.

Source Reference sections: "No current implementation. See atlas material and MITRE reference for public tooling." For T-065 mention tcp_transport.rs as the file where the change would land (verified present). Template's guidance: if no source: "No current implementation. See atlas material and MITRE reference for public tooling." I can augment with the tcp_transport.rs note in Key Implementation Details, and Source Reference can mention it as integration point with line info — the DangerousVerifier is near the top of tcp_transport.rs (lines ~24-46 roughly). I can cite "src/client_rust/src/tcp_transport.rs (DangerousVerifier impl, ~lines 24-46) — integration point". Path in the repo: given file manifest uses client_rust/src/tcp_transport.rs. I'll use that.

Similarly T-062: block_handle.rs at dark_crystal/crowd/src/block_handle.rs — cite as adjacent pattern, not implementation.

Now write. Body word minimum 800 each. I'll write ~1100-1400 per card.