Let me analyze the three cluster specs and the provided source files.

**T-051: VERSIONINFO Resource Impersonation for Binary Spoofing**
- Category: anti-analysis
- Tier: B
- MITRE: This is metadata spoofing. Best fit is T1036 (Masquerading) — specifically T1036.005 (Match Legitimate Name or Location)? Actually VERSIONINFO metadata spoofing fits T1036 (Masquerading) generally. The MITRE ATT&CK technique for metadata/resource spoofing... T1036 Masquerading is the best fit. Some may argue T1027 (Obfuscated Files or Information). But the technique is about impersonating legitimate application metadata — that's masquerading. T1036.001 is "Invalid Code Signature" — no. I'll go with T1036 (Masquerading) as primary. Actually there's no specific sub-technique for VERSIONINFO spoofing. T1036 is the right call.
- No Rust source implements this (runner.rs, nt_create_process.rs, payload_cfg.rs — none touch VERSIONINFO resources). So Key Implementation Details: no current implementation.
- Crate: none
- member_notes: ['lgtm:binary-versioninfo-impersonation']
- Related: T-020 (Anti-Analysis Suite)

**T-052: Advanced Capability Escalation Decision Framework**
- Category: discovery (per spec, though it's operational/conceptual — the enum includes discovery; spec says discovery)
- Tier: B
- MITRE: This is a methodology. Hmm. Best fit ATT&CK... There isn't a perfect one. The spec says "single best-fit ATT&CK technique ID". For a technique selection framework... maybe T1106 (Native API)? No. The framework is about choosing capabilities based on defender posture. Could be T1518 (Software Discovery — security software discovery)? The triggers include "EDR detected". Actually the note is about escalation options including manual image loading, API hooks, syscalls. MITRE doesn't have a "technique selection" ID. Options: T1055 (Process Injection)? T1106? Honestly, the closest for a decision framework driven by defender discovery is T1518.001 (Security Software Discovery) since the primary trigger is detecting EDR. But the note covers more. I think T1518.001 is defensible because trigger 1 is "defender match (EDR detected)". Alternatively T1082 (System Information Discovery). Hmm. The framework is conceptual; the cluster spec says category: discovery. Given the discovery category, T1518.001 Security Software Discovery fits the defender-matching trigger. I'll use T1518.001 with secondary T1082 maybe. Let me keep it simple: mitre: T1518.001, secondary: [T1082].
- Crate: none (no source implements this; it's methodological)
- member_notes: ['lgtm:advanced-capability-selection-framework']
- Related: T-007, T-016, T-022
- Origin: atlas-exploit-dev-part15

**T-053: CreateProcess vs NtCreateUserProcess Policy Boundary**
- Category: discovery (per spec)
- Tier: B
- MITRE: T1106 (Native API) fits — using NT API directly vs Win32. That's the best fit. Secondary: T1134.004 (Parent PID Spoofing) and T1055.
- Crate: dark_crystal — because src/dark_crystal/crowd/src/nt_create_process.rs implements the NtCreateUserProcess side and documents the policy boundary rationale in its header comments. The file explicitly discusses why NtCreateUserProcess over CreateProcessW, PPID spoofing via PS_ATTRIBUTE_PARENT_PROCESS vs STARTUPINFOEX, Block-DLL policy, etc. So this source does implement the NT direct path and the card is about the boundary. Per Rule 8: at least ONE function must implement the primary mechanism. The card's primary mechanism is the policy boundary comparison — the source implements the NT path (create_suspended, create_and_inject) with PS_ATTRIBUTE_LIST including parent process and mitigation options, which is exactly the "NT layer skips Win32 policy" side. I'll attribute it: source_file: src/dark_crystal/crowd/src/nt_create_process.rs
- member_notes: ['lgtm:createprocess-vs-ntcreateuserprocess-policy-boundary']
- Related: T-014, T-015, T-013, T-016
- Origin: atlas-binary-analysis-part6

For T-051: source files provided (runner.rs, nt_create_process.rs, payload_cfg.rs) — none touch resources. So no implementation. Describe what an implementation would look like: a build.rs embedding a .rc-compiled .res, or post-build resource editing via BeginUpdateResource/UpdateResource with VS_VERSION_INFO.

For T-052: no source implements the framework as code — though crowd's chain.rs / runner.rs do technique selection via config. But the provided sources: runner.rs has a multi-phase runner with config-driven selection (selection_config). Hmm — is runner.rs an implementation of a "capability escalation decision framework"? Not really; it's a static compile-time/config-driven phase runner, not a trigger-based runtime escalation framework. Per Rule 8, the primary mechanism of the card is the trigger-based decision methodology. runner.rs doesn't implement runtime triggers (defender detected → escalate). It's static. So: no current implementation. But I could mention runner.rs shows a static phase pipeline. Careful with rule 8: only attribute if a function implements the primary mechanism. The primary mechanism is a decision framework — conceptual. No function implements it. So crate: none, source_file: none.

Wait — but should I mention the source files in "Key Implementation Details"? The rule says: if no source implements, write the standard line and briefly describe what an implementation would look like. I'll do that for T-052. However, I can note that crowd/runner.rs executes a fixed phase pipeline from compile-time config, which is the closest analog. Actually the template says "If no source implements this technique: Write the standard line... Briefly describe what an implementation would look like (one paragraph)." I'll keep to that but can reference the observed static pipeline as contrast. That seems fine and grounded.

Length: 800-1800 words body per card. Let me write substantial, technically deep cards.

Card T-051 details:
- Mechanism: VERSIONINFO resource (VS_VERSION_INFO) embedded in .rsrc section via .rc file compiled by rc.exe / windres / embed-resource crate. Fields: CompanyName, FileDescription, FileVersion, InternalName, LegalCopyright, OriginalFilename, ProductName, ProductVersion. FixedFileInfo (VS_FIXEDFILEINFO) with dwFileVersionMS/LS etc. MalDev Academy metadata.src unit shows Google Chrome impersonation: CompanyName=Google LLC, FileDescription=Google Chrome, OriginalFilename=chrome.exe, ProductVersion=112.0.5615.86.
- OS internals: .rsrc section layout — resource directory tree (IMAGE_RESOURCE_DIRECTORY): Type (RT_VERSION = 16) → Name/ID → Language. VS_VERSION_INFO root, StringFileInfo with StringTable keyed by language/codepage (040904b0 for US English Unicode), VarFileInfo with Translation. Tools read via GetFileVersionInfo / VerQueryValue, or parse raw resource section. Explorer file properties, task manager, AV heuristics display this. SignTool and signature checks bypass metadata.
- Detection: Sysmon doesn't log versioninfo directly; but Process create events include Description/Company/Product fields? Actually Sysmon Event ID 1 includes "Description", "Product", "Company", "OriginalFileName" fields in the event. Yes — Sysmon EID 1 logs file version info extracted from the binary. So spoofed metadata flows into defender telemetry. Mismatch detection: metadata says chrome.exe but path is %TEMP%\foo.exe; unsigned binary claiming to be Google LLC; entropy heuristics. ETW Microsoft-Windows-Kernel-Process includes some info. Defender can check Authenticode signature vs CompanyName mismatch. YARA rules on resource section.
- Implementation would look like: build.rs invoking embed_resource crate to compile a .rc with VS_VERSION_INFO, or post-build BeginUpdateResourceW/UpdateResourceW/EndUpdateResourceW.

Card T-052 details:
- Four triggers: defender match (EDR detected), tech-savvy admin, stealth requirement, basic technique failure. Four escalation options: manual image loading, API hook reimplementation, C2 callbacks, shellcode execution. Actually the consolidated description says escalation options include manual image loading, API hook reimplementation, direct syscalls, custom tooling; the note says (manual image loading, API hook reimplementation, C2 callbacks, shellcode execution). I'll present both lists faithfully — the note's list for options, and description's variants. Let me use the LGTM note as authority: triggers (defender match, tech-savvy admin, stealth requirement, basic technique failure) and options (manual image loading, API hook reimplementation, C2 callbacks, shellcode execution).
- Mechanism: decision process: recon defender posture → classify trigger → select capability tier → validate in lab → deploy → monitor for failure → re-escalate.
- OS internals context: harder for a methodological card. I can discuss what each escalation option touches: manual image loading (LdrLoadDll bypass, PEB LDR lists not updated), API hook reimplementation (inline hooks vs IAT, trampoline), direct syscalls (SSN, syscall instruction, ntdll hooks bypass), custom tooling vs LotL. Frame these in Windows internals terms.
- Detection: each escalation tier has its own telemetry; the framework itself produces none (operator-side). Note that training material doesn't discuss detection for the framework itself.
- MITRE: T1518.001 (Security Software Discovery) primary since EDR detection is the first trigger; secondary T1082? Maybe just primary. The template allows mitre_secondary optional. I'll include [T1082].

Card T-053 details:
- Mechanism: CreateProcessW → kernelbase!CreateProcessInternalW → applies attribute list (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY), validates, then calls NtCreateUserProcess. NT direct path: RtlCreateProcessParametersEx, PS_CREATE_INFO, PS_ATTRIBUTE_LIST with PS_ATTRIBUTE_IMAGE_NAME (0x20005), PS_ATTRIBUTE_PARENT_PROCESS (0x60000... actually the source uses 0x0006_0000 — attribute number 3 with PS_ATTRIBUTE_HANDLE flag 0x20000? Let me look: standard definition: PS_ATTRIBUTE_PARENT_PROCESS = PsAttributeValue(PsAttributeParentProcess, TRUE, TRUE, FALSE) = 6 | 0x20000 | 0x40000 = 0x60006. Hmm. The source defines const PS_ATTRIBUTE_PARENT_PROCESS: usize = 0x0006_0000; That's 0x60000 which is attribute number... wait 0x60000 = PS_ATTRIBUTE_HANDLE (0x20000) + PS_ATTRIBUTE_INPUT (0x40000)? Standard encoding: bits 0-15 attribute number, 0x10000 thread, 0x20000 input, 0x40000 additive, 0x10000000 unknown. PS_ATTRIBUTE_PARENT_PROCESS documented as 0x00060006? Let me recall from process hacker / NtCreateUserProcess docs: PS_ATTRIBUTE_PARENT_PROCESS = 0x00060006 (attribute number 6, PS_ATTRIBUTE_INPUT | PS_ATTRIBUTE_HANDLE... hmm). Actually documented values from Geoff Chappell / phnt: 
  - PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
  - PS_ATTRIBUTE_THREAD 0x00010000
  - PS_ATTRIBUTE_INPUT 0x00020000
  - PS_ATTRIBUTE_ADDITIVE 0x00040000
  - PS_ATTRIBUTE_HANDLE 0x10000000
  PS_ATTRIBUTE_PARENT_PROCESS = PsAttributeValue(PsAttributeParentProcess=6, HANDLE, INPUT, FALSE) — wait phnt defines: #define PS_ATTRIBUTE_PARENT_PROCESS PsAttributeValue(PsAttributeParentProcess, TRUE, TRUE, FALSE) → 6 | 0x20000 | 0x40000 = 0x60006. The source's 0x0006_0000 = 0x60000 which would be attribute number 0 with flags 0x60000? Hmm, that looks like the author encoded PsAttributeValue(0, TRUE, TRUE, FALSE)? That doesn't match. But I shouldn't over-analyze the source's constants correctness; I can note the attribute encodings as the source defines them: IMAGE_NAME = 0x0002_0005 (attribute 5 with PS_ATTRIBUTE_INPUT — standard documented value is 0x20005 for PS_ATTRIBUTE_IMAGE_NAME, correct), PARENT_PROCESS = 0x0006_0000 (documented phnt value is 0x60006; the source omits the attribute number low bits — hmm 0x60000 has low 16 bits zero). Careful: Rule 4 — material is authority; I can describe what the source does without asserting it's the canonical encoding. Or mention the documented encoding. To be safe, describe: the source encodes attribute tags combining the attribute number with flag bits (PS_ATTRIBUTE_INPUT 0x20000, additive 0x40000), e.g. PS_ATTRIBUTE_IMAGE_NAME as 0x20005, PS_ATTRIBUTE_MITIGATION_OPTIONS as 0x20010, PS_ATTRIBUTE_CLIENT_ID as 0x10003 (attribute 3, INPUT flag... 0x10003 = 0x20000? No: 0x0001_0003 = 0x10003 = PS_ATTRIBUTE_THREAD (0x10000) + 3. Hmm, CLIENT_ID documented as 0x10003 in phnt? PS_ATTRIBUTE_CLIENT_ID = PsAttributeValue(PsAttributeClientId=3, TRUE, FALSE, TRUE)? Actually phnt: PS_ATTRIBUTE_CLIENT_ID PsAttributeValue(PsAttributeClientId, TRUE, FALSE, TRUE) — thread flag 0x10000 + input? Let me not go down this hole. I'll describe the flags at a general level and reference the source constants as written. That's grounded in verified source.

- Policy boundary content:
  - Win32 CreateProcess path: CreateProcessW → CreateProcessInternalW (kernelbase) which: converts paths, applies PROC_THREAD_ATTRIBUTE_LIST built via InitializeProcThreadAttributeList/UpdateProcThreadAttribute (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS for PPID spoof, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY for Block-DLL/ACG, PROC_THREAD_ATTRIBUTE_HANDLE_LIST for handle inheritance), checks AppLocker/WDAC policy, Safer levels, calls into NtCreateUserProcess anyway. EDR hooks typically live at kernelbase!CreateProcessInternalW and kernel32!CreateProcessW/A.
  - NT path: caller builds RTL_USER_PROCESS_PARAMETERS via RtlCreateProcessParametersEx, PS_CREATE_INFO (PsCreateInitialState), PS_ATTRIBUTE_LIST, invokes NtCreateUserProcess directly — bypasses all Win32-layer hooks; the kernel performs its own validation in PspCreateProcess.
  - Policy deltas: Win32 layer is where AppLocker/Safer/WDAC user-mode checks can occur (actually WDAC/AppLocker checks happen in kernel via CI.dll and in CreateProcessInternalW via policy checks — hmm). Careful, material authority: the note says "the Win32 layer (which applies mitigation inheritance, block-dll policy, and parent-process validation) and the NT layer (which skips these)". So per the material: Win32 applies mitigation inheritance, block-dll policy, parent-process validation; NT skips them. I'll ground the card on that claim from the material, plus source header comments: "NtCreateUserProcess is the actual syscall — going direct skips all usermode hook chains in kernelbase!CreateProcessInternalW", "A single call handles PPID spoofing + Block-DLL + suspend — no need for separate InitializeProcThreadAttributeList / UpdateProcThreadAttribute".
  - Also note: even NT path ends in same kernel process-creation callbacks (PsSetCreateProcessNotifyRoutineEx), so EDR kernel telemetry still fires; ETW process events still fire. Detection surface: Sysmon EID 1, kernel callbacks, ETW Microsoft-Windows-Kernel-Process. The delta is usermode hooks.
  - The source implements: create_suspended (PS_ATTRIBUTE_LIST with IMAGE_NAME, CLIENT_ID, optional PARENT_PROCESS with auto explorer.exe resolution via crate::ppid::find_pid_by_name, optional MITIGATION_OPTIONS with BLOCK_NON_MS_BINARIES_ALWAYS_ON = 0x0000_1000_0000_0000), create_and_inject (suspended create + NtAllocateVirtualMemory RW + NtWriteVirtualMemory + NtProtectVirtualMemory → RX + NtQueueApcThread + NtResumeThread — Early Bird style), convenience wrappers create_default_suspended/inject_into_svchost. All via RecycledGate (crate::recycled).
  
- Mechanism steps for T-053: 
  1. Operator chooses path (Win32 wrapper vs NT direct).
  2. Win32: CreateProcessW with EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEX, InitializeProcThreadAttributeList, UpdateProcThreadAttribute PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
  3. kernelbase!CreateProcessInternalW processing; EDR hook points.
  4. NT path: build NT path \??\ prefixed UNICODE_STRING, RtlCreateProcessParametersEx with RTL_USER_PROC_PARAMS_NORMALIZED, PS_CREATE_INFO size 88 state 0, PS_ATTRIBUTE_LIST.
  5. NtCreateUserProcess syscall; kernel PspCreateProcess; process/thread creation notify routines.
  
- OS internals: STARTUPINFOEX / attribute list structure (PPROC_THREAD_ATTRIBUTE_LIST, opaque, sized by InitializeProcThreadAttributeList), PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000 (attribute number 2 with PROC_THREAD_ATTRIBUTE_INPUT flag). PS_ATTRIBUTE encoding (16-bit attribute number, thread/input/additive flags). RtlCreateProcessParametersEx normalized params. The fact CreateProcessW internally calls NtCreateUserProcess since Vista (earlier it used NtCreateProcess? Actually since Win7? CreateProcessInternalW → NtCreateUserProcess; on older Windows it was NtCreateProcess/NtCreateProcessEx. Vista+ NtCreateUserProcess exists. I believe NtCreateUserProcess was introduced in Vista). Also kernel-side: PsCreateProcessNotifyRoutineEx still fires regardless of path — the boundary is user-mode only.

Now, words count per card: target 1200-1800. Let me draft.

Frontmatter tags:
T-051: ['versioninfo', 'metadata-spoofing', 'resource-section', 'masquerading', 'rsrc', 'anti-analysis', 'static-analysis-evasion', 'pe-resources']
T-052: ['operational', 'trigger-framework', 'technique-selection', 'tradecraft', 'escalation', 'edr-detection', 'capability-tiers']
T-053: ['createprocess', 'ntcreateuserprocess', 'ppid-spoofing', 'policy-boundary', 'win32-vs-nt', 'startupinfoex', 'ps-attribute-list', 'block-dll']

MITRE:
- T-051: T1036 (Masquerading). URL: https://attack.mitre.org/techniques/T1036/
- T-052: T1518.001 (Security Software Discovery). URL: https://attack.mitre.org/techniques/T1518/001/
- T-053: T1106 (Native API). secondary: [T1134.004, T1055]. URLs accordingly.

Tier: B for all three per specs.

Category: T-051 anti-analysis; T-052 discovery; T-053 discovery.

Crate: T-051 none; T-052 none; T-053 dark_crystal.

source_file: T-053: src/dark_crystal/crowd/src/nt_create_process.rs. Others "none".

Now write the cards. Each needs: Summary (3-5 sentences, first sentence standalone), Mechanism (numbered), OS Internals Context, Key Implementation Details, Why It Matters, Detection Considerations, Related Techniques, References, Source Reference.

T-051 detection: Sysmon EID 1 logs Description, Company, Product, OriginalFileName — spoofed values flow into telemetry but can be cross-checked (unsigned binary with Google LLC CompanyName; OriginalFilename mismatch with actual filename/path). ETW Kernel-Process events include ImageFileName but not full version info. Defender heuristics: signature-company mismatch, entropy, resource-only analysis with peframe/YARA. Bypass options: sign with valid cert (out of scope), match metadata to actual filename/location (chrome.exe impersonation works best if binary named chrome.exe in plausible path), copy metadata from genuine binaries verbatim. Residual artifacts: the .rsrc section itself is a static artifact; YARA rules.

T-051 mechanism steps:
1. Author .rc file with VS_VERSION_INFO block.
2. Set StringFileInfo entries (CompanyName, FileDescription, FileVersion, InternalName, LegalCopyright, OriginalFilename, ProductName, ProductVersion) to mimic target vendor (Google Chrome example).
3. Set fixed file info (FILEVERSION/PRODUCTVERSION numbers, VOS_NT_WINDOWS32, VFT_APP).
4. Compile .rc → .res (rc.exe / llvm-rc / windres; embed-resource crate in build.rs for Rust).
5. Linker merges .res into .rsrc section of PE.
6. At runtime/on disk, tools (Explorer, tasklist, Sysmon, peframe) read via GetFileVersionInfoSize/GetFileVersionInfo/VerQueryValue or raw resource parse.

OS internals for T-051: .rsrc section: IMAGE_RESOURCE_DIRECTORY tree, three levels (Type RT_VERSION=16 → Name → Language), IMAGE_RESOURCE_DATA_ENTRY pointing to VS_VERSION_INFO blob. VS_FIXEDFILEINFO (dwSignature 0xFEEF04BD). StringFileInfo → StringTable (lang+codepage key "040904b0") → String entries. VarFileInfo → Translation. Version info has no bearing on loader — purely informational; loader ignores RT_VERSION. Explorer, WMI Win32_Process doesn't expose, but CIM Win32_ProcessExecutable? Actually file version via WMI CIM_DataFile. Security tools extract at scan time.

T-052 mechanism: as a methodology: 
1. Baseline: deploy lowest-tier capability.
2. Recon: enumerate defender products (process list, services, drivers, EDR DLLs in processes).
3. Evaluate triggers: (1) defender match — EDR present whose telemetry targets the technique; (2) tech-savvy admin — indicators of active defense (Sysmon, scripts, hunting tooling); (3) stealth requirement — ROE/mission constraint; (4) basic technique failure — API call blocked/alerted.
4. Map trigger to escalation options: manual image loading (replace LoadLibrary), API hook reimplementation (own hooking instead of intercepted APIs), C2 callbacks, direct shellcode execution; (also direct syscalls / custom tooling per consolidated description).
5. Validate: lab-replicate the defender stack, confirm telemetry gap.
6. Deploy and monitor; on failure, escalate again.

OS internals for T-052: explain why each escalation option changes the telemetry surface: LoadLibrary → LdrLoadDll → loader snaps, PEB LDR lists updated, ETW ImageLoad events; manual image loader skips loader bookkeeping. Win32 APIs hooked at kernelbase/ntdll — reimplementing functionality (LotL reimplementation, cf. T-025) avoids hooked entry points. Direct syscalls bypass ntdll stubs but hit kernel callbacks/ETW. Custom tooling vs known-bad binaries (signature avoidance).

Why it matters T-052: the vault's cards exist in isolation; framework provides selection logic; avoids over-exposure (using S-tier when B-tier suffices burns capability), avoids under-matching.

Detection T-052: framework itself is operator-side, no endpoint telemetry. But triggers depend on discovery actions (process/service enumeration) that have their own telemetry (Sysmon doesn't log local process enumeration by default; ETW-Threat-Intelligence can flag suspicious handle opens). Training material doesn't discuss detection for the framework itself — include per template that line? The template says if material does not cover detection, write that line. I can do both: note the framework generates no telemetry but its discovery inputs do, then note material silence. Hmm — better: provide detection considerations of the reconnaissance inputs and escalation artifacts, and state material doesn't discuss detection for the framework itself. That satisfies.

T-053 mechanism (numbered, concrete):
1. Operator decision: Win32 vs NT path.
2. Win32: allocate STARTUPINFOEX, InitializeProcThreadAttributeList(size for N attrs), UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS=0x00020000, hParent), CreateProcessW with EXTENDED_STARTUPINFO_PRESENT.
3. CreateProcessW → kernelbase!CreateProcessInternalW: path conversion, attribute processing, policy application; EDR user-mode hook surface.
4. NT: build_nt_image_path (\??\ prefix), RtlCreateProcessParametersEx(... RTL_USER_PROC_PARAMS_NORMALIZED), PS_CREATE_INFO {size=88, state=PsCreateInitialState=0}, PS_ATTRIBUTE_LIST with IMAGE_NAME (0x20005), CLIENT_ID (0x10003), optional PARENT_PROCESS (source: 0x60000 with opened PROCESS_CREATE_PROCESS handle), optional MITIGATION_OPTIONS (0x20010, u64 BLOCK_NON_MS_BINARIES_ALWAYS_ON=0x0000_1000_0000_0000).
5. NtCreateUserProcess via RecycledGate; returns hProcess/hThread + ClientId PID/TID; RtlDestroyProcessParameters; close parent handle.
6. Kernel side identical: PspCreateProcess → notify routines, ETW.

OS internals T-053: 
- PROC_THREAD_ATTRIBUTE encoding: attribute number in low bits + PROC_THREAD_ATTRIBUTE_INPUT flag 0x00020000; PARENT_PROCESS attribute number 2 → 0x00020000. Wait: PROC_THREAD_ATTRIBUTE_PARENT_PROCESS is defined as ProcThreadAttributeValue(ProcThreadAttributeParentProcess=7? hmm). Actual: PROC_THREAD_ATTRIBUTE_NUMBER mask 0x0000FFFF; ProcThreadAttributeParentProcess = 0x00000007? Let me recall: #define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS ProcThreadAttributeValue (ProcThreadAttributeParentProcess, FALSE, TRUE, FALSE) where ProcThreadAttributeParentProcess = 0x00000007? No wait. Values: ProcThreadAttributeHandleList = 2, ParentProcess = 7? Hmm. PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000 per Windows SDK? Let me check memory: In WinNT.h: #define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS ProcThreadAttributeValue(ProcThreadAttributeParentProcess, FALSE, TRUE, FALSE) → ProcThreadAttributeParentProcess is 0x00000007? Hmm, I recall PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000 is wrong; actual documented constant value: 131072 = 0x20000. Many sources: PROC_THREAD_ATTRIBUTE_PARENT_PROCESS (0x00020000)? Let me think: ProcThreadAttributeValue(Number, Thread, Input, Additive) = ((Number & PROC_THREAD_ATTRIBUTE_NUMBER) | (Thread ? PROC_THREAD_ATTRIBUTE_THREAD : 0) | (Input ? PROC_THREAD_ATTRIBUTE_INPUT : 0) | (Additive ? PROC_THREAD_ATTRIBUTE_ADDITIVE : 0)) with PROC_THREAD_ATTRIBUTE_NUMBER = 0x0000FFFF, THREAD = 0x00010000, INPUT = 0x00020000, ADDITIVE = 0x00040000. ProcThreadAttributeParentProcess = 0x00000007? No — ProcThreadAttributeParentProcess enum = 0x00000007 would give 0x00020007. I've seen PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020007? Hmm... Actually I'm fairly sure PROC_THREAD_ATTRIBUTE_PARENT_PROCESS is defined with number 7? Let me recall from MSDN: PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = ProcThreadAttributeValue(ProcThreadAttributeParentProcess, FALSE, TRUE, FALSE). And the enum: ProcThreadAttributeHandleList = 2, ProcThreadAttributeParentProcess = 7? There is also ProcThreadAttributeMitigationPolicy = 8? Documented: PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007? I genuinely recall MITIGATION_POLICY being 0x20007 and PARENT_PROCESS being 0x20006? Hmm. From winnt.h (documented publicly): 
  #define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS ProcThreadAttributeValue(ProcThreadAttributeParentProcess, FALSE, TRUE, FALSE)
  enum: ProcThreadAttributeHandleList = 2, ProcThreadAttributeParentProcess = 7, ProcThreadAttributePreferredNode = 4, ... Actually the order: ProcThreadAttributePackageFullName = 3? I don't remember exactly. Common known constants: PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020006? I've seen code use 0x20006. Yes — I'm fairly confident PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020006 (attribute 6? hmm). Many snippets: "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000 + 6". Wait no, commonly quoted value is 131072+6=131078? Let me recall a real snippet: In PPID spoofing PoCs: attributes[0].Attribute = 0x00020000 | 6? Hmm. I recall from Adam Chester's blog / ired.team: PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x20006? Hmm, but ired.team uses the named macro. MITIGATION_POLICY: PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x20007. I think ParentProcess number = 6, MitigationPolicy = 7. Yes: ProcThreadAttributeParentProcess = 6 → PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020006. And ProcThreadAttributeMitigationPolicy = 7 → 0x00020007. That matches the NT-side PS attribute numbers being 6 (parent) and 0x10? Hmm interestingly the source's PS_ATTRIBUTE_MITIGATION_OPTIONS = 0x20010 → attribute number 0x10=16? Documented PS_ATTRIBUTE_MITIGATION_OPTIONS = 0x20010 per phnt (attribute number 16? phnt says PsAttributeMitigationOptions = 10 (0x0A)?? not sure). I'll avoid asserting exact numeric constants beyond what the source uses, and for Win32 side use the named macros only (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY) without hard numeric claims. Safe.

- NtCreateUserProcess introduced Vista; before it CreateProcessW used NtCreateProcess(Ex). 
- The Win32 wrapper also: converts DOS paths, creates PEB params (actually RtlCreateProcessParametersEx happens inside CreateProcessInternalW too), handles console allocation, job objects? Job assignment happens after. AppContainer tokens via CreateProcessAsUser / attribute PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES.
- Policy: material says Win32 applies mitigation inheritance, block-dll policy, parent-process validation; NT skips. Hmm — but note: the NT path CAN pass mitigation options via PS_ATTRIBUTE_MITIGATION_OPTIONS (as source does) — the point is the operator chooses explicitly rather than inheriting. I'll present it as: the Win32 layer computes/inherits policy automatically; the NT layer requires explicit opt-in via PS_ATTRIBUTE_LIST, so the operator controls exactly which policies apply.
- Kernel-side convergence: both paths end at PspCreateProcess / nt!NtCreateUserProcess; process notify routines (PsSetCreateProcessNotifyRoutineEx), ETW Microsoft-Windows-Kernel-Process event ID 1, Sysmon EID 1 fire identically — the evasion delta is user-mode hooks and ETW from Win32 subsystem per source header ("Fewer ETW events from the Win32 subsystem").

Detection T-053: user-mode hook bypass means EDRs relying solely on usermode CreateProcess hooks lose visibility; but kernel callbacks still fire; parent-child anomalies (Sysmon EID 1 ParentImage) reveal PPID spoof only if defender compares against CreatorProcessId from kernel ETW (which reports real creator). Microsoft-Windows-Kernel-Process ETW includes CreatorProcessId vs spoofed ParentProcessId mismatch — that's a documented detection for PPID spoofing (F-Secure Countercept research). Since material doesn't cover detection... the note doesn't. But T-015 card presumably does. I'll write detection considerations grounded in well-established Windows internals: ETW Kernel-Process CreatorProcessId vs ParentProcessId mismatch; kernel process callbacks; the source comment claims fewer Win32 ETW events. Residual: none on disk (in-memory only), handles.

Related techniques:
- T-051: T-020 Anti-Analysis Suite — suite covers IAT camouflage/self-deletion but not resource spoofing; VERSIONINFO complements IAT camouflage at static-analysis layer.
- T-052: T-007 (process injection — escalation target for manual image loading/shellcode), T-016 (EDR evasion suite — capabilities selected when defender-match trigger fires), T-022 (networking — C2 callbacks escalation option).
- T-053: T-014 NtCreateUserProcess (implementation of NT side), T-015 PPID Spoofing (both layers), T-013 remaining injection (Early Bird APC combine), T-016 EDR evasion (block-dll policy interplay).

References:
- T-051: atlas-binary-analysis-part8.md; MITRE T1036; lgtm:binary-versioninfo-impersonation; Public references: MalDev Academy (explicitly in material — "MalDev Academy metadata.src unit"). Good.
- T-052: atlas-exploit-dev-part15.md; MITRE T1518.001; lgtm:advanced-capability-selection-framework; Public: SEC670 (explicitly in material).
- T-053: atlas-binary-analysis-part6.md; MITRE T1106 (+T1134.004); lgtm:createprocess-vs-ntcreateuserprocess-policy-boundary; Public: none explicit? The material mentions units 16/17/19 of binary-analysis part6 (likely MalDev Academy). The source header mentions ReactOS/Windows Internals for attribute IDs — "Not all are exposed by ntapi; we define them from ReactOS/Windows Internals sources." So public references: ReactOS, Windows Internals. Both explicitly in source. OK.

Source Reference:
- T-051: "No current implementation. See atlas material and MITRE reference for public tooling."
- T-052: same.
- T-053: src/dark_crystal/crowd/src/nt_create_process.rs — create_suspended (attribute list construction ~lines 240-380), create_and_inject, open_parent_handle, build_nt_image_path. I don't have exact line numbers; give function names and approximate ranges. I can estimate: build_nt_image_path ~lines 190-215, open_parent_handle ~155-185, create_suspended ~240-390, create_and_inject ~410-560. I'll cite function names with approximate ranges but be vague enough ("create_suspended", "create_and_inject"). The template says "File path(s) and line ranges if Rust source implements". I'll give rough ranges based on the file: file is ~570 lines. create_suspended spans roughly lines 245–395; create_and_inject roughly 410–565. Fine.

Key Implementation Details for T-053: verified — the file implements the NT-direct half of the boundary and documents the comparison in its module header. Describe: constants, open_parent_handle via recycled::nt_open_process with PROCESS_CREATE_PROCESS (0x0080), build_nt_image_path prepending \??\, RtlCreateProcessParametersEx from ntapi crate, PsCreateInfo 88 bytes, attribute list max 4, RecycledGate syscall, error cleanup with RtlDestroyProcessParameters + nt_close. create_and_inject: BLOCK_DLL always on, RW alloc (0x3000 MEM_COMMIT|MEM_RESERVE, 0x04 PAGE_READWRITE), write, protect 0x20 PAGE_EXECUTE_READ (non-fatal on failure), NtQueueApcThread with shellcode as APC routine, NtResumeThread — APC fires before entry point.

Word counts: aim ~1300-1600 each. Let me write.

Also note Rule 1 banned words — avoid "elegant", "notable", etc. Avoid "worth noting". Careful.

Also don't define widely-known terms (PEB, syscall, RVA, DLL). Fine.

Let me draft card T-051.

---

# VERSIONINFO Resource Impersonation for Binary Spoofing — Forge Legitimate Vendor Metadata in the PE Resource Section

## Summary
VERSIONINFO resource impersonation embeds forged vendor metadata — CompanyName, FileDescription, OriginalFilename, ProductVersion — into the PE `.rsrc` section so that static analysis tooling attributes the binary to a legitimate application such as Google Chrome or a Windows component. The technique exploits the fact that VS_VERSION_INFO is purely informational: the Windows loader ignores it, while Explorer, Task Manager, Sysmon, and triage tools surface it as authoritative attribution. Operators use it to defeat human triage and metadata-based heuristics that compare binary provenance against known-good vendor strings. Primary detection surface: static scanners and Sysmon Event ID 1 fields (Company, Description, Product, OriginalFileName) that can be cross-checked against Authenticode signatures and file paths.

## Mechanism
1. Author a `.rc` resource script containing a VS_VERSION_INFO root block.
2. Populate StringFileInfo entries: CompanyName=Google LLC, FileDescription=Google Chrome, OriginalFilename=chrome.exe, ProductVersion=112.0.5615.86 (values from the MalDev Academy metadata.src unit), plus FileVersion, InternalName, ProductName, LegalCopyright.
3. Populate the fixed file info: FILEVERSION/PRODUCTVERSION numeric quad, VOS_NT_WINDOWS32, VFT_APP file type, flags 0.
4. Compile the .rc to .res (rc.exe, llvm-rc, windres) and link it; the linker emits a .rsrc section containing the version resource under type RT_VERSION (16).
5. On disk, any tool calling GetFileVersionInfoSize/GetFileVersionInfo/VerQueryValue, or parsing the resource tree directly, receives the forged strings.
6. The binary executes identically — the loader never reads RT_VERSION — so impersonation survives compilation, packing, and in-memory loading because it is data, not code.

## OS Internals Context
The .rsrc section is a three-level resource directory tree: IMAGE_RESOURCE_DIRECTORY at Type level (RT_VERSION = 16), then Name/ID level, then Language level, terminating in IMAGE_RESOURCE_DATA_ENTRY whose OffsetToData/Size locate the VS_VERSION_INFO blob. The blob begins with VS_FIXEDFILEINFO (dwSignature 0xFEEF04BD, dwFileVersionMS/LS numeric version consumed by installer/version-compare APIs), followed by StringFileInfo → one or more StringTable blocks keyed by language+codepage ("040904b0" = en-US Unicode) holding the human-visible strings, then VarFileInfo → Translation. Two representations diverge: VerQueryValue returns the localized strings; the numeric FILEVERSION drives version-comparison logic. Spoofing both keeps the numeric and string forms consistent (112.0.5615.86 as both string and numeric quad). Because the loader, the memory manager, and Authenticode (which hashes specific PE regions via ImageGetDigestStream, excluding none of .rsrc... hmm — actually Authenticode hashes the whole file excluding the checksum field, security directory entry, and the certificate table; .rsrc IS hashed. So modifying version info invalidates an existing signature — worth stating: a signed binary's resource edit breaks its signature; the technique is used on unsigned implants. Careful: Authenticode excludes the Attribute Certificate Table from hashing but includes resources. Yes.) So: editing VERSIONINFO on a signed binary invalidates the signature because .rsrc is within the hashed region; therefore impersonation is applied to unsigned binaries, and the gap "claims Google LLC, carries no signature" is itself a detection heuristic.

Tools differ in what they read: Explorer's Properties → Details tab uses VerQueryValue; Sysmon EID 1 fields Description/Product/Company/OriginalFileName are extracted at process-create time from the on-disk image; some EDR user interfaces display Company as attribution. None of these consumers validate the strings against the signature.

## Key Implementation Details
**No current implementation in the HUGIN source.** This card documents the technique for future implementation. An implementation would add a build step to dark_crystal: a `.rc` script with the VS_VERSION_INFO block compiled via the `embed-resource` crate in `build.rs`, parameterized by a builder profile selecting the impersonation target (chrome.exe, svchost-adjacent Microsoft strings, etc.). A post-build variant would open the compiled binary with BeginUpdateResourceW/UpdateResourceW (RT_VERSION) and commit with EndUpdateResourceW, allowing per-build metadata rotation without recompiling.

## Why It Matters
The vault's T-020 anti-analysis suite manipulates imports (IAT camouflage) and on-disk presence (self-deletion) but does not address provenance metadata, which is the first thing an analyst sees in triage and a field that flows directly into Sysmon EID 1. VERSIONINFO impersonation is a compile-time, zero-runtime-cost control that shapes both human and heuristic judgment before any behavioral analysis begins. It composes with filename/path masquerading: the chrome.exe strings are most effective when the binary actually presents as chrome.exe in a plausible directory.

## Detection Considerations
- **Telemetry sources**: Sysmon Event ID 1 logs Description, Product, Company, OriginalFileName extracted from the image; EDR consoles surface the same; static scanners (peframe, YARA with pe module) read .rsrc directly.
- **Bypass options**: copy metadata verbatim from a genuine binary of the impersonated product (matching both string and numeric versions); align OriginalFilename with the actual on-disk filename; select vendors whose products are unsigned or whose signature absence is unremarkable in the environment.
- **Residual artifacts**: the forged resource is a permanent static artifact — mismatch heuristics (CompanyName "Google LLC" with no Authenticode signature, or OriginalFilename ≠ actual filename/path, or version strings inconsistent with PE timestamps/entropy) are the primary catch. YARA rules matching suspicious vendor strings on unsigned binaries exist in public feeds.
- Training material does not discuss detection beyond the technique's intent to bypass metadata heuristics.

Hmm — the template says "If material does not cover detection: 'Training material does not discuss detection for this technique.'" I provided detection from established knowledge (Sysmon EID 1 fields are well-established). That's allowed under Rule 4 (well-established Windows internals documentation). I'll keep the bullets and drop the last line, or keep a variant. I'll keep bullets without the "material doesn't discuss" line since I have grounded content. Actually the material does frame it as heuristic bypass; detection content from Sysmon is well-established. Fine.

## Related Techniques
- **T-020 Anti-Analysis Suite** — T-020 covers IAT camouflage, self-deletion, and anti-VM; VERSIONINFO impersonation is the static-provenance complement that T-020 does not surface.

## References
- Atlas material: atlas-binary-analysis-part8.md (unit 39, metadata.src)
- MITRE ATT&CK: T1036 — Masquerading (https://attack.mitre.org/techniques/T1036/)
- LGTM notes: lgtm:binary-versioninfo-impersonation
- Public references: MalDev Academy (metadata.src unit)

## Source Reference
No current implementation. See atlas material and MITRE reference for public tooling.

Word count check: summary+mechanism+internals+impl+why+detection ≈ 850-950. Should add a bit more depth. I can expand OS internals (Authenticode hashing detail, VerQueryValue vs raw parse, WMI CIM_DataFile, version compare in installers) and mechanism detail. Good.

---

Card T-052:

# Advanced Capability Escalation Decision Framework — Trigger-Based Selection of Implant Capabilities

## Summary
The Advanced Capability Escalation Decision Framework is a SEC670 methodology for deciding when an implant must move from basic to advanced capabilities based on four explicit triggers and four escalation options. It is an operator-side decision process, not endpoint code: it maps observed defender posture to the minimum sufficient technique tier so that advanced tradecraft is only burned when required. Operators use it to avoid two failure modes — under-matching (a hooked-API technique against an EDR that catches it) and over-matching (deploying direct syscalls where LoadLibrary would have sufficed, exposing premium capability to telemetry and reverse engineering). The framework itself generates no endpoint telemetry; its inputs (defender discovery) and outputs (deployed techniques) carry the detection surface.

## Mechanism
1. Deploy baseline capability tier appropriate to a default-assumed environment.
2. Enumerate defender posture: installed security products, running services/drivers, EDR DLL presence in processes, monitoring tooling.
3. Evaluate the four triggers: (1) **defender match** — a specific EDR is identified whose instrumentation covers the current technique; (2) **tech-savvy admin** — indicators of active, competent defense (hunting scripts, Sysmon, rapid incident response); (3) **stealth requirement** — mission constraint demands minimal telemetry regardless of observed defense; (4) **basic technique failure** — an API call is blocked, an alert fires, or a payload dies in a way that indicates interception.
4. Map the fired trigger(s) to escalation options: **manual image loading** (replace LoadLibrary-based module introduction), **API hook reimplementation** (provide own implementations instead of calling hooked APIs), **C2 callbacks** (shift execution into the communication channel), **shellcode execution** (drop PE artifacts entirely in favor of position-independent payloads). The consolidated cluster description records the same option set in broader terms: manual image loading, hook reimplementation, direct syscalls, custom tooling.
5. Validate the selected technique against a replica of the observed defender stack before deployment.
6. Deploy, monitor for the failure trigger, and re-enter the loop at step 3 if interception recurs.

## OS Internals Context
Each escalation option changes which OS boundary the implant crosses, and therefore which instrumentation sees it. LoadLibrary crosses the user-mode loader (LdrLoadDll in ntdll, loader snaps, PEB LDR list updates, ImageLoad ETW); a manual image loader performs its own mapping, relocation, and import resolution so the loader's bookkeeping and its ETW surface are skipped — at the cost of missing LDR entries that themselves become an anomaly. Calling Win32 APIs crosses kernelbase/ntdll stubs where EDR inline hooks live; reimplementing the functionality (the LotL-reimplementation pattern) or invoking the syscall instruction directly removes the hooked entry points from the call path, leaving only kernel callbacks and ETW-TI as observers. C2 callbacks shift work off the endpoint entirely, reducing local API volume at the price of network telemetry. Shellcode execution removes PE structure from memory, defeating image-based scanning but encountering RWX-page and thread-start-address heuristics. The framework is the act of choosing which boundary to cross after learning which boundaries are watched.

## Key Implementation Details
**No current implementation in the HUGIN source.** This card documents the technique for future implementation. The closest existing analog is the static phase pipeline in `src/dark_crystal/crates/core/src/runner.rs` and crowd's `chain.rs`/`payload_cfg.rs`: technique selection there is fixed at build time by `selection_config` constants (anti-VM on/off, injection type, syscall mode), not re-evaluated at runtime from defender telemetry. A framework implementation would make that pipeline conditional: a posture-assessment phase (EDR process/driver/DLL enumeration) whose results gate which later phases activate, plus failure-feedback handling that re-selects the injection path when a phase returns an interception-indicating error, rather than the current try-next-fallback ordering in `dispatch_injection`.

Wait — rule 3: no suggestions or variant ideas. But the template explicitly instructs: "Briefly describe what an implementation would look like (one paragraph)." That's required by the template, overriding rule 3 for this section. Good.

Careful with claim about runner.rs: "dispatch_injection" tries module_overload → ghosting → threadless → reflection → fiber in fixed order. That's a static cascade, yes. And it uses selection_config gates. Accurate per source.

## Why It Matters
The vault documents 80+ techniques as isolated cards; nothing recorded the selection logic that SEC670 teaches for navigating among them. The framework fills the operational gap between "technique exists" and "technique is appropriate," and it protects high-tier capabilities (RecycledGate, VEH Gate, Early Cascade) from premature exposure against targets that basic tradecraft would have handled. It also gives engagement teams a shared vocabulary for escalation decisions when defender posture shifts mid-operation.

## Detection Considerations
- **Telemetry sources**: the framework is operator-side and emits nothing; its posture-enumeration inputs (process, service, driver, loaded-module inventory) can touch ETW-Threat-Intelligence when suspicious handles are opened, and its outputs inherit the full detection surface of whichever T-NNN is selected.
- **Bypass options**: derive posture from passive sources where possible (file-system artifacts of EDR installs, registry keys) rather than live enumeration; validate escalations in a lab replica to avoid generating the very alerts that confirm defender presence.
- **Residual artifacts**: none from the framework itself; each escalated technique leaves its own artifacts per its card.
- The training material documents the triggers and options but does not discuss detection of the framework itself.

## Related Techniques
- **T-007 Pool Party / process injection** — injection methods are primary escalation targets when the basic-technique-failure trigger fires on module introduction or shellcode execution.
- **T-016 EDR Evasion Suite** — the capability pool selected when the defender-match trigger identifies specific instrumentation (AMSI, ETW, hooks).
- **T-022 Network Suite** — C2 callback escalation shifts execution into the networking layer documented here.

## References
- Atlas material: atlas-exploit-dev-part15.md (unit 38)
- MITRE ATT&CK: T1518.001 — Software Discovery: Security Software Discovery (https://attack.mitre.org/techniques/T1518/001/)
- LGTM notes: lgtm:advanced-capability-selection-framework
- Public references: SEC670 (trigger framework unit)

## Source Reference
No current implementation. The static selection pipeline in src/dark_crystal/crates/core/src/runner.rs and dark_crystal/crowd/src/payload_cfg.rs is the nearest analog; see atlas material for the methodology.

---

Card T-053:

# CreateProcess vs NtCreateUserProcess Policy Boundary — Choosing the Process-Creation Layer

## Summary
Every Win32 process creation flows through one of two layers: CreateProcessW (and its kernelbase internal) which applies attribute-driven policy automatically, or NtCreateUserProcess which accepts a caller-built PS_ATTRIBUTE_LIST and skips the Win32 wrapper entirely. The boundary matters because the Win32 layer is the standard EDR hook point (kernelbase!CreateProcessInternalW) and the layer where mitigation inheritance, Block-DLL policy, and parent-process assignment are handled implicitly, whereas the NT layer requires the operator to specify each policy explicitly and bypasses all user-mode hook chains in the wrapper. Operators choose the NT path when they need PPID spoofing, Block-DLL, and suspended creation in a single syscall with no Win32 API footprint; the Win32 path remains relevant when default policy inheritance and subsystem integration (console, job, AppContainer) are desired. Detection delta: user-mode hooks are skipped, but kernel process-creation notify routines and Kernel-Process ETW fire identically on both paths.

## Mechanism
Win32 path:
1. Caller allocates STARTUPINFOEX and builds a PROC_THREAD_ATTRIBUTE_LIST via InitializeProcThreadAttributeList (which sizes the opaque buffer) and UpdateProcThreadAttribute.
2. PROC_THREAD_ATTRIBUTE_PARENT_PROCESS carries a handle to the spoofed parent (opened with PROCESS_CREATE_PROCESS); PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY carries Block-DLL / ACG bits.
3. CreateProcessW with EXTENDED_STARTUPINFO_PRESENT enters kernelbase!CreateProcessInternalW — the canonical EDR user-mode hook point — which converts paths, processes the attribute list, applies policy, and ultimately calls NtCreateUserProcess itself.

NT-direct path (as implemented in crowd):
4. Convert the image path to an NT path UNICODE_STRING (\??\ prefix applied by build_nt_image_path).
5. Build RTL_USER_PROCESS_PARAMETERS via RtlCreateProcessParametersEx with RTL_USER_PROC_PARAMS_NORMALIZED, using the image path for both ImagePathName and CommandLine.
6. Zero an 88-byte PS_CREATE_INFO with state = PsCreateInitialState (0).
7. Build a PS_ATTRIBUTE_LIST (header length + up to 4 entries): PS_ATTRIBUTE_IMAGE_NAME (0x20005) pointing at the NT path buffer; PS_ATTRIBUTE_CLIENT_ID (0x10003) to receive PID/TID; optionally PS_ATTRIBUTE_PARENT_PROCESS (0x60000) with the spoofed-parent handle — auto-resolving explorer.exe when ppid == 0; optionally PS_ATTRIBUTE_MITIGATION_OPTIONS (0x20010) with BLOCK_NON_MS_BINARIES_ALWAYS_ON (0x0000_1000_0000_0000).
8. Invoke NtCreateUserProcess via RecycledGate with PROCESS_CREATE_FLAGS_SUSPENDED (0x1); on success, destroy the process parameters with RtlDestroyProcessParameters and close the parent handle.
9. For injection, follow with NtAllocateVirtualMemory (MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) → NtWriteVirtualMemory → NtProtectVirtualMemory (PAGE_EXECUTE_READ) → NtQueueApcThread (shellcode as APC routine) → NtResumeThread, so the APC fires before the PE entry point (Early Bird).

## OS Internals Context
CreateProcessW has not performed process creation itself since Vista: CreateProcessInternalW is a thick wrapper that normalizes paths, builds RTL_USER_PROCESS_PARAMETERS, assembles the PS_ATTRIBUTE_LIST from the Win32 attribute list, and calls NtCreateUserProcess. The material frames the policy delta as: the Win32 layer applies mitigation inheritance, Block-DLL policy, and parent-process validation; the NT layer skips these implicit behaviors. Concretely, the Win32 wrapper computes defaults (inheriting the creator's mitigation policy unless overridden, validating the parent handle attribute, selecting console/desktop state), while the NT caller receives exactly the policies encoded in its PS_ATTRIBUTE_LIST — nothing inherited, nothing validated at the wrapper layer. Attribute encodings differ between layers: PROC_THREAD_ATTRIBUTE_* values pack a 16-bit attribute number with THREAD/INPUT/ADDITIVE flag bits, and PS_ATTRIBUTE_* uses the analogous NT-side encoding (attribute number in the low 16 bits, INPUT 0x20000, ADDITIVE 0x40000), which is why crowd defines PS_ATTRIBUTE_IMAGE_NAME as 0x20005 and PS_ATTRIBUTE_MITIGATION_OPTIONS as 0x20010. Both paths converge in the kernel at PspCreateProcess: PsSetCreateProcessNotifyRoutineEx callbacks, WDAC/CI policy evaluation in the kernel, and ETW Microsoft-Windows-Kernel-Process fire regardless of which user-mode layer was used. The crowd header records the practical consequences: CreateProcessW is the most-hooked API across major EDRs, going direct skips the kernelbase hook chain, fewer Win32-subsystem ETW events are generated, and one syscall replaces the InitializeProcThreadAttributeList / UpdateProcThreadAttribute / CreateProcessW sequence.

## Key Implementation Details
`src/dark_crystal/crowd/src/nt_create_process.rs` implements the NT-direct side of the boundary. `build_nt_image_path` prepends `\??\` to Win32 paths and produces the UNICODE_STRING. `open_parent_handle` opens the spoof parent via `crate::recycled::nt_open_process` with PROCESS_CREATE_PROCESS (0x0080). `create_suspended` constructs the 88-byte PS_CREATE_INFO (state 0), assembles the attribute list (IMAGE_NAME always; CLIENT_ID always; PARENT_PROCESS when a PPID is supplied, with `Some(0)` auto-resolving explorer.exe through `crate::ppid::find_pid_by_name`; MITIGATION_OPTIONS when block_dll is set), and issues the syscall through `crate::recycled::nt_create_user_process` — the module documents PS_ATTRIBUTE_PARENT_PROCESS as 0x0006_0000 and notes the constants come from ReactOS/Windows Internals because ntapi does not expose them. `create_and_inject` forces Block-DLL on, then runs the allocate→write→protect→APC→resume chain entirely over RecycledGate (nt_allocate_virtual_memory, nt_write_virtual_memory, nt_protect_virtual_memory, nt_queue_apc_thread, nt_resume_thread) with failure paths that free, terminate, and close in order. Convenience wrappers `create_default_suspended` / `inject_into_svchost` hardcode svchost.exe with explorer.exe PPID spoof.

## Why It Matters
T-014 documents NtCreateUserProcess as a creation primitive and T-015 documents PPID spoofing, but neither card records the policy delta that drives the choice between the layers. That delta is the operational decision: the Win32 wrapper gives automatic policy inheritance and maximal hook exposure; the NT layer gives explicit policy control, single-syscall PPID+Block-DLL+suspend, and no Win32 footprint — while kernel telemetry remains constant on both. Knowing which protections each layer applies prevents both redundant work (spoofing PPID through a hooked API) and false assumptions (expecting the NT path to evade kernel callbacks).

## Detection Considerations
- **Telemetry sources**: ETW Microsoft-Windows-Kernel-Process and PsSetCreateProcessNotifyRoutineEx fire on both paths; Sysmon Event ID 1 logs process creation with ParentImage/ParentProcessId derived from the reported parent. For PPID spoofing on either layer, the kernel ETW CreatorProcessId (the real creator) and the spoofed ParentProcessId diverge — a documented anomaly defenders correlate.
- **Bypass options**: the NT path removes user-mode hook visibility (kernelbase!CreateProcessInternalW is never reached) and reduces Win32-subsystem ETW; crowd's implementation additionally applies BLOCK_NON_MS_BINARIES_ALWAYS_ON at creation so EDR DLLs cannot load into the new process, and delivers the payload by APC before the entry point runs.
- **Residual artifacts**: none on disk — the technique is in-memory; detectable state lives in the new process's creation parameters (reported parent, mitigation flags) and in the Early Bird sequence (suspended create → remote write → APC before first instruction).

## Related Techniques
- **T-014 NtCreateUserProcess** — implements the NT-side primitive this card contrasts against the Win32 wrapper.
- **T-015 PPID Spoofing** — both layers can spoof the parent (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS vs PS_ATTRIBUTE_PARENT_PROCESS); this card defines where each is enforced.
- **T-013 Remaining Injection Methods** — Early Bird APC is the natural payload-delivery follow-on to suspended NT creation, as used by create_and_inject.
- **T-016 EDR Evasion Suite** — Block-DLL policy and hook bypass are the evasion controls whose layer-of-application this card clarifies.

## References
- Atlas material: atlas-binary-analysis-part6.md (units 16, 17, 19)
- MITRE ATT&CK: T1106 — Native API (https://attack.mitre.org/techniques/T1106/); T1134.004 — Access Token Manipulation: Parent PID Spoofing
- LGTM notes: lgtm:createprocess-vs-ntcreateuserprocess-policy-boundary
- Public references: ReactOS, Windows Internals (attribute constant sources cited in crowd module header)

## Source Reference
src/dark_crystal/crowd/src/nt_create_process.rs — build_nt_image_path, open_parent_handle, create_suspended (PS_ATTRIBUTE_LIST construction and RecycledGate dispatch), create_and_inject (allocate→write→protect→APC→resume), convenience wrappers create_default_suspended / inject_into_svchost.

---

Check rules:
- Banned words: scan... "canonical EDR user-mode hook point" — fine. Avoid "essentially" — not used. Avoid "notably". OK.
- No first person. OK.
- Frontmatter: check enum category: T-052/T-053 = discovery (allowed enum). T-051 anti-analysis.
- mitre_secondary optional. T-053: [T1134.004, T1055]? I referenced T1134.004. Add secondary list: ["T1134.004"]. T-052: maybe omit secondary. T-051: omit.
- member_notes exact IDs. OK.
- tags 5-10 kebab-case. OK.
- Length: each card should hit 1200+. T-051 draft is ~950; expand. T-052 ~1100; expand OS internals a bit. T-053 ~1300+. Let me expand T-051 and T-052.

Expand T-051: add detail in OS Internals: how Authenticode hashing interacts (editing .rsrc invalidates signature), consumers (Explorer Details tab, tasklist /M? no — Get-FileVersionInfo in PowerShell, WMI CIM_DataFile.Version, sigcheck), ML classifiers using metadata features (company name presence, originality filename match) — the note says "bypass heuristics that check binary metadata against known-good vendor signatures". Add mechanism step about surviving binary modification: "resource-based impersonation survives compilation and binary modification" per consolidated description. Also mention that version info doesn't affect loading — purely informational.

Expand T-052: more on each trigger's observables and each option's mechanics. Also maybe map triggers→options explicitly.

Also Detection Considerations for T-051: mention ETW ImageLoad? Version info not in ETW. Sysmon EID 1 includes the fields — yes, well-established (Sysmon schema includes Company, Description, Product, OriginalFileName). Good.

For T-052 mitre: T1518.001 with secondary T1082? The framework's first step is defender posture discovery. I'll include mitre_secondary: ["T1082"] maybe. Eh — keep single T1518.001 to be safe; the template says omit if not needed. Keep it.

h1 format: "# <Technique Name> — <One-Line Purpose>". 

For the "Why It Matters" — 2-4 sentences. OK.

One more check on T-053 frontmatter: source_file: src/dark_crystal/crowd/src/nt_create_process.rs (relative path from repo root — given as src/dark_crystal/crowd/src/nt_create_process.rs in the prompt). Use exactly that.

crate: dark_crystal. OK.

Now finalize word counts. T-051 needs expansion. Let me write final versions with fuller paragraphs.

Also make sure Summary first sentence is complete and standalone.

Avoid defining PEB etc. I mention PEB LDR lists in T-052 — fine, no definition.

Write final output now. Also ensure exact delimiters and no text outside.