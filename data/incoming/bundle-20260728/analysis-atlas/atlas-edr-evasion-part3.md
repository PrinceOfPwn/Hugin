## Synthesis Summary

This batch maps primarily to four HUGIN techniques: **T-015 (PPID Spoofing)** via the "Choose Your Parent Process" walkthrough using `InitializeProcThreadAttributeList` and `UpdateProcThreadAttribute`; **T-016 (EDR Evasion Suite)** via extensive NTDLL unhooking material covering fresh-copy (file-mapping) and suspended-copy variants, plus AMSI patching in `amsi.dll`; **T-021 (Crypto & Obfuscation)** via string obfuscation through character arrays and global-variable avoidance; and **T-022 (Network Suite)** via certificate pinning (`CertGetNameString`, `CertGetCertificateContextProperty`) and malleable C2 profile concepts. SANS SEC670 covers the inline-hook byte mechanics (32-bit `MOV EDI, EDI` hot-patch slots, 64-bit `MOV rax, imm64; JMP rax` patterns), the three NTDLL unhook variants, and the parent-process relationship detection rationale that motivates PPID spoofing. CRTO contributes PowerShell Constrained Language Mode verification, Defender exclusion path abuse, and malleable C2 profile semantics. The knowledge gap filled by this material is the *why* behind each technique: why hot-patch slots exist, why a suspended process has a pristine NTDLL, why AV engines flag browser→PowerShell process relationships, and what specifically each evasion counters in the defense stack — none of which appears in the dark_crystal source code.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "suspended-process-pristine-ntdll"
    target: "T-016"
    type: enables
    rationale: "Suspended-process unhooking leverages the fact that only ntdll.dll is loaded and no EDR hooks are installed yet — copying the .text section from the suspended process yields a clean syscall table the hooked process can use."
  - source: "fresh-copy-file-mapping-unhook"
    target: "T-016"
    type: alternative_to
    rationale: "The fresh-copy approach using CreateFileA/CreateFileMapping/MapViewOfFile to copy ntdll.dll's .text from disk serves the same operational purpose as the suspended-copy variant and is interchangeable as an NTDLL unhook."
  - source: "T-015"
    target: "T-016"
    type: enhances
    rationale: "PPID spoofing is described as 'an addition to avoid detection' — combining parent-process selection with other evasion raises the bar for behavioral parent-child anomaly detections."
  - source: "av-static-signature-engine"
    target: "T-021"
    type: detects
    rationale: "Static signature matching (YARA-style) is the named detection for strings stored in the .data section; the character-array obfuscation directly counters this."
  - source: "av-dynamic-analysis-container"
    target: "T-016"
    type: detects
    rationale: "Dynamic analysis executes samples in a virtualized container to detect malicious behavior; SEC670 frames user-mode unhooking as a method to evade these behavioral monitors."
  - source: "parent-child-process-anomaly"
    target: "T-015"
    type: detects
    rationale: "AV/EDR solutions monitor process relationships and flag suspicious chains like browser→PowerShell or Office→cmd; PPID spoofing counters this by selecting a legitimate parent such as explorer.exe."
  - source: "amsi-in-process-scan"
    target: "T-016"
    type: detects
    rationale: "AMSI passes script content into amsi.dll for analysis; patching amsi.dll inside the hosting process (e.g., powershell.exe) silences this inspection."
  - source: "cert-context-hash-pinning"
    target: "T-022"
    type: enhances
    rationale: "Certificate pinning via CERT_HASH_PROP_ID adds MITM resistance to WinHTTP/WinInet C2 channels, preventing proxy interception of beacon traffic."
  - source: "powershell-constrained-language-mode"
    target: "T-016"
    type: concept_link
    rationale: "CLM restricts which language features PowerShell exposes, acting as a defense that intersects with AMSI and script-content inspection covered by the evasion suite."
```

### Concept Nodes

```yaml
concepts:
  - id: "inline-hook-prologue-pattern"
    name: "Inline Function Prologue Hook Byte Patterns"
    category: edr-mechanism
    description: "EDR user-mode inline hooks overwrite the first bytes of a target NT API with a jump to a detour. 32-bit (Wow64) functions reserve hot-patch slots filled with `MOV EDI, EDI` (2 bytes) preceded by 5 NOPs, allowing a 5-byte `JMP rel32` (E9 xx xx xx xx) overwrite. 64-bit functions lack a fixed-length hot-patch slot due to variable instruction length, so EDRs typically patch 15+ bytes with a `MOV rax, imm64; JMP rax` (48 B8 imm64 / FF E0) sequence using RAX as an intermediate because no direct 8-byte immediate JMP exists in x64."
    relevant_to: [T-016]
    tags: [inline-hook, edr, unhooking, x86, x64, hot-patch]

  - id: "ntdll-text-section-restore"
    name: "NTDLL .text Section Restoration (Fresh Copy)"
    category: attack-pattern
    description: "Unhooking technique that opens C:\\Windows\\System32\\ntdll.dll with CreateFileA, creates a section object via CreateFileMapping, maps it with MapViewOfFile, locates the NtHeader, walks to the .text section, and memcpy's the pristine .text bytes over the in-memory hooked copy. Restores all syscall stubs in one operation. SEC670 notes detections exist but are uncommon, and warns against patching the on-disk file itself."
    relevant_to: [T-016]
    tags: [unhooking, ntdll, fresh-copy, file-mapping, evasion]

  - id: "suspended-process-pristine-ntdll"
    name: "Suspended-Process Pristine NTDLL Retrieval"
    category: attack-pattern
    description: "Alternative to fresh-copy unhooking: spawn a process with CREATE_SUSPENDED. At this point only ntdll.dll is implicitly loaded and the main thread has not executed, so EDR DLLs have not yet injected and no hooks are installed. The .text section of this suspended process's ntdll is pristine and can be copied into the hooked process. The suspended process yields both a clean .text section and a clean syscall table in a single snapshot."
    relevant_to: [T-016]
    tags: [unhooking, ntdll, suspended-process, create-suspended, evasion]

  - id: "av-detection-engines-static-dynamic-scan"
    name: "AV Detection Engine Tiers (Static, Dynamic, Scan)"
    category: defense-mechanism
    description: "SEC670 frames AV solutions as composed of three engine tiers. Static uses signature matching (YARA-style rules) before runtime to catch known-bad byte patterns. Dynamic executes samples in a virtualized container and observes behavior. Scan engines offer configurable modes (Automatic/Custom) and increasingly use ML-based scoring (Bitdefender named as example). Bypassing one tier does not bypass all three."
    relevant_to: [T-016, T-021]
    tags: [av, detection, static-analysis, dynamic-analysis, yara, ml-scanning]

  - id: "parent-child-process-anomaly"
    name: "Parent-Child Process Relationship Anomaly Detection"
    category: defense-mechanism
    description: "AV/EDR solutions monitor process trees for suspicious parent-child combinations. Processes that should never spawn children — browsers, Office apps, PowerShell, cmd — spawning other processes (especially shells or downloaders) trigger alerts. explorer.exe spawning arbitrary processes is treated as normal background activity, which is why operators choose it as a spoofed parent."
    relevant_to: [T-015]
    tags: [behavioral-detection, process-tree, edr, ppid-spoofing]

  - id: "proc-thread-attribute-list"
    name: "PROC_THREAD_ATTRIBUTE_LIST for Parent Assignment"
    category: windows-structure
    description: "Windows structure used to pass extended attributes to CreateProcess. The PPID-spoofing sequence requires two API calls against this structure: InitializeProcThreadAttributeList (twice — first to get buffer size, second to populate), then UpdateProcThreadAttribute with the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute and a handle to the desired parent. The resulting attribute list is passed via STARTUPINFOEX to CreateProcess, causing the kernel to use the inherited-parent token, process parameters, and affinity of the spoofed parent rather than the calling process."
    relevant_to: [T-015]
    tags: [ppid-spoofing, create-process, proc-thread-attribute, windows-api]

  - id: "cert-context-hash-pinning"
    name: "Certificate Context Hash Pinning"
    category: crypto-primitive
    description: "Pinning mechanism used by Windows implants to reject MITM proxies. The implant calls InternetQueryOption with INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT to fetch the server's cert chain, CertGetNameString with CERT_NAME_SIMPLE_DISPLAY_TYPE to extract CN/OU/O, CertGetCertificateContextProperty with CERT_HASH_PROP_ID to retrieve an encrypted key hash, converts the hash to hex bytes, and compares against a hardcoded pin. Both WinHTTP and WinInet support this pattern. Prevents proxy interception even when the proxy presents a trusted CA chain."
    relevant_to: [T-022]
    tags: [cert-pinning, mitm, winhttp, wininet, tls, c2]

  - id: "powershell-constrained-language-mode"
    name: "PowerShell Constrained Language Mode (CLM)"
    category: defense-mechanism
    description: "PowerShell language tier that restricts COM invocation, dot-sourcing of modules, and access to type accelerators. CLM is enforced by Device Guard, AppLocker, and WDAC policies. Operators detect CLM by checking $ExecutionContext.SessionState.LanguageMode and testing features like [Math]::Pow(2,10). CLM runs alongside ExecutionPolicy (which can be bypassed with -executionpolicy bypass) but is itself a separate, harder restriction that ExecutionPolicy bypass does not disable."
    relevant_to: []
    tags: [powershell, clm, device-guard, applocker, wdac, orphan]

  - id: "av-exclusion-path-abuse"
    name: "Defender Exclusion Path Abuse"
    category: attack-pattern
    description: "Technique for keeping payloads out of AV scanning scope by configuring folder exclusions. CRTO documents Set-MpPreference -ExclusionPath 'C:\\Windows\\System32' (and similar) as an administrative path; the corresponding registry key persists exclusions across reboots. Requires admin privilege. Useful as a low-effort evasion when operator already has admin but cannot disable the AV service outright."
    relevant_to: [T-016]
    tags: [defender, exclusion, av-bypass, persistence, admin]

  - id: "string-character-array-obfuscation"
    name: "String Character-Array Obfuscation"
    category: attack-pattern
    description: "Static-analysis counter that replaces `char* s = \"GetProcAddress\"` (which places the literal in .data and surfaces under the `strings` utility) with `char s[] = {'G','e','t','P',...,'A',0}`. The compiler emits individual character assignments on the stack or .text rather than a contiguous .data string. SEC670 notes this defeats simple automated scanners but not manual reverse engineering in IDA Pro or Ghidra, and global variables (`int g_c2port = 4444;`) should also be avoided."
    relevant_to: [T-021]
    tags: [string-obfuscation, static-analysis, yara, ida, ghidra]

  - id: "amsi-in-process-scan"
    name: "AMSI In-Process Content Inspection"
    category: edr-mechanism
    description: "Anti-Malware Scan Interface (AMSI) ships as amsi.dll loaded into script and Office host processes (powershell.exe, excel.exe, etc.). Script content submitted for execution is passed into AmsiScanBuffer for inspection before the script engine executes it. Patching amsi.dll (overwriting AmsiScanBuffer or AmsiScanString prologue with an early return) silences inspection inside that process. SEC670 Lab 5.4 specifically walks patching amsi.dll inside powershell.exe and observing how content flows into the scan function."
    relevant_to: [T-016]
    tags: [amsi, edr, script-inspection, powershell, patching]

  - id: "malleable-c2-profile"
    name: "Malleable C2 Network Artifact Profile"
    category: attack-pattern
    description: "Cobalt Strike concept for shaping beacon HTTP artifacts to blend with legitimate traffic. A profile defines http.get (uri, client headers, server response shape) and http.post blocks. Each block specifies how the beacon encodes data into the request and how the team server shapes the response. The CRTO material names uri, client, server, http.get, and http.post as the configurable knobs. HUGIN's henge.rs malleable C2 engine is the analogue."
    relevant_to: [T-022]
    tags: [c2, malleable, cobalt-strike, http, beacon, network-artifacts]
```

### Detection Insights

```yaml
detection:
  - indicator: "Suspicious parent-child process relationship (browser/Office spawning cmd/powershell)"
    source: behavioral
    confidence: high
    relevant_to: [T-015]
    description: "AV/EDR monitors process tree edges and flags paths where processes that should never spawn children (browsers, Office apps, cmd, powershell) create new processes. SEC670 explicitly names these as 'processes that should never spawn other processes' and identifies them as the trigger PPID spoofing is designed to defeat."
    bypassed_by: "Spoof parent as explorer.exe or another routinely-spawning benign parent using PROC_THREAD_ATTRIBUTE_PARENT_PROCESS via STARTUPINFOEX passed to CreateProcess."

  - indicator: "Inline hook byte pattern in ntdll.dll .text section"
    source: memory-scan
    confidence: medium
    relevant_to: [T-016]
    description: "EDR-installed hooks leave detectable byte signatures: 32-bit `JMP rel32` (E9) overwriting `MOV EDI, EDI` hot-patch slots; 64-bit `MOV rax, imm64; JMP rax` (48 B8 ... FF E0) 15-byte patch. Integrity scanners comparing the in-memory .text against the on-disk copy detect this delta."
    bypassed_by: "Restoring the pristine .text via fresh-copy file mapping or suspended-process snapshot removes the patched bytes but is itself detectable by ETW-TI or kernel callbacks observing the write."

  - indicator: "Strings in .data section matching known-bad signatures"
    source: memory-scan
    confidence: high
    relevant_to: [T-021]
    description: "Static signature engines (YARA-style) scan the .data section for contiguous string literals like 'GetProcAddress', 'LoadLibraryA', 'NtAllocateVirtualMemory', and port numbers stored as global variables. SEC670 frames this as the primary static-detection vector for implants."
    bypassed_by: "Declare strings as character arrays on the stack or in .text, avoid global variables for sensitive constants. Manual static analysis in IDA Pro/Ghidra still recovers them."

  - indicator: "AMSI scan content flagged as malicious by cloud ML"
    source: behavioral
    confidence: medium
    relevant_to: [T-016]
    description: "Script content submitted to AmsiScanBuffer is forwarded to the AV/EDR signature and ML engines. Flagged content blocks script execution and may raise an alert. SEC670 Lab 5.4 observes 'how data is being passed in for analysis' to demonstrate this pipeline."
    bypassed_by: "Patch the amsi.dll AmsiScanBuffer/AmsiScanString prologue inside the hosting process (e.g., powershell.exe) to return AMSI_RESULT_CLEAN unconditionally."

  - indicator: "Process spawned with CREATE_SUSPENDED that never resumes"
    source: windows-security-log
    confidence: low
    relevant_to: [T-016]
    description: "Creating a process with CREATE_SUSPENDED, reading its memory, then terminating without resume leaves an event trail in process creation logs. Repeated patterns suggest NTDLL .text harvesting for unhooking. SEC670 does not discuss this detection explicitly but the suspended-process unhook pattern produces this artifact."
    bypassed_by: "not discussed"

  - indicator: "Defender exclusion path added via Set-MpPreference"
    source: windows-security-log
    confidence: high
    relevant_to: [T-016]
    description: "Set-MpPreference -ExclusionPath writes to a registry key under Microsoft\\Windows Defender. CRTO notes the registry key is the persistence mechanism. Event ID 4657 (registry value modification) and Defender operational channel events surface this change. Admins auditing exclusion lists will flag paths covering C:\\Windows\\System32 or other broad scopes."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Suspicious Process Parent-Child Chain"
    logsource: process-creation
    condition_summary: "Sysmon EID 1 where ParentImage matches browser or Office process (chrome.exe, msedge.exe, iexplore.exe, outlook.exe, excel.exe, winword.exe) and Image matches cmd.exe, powershell.exe, wscript.exe, or rundll32.exe"
  - title: "Defender Exclusion Path Added"
    logsource: windows-security
    condition_summary: "EID 4657 on HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths value creation or modification, OR Defender operational channel event for ExclusionPath add"
  - title: "AMSI Content Block Event"
    logsource: etw
    condition_summary: "Microsoft-Windows-AMSI ETW provider event where Result == 1 (AMSI_RESULT_DETECTED) — absence of expected scan events for a powershell.exe session with script activity suggests amsi.dll patching"
```

### Operational Chains

```yaml
chains:
  - name: "NTDLL Unhook via Suspended Process Snapshot"
    description: "Retrieve a pristine ntdll.dll .text section by snapshotting a freshly-created suspended process and copying its syscall stubs into the hooked current process."
    steps:
      - technique: T-016
        role: "Spawn a sacrificial process (e.g., notepad.exe or calc.exe) with CREATE_SUSPENDED — only ntdll.dll is loaded and no EDR DLL has injected yet"
      - technique: T-016
        role: "Locate the suspended process's ntdll base via its PEB, walk to the NtHeader, find the .text section"
      - technique: T-016
        role: "memcpy the pristine .text section over the current (hooked) process's in-memory ntdll .text — restoring all syscall stubs"
      - technique: T-016
        role: "Terminate the sacrificial suspended process to avoid leaving it parked"
      - technique: T-001
        role: "Syscall dispatch via RecycledGate now executes against unhooked stubs"
    notes: "SEC670 explicitly frames this as an alternative to the on-disk fresh-copy method. Detection surface includes CREATE_SUSPENDED process creation events and the cross-process memory read; both are observable by ETW-TI."

  - name: "PPID-Spoofed Process Spawn with Evasion"
    description: "Spawn a child process with a benign parent (explorer.exe) to avoid parent-child process-tree behavioral detection."
    steps:
      - technique: T-015
        role: "Open a handle to the desired parent (e.g., explorer.exe) with PROCESS_CREATE_PROCESS access"
      - technique: T-015
        role: "Call InitializeProcThreadAttributeList twice — first to query buffer size, second to initialize — to allocate a PROC_THREAD_ATTRIBUTE_LIST"
      - technique: T-015
        role: "Call UpdateProcThreadAttribute with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS and the parent handle"
      - technique: T-015
        role: "Pass the attribute list via STARTUPINFOEX to CreateProcess — kernel uses the inherited parent token and parameters"
    notes: "SEC670 emphasizes this requires 'just two API calls' against the attribute list plus a handle open. Combine with T-016 Block-DLL policy to also prevent non-Microsoft DLLs (including EDR DLLs) from loading into the child."

  - name: "AMSI Bypass Inside PowerShell Host"
    description: "Patch amsi.dll's scan function inside a running powershell.exe to silence script-content inspection."
    steps:
      - technique: T-016
        role: "Locate amsi.dll base in the powershell.exe process via the PEB loader list"
      - technique: T-016
        role: "Resolve AmsiScanBuffer (or AmsiScanString) RVA and patch its prologue to return AMSI_RESULT_CLEAN (0x80070057) immediately"
      - technique: T-021
        role: "Subsequent script execution via PowerShell now bypasses in-process content inspection"
    notes: "SEC670 Lab 5.4 'AMSI No More' walks this in a powershell.exe host. Alternative patches include HW-breakpoint mediation (T-016 AMSI HBP variant in dark_crystal/src/experimental/amsi_hbp.rs) and PAGE_GUARD-based patching (amsi_page_guard.rs)."

  - name: "C2 Channel with Certificate Pinning"
    description: "Establish a WinHTTP/WinInet C2 channel that rejects MITM proxy interception by pinning the team server cert hash."
    steps:
      - technique: T-022
        role: "Open WinHTTP/WinInet session to the team server URL"
      - technique: T-022
        role: "InternetQueryOption with INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT to fetch the server cert chain"
      - technique: T-022
        role: "CertGetNameString with CERT_NAME_SIMPLE_DISPLAY_TYPE extracts CN/OU/O; CertGetCertificateContextProperty with CERT_HASH_PROP_ID retrieves the encrypted hash"
      - technique: T-022
        role: "Compare hex-converted hash against hardcoded pin; abort channel if mismatch"
    notes: "SEC670 notes both WinHTTP and WinInet support this pattern. Pin must be rotated when the team server cert rotates."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "clm-detection-and-bypass-coverage"
    title: "PowerShell Constrained Language Mode Detection and Bypass"
    kind: coverage-gap
    description: "CRTO explicitly covers detecting CLM via $ExecutionContext.SessionState.LanguageMode and the [Math]::Pow(2,10) feature probe, distinguishing CLM from the weaker ExecutionPolicy. HUGIN's T-016 evasion suite and T-023 client capabilities cover AMSI patching and PowerShell execution but do not document CLM as a distinct defensive layer operators must enumerate before launching in-process PowerShell tradecraft. CLM interacts with WDAC and Device Guard and changes which evasion primitive is required."
    would_relate_to: [T-016, T-023]
    source_units: ["unit 39"]
    tags: [powershell, clm, wdac, device-guard, coverage-gap]

  - id: "defender-exclusion-path-abuse-as-evasion"
    title: "Defender Exclusion Path Abuse for Payload Staging"
    kind: coverage-gap
    description: "CRTO documents Set-MpPreference -ExclusionPath as a simple administrative path to keep payloads out of scanning scope, with the registry key persisting the exclusion. The vault's T-016 evasion suite covers AMSI, ETW, hooks, and policy enforcement (Block-DLL, ACG) but does not surface exclusion-path abuse as a low-effort evasion when the operator already holds admin. This is operationally distinct from disabling the AV service and is quieter."
    would_relate_to: [T-016]
    source_units: ["unit 38"]
    tags: [defender, exclusion, av-bypass, admin, coverage-gap]

  - id: "sywshipers3-random-syscall-dispatch"
    title: "Random Syscall Dispatch via Sywshipers3 (EGH-based)"
    kind: proposed-technique
    description: "SEC670 surfaces Sywshipers3 as a syscall-detection bypass tool that uses EGGs (egg-hunter style stubs) and direct syscall jumps to random syscall numbers, in both Wow64 and x64. This is operationally distinct from HUGIN's T-001 (RecycledGate indirect via ntdll gadget), T-002 (Hells/Halo's/Tartarus SSN sort cascade), and T-003 (VEH HW-breakpoint dispatch) — Sywshipers3 deliberately randomizes which syscall SSN is invoked per call to defeat static pattern matching on syscall sequences. A dedicated T-NNN for randomized SSN dispatch would document this alternative dispatch philosophy."
    would_relate_to: [T-001, T-002, T-003, T-006]
    source_units: ["unit 13"]
    tags: [syscall, ssn, randomization, sywshipers, proposed-technique]

  - id: "cross-source-ntdll-unhook-convergence"
    title: "NTDLL Unhook Convergence Across Three Variants"
    kind: cross-source-convergence
    description: "SEC670 dedicates an entire module to NTDLL unhooking and enumerates three distinct variants — byte-level prologue patch (per-function), fresh-copy file mapping (whole .text from disk), and suspended-copy snapshot (whole .text from a CREATE_SUSPENDED child). HUGIN's T-016 documents NTDLL unhook via suspended process (dark_crystal/src/experimental/evasion/ntdll_unhook.rs) but does not surface the file-mapping variant as a documented alternative. The convergence indicates strong tradecraft consensus that the suspended-copy path is the operational default — worth surfacing in the vault as a variant selector."
    would_relate_to: [T-016]
    source_units: ["unit 4", "unit 5", "unit 6", "unit 7", "unit 8", "unit 9", "unit 10"]
    tags: [ntdll, unhook, fresh-copy, suspended-copy, convergence]

  - id: "inline-hook-byte-forensics"
    title: "Inline Hook Byte-Pattern Forensics"
    kind: coverage-gap
    description: "SEC670 documents the exact byte patterns EDRs leave when inline-hooking ntdll — 32-bit `MOV EDI, EDI` hot-patch slot followed by 5-byte `JMP rel32`, and 64-bit 15-byte `MOV rax, imm64; JMP rax` (48 B8 ... FF E0) — and explains *why* RAX is the intermediate register (x64 lacks a direct 8-byte immediate JMP). The vault's T-016 documents the unhook operation but not the byte-forensic fingerprint operators can scan for to enumerate which functions an EDR has hooked before deciding what to unhook. This pre-unhook enumeration step has operational value."
    would_relate_to: [T-016]
    source_units: ["unit 1", "unit 2", "unit 3"]
    tags: [inline-hook, byte-pattern, forensics, enumeration, coverage-gap]

  - id: "av-detection-tier-taxonomy"
    title: "AV Detection Tier Taxonomy (Static, Dynamic, Scan)"
    kind: coverage-gap
    description: "SEC670 explicitly distinguishes static signature matching (YARA-style, pre-runtime) from dynamic execution in virtualized containers, and from configurable scan-engine modes (Automatic/Custom with ML scoring, Bitdefender named). HUGIN's detection insights reference ETW providers, Sysmon IDs, and memory scanners but do not document this AV-tier taxonomy that determines *which* class of bypass a given evasion counters. Surfacing this as cross-cutting context would help operators pick the right evasion tier (string obfuscation for static, unhooking for dynamic, malleable C2 for network scan)."
    would_relate_to: [T-016, T-021, T-022]
    source_units: ["unit 20", "unit 21", "unit 22"]
    tags: [av, detection-tier, static, dynamic, scan, taxonomy, coverage-gap]
```