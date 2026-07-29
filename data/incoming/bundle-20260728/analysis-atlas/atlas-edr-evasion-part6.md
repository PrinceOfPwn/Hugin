## Synthesis Summary

This batch of SANS SEC670 material maps primarily to T-015 (PPID Spoofing), T-016 (EDR Evasion Suite — specifically the AMSI patching and NTDLL unhooking subsets), T-013 (Reflective PE loader / Remaining Methods), T-017 (Persistence — AppInit/AppCert/RunOnce context), and tangentially T-022 (Network Suite, for the WSASocket C2 socket discussion). The material covers the operational rationale behind evasion choices rather than implementation details: AV detection engine architecture (static YARA signatures vs. dynamic sandboxed execution), the InitializeProcThreadAttributeList/UpdateProcThreadAttribute sequence that enables PPID spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, the IAT hooking mechanism EDRs use (parse PE headers → locate module → flip page protections to PAGE_READWRITE → overwrite pointer → restore), the lab-driven tradecraft of patching amsi.dll inside PowerShell processes, the explicit reminder that userland NTDLL unhooking does NOT blind kernel-mode callbacks (kernel modules still watch), and the use of PE-sieve as a defender-side scanner of injected/unbacked modules. The knowledge gap this fills that source code alone cannot provide is the "why" layer — the defensive heuristics these techniques are designed against (parent-child process relationship alerts, unbacked executable memory, AMSI submission paths, kernel-callback resilience to userland unhooking), and the cost/benefit framing of cloud sample submission risk when operating custom bypasses.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "proc-thread-attribute-list"
    target: T-015
    type: enables
    rationale: "SEC670 units 5 and 6 establish that InitializeProcThreadAttributeList plus UpdateProcThreadAttribute with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS is the two-API sequence that produces parent-process spoofing — the technique cannot function without this attribute-list mechanism."

  - source: "kernel-callback-mechanism"
    target: T-016
    type: counters
    rationale: "SEC670 units 18-20 explicitly state that unhooking userland hooks does not fully blind a security product because a kernel module may still be watching. Kernel callbacks survive NTDLL .text restoration and continue producing telemetry on the operations T-016's unhook subset was meant to hide."

  - source: "amsi-patching"
    target: T-016
    type: concept_link
    rationale: "Lab 5.4 'AMSI No More' (units 22, 26) is the hands-on instantiation of the AMSI bypass subset documented in T-016 — patching amsi.dll inside a PowerShell process to neutralize content submission to AMSI."

  - source: "pe-sieve-memory-scanner"
    target: T-013
    type: detects
    rationale: "SEC670 units 12 and 23 name PE-sieve as a defensive tool purpose-built to detect the effects of offensive tools like reflective PE loaders and module stomping — exactly the T-013 remaining-methods surface."

  - source: "iat-hooking"
    target: T-016
    type: concept_link
    rationale: "Unit 27 documents IAT hooking as the function-pointer-overwrite pattern EDRs use for introspection. T-016's NTDLL unhook subset is the offensive counterpart that undoes exactly this category of hooking on ntdll's import surface."

  - source: T-015
    target: "av-parent-child-heuristic"
    type: counters
    rationale: "Unit 2 explains defenders alert when 'certain processes that should never spawn other processes, including PowerShell or CMD prompt; browsers, or office applications' produce children. T-015's PPID spoofing to explorer.exe directly counters this heuristic."

  - source: "reflective-dll-injection"
    target: T-013
    type: alternative_to
    rationale: "Unit 11 describes RDI as manually mapping a DLL into a target's virtual address space so the full path is not listed by the system loader — operationally the same purpose as the T-013 PE loader and module-overloading variants, just with the self-bootstrapping reflective stub."

  - source: "appinit-dlls-persistence"
    target: T-017
    type: alternative_to
    rationale: "Unit 14 names AppInit as an evasion/persistence mechanism for processes linked against User32.dll — a persistence vector not enumerated in T-017's five-layer list (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist), making it an alternative persistence path."
```

### Concept Nodes

```yaml
concepts:
  - id: "proc-thread-attribute-list"
    name: "PROC_THREAD_ATTRIBUTE_LIST and Parent Process Attribution"
    category: os-internal
    description: "The PROC_THREAD_ATTRIBUTE_LIST structure, populated via InitializeProcThreadAttributeList and UpdateProcThreadAttribute, allows process-creation attributes (including PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) to be set before CreateProcess is called. SEC670 specifies this requires only two API calls and lets the operator choose the sponsoring parent process, replacing the default creator-PID attribution that defenders use in parent-child relationship heuristics."
    relevant_to: [T-015]
    tags: [process-creation, attribute-list, ppid-spoofing, windows-internals]

  - id: "kernel-callback-mechanism"
    name: "Kernel Callback Resilience to Userland Unhooking"
    category: edr-mechanism
    description: "SEC670 unit 18-20 explicitly teaches that unhooking userland ntdll hooks does not fully blind a security product because a kernel module may still be watching. Kernel-mode callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks, PsSetCreateThreadNotifyRoutine, CmRegisterCallback) operate at PASSIVE_LEVEL inside the kernel and observe the same NT operations the userland hooks were intercepting, completely independent of ntdll's .text section state."
    relevant_to: [T-016]
    tags: [kernel-callbacks, edr, unhooking-limitation, detection]

  - id: "iat-hooking"
    name: "Import Address Table Hooking"
    category: edr-mechanism
    description: "IAT hooking (a.k.a. function-pointer hooking) modifies the array of imported-function addresses in a PE's IAT. SEC670 unit 27 documents the sequence: parse PE headers to find the import table, locate the module that implements the hooked function, change page protections on the IAT from read-only to PAGE_READWRITE (saving old permissions), overwrite the function pointer, then restore prior protections. EDRs use this to redirect API calls through introspection stubs."
    relevant_to: [T-016]
    tags: [iat-hooking, edr, function-pointer, page-protection]

  - id: "av-detection-engine-static-dynamic"
    name: "AV Detection Engine: Static vs Dynamic Analysis"
    category: defense-mechanism
    description: "SEC670 unit 1 frames AV solutions as composed of static and dynamic detection engines. Static uses signature matching (YARA-like rules) against the file before runtime; dynamic executes samples in a virtualized container to observe malicious behavior. Bypass strategies differ per engine: static signatures are bypassed by changing code bases (encryption, polymorphism), while dynamic analysis is bypassed by delaying execution or encrypting payload until sandbox exit."
    relevant_to: [T-016, T-020]
    tags: [av, detection, yara, sandbox, static, dynamic]

  - id: "amsi-patching"
    name: "AMSI In-Process Patching of amsi.dll"
    category: attack-pattern
    description: "SEC670 Lab 5.4 'AMSI No More' has the operator patch a PowerShell process that already has amsi.dll loaded, first observing how data is passed in for analysis, then exploring various methods to patch amsi.dll so AmsiScanBuffer returns clean without triggering. The lab emphasizes that the patch must be applied after amsi.dll is loaded and that the patch site is the buffer-submission function inside the loaded amsi.dll instance."
    relevant_to: [T-016]
    tags: [amsi, patching, powershell, evasion]

  - id: "reflective-dll-injection"
    name: "Reflective DLL Injection (RDI)"
    category: attack-pattern
    description: "SEC670 unit 11 describes RDI as manually mapping a source DLL into a target's virtual address space so the system loader never lists the DLL's full path. The DLL bootstraps itself via a reflective loader stub compiled into the DLL, performing its own base relocation, import resolution, and DLL_PROCESS_ATTACH invocation. This places the loaded image outside the PEB loader module list, defeating tools that enumerate only registered modules."
    relevant_to: [T-013, T-007]
    tags: [rdi, manual-mapping, pe-loader, stealth]

  - id: "appinit-dlls-persistence"
    name: "AppInit_DLLs Persistence for User32-linked Processes"
    category: attack-pattern
    description: "SEC670 unit 14 names AppInit as the technique to use for processes linked against User32.dll. AppInit_DLLs is loaded into every process that loads User32.dll via the HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs registry value, making it a broad-spectrum persistence and injection vector that piggybacks on the User32 import graph."
    relevant_to: [T-017]
    tags: [appinit, persistence, user32, registry, injection]

  - id: "pe-sieve-memory-scanner"
    name: "PE-sieve Memory Scanner"
    category: defense-mechanism
    description: "SEC670 units 12 and 23 reference PE-sieve as a representative defensive tool that scans a running process for the effects of offensive techniques — specifically detecting manually mapped / injected / hollowed modules by comparing in-memory PE headers and section contents against their on-disk originals and flagging memory regions whose backing image cannot be reconciled with a file path."
    relevant_to: [T-013, T-007, T-016]
    tags: [pe-sieve, memory-scan, defensive-tool, unbacked-memory]

  - id: "av-parent-child-heuristic"
    name: "Parent-Child Process Relationship Heuristic"
    category: edr-mechanism
    description: "SEC670 unit 2 describes the defender heuristic of alerting when a process that should never spawn children (browsers, Office applications, PowerShell, cmd) produces unexpected child processes. Conversely, explorer.exe spawning many child processes is treated as benign. This heuristic is what T-015's PPID spoofing directly counters by re-attributing the implant's parent to explorer.exe."
    relevant_to: [T-015]
    tags: [behavioral, process-tree, detection, ppid]

  - id: "cloud-sample-submission-risk"
    name: "AV/EDR Cloud Sample Submission Risk"
    category: edr-mechanism
    description: "SEC670 unit 7 lists sample submission to the cloud engine as the principal con of operating a custom bypass: if the implant is not properly cut off from internet, an unfamiliar sample is uploaded for cloud analysis, where reverse engineering can produce and distribute a new signature invalidating the bypass. This makes network egress filtering a prerequisite for operating custom evasion code."
    relevant_to: [T-016, T-020]
    tags: [cloud, sample-submission, signature, evasion-tradeoff]

  - id: "wsasocket-af-inet-stream"
    name: "WSASocket AF_INET SOCK_STREAM IPPROTO_TCP"
    category: os-internal
    description: "SEC670 unit 10 documents WSASocket as the API used to create the C2 socket before callback to the listening post. The parameters af=AF_INET, type=SOCK_STREAM, protocol=IPPROTO_TCP produce a TCP socket with SOCKET return type. WSASocket is preferred over socket() for C2 implants because it accepts a WSAPROTOCOL_INFO structure allowing explicit provider selection and overlaps cleanly with subsequent bind/connect calls."
    relevant_to: [T-022]
    tags: [winsock, networking, c2, socket]
```

### Detection Insights

```yaml
detection:
  - indicator: "Unbacked executable memory region with no corresponding on-disk module"
    source: memory-scan
    confidence: high
    relevant_to: [T-013, T-007, T-016]
    description: "PE-sieve (and equivalent memory scanners) walk the process's VAD tree, identify regions flagged as executable with no file backing (MEM_PRIVATE VadS nodes) or whose in-memory content diverges from the on-disk PE, and report them as injected/hollowed. SEC670 units 12 and 23 frame PE-sieve as the canonical detector for RDI, module stomping, and reflective PE loader effects."
    bypassed_by: "Map shellcode/PE as a section backed by a legitimate on-disk file (SEC_IMAGE) so the VAD node carries a file path; this produces a Vad node that reconciles against disk and defeats the unbacked-memory heuristic specifically"

  - indicator: "Suspicious parent-child process relationship (browser/Office/PowerShell as parent)"
    source: behavioral
    confidence: high
    relevant_to: [T-015]
    description: "EDR process-tree heuristics alert when a process category that should never spawn children (browsers, Office applications, PowerShell, cmd.exe) produces child processes. SEC670 unit 2 specifies explorer.exe as the benign parent that spawns many children freely — the asymmetric heuristic is what T-015's PPID spoofing to explorer.exe is designed to satisfy."
    bypassed_by: "Spoof parent PID to explorer.exe via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS so the implant's parent attribution matches the benign multi-child pattern explorer.exe routinely exhibits"

  - indicator: "NT operations continue generating telemetry after userland ntdll unhook"
    source: kernel-callback
    confidence: high
    relevant_to: [T-016]
    description: "SEC670 units 18-20 explicitly state that unhooking userland hooks does not fully blind a security product because a kernel module may still be watching. Kernel callbacks (process/thread/object-handle notification routines) continue to fire on NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, etc. regardless of the userland ntdll .text state."
    bypassed_by: "not discussed"

  - indicator: "PowerShell script content submitted to AmsiScanBuffer"
    source: etw
    confidence: medium
    relevant_to: [T-016]
    description: "When PowerShell loads amsi.dll and submits script content to AmsiScanBuffer for classification, AMSI emits the AMSI_CONTENT event via the Microsoft-AntiMalware provider (GUID {631fe7f0-5f6e-4d35-901e-3e5cf2c00540). Patching the AmsiScanBuffer function so it returns AMSI_RESULT_CLEAN prevents the content from being classified, eliminating the AMSI event. SEC670 Lab 5.4 walks observing the data flow then applying the patch."
    bypassed_by: "Locate amsi.dll in the PowerShell process, change page protection on AmsiScanBuffer to PAGE_READWRITE, overwrite the prologue with a return-clean stub, restore protection"

  - indicator: "Static YARA signature match on known shellcode or PE byte patterns"
    source: memory-scan
    confidence: medium
    relevant_to: [T-013, T-016]
    description: "SEC670 unit 1 describes static detection engines that use YARA-like signature rules against file payloads before runtime. Signatures are bypassed by changing the code base — encryption, polymorphism, encoding formats like UUID/IPv4/IPv6/MAC — so the on-disk byte pattern no longer matches the rule."
    bypassed_by: "Encrypt the payload at rest and decode only in memory immediately before execution; encode shellcode as IPv4/IPv6/MAC/UUID strings so the staged form does not match shellcode YARA rules"

sigma_ideas:
  - title: "Process spawned by browser or office application"
    logsource: process-creation
    condition_summary: "Sysmon EID 1 where ParentImage matches *.exe for known browser binaries (chrome.exe, msedge.exe, firefox.exe, iexplore.exe) or Office binaries (winword.exe, excel.exe, outlook.exe, powerpnt.exe) and Image is NOT an expected updater binary"

  - title: "PowerShell child of explorer.exe after PPID spoof attempt"
    logsource: process-creation
    condition_summary: "Sysmon EID 1 where Image endswith powershell.exe and ParentImage endswith explorer.exe — combines with opcode-level PROC_THREAD_ATTRIBUTE_PARENT_PROCESS usage telemetry to flag spoofed parent attribution"

  - title: "AMSI content event with AMSI_RESULT_CLEAN on suspicious content"
    logsource: etw
    condition_summary: "Microsoft-AntiMalware AMSI provider event where scan result is clean but content hash matches known-bad hash from threat-intel feed — indicates AmsiScanBuffer patched or otherwise returned false clean"
```

### Operational Chains

```yaml
chains:
  - name: "PPID-Spoofed Process Creation"
    description: "Create a child process with a chosen benign parent to satisfy parent-child heuristics"
    steps:
      - technique: "proc-thread-attribute-list"
        role: "Call InitializeProcThreadAttributeList to size and allocate the attribute list"
      - technique: "proc-thread-attribute-list"
        role: "Call UpdateProcThreadAttribute with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS pointing at the sponsoring process handle (e.g., explorer.exe PID)"
      - technique: T-015
        role: "Pass the populated attribute list to CreateProcess / NtCreateUserProcess so the new process inherits the spoofed parent PID"
    notes: "SEC670 unit 4 specifies this requires only two API calls. The sponsoring process handle must be opened with PROCESS_CREATE_PROCESS access. If combined with T-016's block-DLL policy the attribute list can carry both entries."

  - name: "AMSI Bypass Inside PowerShell Session"
    description: "Neutralize AMSI content scanning in a live PowerShell process to allow unrestricted script execution"
    steps:
      - technique: "amsi-patching"
        role: "Identify that amsi.dll is loaded in the target PowerShell process and locate AmsiScanBuffer's address via export resolution"
      - technique: "amsi-patching"
        role: "Observe the data flow into AmsiScanBuffer to confirm the patch target (SEC670 Lab 5.4 explicitly directs observing how data is passed in for analysis before patching)"
      - technique: "amsi-patching"
        role: "Change page protection on the patch site to PAGE_READWRITE, overwrite AmsiScanBuffer's prologue with a return-clean stub, restore protection"
      - technique: T-016
        role: "AMSI is now neutralized for the lifetime of this PowerShell process; subsequent script content bypasses the AMSI classification path"
    notes: "SEC670 Lab 5.4 (units 22, 26). The patch is per-process; a new PowerShell instance requires re-patching. Patch site selection must avoid the g_amsiContext initialization check — patching the prologue avoids the context-check branch."

  - name: "Reflective DLL Loading Under Memory-Scanner Pressure"
    description: "Load a DLL into a target process such that its presence is not visible to module enumeration"
    steps:
      - technique: "reflective-dll-injection"
        role: "Bootstrap the DLL via its reflective loader stub which performs its own base relocation, import resolution, and DllMain invocation"
      - technique: T-013
        role: "The DLL is manually mapped into the target's virtual address space without going through the system loader, so it never appears in the PEB loader module list"
    notes: "SEC670 unit 11. The tradeoff is that the mapped region is unbacked private memory (VadS node) which PE-sieve (units 12, 23) detects. Combining with SEC_IMAGE section mapping that supplies a file path would close this detection gap."

  - name: "NTDLL Unhook With Kernel-Callback Caveat"
    description: "Restore ntdll .text from a clean source to neutralize userland hooks, acknowledging kernel callbacks continue"
    steps:
      - technique: T-016
        role: "Acquire a clean ntdll .text section (from disk or a freshly spawned suspended process) and overwrite the hooked ntdll .text in the current process"
      - technique: "kernel-callback-mechanism"
        role: "Residual detection surface remains — kernel callbacks continue firing on the underlying NT operations the userland hooks were intercepting, so operations must still be chosen to minimize kernel-callback noise"
    notes: "SEC670 units 18-20 explicitly answer that unhooking does not truly blind the product because a kernel module may still be watching. The chain is only partial evasion; subsequent injection primitives should still avoid operations that kernel callbacks observe."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "appinit-dlls-persistence-card"
    title: "AppInit_DLLs as a Standalone Persistence Technique Card"
    kind: proposed-technique
    description: "SEC670 unit 14 names AppInit as the correct technique for processes linked against User32.dll, distinct from AppCert and RunOnce. The vault's T-017 five-layer persistence suite (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) does not include AppInit_DLLs, despite it being a classic User32-graph-wide injection and persistence vector with its own registry semantics, AppInit_Dlls bypass mitigation via LoadAppInit_DLLs=0, and a distinct process-scope profile. Worth a dedicated T-NNN card or an explicit addition to T-017."
    would_relate_to: [T-017, T-016]
    source_units: ["unit 14"]
    tags: [appinit, persistence, registry, user32, coverage-gap]

  - id: "kernel-callback-resilience-metadata"
    title: "Kernel-Callback Resilience as Cross-Cutting Metadata on T-016"
    kind: coverage-gap
    description: "SEC670 units 18-20 drive home that userland NTDLL unhooking is only partial evasion because kernel callbacks continue to observe operations. The vault's T-016 EDR evasion suite documents NTDLL unhook as a discrete technique but does not surface the kernel-callback residual detection surface as metadata on every userland-evasion entry. A cross-cutting annotation on which T-016 subset bypasses which detection layer (userland hook only vs. userland+kernel) would make the card more honest about residual risk."
    would_relate_to: [T-016]
    source_units: ["unit 18", "unit 19", "unit 20"]
    tags: [kernel-callbacks, coverage-gap, evasion-limitation, metadata]

  - id: "cloud-sample-submission-egress-discipline"
    title: "Cloud Sample Submission Risk as an Operational Discipline"
    kind: coverage-gap
    description: "SEC670 unit 7 explicitly lists sample submission to AV/EDR cloud engines as the principal downside of operating custom bypasses, and frames cutting the implant off from internet as the precondition. The vault has no card or cross-cutting note on egress discipline for evasion R&D — when an operator iterates a custom bypass against a real EDR, network egress must be cut or the sample is uploaded and reverse-engineered into a new signature. This is operational tradecraft that exists between T-016 (evasion) and T-020 (anti-analysis) but neither card surfaces it."
    would_relate_to: [T-016, T-020]
    source_units: ["unit 7"]
    tags: [cloud-submission, egress, evasion-tradeoff, signature-generation]

  - id: "pe-sieve-detection-tool-card"
    title: "Defensive Memory Scanner Coverage (PE-sieve Class)"
    kind: proposed-technique
    description: "SEC670 units 12 and 23 reference PE-sieve as the canonical defender-side tool for detecting manually mapped, hollowed, and stomped modules — the exact effects produced by T-013 and T-007. The vault's detection insights are written from first-principle indicators (unbacked memory, VAD analysis) but do not name specific defender tools an operator will encounter. A dedicated card cataloguing defender-side scanners (PE-sieve, Moneta, Hunt-Sleeping-Beacons, hollows_hunter) with their specific detection algorithms would let operators pre-test techniques against real tools."
    would_relate_to: [T-007, T-013, T-016]
    source_units: ["unit 12", "unit 23"]
    tags: [pe-sieve, moneta, defensive-tool, memory-scanner, coverage-gap]

  - id: "av-detection-engine-lifecycle-convergence"
    title: "AV Static/Dynamic Engine Bypass Lifecycle Cross-Course Convergence"
    kind: cross-source-convergence
    description: "SEC670 unit 1's framing of AV detection engines as static (signature/YARA, bypassable by changing code base) vs. dynamic (sandboxed execution, bypassable by delaying/encrypting) is the same lifecycle decomposition MalDev Academy and CRTO use to structure their evasion modules. The convergence indicates this is the canonical mental model the vault should adopt when categorizing T-016 and T-020 techniques by which detection engine they target."
    would_relate_to: [T-016, T-020]
    source_units: ["unit 1"]
    tags: [static, dynamic, yara, sandbox, convergence, lifecycle]
```