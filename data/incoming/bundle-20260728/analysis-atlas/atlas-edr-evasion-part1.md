## Synthesis Summary

This batch of 40 SANS SEC670 units maps to T-001 (RecycledGate — indirect syscalls), T-002 (Hell's/Halo's/Tartarus Gate — SSN resolution), T-015 (PPID Spoofing via InitializeProcThreadAttributeList), T-016 (EDR Evasion Suite — NTDLL unhooking, inline hook mechanics, binary patching risks), T-009 (Process Ghosting — referenced via the Skrull DRM PoC), T-021 (Crypto & Obfuscation — CNG/BCrypt AES sequence), and T-007/T-013 (process injection definition). The material covers the operational "why" behind these techniques: why indirect syscalls yield cleaner call stacks by jumping into ntdll, why Halo's Gate addresses Hell's Gate's failure on hooked stubs via sequential SSN neighbor scanning, why a suspended-process ntdll copy is clean (AV/EDR cannot hook functions before the loader initializes), why unhooking alone does not blind kernel-mode EDR components, and the CNG API sequence for AES shellcode decryption. The gap filled is the practitioner's rationale for each evasion — the tradeoffs, detection surfaces (PE-sieve, Moneta, Volatility, AV cloud submission), and the operational sequencing — none of which is recoverable from the Rust source.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: T-002
    target: T-001
    type: requires
    rationale: "Indirect syscalls require a resolved SSN before the implant can jump into the ntdll syscall stub. SEC670 frames indirect syscalls as still needing to 'find the correct syscall number' — the Hell's/Halo's Gate cascade supplies that SSN."

  - source: concept-halos-gate-neighbor-scan
    target: T-002
    type: enhances
    rationale: "Halo's Gate enhances Hell's Gate by leveraging that syscall IDs in ntdll are numerically sequential ('4F will come immediately after 4E'), so a hooked stub's SSN can be recovered by inspecting the neighbor stub. Hell's Gate fails on hooked stubs; Halo's Gate resolves this."

  - source: concept-suspended-process-ntdll-copy
    target: T-016
    type: enables
    rationale: "The suspended-copy technique supplies a clean ntdll .text section for unhooking because 'if a process is created in the suspended state, its thread does not execute yet, thus no AV/EDR hooks can be implemented yet.' This is one of several unhook paths under T-016."

  - source: T-001
    target: concept-userland-ntll-hook
    type: counters
    rationale: "Indirect syscalls bypass userland ntdll hooks by jumping into ntdll's own memory to execute the syscall instruction rather than invoking it from the implant's own image. The slide explicitly contrasts this with direct syscalls inside malware.exe."

  - source: T-015
    target: T-016
    type: enhances
    rationale: "Choosing a legitimate parent process via InitializeProcThreadAttributeList/UpdateProcThreadAttribute 'helps avoid detection' by ensuring suspicious children (e.g., cmd.exe from an Office parent) do not appear — composing PPID spoofing with other evasion techniques strengthens the overall evasion posture."

  - source: concept-pe-sieve-memory-scanner
    target: T-007
    type: detects
    rationale: "PE-sieve 'is designed to scan a single process, but does a great job at detecting various items like injected PEs and hooks. It also has the ability to dump an implant.' It is a concrete defensive detector for the injection family."

  - source: concept-kernel-edr-component
    target: T-016
    type: counters
    rationale: "SEC670 explicitly notes that unhooking userland ntdll does not blind a security product if a kernel module is still watching — 'Depends, there could be a kernel module still watching.' Kernel-mode EDR counters userland unhooking."

  - source: concept-av-cloud-sample-submission
    target: T-009
    type: concept_link
    rationale: "The Skrull DRM PoC uses process ghosting to make launchers anti-copy so they 'are broken if, and when, they are submitted for analysis.' Process ghosting is operationally linked to defending against AV cloud sample submission."
```

### Concept Nodes

```yaml
concepts:
  - id: "ntdll-text-syscall-stub-region"
    name: "NTDLL .text Syscall Stub Region"
    category: windows-structure
    description: "The .text section of ntdll.dll contains the syscall stubs for every Nt/Zw function. Each stub begins with 'mov r10, rcx; mov eax, <SSN>' followed by 'syscall; ret'. EDRs patch this region with inline jumps to redirect execution into the EDR's own userland hook DLL. The stub sequence is numerically ordered by SSN, which Halo's Gate exploits."
    relevant_to: [T-002, T-016, T-001]
    tags: [ntdll, syscall-stubs, ssn, inline-hook, evasion]

  - id: "inline-hook-mov-edi-edi-prologue"
    name: "MOV EDI, EDI Prologue as Hook Detection Signature"
    category: defense-mechanism
    description: "SEC670 states that legitimate ntdll function bytes 'should start with MOV EDI, EDI' (the 2-byte hot-patch nop pad). Scanning for bytes that do not match this expected prologue is the search criterion for detecting inline hooks. Validation is best done against the on-disk version at C:\\Windows\\System32\\ntdll.dll."
    relevant_to: [T-016]
    tags: [hook-detection, mov-edi-edi, ntdll, hot-patch]

  - id: "suspended-process-ntdll-copy"
    name: "Suspended-Process Clean NTDLL Copy"
    category: attack-pattern
    description: "Creating a process with CREATE_SUSPENDED yields a process whose only implicitly loaded module is ntdll.dll. Because the main thread has not yet executed, 'no AV/EDR hooks can be implemented yet.' The .text section of this pristine ntdll can be located via pattern scanning and copied over the hooked ntdll .text in the implant's own process, restoring unhooked syscall stubs."
    relevant_to: [T-016]
    tags: [unhooking, create-suspended, ntdll, syscall-table, pattern-scan]

  - id: "indirect-syscall-ntdll-gadget"
    name: "Indirect Syscall via NTDLL Syscall Instruction Gadget"
    category: attack-pattern
    description: "Rather than executing the syscall instruction inside the implant's own image (direct syscall), the implant jumps into ntdll's syscall stub and executes the syscall instruction there. SEC670 notes this provides 'a cleaner call stack compared to direct syscalls' because the return address originates from ntdll rather than from an unbacked implant region. The SSN must still be resolved separately."
    relevant_to: [T-001]
    tags: [indirect-syscall, call-stack-spoofing, ntdll-gadget, evasion]

  - id: "concept-halos-gate-neighbor-scan"
    name: "Halo's Gate Sequential SSN Neighbor Scan"
    category: attack-pattern
    description: "Hell's Gate reads the SSN from a target stub's 'mov eax, <SSN>' bytes, but fails if that stub is already hooked (the bytes are patched). Halo's Gate exploits that ntdll syscall stubs are numerically ordered ('syscall 4F comes immediately after 4E'). When a target stub is hooked, the implant walks neighbor stubs (±1) until it finds an unhooked one, reads that SSN, and arithmetic-adjusts by the offset to recover the original target SSN."
    relevant_to: [T-002]
    tags: [halos-gate, ssn-resolution, neighbor-scan, hook-detection]

  - id: "procthread-attributelist-ppid-spoofing"
    name: "PROC_THREAD_ATTRIBUTE_LIST for Parent Assignment"
    category: windows-structure
    description: "InitializeProcThreadAttributeList allocates an attribute list buffer; UpdateProcThreadAttribute then populates it with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, binding the new process to a caller-supplied parent handle. SEC670 notes this requires 'just two API calls' and is used so that suspicious child processes (cmd.exe) are not spawned from obviously-wrong parents (Office apps). The attribute list is passed to CreateProcess via EXTENDED_STARTUPINFO_PRESENT."
    relevant_to: [T-015]
    tags: [ppid-spoofing, procthread-attributelist, parent-process, detection-evasion]

  - id: "cng-bcrypt-aes-decrypt-sequence"
    name: "CNG BCrypt AES Decryption Sequence"
    category: crypto-primitive
    description: "SEC670 specifies a fixed sequence for AES shellcode decryption using CNG: BCryptOpenAlgorithmProvider → BCryptGetProperty (twice, for chaining mode and block length) → BCryptSetProperty (set chaining mode) → BCryptGenerateSymmetricKey → BCryptDecrypt. The deprecated legacy CryptoAPI is replaced by CNG for 'more advanced and extensible' capability. This is the canonical sequence for native Windows-shellcode decryption without third-party crypto."
    relevant_to: [T-021]
    tags: [cng, bcrypt, aes, shellcode-decryption, crypto-api]

  - id: "ntquerysysteminformation-process-enum"
    name: "NtQuerySystemInformation for Process Enumeration"
    category: os-internal
    description: "SEC670 identifies NtQuerySystemInformation with SYSTEM_INFORMATION_CLASS as an 'undocumented method' for process enumeration in red team contexts. By querying SystemProcessInformation directly via the native API, an implant avoids the Win32 Process32First/Next toolhelp32 path that EDRs commonly monitor."
    relevant_to: []
    tags: [orphan, ntquerysysteminformation, process-enum, native-api, evasion]

  - id: "regnotifychangekey-registry-watchdog"
    name: "RegNotifyChangeKey Registry Watchdog"
    category: os-internal
    description: "RegNotifyChangeKey lets an implant receive notifications when a registry subtree changes — useful for detecting AV product installation in real time without polling. Filters include REG_NOTIFY_CHANGE_NAME, REG_NOTIFY_CHANGE_ATTRIBUTES, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_SECURITY, and REG_NOTIFY_THREAD_AGNOSTIC (notification not tied to the calling thread). SEC670 warns not to 'poll too often.'"
    relevant_to: []
    tags: [orphan, registry, situational-awareness, regnotifychangekey, watchdog]

  - id: "concept-pe-sieve-memory-scanner"
    name: "PE-sieve Memory Scanner"
    category: defense-mechanism
    description: "PE-sieve (hasherezade) scans a single process and detects injected PEs, hooks, and can dump a discovered implant for analysis. It compares in-memory module images against their on-disk counterparts to find patched .text regions and unbacked executable memory. SEC670 uses PE-sieve as the canonical example of how defensive tools catch injection effects."
    relevant_to: [T-007, T-013, T-016]
    tags: [pe-sieve, memory-scanner, hasherezade, injection-detection, defensive-tool]

  - id: "volatility-memory-forensics"
    name: "Volatility Memory Forensics Framework"
    category: defense-mechanism
    description: "Volatility (Volatility Foundation) ingests full memory dumps and runs numerous plug-ins to recover process state, injected code, and unbacked executable regions. SEC670 emphasizes that 'being in memory is not a get out of jail free card' against motivated memory analysts using Volatility."
    relevant_to: [T-007, T-016]
    tags: [volatility, memory-forensics, memory-dump, defensive-tool]

  - id: "moneta-memory-scanner"
    name: "Moneta User-Mode Memory Scanner"
    category: defense-mechanism
    description: "Moneta (forrest-orr) is a user-mode Windows memory analysis tool similar in purpose to PE-sieve. It identifies suspicious memory regions — unbacked executable pages, modified module .text, private commit with execute permissions — against the live process address space rather than a memory dump."
    relevant_to: [T-007, T-013, T-016]
    tags: [moneta, memory-scanner, forrest-orr, unbacked-exec, defensive-tool]

  - id: "concept-av-cloud-sample-submission"
    name: "AV Cloud Sample Submission OPSEC"
    category: edr-mechanism
    description: "Some AV solutions require cloud-based analysis of unique binaries and 'some AV solutions requi[re]' submission of the binary for remote detonation. A 100% unique implant scanned by such an AV may expose 'all tool capabilities' or 'trade secrets' to the vendor. SEC670 frames this as a tradeoff between full-featured tools and minimal-access tools that limit exposure if picked up."
    relevant_to: []
    tags: [orphan, av, cloud-submission, opsec, sample-submission]

  - id: "themida-commercial-packer"
    name: "Themida Commercial Packer/Protector"
    category: defense-mechanism
    description: "Themida (Oreans) is a commercial packer/encryptor that 'does a tremendous job annoying reverse engineers' by protecting code blocks with virtualization and anti-debug. SEC670 cites it as an example of how operators can apply commercial DRM-style protection to their own implants to slow analyst reverse engineering."
    relevant_to: []
    tags: [orphan, themida, packer, drm, anti-reversing]

  - id: "binary-patching-ntdll-risks"
    name: "Binary Patching of NTDLL Risks"
    category: attack-pattern
    description: "SEC670 explicitly warns against patching ntdll on disk in System32: 'your hooks would be implemented all over the place and it could draw way too much attention to you.' Patching a secondary/tertiary DLL that ntdll loads is the safer alternative. AV/EDR solutions themselves patch ntdll in memory to implement function hooks — in-memory patching is the operational norm, not on-disk patching."
    relevant_to: [T-016]
    tags: [binary-patching, ntdll, opsec, system-stability, hook-implementation]

  - id: "fileless-malware-static-detection-bypass"
    name: "Fileless Malware Static Detection Bypass"
    category: attack-pattern
    description: "Staying off disk means 'no files to be analyzed' and 'bypass static detection' because there is nothing for an analyst to retrieve or hash pre-execution. SEC670 notes EDRs have improved behavior detection but cannot continuously scan all memory regions due to performance constraints — being in memory is a tactical advantage, not a guarantee of safety."
    relevant_to: [T-007, T-013, T-016]
    tags: [fileless, static-detection-bypass, memory-resident, opsec]

  - id: "system32-blending-strategy"
    name: "System32 Folder Blending Strategy"
    category: attack-pattern
    description: "SEC670 notes the System32 folder contains 'over 4,200 items' on Windows 10, providing many neighbors to blend with. The recommended strategy: choose a middle position rather than first/last entry, pick a filename matching surrounding conventions, and align timestamps with adjacent files to evade casual visual inspection."
    relevant_to: []
    tags: [orphan, blending, system32, filename-masquerade, timestamp-alignment]

  - id: "concept-userland-ntll-hook"
    name: "Userland NTDLL Inline Hook"
    category: edr-mechanism
    description: "EDRs patch the first bytes of Nt/Zw stubs in ntdll's .text with a jump instruction redirecting execution into the EDR's userland hook DLL. The hook inspects arguments and call order, then either passes through to the real syscall or blocks. This is the principal userland detection surface that indirect syscalls, Hell's/Halo's Gate, and ntdll unhooking all aim to defeat."
    relevant_to: [T-001, T-002, T-016]
    tags: [edr, userland-hook, ntdll, inline-patch, detection-surface]

  - id: "concept-kernel-edr-component"
    name: "Kernel-Mode EDR Component"
    category: edr-mechanism
    description: "SEC670 explicitly notes that unhooking userland ntdll does not fully blind a security product because 'there could be a kernel module still watching.' Kernel-mode EDR components — via callbacks, ETW-TI, or minifilter drivers — observe the same operations from kernel context and are unaffected by userland unhooking."
    relevant_to: [T-016, T-007, T-013]
    tags: [edr, kernel-mode, callback, etw-ti, minifilter]
```

### Detection Insights

```yaml
detection:
  - indicator: "NTDLL stub bytes not beginning with MOV EDI, EDI"
    source: memory-scan
    confidence: medium
    relevant_to: [T-016]
    description: "A memory scan of ntdll's .text section comparing each stub's first two bytes against the expected 'mov edi, edi' hot-patch prologue detects inline hooks. SEC670 recommends validating findings against the on-disk C:\\Windows\\System32\\ntdll.dll version. PE-sieve and Moneta both implement this heuristic."
    bypassed_by: "not discussed"

  - indicator: "Process created with CREATE_SUSPENDED followed by cross-process memory read from its ntdll"
    source: behavioral
    confidence: medium
    relevant_to: [T-016]
    description: "The suspended-copy unhooking technique requires creating a suspended process and then reading its ntdll .text. Behavioral detection can correlate a CREATE_SUSPENDED process creation event with subsequent cross-process memory reads targeting ntdll's .text region. Suspended processes created without ever being resumed are themselves suspicious."
    bypassed_by: "not discussed"

  - indicator: "Injected PE module with no on-disk backing file"
    source: memory-scan
    confidence: high
    relevant_to: [T-007, T-013]
    description: "PE-sieve detects injected PEs by comparing in-memory module images to their on-disk counterparts. Injected PEs that have no disk backing or whose in-memory .text differs from the on-disk .text are flagged. SEC670 explicitly cites PE-sieve as 'a defensive tool that can catch injection methods.'"
    bypassed_by: "Map shellcode as a section backed by a legitimate file (module stomping / mapping injection) so the in-memory image matches an on-disk file, defeating the disk-vs-memory comparison"

  - indicator: "Unbacked executable private memory region"
    source: memory-scan
    confidence: high
    relevant_to: [T-007, T-013, T-016]
    description: "Moneta and PE-sieve flag private commit (MEM_PRIVATE) regions with execute permissions that have no corresponding module on disk. SEC670 notes EDRs cannot continuously scan all memory for performance reasons, but a targeted scan of a suspect process will find these regions."
    bypassed_by: "Use module overloading or mapping injection so shellcode resides in a MEM_IMAGE region backed by a real file, removing the MEM_PRIVATE+EXECUTE signature"

  - indicator: "Process creation where child is cmd.exe/powershell.exe and parent is an Office application"
    source: behavioral
    confidence: high
    relevant_to: [T-015]
    description: "SEC670 states 'there are certain processes that should never spawn other processes' — Office apps spawning cmd.exe or powershell.exe is the canonical example. PPID spoofing exists specifically to avoid this detection by reassigning the parent to a legitimate process."
    bypassed_by: "Spoof the parent process to a legitimate parent (explorer.exe, svchost.exe) via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS so the child-parent pair looks normal"

  - indicator: "Sysmon Event ID 1 process creation with CREATE_SUSPENDED flag in process creation flags"
    source: sysmon
    confidence: low
    relevant_to: [T-016]
    description: "Sysmon Event ID 1 captures process creation including command-line and process flags. A CREATE_SUSPENDED process that is never resumed — or one immediately followed by handle duplication and cross-process memory access — is suspicious. SEC670 references Sysmon/ProcMon as part of the defensive tool landscape."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Suspended Process Followed by Remote Memory Read"
    logsource: sysmon
    condition_summary: "Sysmon EID 1 (process create) with CREATE_SUSPENDED flag, followed within 5s by Sysmon EID 10 (ProcessAccess) where TargetImage contains 'ntdll.dll' or GrantedAccess includes VM_READ"

  - title: "Office Parent Spawning Command Shell"
    logsource: process-creation
    condition_summary: "ParentImage ends with winword.exe|excel|powerpnt|outlook AND Image ends with cmd.exe|powershell.exe|wscript.exe|mshta.exe"

  - title: "Unbacked Executable Private Memory via Memory Scan"
    logsource: memory-scan
    condition_summary: "Memory scanner reports MEM_PRIVATE region with PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_READ and no matching loaded module entry in PEB Ldr lists"
```

### Operational Chains

```yaml
chains:
  - name: "Indirect Syscall Dispatch Chain"
    description: "Resolve SSN, locate ntdll syscall gadget, dispatch syscall from inside ntdll to maintain clean call stack"
    steps:
      - technique: T-002
        role: "Resolve SSN for target Nt function via Hell's/Halo's/Tartarus cascade — handle hooked stubs via neighbor scan"
      - technique: T-004
        role: "Walk PEB to locate ntdll base address and .text section bounds for gadget discovery"
      - technique: T-001
        role: "Jump into ntdll syscall stub so syscall instruction executes from ntdll memory, yielding a return address inside ntdll rather than the implant image"
    notes: "SEC670 emphasizes that indirect syscalls still require 'finding the correct syscall number' — SSN resolution is a prerequisite, not eliminated by indirect dispatch."

  - name: "Suspended-Copy NTDLL Unhooking Chain"
    description: "Acquire pristine ntdll from a freshly-created suspended process and copy its .text over the implant process's hooked ntdll"
    steps:
      - technique: "shellcode staging"
        role: "Prepare injection payload — unhooking is performed before injection so subsequent injection syscalls execute cleanly"
      - technique: "create suspended process"
        role: "Call CreateProcess with CREATE_SUSPENDED so the new process loads only ntdll.dll before main thread runs — no AV/EDR hooks installed yet"
      - technique: "locate ntdll .text section"
        role: "Walk the suspended process's PEB to find ntdll base, parse PE headers to locate .text section bounds"
      - technique: "pattern scan syscall table"
        role: "Pattern-scan within .text to locate the syscall table region since SEC670 notes there is 'no perfect way to find boundaries'"
      - technique: T-016
        role: "Copy the clean syscall table / .text region over the implant's hooked ntdll, restoring original stub bytes"
      - technique: "inject shellcode"
        role: "With hooks cleared, inject shellcode via now-unhooked syscalls"
    notes: "SEC670 describes this as 'yet another way to unhook hooks' — an in-memory alternative to reading ntdll from disk. Both approaches appear under T-016."

  - name: "PPID Spoofing Process Creation Chain"
    description: "Spoof a legitimate parent process when spawning child processes to evade parent-child anomaly detection"
    steps:
      - technique: "acquire parent handle"
        role: "OpenProcess on the desired parent (e.g., explorer.exe) with PROCESS_CREATE_PROCESS access"
      - technique: T-015
        role: "InitializeProcThreadAttributeList → UpdateProcThreadAttribute with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS and the parent handle — SEC670 notes this requires 'just two API calls'"
      - technique: "create process with attribute list"
        role: "CreateProcess with EXTENDED_STARTUPINFO_PRESENT and the populated attribute list so the new process inherits the spoofed parent PID"
    notes: "SEC670 frames PPID spoofing as 'one method that can be used as an addition to avoid detection' — it composes with other evasion rather than standing alone."

  - name: "CNG AES Shellcode Decryption Chain"
    description: "Use Windows CNG/BCrypt native APIs to decrypt AES-encrypted shellcode at runtime without third-party crypto libraries"
    steps:
      - technique: "BCryptOpenAlgorithmProvider"
        role: "Open the AES algorithm provider"
      - technique: "BCryptGetProperty x2"
        role: "Query chaining mode and block length properties for the algorithm object"
      - technique: "BCryptSetProperty"
        role: "Set the chaining mode (e.g., CBC or GCM) on the algorithm object"
      - technique: "BCryptGenerateSymmetricKey"
        role: "Import the embedded AES key material into a key handle"
      - technique: "BCryptDecrypt"
        role: "Decrypt the shellcode blob in place; the plaintext shellcode is then ready for execution"
    notes: "SEC670 notes the legacy CryptoAPI is deprecated but still usable; CNG is 'more advanced and extensible' and the recommended path for new implants."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "registry-watchdog-situational-awareness"
    title: "Registry Watchdog for Situational Awareness"
    kind: proposed-technique
    description: "SEC670 dedicates material to RegNotifyChangeKey and the REG_NOTIFY_CHANGE_* filter set as a watchdog primitive — detecting AV product installation in real time without polling, with REG_NOTIFY_THREAD_AGNOSTIC enabling thread-persistent notifications. The vault has no technique card for registry-driven situational awareness; this would fit as a distinct T-NNN since it is a reusable primitive across persistence, evasion, and self-deletion chains."
    would_relate_to: [T-017, T-020]
    source_units: ["unit 26", "unit 27"]
    tags: [registry, situational-awareness, regnotifychangekey, watchdog]

  - id: "memory-forensics-tooling-coverage-gap"
    title: "Memory Forensics Tooling Awareness Coverage Gap"
    kind: coverage-gap
    description: "SEC670 explicitly names Volatility, PE-sieve, and Moneta as the defensive memory-forensics stack an operator must assume is in use, and frames the 'being in memory is not a get out of jail free card' constraint. The vault's evasion cards (T-016) describe evasion techniques but do not document which specific scanner heuristics each technique defeats. Cross-cutting metadata linking each evasion to its memory-scanner counter-evasion would close this gap."
    would_relate_to: [T-007, T-013, T-016]
    source_units: ["unit 23", "unit 24", "unit 25", "unit 32"]
    tags: [memory-forensics, pe-sieve, volatility, moneta, coverage-gap, detection]

  - id: "av-cloud-sample-submission-opsec"
    title: "AV Cloud Sample Submission OPSEC"
    kind: coverage-gap
    description: "SEC670 covers the OPSEC risk that 'some AV solutions require' cloud submission of unique binaries, potentially exposing 'all tool capabilities' or 'trade secrets' to the vendor. The vault does not currently document the OPSEC tradeoff between full-featured and minimal-access builds against cloud-submission risk. This would merit cross-cutting metadata on build-feature gating decisions."
    would_relate_to: [T-020, T-021]
    source_units: ["unit 11", "unit 35", "unit 36", "unit 37"]
    tags: [opsec, av, cloud-submission, build-features, minimal-access]

  - id: "system32-blending-evasion"
    title: "System32 Folder Blending as Evasion Technique"
    kind: proposed-technique
    description: "SEC670 documents a concrete strategy for file-based blending: place payloads in System32 (4,200+ files to hide among), choose a middle-listing position, match filename conventions of surrounding entries, and align timestamps. The vault's persistence card (T-017) covers persistence locations but not this file-system blending tradecraft as a distinct evasion step. Worth its own treatment because it composes with persistence and is reusable."
    would_relate_to: [T-017, T-020]
    source_units: ["unit 33", "unit 34"]
    tags: [blending, system32, filename-masquerade, timestamp-alignment, evasion]

  - id: "malware-drm-via-process-ghosting"
    title: "Malware DRM via Process Ghosting for Anti-Copy Launchers"
    kind: emerging-tradecraft
    description: "SEC670 references the Skrull PoC, which uses process ghosting to make launchers 'anti-copy' so they break when submitted for analysis — applying DRM-style protection to malware. This converges with the vault's T-009 (Process Ghosting) but reframes the technique's operational purpose from evasion-of-execution to anti-analysis-of-sample. Worth surfacing as a distinct tradecraft trend: anti-forensic use of process creation races."
    would_relate_to: [T-009, T-020]
    source_units: ["unit 38", "unit 39"]
    tags: [process-ghosting, drm, anti-copy, skrull, emerging-tradecraft]

  - id: "undocumented-native-api-process-enum"
    title: "Undocumented Native API Process Enumeration"
    kind: coverage-gap
    description: "SEC670 explicitly surfaces NtQuerySystemInformation with SYSTEM_INFORMATION_CLASS as an 'undocumented method' for process enumeration that bypasses the Win32 toolhelp32 path EDRs commonly monitor. The vault has no concept or technique entry covering native-API-based process enumeration as an evasion-aware alternative to Process32First/Next. This is reusable across recon, injection target selection, and anti-analysis."
    would_relate_to: [T-023, T-020]
    source_units: ["unit 21"]
    tags: [native-api, ntquerysysteminformation, process-enum, evasion, undocumented]
```