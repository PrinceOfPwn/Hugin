## Synthesis Summary

The material in this batch spans SANS SEC670's evasion and tradecraft modules and maps primarily to T-001 (RecycledGate), T-002 (Hell's/Halo's/Tartarus Gate), T-007 (Process Injection), T-016 (EDR Evasion Suite), T-017 (Five-Layer Persistence), T-020 (Anti-Analysis Suite), T-021 (Crypto & Obfuscation), and T-022 (Network Suite). The training material covers the syscall dispatch model (user-mode hook mechanics in ntdll.dll and win32u.dll, syscall stub structure including KUSER_SHARED_DATA, direct vs indirect syscalls, SSN variability across OS versions), fileless malware advantages and memory-forensics defensive tools (Volatility, PE-sieve, Moneta), persistence mechanisms not currently detailed in the vault (AppCert DLLs, AppInit DLLs, IFEO GlobalFlag silent process exit), AMSI patching labs, and shellcode encryption tradecraft (AES via CNG, XOR, Base64 via CryptStringToBinaryA). The gap this material fills is the operational and defensive context that source code alone cannot provide: why syscall stubs have the specific assembly structure they do, why syscall numbers cannot be hardcoded, why user-mode hooks exist in both ntdll.dll and win32u.dll for native vs GUI thread syscalls, how memory scanners identify injected PEs, and what persistence surfaces Windows exposes via registry-based monitoring keys.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "win-syscall-number-variability"
    target: T-002
    type: requires
    rationale: "SEC670 states that Windows syscall numbers change across OS versions, so dynamic SSN resolution (Hells/Halo's/Tartarus Gate) is required rather than hardcoding."

  - source: "user-mode-ntdll-hooks"
    target: T-001
    type: enables
    rationale: "SEC670 explains that security products implement user-mode hooks in ntdll.dll; this motivates indirect syscalls via ntdll gadgets (RecycledGate) to bypass those hooks."

  - source: "user-mode-ntdll-hooks"
    target: T-016
    type: concept_link
    rationale: "SEC670 frames ntdll unhooking as the response to detected user-mode hooks; the EDR evasion suite's NTDLL unhook operation directly addresses these hooks."

  - source: "direct-syscall-pattern"
    target: "indirect-syscall-pattern"
    type: alternative_to
    rationale: "SEC670 presents direct syscalls and indirect syscalls as related but distinct approaches: direct invokes the syscall instruction from implant code, indirect jumps to a known location in ntdll.dll."

  - source: "indirect-syscall-pattern"
    target: T-001
    type: concept_link
    rationale: "RecycledGate implements indirect syscalls by jumping to ntdll gadgets, matching the SEC670 description of indirect syscalls jumping to known ntdll.dll locations."

  - source: "pe-sieve-tool"
    target: T-007
    type: detects
    rationale: "SEC670 describes PE-sieve as scanning a single process and detecting injected PEs and hooks, directly relevant to the process injection technique space."

  - source: "memory-forensics-tools"
    target: T-007
    type: detects
    rationale: "SEC670 lists Volatility, PE-sieve, and Moneta as tools that detect implants in memory, noting that being in memory is not a guaranteed evasion."

  - source: "reflective-pe-loading"
    target: T-007
    type: concept_link
    rationale: "SEC670 describes reflective loading as manually loading PE images in memory to avoid disk artifacts; the vault's T-007 includes a reflective PE loader implementation."

  - source: "cng-crypto-apis"
    target: T-021
    type: concept_link
    rationale: "SEC670 explicitly recommends CNG APIs (BCryptOpenAlgorithmProvider, BCryptSetProperty, BCryptEncrypt) for AES-CTR or AES-GCM encryption, which T-021's AES-GCM implementation uses."

  - source: "sysmon-wmi-detection"
    target: T-017
    type: detects
    rationale: "SEC670 states Sysmon can be configured to log WMI Event Filters, Event Consumer, and binding events — directly relevant to persistence detection for T-017."

  - source: "win32u-gui-syscall-path"
    target: T-001
    type: concept_link
    rationale: "SEC670 documents that GUI syscalls route through win32u.dll to win32k.sys, a separate path from native ntdll syscalls; syscall dispatch techniques must account for both paths."

  - source: "appcert-dll-monitoring"
    target: T-017
    type: concept_link
    rationale: "SEC670 describes AppCert DLLs as a Windows monitoring mechanism loaded into processes that call CreateProcess/WinExec; this is a persistence and detection surface adjacent to T-017."

  - source: "ifeo-globalflag-silent-exit"
    target: T-017
    type: concept_link
    rationale: "SEC670 describes IFEO GlobalFlag as enabling silent process exit monitoring, a persistence-adjacent mechanism not currently covered by the vault's five persistence layers."
```

### Concept Nodes

```yaml
concepts:
  - id: "kuser-shared-data"
    name: "KUSER_SHARED_DATA (Shared User Data Page)"
    category: windows-structure
    description: "A read-only page mapped at fixed address 0x7FFE0000 in every user-mode process, containing system information including the SystemCall and SystemCallReturn addresses. The syscall stub's 'test byte ptr [7FFE0308h], 1' instruction checks a flag in this page to determine whether to use the syscall instruction or the int 0x2E fallback for kernel transition. SEC670 documents this check as part of the standard ntdll syscall stub structure."
    relevant_to: [T-001, T-002]
    tags: [windows-internals, syscall, shared-memory, kernel-transition]

  - id: "win32u-gui-syscall-path"
    name: "win32u.dll GUI Syscall Path vs ntdll Native Path"
    category: os-internal
    description: "SEC670 documents that Windows splits syscalls into two paths: native syscalls (NtOpenProcess, NtCreateProcess) route through ntdll.dll to the kernel/executive; GUI syscalls (NtUserOpenClipboard, NtUserCloseClipboard) route through win32u.dll to win32k.sys. A thread invoking a syscall lands in different kernel components depending on whether the call is native or GUI. EDR products monitoring syscall activity must hook both ntdll.dll and win32u.dll to capture the full syscall surface."
    relevant_to: [T-001, T-002, T-016]
    tags: [syscall, win32u, win32k, gui, kernel, edr-hooking]

  - id: "syscall-stub-structure"
    name: "NTDLL Syscall Stub Assembly Pattern"
    category: os-internal
    description: "SEC670 documents the standard ntdll syscall stub structure as: mov r10, rcx; mov eax, <syscall_number>; test byte ptr [7FFE0308h], 1; jne <fallback>; syscall; ret; (fallback) int 2Eh; ret. Unlike standard functions, syscall stubs lack prologue/epilogue and stack frame setup. The mov r10, rcx instruction copies the RCX argument register to R10 because the syscall instruction clobbers RCX. EDR user-mode hooks typically overwrite the first bytes of these stubs with a jmp instruction."
    relevant_to: [T-001, T-002, T-003, T-016]
    tags: [syscall, assembly, ntdll, stub, kernel-transition]

  - id: "win-syscall-number-variability"
    name: "Windows Syscall Number Variability Across OS Versions"
    category: os-internal
    description: "SEC670 documents that Windows syscall numbers change across OS versions, unlike Linux where interrupt 0x80 is relatively stable. j00ru's syscall table documents syscalls from Windows XP SP1 through Windows 11, showing that syscall 0x00 maps to NtAccessCheck on Windows 10/11 but to a different function on earlier versions. Hardcoding syscall numbers in shellcode breaks portability across Windows versions, motivating dynamic SSN resolution techniques like Hells Gate, Halo's Gate, and Tartarus Gate."
    relevant_to: [T-002, T-004]
    tags: [syscall, ssn, portability, version-differences]

  - id: "user-mode-ntdll-hooks"
    name: "EDR User-Mode Hooks in ntdll.dll and win32u.dll"
    category: edr-mechanism
    description: "SEC670 documents that security products implement user-mode hooks by overwriting the first bytes of syscall stubs in ntdll.dll, kernelbase.dll, and win32u.dll with jmp instructions. These hooks let the EDR inspect function arguments before allowing the syscall to proceed. Individual API calls are benign but combinations (e.g., NtOpenProcess followed by NtAllocateVirtualMemory followed by NtWriteVirtualMemory) are suspicious. VX-Underground's 'AntiVirus Artifacts' whitepaper documents which functions each EDR product hooks."
    relevant_to: [T-001, T-016]
    tags: [edr, hooking, ntdll, win32u, detection, user-mode]

  - id: "direct-syscall-pattern"
    name: "Direct Syscalls (Invoke syscall from Implant Code)"
    category: attack-pattern
    description: "SEC670 describes direct syscalls as a technique where the implant invokes the syscall instruction directly from its own code rather than calling through ntdll.dll. This bypasses user-mode hooks in ntdll because the EDR's hooked stub is never executed. The trade-off is that the call stack no longer originates from ntdll, and kernel-mode components checking call stacks can detect this anomaly. SEC670 notes direct syscalls have been used for at least 10 years."
    relevant_to: [T-001, T-002]
    tags: [syscall, evasion, edr-bypass, direct-syscall]

  - id: "indirect-syscall-pattern"
    name: "Indirect Syscalls (Jump to ntdll Gadget)"
    category: attack-pattern
    description: "SEC670 describes indirect syscalls as jumping to a known location within ntdll.dll (specifically a syscall; ret gadget) to execute the syscall instruction from ntdll's own code rather than the implant's. This avoids user-mode hooks while producing a call stack that appears to originate from ntdll, addressing the call-stack detection weakness of direct syscalls. The material explicitly frames this as an evolution of direct syscalls for EDR evasion."
    relevant_to: [T-001]
    tags: [syscall, evasion, edr-bypass, indirect-syscall, call-stack]

  - id: "pe-sieve-tool"
    name: "PE-sieve Memory Scanner"
    category: defense-mechanism
    description: "PE-sieve, authored by hasherezade, scans a single process to detect injected PEs and hooks. It can dump discovered implants for further analysis. SEC670 positions it as a primary defensive tool for catching injection methods, alongside Volatility and Moneta. The tool's per-process scanning model means an operator must evade detection within each scanned process individually."
    relevant_to: [T-007, T-016]
    tags: [memory-scan, defense, pe-sieve, injection-detection]

  - id: "memory-forensics-tools"
    name: "Memory Forensics Tool Suite (Volatility, PE-sieve, Moneta)"
    category: defense-mechanism
    description: "SEC670 documents three memory forensics tools: Volatility (from Volatility Foundation, ingests memory dumps with plugins), PE-sieve (from hasherezade, scans a process and dumps implants), and Moneta (from forrest-orr, user-mode Windows memory analysis similar to PE-sieve). The material emphasizes that being in memory is not guaranteed evasion — motivated analysts using these tools will likely detect implants. EDR products face performance constraints that prevent constant scanning of all memory regions."
    relevant_to: [T-007, T-016]
    tags: [memory-forensics, defense, volatility, moneta, pe-sieve]

  - id: "appcert-dll-monitoring"
    name: "AppCert DLLs"
    category: windows-structure
    description: "SEC670 documents AppCert DLLs as a Windows mechanism where certain Create* API calls (CreateProcess, WinExec) trigger the system to check the Registry for DLLs that must be loaded into the process. This is similar to AppInit DLLs but applies to a different set of API calls. AppCert DLLs represent both a persistence surface (loading a malicious DLL into every process that creates a child process) and a detection surface (EDR products can leverage this mechanism)."
    relevant_to: [T-017]
    tags: [persistence, appcert, registry, dll-loading, windows-internals]

  - id: "ifeo-globalflag-silent-exit"
    name: "IFEO GlobalFlag Silent Process Exit Monitoring"
    category: windows-structure
    description: "SEC670 documents the IFEO (Image File Execution Options) GlobalFlag setting as an addition to traditional IFEO debugger keys. When configured, it enables silent process exit monitoring for a specified process. The gflags/sflg tooling (bundled with Windows SDK) configures this monitoring. The GflagsX tool consolidates Silent Process Exit options under the Image tab. This mechanism can be abused for persistence and is also a detection surface EDR products can leverage."
    relevant_to: [T-017]
    tags: [persistence, ifeo, globalflag, silent-process-exit, registry]

  - id: "cng-crypto-apis"
    name: "Cryptography Next Generation (CNG) APIs"
    category: crypto-primitive
    description: "SEC670 recommends CNG APIs for implant encryption, specifically BCryptOpenAlgorithmProvider, BCryptSetProperty, BCryptGenerateSymmetricKey, BCryptEncrypt, and BCryptDecrypt. The material explicitly deprecates older CryptoAPI calls (CryptAcquireContextA, CryptCreateHash, CryptHashData, CryptDeriveKey, CryptDecrypt) and recommends CNG for AES-CTR or AES-GCM to protect against SSL interception by proxies like F5 BIG-IP or Blue Coat."
    relevant_to: [T-021, T-022]
    tags: [crypto, cng, bcrypt, aes, ssl-interception]

  - id: "certificate-pinning"
    name: "Certificate Pinning for C2 Communications"
    category: attack-pattern
    description: "SEC670 documents certificate pinning as a technique to prevent MITM attacks by validating specific certificate thumbprints in implant communications. The implementation uses InternetQueryOption with INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, CertGetNameString with CERT_NAME_SIMPLE_DISPLAY_TYPE, and CertGetCertificateContextProperty with CERT_HASH_PROP_ID. Windows, Apple, and Android platforms all use certificate pinning. This protects C2 traffic from SSL inspection appliances."
    relevant_to: [T-022]
    tags: [network, certificate-pinning, mitm, c2, ssl]

  - id: "reflective-pe-loading"
    name: "Reflective PE Loading"
    category: attack-pattern
    description: "SEC670 describes reflective loading as manually loading PE images or DLLs in memory without dropping them to disk. A custom loader allows an implant to pull down PE images over a socket and execute them without disk artifacts. The material frames this as a primary technique for fileless malware operations where avoiding disk presence is required."
    relevant_to: [T-007]
    tags: [fileless, reflective-loading, pe-loader, memory-execution]

  - id: "string-obfuscation-arrays"
    name: "String Obfuscation via Character Arrays"
    category: attack-pattern
    description: "SEC670 documents a string obfuscation technique where plain-text string declarations (char* name = \"GetProcAddress\") are replaced with character arrays (char name[] = {'G','e','t','P',...,'\\0'}). The material notes this evades automated string extraction tools like Sysinternals Strings and IDAPro's Strings view, though manual analysis in IDAPro or Ghidra can still recover the strings. Global variables storing strings or constants (ports, function names) are also flagged as static analysis risks."
    relevant_to: [T-021]
    tags: [obfuscation, strings, static-analysis, idapro, ghidra]

  - id: "fileless-malware-advantages"
    name: "Fileless Malware Advantages Over Disk-Based Implants"
    category: attack-pattern
    description: "SEC670 documents the operational advantages of fileless malware: no files on disk for analysts to retrieve, no static analysis risk, and no risk of static detection. The material notes that while EDRs have improved behavior detection, they cannot scan all memory regions constantly due to performance constraints. Fileless techniques are positioned as evasion against static analysis specifically."
    relevant_to: [T-007, T-016]
    tags: [fileless, evasion, static-analysis, memory-resident]

  - id: "shellcode-encoding-methods"
    name: "Shellcode Encoding and Encryption Methods"
    category: attack-pattern
    description: "SEC670 documents three shellcode transformation methods: AES encryption via CNG (preferred over deprecated CryptoAPI), XOR with a key (same routine for encrypt/decrypt), and Base64 encoding via CryptStringToBinaryA/CryptBinaryToStringA or certutil.exe -encode. The material distinguishes encoding (no key) from encryption (requires key) and notes XOR is technically encryption because it uses a key. Raw shellcode in a binary is flagged by AV/EDR solutions."
    relevant_to: [T-021]
    tags: [shellcode, encryption, xor, base64, aes, evasion]
```

### Detection Insights

```yaml
detection:
  - indicator: "Injected PEs and hooks in process memory"
    source: memory-scan
    confidence: high
    relevant_to: [T-007, T-016]
    description: "PE-sieve scans a single process and detects injected PEs and user-mode hooks. It can dump discovered implants for analysis. SEC670 positions PE-sieve as a tool that catches various injection methods."
    bypassed_by: "SEC670 does not discuss specific bypass techniques for PE-sieve in this material."

  - indicator: "Memory-resident implants without disk artifacts"
    source: memory-scan
    confidence: medium
    relevant_to: [T-007, T-016]
    description: "Volatility ingests memory dumps and uses plugins to detect implants. Moneta performs user-mode Windows memory analysis similar to PE-sieve. SEC670 emphasizes that motivated analysts using these tools will likely detect in-memory implants despite fileless techniques."
    bypassed_by: "SEC670 notes that EDR products face performance constraints preventing constant memory scanning, but does not detail specific bypass techniques."

  - indicator: "WMI Event Filter, Event Consumer, and binding creation"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Sysmon can be configured to log WMI Event Filters, Event Consumers, and the bindings between them. SEC670 states this configuration catches WMI-based attacks but requires analysis to determine if events are malicious."
    bypassed_by: "not discussed"

  - indicator: "User-mode hooks overwritten in ntdll.dll and win32u.dll"
    source: memory-scan
    confidence: high
    relevant_to: [T-016]
    description: "EDR products overwrite the first bytes of syscall stubs with jmp instructions. SEC670 shows the hooked stub pattern as 'e93b3c1600 jmp <address>' followed by int 3 padding. Implants can detect these hooks by reading the first bytes of ntdll syscall stubs and comparing against the expected 'mov r10, rcx' pattern."
    bypassed_by: "SEC670 describes NTDLL unhooking as the response — restoring the original syscall stub bytes from a clean ntdll.dll copy."

  - indicator: "Call stack originating outside ntdll for syscall invocation"
    source: kernel-callback
    confidence: medium
    relevant_to: [T-001, T-002]
    description: "SEC670 states that direct syscalls, while bypassing user-mode hooks, can be detected by kernel-mode components that check call stacks. A syscall invoked from implant code rather than ntdll produces an anomalous call stack."
    bypassed_by: "SEC670 mentions call stack spoofing or cloning techniques exist to address this, and frames indirect syscalls (jumping to ntdll gadgets) as the alternative that produces a legitimate-looking call stack."

  - indicator: "Hardcoded syscall numbers in shellcode or binary"
    source: behavioral
    confidence: low
    relevant_to: [T-002]
    description: "SEC670 documents that syscall numbers vary across Windows versions; hardcoding them produces a binary that fails on mismatched OS versions, which can appear as crashes or unexpected behavior in telemetry."
    bypassed_by: "Use dynamic SSN resolution (Hells Gate, Halo's Gate, Tartarus Gate) instead of hardcoding."

sigma_ideas:
  - title: "WMI Persistence via Event Filter and Consumer Binding"
    logsource: sysmon
    condition_summary: "Sysmon Event ID 19 (WMI filter), 20 (WMI consumer), and 21 (WMI filter-to-consumer binding) events, with correlation to identify persistence chains"

  - title: "NTDLL Syscall Stub Hook Detection"
    logsource: memory-scan
    condition_summary: "First bytes of ntdll.dll syscall stubs deviate from expected pattern (mov r10, rcx; mov eax, <num>), indicating jmp overwrite by EDR or malicious hook"

  - title: "AppCert DLL Registry Key Modification"
    logsource: windows-security
    condition_summary: "Registry modifications to HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls adding DLL paths"

  - title: "IFEO GlobalFlag Silent Process Exit Configuration"
    logsource: windows-security
    condition_summary: "Registry modifications to HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\GlobalFlag setting SFL bit for silent process exit monitoring"
```

### Operational Chains

```yaml
chains:
  - name: "Syscall Evasion Chain — From SSN Resolution to Indirect Dispatch"
    description: "Sequence for evading user-mode EDR hooks while maintaining a legitimate call stack"
    steps:
      - technique: T-004
        role: "Resolve ntdll base via PEB walker (gs:[0x60]) without calling any hooked API"
      - technique: T-002
        role: "Dynamically resolve syscall numbers (SSNs) via Hells/Halo's/Tartarus Gate cascade, avoiding hardcoded numbers that break across OS versions"
      - technique: T-016
        role: "Optionally unhook ntdll.dll by restoring original syscall stub bytes from a clean copy, removing EDR's jmp hooks"
      - technique: T-001
        role: "Dispatch syscalls indirectly via ntdll gadgets (RecycledGate) so the call stack originates from ntdll, evading kernel call-stack checks"
    notes: "SEC670 frames this as a layered approach: direct syscalls bypass user-mode hooks but introduce call-stack anomalies; indirect syscalls (jumping to ntdll gadgets) address both. The material notes this technique has been used for at least 10 years."

  - name: "Fileless Implant Execution Chain — Reflective Loading"
    description: "Sequence for executing PE payloads in memory without disk artifacts"
    steps:
      - technique: "shellcode staging"
        role: "Acquire encrypted/encoded shellcode or PE image over network socket or C2 channel"
      - technique: T-021
        role: "Decrypt shellcode in memory using AES-GCM (CNG) or XOR with a key"
      - technique: "reflective-pe-loading"
        role: "Manually load the PE image in memory without dropping to disk, avoiding static analysis"
      - technique: T-007
        role: "Execute the loaded PE via injection into a legitimate process to blend with legitimate activity"
    notes: "SEC670 emphasizes that fileless techniques avoid static detection but are not guaranteed evasion against memory forensics tools (Volatility, PE-sieve, Moneta)."

  - name: "Persistence via AppCert/AppInit DLL Loading"
    description: "Sequence for achieving persistence through Windows DLL loading mechanisms that trigger on specific API calls"
    steps:
      - technique: "registry key modification"
        role: "Write malicious DLL path to AppCert or AppInit registry key"
      - technique: "wait for trigger process"
        role: "Wait for a process to call CreateProcess (AppCert) or load User32.dll (AppInit), triggering DLL load"
      - technique: "dll execution"
        role: "Malicious DLL executes within the new process context, establishing persistence"
    notes: "SEC670 distinguishes AppCert (CreateProcess/WinExec trigger) from AppInit (User32.dll load trigger). Both are registry-based persistence surfaces not currently detailed in the vault's T-017 five-layer persistence suite."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "appcert-dll-persistence-coverage"
    title: "AppCert DLLs as Persistence Surface"
    kind: coverage-gap
    description: "SEC670 documents AppCert DLLs as a Windows persistence mechanism where CreateProcess and WinExec trigger loading of DLLs registered in the Registry. The vault's T-017 persistence suite covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist, but does not document AppCert DLLs. This is a distinct persistence surface with different trigger conditions (process creation APIs) and would merit documentation as a sixth persistence layer or an extension to T-017."
    would_relate_to: [T-017]
    source_units: ["unit 13", "unit 14"]
    tags: [persistence, appcert, registry, coverage-gap]

  - id: "ifeo-globalflag-silent-exit-persistence"
    title: "IFEO GlobalFlag Silent Process Exit as Persistence/Monitoring"
    kind: coverage-gap
    description: "SEC670 documents the IFEO GlobalFlag setting as enabling silent process exit monitoring, configurable via gflags/sflg (bundled with Windows SDK). This is distinct from traditional IFEO debugger keys and represents both a persistence surface and a detection surface. The vault's T-017 does not currently cover this mechanism. SEC670 shows both the legacy gflags.exe GUI and the modernized GflagsX tool, indicating this is a documented, accessible Windows feature."
    would_relate_to: [T-017]
    source_units: ["unit 15", "unit 16", "unit 17"]
    tags: [persistence, ifeo, globalflag, silent-process-exit, coverage-gap]

  - id: "certificate-pinning-c2-tradecraft"
    title: "Certificate Pinning for C2 SSL Inspection Evasion"
    kind: coverage-gap
    description: "SEC670 documents certificate pinning as a technique to prevent MITM inspection of C2 traffic by SSL proxies (F5 BIG-IP, Blue Coat). The implementation uses InternetQueryOption with INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, CertGetNameString, and CertGetCertificateContextProperty. The vault's T-022 networking suite documents malleable C2 and HTTP polling but does not appear to cover certificate pinning as a tradecraft for evading SSL inspection appliances."
    would_relate_to: [T-022]
    source_units: ["unit 19"]
    tags: [network, certificate-pinning, ssl, c2, coverage-gap]

  - id: "memory-forensics-defense-landscape"
    title: "Memory Forensics Tool Coverage Gap"
    kind: coverage-gap
    description: "SEC670 documents three memory forensics tools (Volatility, PE-sieve, Moneta) as defensive capabilities that detect in-memory implants despite fileless techniques. The vault's technique cards document injection and evasion methods but do not currently document the specific defensive tools operators must evade. Documenting PE-sieve's per-process scanning model and Moneta's user-mode analysis approach would help operators understand the threat landscape for T-007 and T-016 techniques."
    would_relate_to: [T-007, T-016]
    source_units: ["unit 1", "unit 9"]
    tags: [memory-forensics, defense, pe-sieve, moneta, volatility, coverage-gap]

  - id: "cng-vs-legacy-cryptoapi-modernization"
    title: "CNG API Migration from Legacy CryptoAPI"
    kind: cross-source-convergence
    description: "SEC670 explicitly deprecates legacy CryptoAPI calls (CryptAcquireContextA, CryptCreateHash, CryptHashData, CryptDeriveKey, CryptDecrypt) and recommends CNG APIs (BCryptOpenAlgorithmProvider, BCryptSetProperty, BCryptEncrypt) for AES-CTR or AES-GCM. The vault's T-021 already uses AES-GCM, suggesting convergence on CNG as the standard crypto primitive. This convergence across training material and vault implementation indicates CNG is the established modern approach for implant crypto."
    would_relate_to: [T-021]
    source_units: ["unit 18", "unit 22"]
    tags: [crypto, cng, cryptoapi, aes, modernization, convergence]

  - id: "gui-vs-native-syscall-path-awareness"
    title: "GUI Syscall Path via win32u.dll and win32k.sys"
    kind: emerging-tradecraft
    description: "SEC670 documents that Windows splits syscalls into native (ntdll.dll → kernel/executive) and GUI (win32u.dll → win32k.sys) paths, with different thread types routing to different kernel components. EDR products must hook both ntdll.dll and win32u.dll to capture the full syscall surface. The vault's syscall dispatch techniques (T-001, T-002, T-003) appear to focus on native ntdll syscalls; documenting the win32u.dll GUI syscall path would expand coverage to cover GUI-related operations (clipboard, window manipulation) relevant to T-023 client capabilities."
    would_relate_to: [T-001, T-002, T-023]
    source_units: ["unit 34", "unit 35", "unit 36"]
    tags: [syscall, win32u, win32k, gui, edr-hooking, emerging-tradecraft]
```