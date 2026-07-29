## Synthesis Summary

This batch from SANS SEC670 (Red Teaming Tools: Developing Windows Implants) maps primarily to **T-001 (RecycledGate)**, **T-002 (Hell's/Halo's/Tartarus Gate)**, **T-016 (EDR Evasion Suite — NTDLL unhooking, syscall dispatch)**, **T-013 (PE Loader / Reflective DLL Injection)**, and **T-017 (Five-Layer Persistence — IFEO/AppCert adjacency)**. The material covers user-mode hooking architecture in ntdll/kernelbase/win32u, the syscall transition path through VirtualAlloc→NtAllocateVirtualMemory, direct and indirect syscalls as EDR hook bypasses, the Hell's/Halo's Gate SSN resolution family, the 32-bit MOV EDI, EDI hot-patch prologue exploited for unhooking, IFEO GlobalFlag and Silent Process Exit as persistence/monitoring primitives, AppCert DLLs, SDDL-based service hiding, and Reflective DLL Injection. The gap the source code alone cannot fill is the operational "why": why EDRs hook at the userland ntdll layer, what syscall stub bytes look like before and after hooking (mov r10, rcx; mov eax, SSN; test byte ptr [...]; syscall), how Halo's Gate exploits the numerical ordering of SSNs in ntdll to recover hooked syscall IDs by inspecting neighbors, why disk-side ntdll.dll at C:\Windows\System32\Ntdll.dll is the canonical validation source, and what 32-bit hot-patch prologues reveal about hook detection signatures. No units were skipped as off-theme; all 40 units fall within offensive Windows tradecraft.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "ntdll-usermode-hook"
    target: T-002
    type: requires
    rationale: "Hell's Gate assumes the target ntdll syscall stub is unhooked; if a stub is hooked the technique fails, which is the operational gap Halo's Gate exists to close per the SEC670 material."
  - source: "halos-gate"
    target: T-002
    type: alternative_to
    rationale: "Halo's Gate is presented as the alternative to Hell's Gate when the target stub is hooked, recovering the SSN by inspecting neighboring unhooked stubs."
  - source: "halos-gate"
    target: "ntdll-usermode-hook"
    type: counters
    rationale: "Halo's Gate specifically defeats the hooked-stub condition by relying on the numerical ordering of SSNs in ntdll, recovering an SSN from an unhooked neighbor stub."
  - source: "direct-syscalls"
    target: "ntdll-usermode-hook"
    type: counters
    rationale: "SEC670 describes direct syscalls as a bypass for EDR user-mode hooks by avoiding the standard ntdll execution path."
  - source: "indirect-syscalls"
    target: "direct-syscalls"
    type: enhances
    rationale: "Indirect syscalls improve on direct syscalls by jumping to a known location inside ntdll.dll, addressing the kernel-mode call-stack origin check that defeats direct syscalls."
  - source: T-001
    target: "indirect-syscalls"
    type: concept_link
    rationale: "RecycledGate in the vault implements the indirect-syscall pattern the SEC670 material describes at the conceptual level — jumping into ntdll to dispatch the syscall rather than executing the syscall instruction from implant memory."
  - source: "ntdll-disk-validation"
    target: T-016
    type: enables
    rationale: "SEC670 identifies C:\\Windows\\System32\\Ntdll.dll on disk as the canonical validation source for restoring hooked ntdll bytes, which is the core of NTDLL unhooking in T-016."
  - source: "mov-edi-edi-hotpatch"
    target: T-016
    rationale: "The 32-bit MOV EDI, EDI hot-patch prologue is the byte signature SEC670 uses to identify unhooked function starts versus hooked stubs that begin with a jmp rel32, informing the unhook detection logic in T-016."
  - source: "ifeo-globalflag"
    target: T-017
    type: alternative_to
    rationale: "IFEO GlobalFlag and Silent Process Exit are presented as persistence/monitoring primitives adjacent to the persistence layer in T-017, offering alternative trigger mechanisms to TLS callbacks and scheduled tasks."
  - source: "appcert-dlls"
    target: T-017
    type: alternative_to
    rationale: "AppCert DLLs load into processes that call CreateProcess-family APIs, offering a persistence path parallel to the COM hijack and schtask vectors in T-017."
  - source: "reflective-dll-injection"
    target: T-013
    type: concept_link
    rationale: "RDI manually maps a DLL into a target's virtual address space without listing it via the system loader, which is the operational concept underlying the PE Loader entry in T-013."
```

### Concept Nodes

```yaml
concepts:
  - id: "ntdll-usermode-hook"
    name: "NTDLL User-Mode Hooking by EDRs"
    category: edr-mechanism
    description: "Security products place inline hooks (typically jmp rel32) on Nt* functions in ntdll.dll, kernelbase.dll, and win32u.dll to inspect arguments before delegating to the kernel. Hooked stubs lose the original mov r10, rcx; mov eax, SSN; syscall sequence, replacing it with a jump into the EDR's userland DLL. SEC670 cites the VX-Underground 'AntiVirus Artifacts' whitepaper as a documented catalog of which APIs EDRs hook and in which modules."
    relevant_to: [T-001, T-002, T-016]
    tags: [edr, hooking, ntdll, kernelbase, win32u, userland]

  - id: "direct-syscalls"
    name: "Direct Syscalls"
    category: attack-pattern
    description: "Direct syscalls bypass userland EDR hooks by issuing the syscall instruction directly from implant code rather than routing through the ntdll stub. The SEC670 material shows the canonical ntdll NtAllocateVirtualMemory stub (mov r10, rcx; mov eax, 0x18; test byte ptr [7FFE0308h], 1; jne; syscall; ret) and contrasts it with the direct approach. The material notes this technique has been in use for roughly a decade and still bypasses EDRs that have not advanced to kernel-mode telemetry."
    relevant_to: [T-001, T-002, T-016]
    tags: [syscalls, evasion, edr-bypass, userland]

  - id: "indirect-syscalls"
    name: "Indirect Syscalls"
    category: attack-pattern
    description: "Indirect syscalls extend direct syscalls by jumping to a known location inside ntdll.dll to execute the syscall instruction, addressing the kernel-mode check that the return address originates from ntdll. SEC670 presents this as an evolution of direct syscalls intended to evade kernel-side call-stack inspection that flags syscalls not originating from ntdll."
    relevant_to: [T-001, T-016]
    tags: [syscalls, evasion, edr-bypass, call-stack, indirect]

  - id: "hells-gate"
    name: "Hell's Gate"
    category: attack-pattern
    description: "Hell's Gate dynamically locates the System Service Number (SSN) embedded in a target ntdll syscall stub at runtime, then executes the syscall directly from position-independent code. The SEC670 material classifies it as one of three 'gates' for kernel-mode access and notes it requires the target stub to be unhooked — a limitation Halo's Gate was designed to address."
    relevant_to: [T-002, T-016]
    tags: [syscalls, ssn-resolution, dynamic, gate]

  - id: "halos-gate"
    name: "Halo's Gate"
    category: attack-pattern
    description: "Halo's Gate recovers the SSN of a hooked ntdll stub by walking neighboring stubs in either direction and reading their syscall numbers. Because SSNs in ntdll are laid out in numerical order, an unhooked neighbor's SSN plus or minus the offset yields the hooked function's SSN. SEC670 emphasizes that this allows syscall execution without repairing the hook, evading detection."
    relevant_to: [T-002, T-016]
    tags: [syscalls, ssn-resolution, neighbor-walk, gate, hooked-stub]

  - id: "heavens-gate"
    name: "Heaven's Gate"
    category: attack-pattern
    description: "Heaven's Gate is a Wow64-era technique that allows a 32-bit process to transition to 64-bit code by jumping through the 0x33 segment selector, accessing the 64-bit ntdll and its syscall stubs directly. SEC670 lists it alongside Hell's Gate and Halo's Gate as one of the three 'gatekeepers to kernel mode.'"
    relevant_to: [T-002]
    tags: [syscalls, wow64, 32-bit, segment-selector, gate]

  - id: "mov-edi-edi-hotpatch"
    name: "32-bit MOV EDI, EDI Hot-Patch Prologue"
    category: os-internal
    description: "32-bit Windows function prologues historically begin with MOV EDI, EDI — a two-byte NOP-equivalent instruction reserved for Microsoft's hot-patching mechanism. The five one-byte NOPs preceding the function provide space for a short relative jump. SEC670 uses this byte signature as the canonical indicator of an unhooked function; deviation (typically a jmp rel32 at the start) indicates a hook. Hooked 32-bit stubs exhibit a jmp 0xFB (-5) back to a trampoline or jmp rel32 (E9) into an EDR module."
    relevant_to: [T-016]
    tags: [hotpatch, prologue, 32-bit, wow64, hook-detection, mov-edi-edi]

  - id: "ntdll-disk-validation"
    name: "NTDLL Disk Image as Validation Source"
    category: attack-pattern
    description: "SEC670 identifies C:\\Windows\\System32\\Ntdll.dll on disk as the canonical validation source for verifying whether the in-memory ntdll has been hooked. The methodology is: scan function headers for unexpected bytes (jumps, missing MOV EDI, EDI), compare against the disk version, then replace patched bytes with either original bytes from the disk file or a custom patch."
    relevant_to: [T-016]
    tags: [unhooking, validation, disk-vs-memory, ntdll, methodology]

  - id: "win32u-dll"
    name: "win32u.dll as GUI Syscall Layer"
    category: windows-structure
    description: "win32u.dll hosts the user32/windowing syscall stubs (e.g., NtUserOpenClipboard) on modern Windows. SEC670 distinguishes between the 'Native' (ntdll.dll) and 'GUI' (win32u.dll) syscall layers and notes that EDRs hook both — a tool scanning only ntdll will miss win32u hooks and vice versa."
    relevant_to: [T-016]
    tags: [win32u, gui-syscalls, user32, hooking, layered]

  - id: "syscall-stub-canonical"
    name: "Canonical ntdll Syscall Stub Layout"
    category: windows-structure
    description: "The canonical x64 ntdll syscall stub for NtAllocateVirtualMemory is: mov r10, rcx; mov eax, 0x18 (the SSN); test byte ptr [7FFE0308h], 1; jne ntdll!NtAllocateVirtualMemory+0x15; syscall; ret; int 0x2e; ret. The SharedUserData!SystemCall flag at 0x7FFE0308 determines whether the syscall uses the int 0x2e fallback path. SEC670 uses this exact layout as the reference against which hooked stubs are compared."
    relevant_to: [T-001, T-002, T-016]
    tags: [syscall-stub, ntdll, canonical-layout, shareduserdata, ssn]

  - id: "appcert-dlls"
    name: "AppCert DLL Loading Mechanism"
    category: os-internal
    description: "The AppCert registry key (System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls) is queried by CreateProcess, CreateProcessAsUser, CreateProcessWithLogon, CreateProcessWithToken, and WinExec to enumerate DLLs that must be loaded into the new process. SEC670 notes this requires administrative privileges and a reboot to take effect."
    relevant_to: [T-017]
    tags: [persistence, appcert, createprocess, registry, dll-loading]

  - id: "ifeo-globalflag"
    name: "IFEO GlobalFlag"
    category: os-internal
    description: "Image File Execution Options (IFEO) support a GlobalFlag value that enables silent process exit monitoring, pageheap diagnostics, and other debug-oriented behaviors per-process. SEC670 pairs this with gflags.exe (Windows SDK) and the modernized GflagsX tool by Paweł Baśsiorski as the canonical interface for setting these flags. IFEO/GlobalFlag modifications require elevated permissions."
    relevant_to: [T-017]
    tags: [ifeo, globalflag, silent-process-exit, persistence, gflags]

  - id: "silent-process-exit"
    name: "Silent Process Exit Monitoring"
    category: os-internal
    description: "Silent Process Exit is an IFEO sub-feature that triggers monitoring actions when a process exits unexpectedly. SEC670 classes it alongside IFEO as a feature intended for debugging that can be abused for persistence or process-state monitoring, gated on Admin/SYSTEM permissions."
    relevant_to: [T-017]
    tags: [silent-process-exit, ifeo, monitoring, persistence, elevated]

  - id: "sddl-service-hiding"
    name: "SDDL-Based Service Hiding"
    category: attack-pattern
    description: "A Security Descriptor Definition Language (SDDL) string crafted by SANS instructor Joshua Wright uses deny ACEs (D;;DCLCWPDTSD;;IU/SU/BA) against Interactive Users, Service Users, and Built-in Administrators to remove standard query visibility from a service while preserving SYSTEM and explicit BA allow rights. SEC670 demonstrates both manual SDDL strings and programmatic implementation via SetSecurityDescriptorControl and SetNamedSecurityInfo from securitybaseapi.h and aclapi.h."
    relevant_to: [T-017]
    tags: [sddl, service-hiding, acl, security-descriptor, tradecraft]

  - id: "reflective-dll-injection"
    name: "Reflective DLL Injection (RDI)"
    category: attack-pattern
    description: "RDI manually maps a source DLL into a target process's virtual address space without invoking the Windows loader. SEC670 presents this as a stealth technique because the full path of the DLL will not appear in the loader's module list, evading tools that enumerate loaded modules via the PEB."
    relevant_to: [T-013]
    tags: [rdi, manual-mapping, loader-bypass, peb-evasion, injection]

  - id: "dll-base-relocation-aslr"
    name: "DLL Preferred Base and ASLR Relocation"
    category: os-internal
    description: "DLLs carry a preferred base address in their optional header; the loader maps them there if free, but ASLR and conflicts force relocation. The loader applies base relocations to fix RVAs when the DLL is mapped elsewhere. SEC670 uses this as background for understanding module resolution and PEB-walker pattern lookup."
    relevant_to: [T-004]
    tags: [dll, relocation, aslr, base-address, loader]

  - id: "on-disk-patching-risks"
    name: "On-Disk Patching Risks and Considerations"
    category: attack-pattern
    description: "SEC670 catalogues the trade-offs of patching binaries on disk: changes survive reboots and propagate to every process that loads the file (cascading effect), but the system can become unstable if a critical system DLL like ntdll.dll is patched incorrectly, and detection risk is higher because integrity scanners compare on-disk files against known signatures."
    relevant_to: [T-016]
    tags: [on-disk-patching, ntdll, stability, detection-risk, tradecraft]
```

### Detection Insights

```yaml
detection:
  - indicator: "ntdll function prologue begins with jmp rel32 instead of MOV EDI, EDI or mov r10, rcx"
    source: memory-scan
    confidence: high
    relevant_to: [T-016]
    description: "A byte-level scan of ntdll.dll .text section comparing each function's first bytes against the canonical stub layout (mov r10, rcx on x64; MOV EDI, EDI on 32-bit) exposes userland hooks. SEC670 specifically identifies jmp rel32 (E9) or jmp short (EB) at function start as hook signatures, with the canonical 32-bit unhooked pattern being 'nop nop nop nop nop mov edi, edi push ebp mov ebp, esp'."
    bypassed_by: "Halo's Gate bypasses the need to unhook by deriving SSNs from neighboring unhooked stubs; direct and indirect syscalls avoid the hooked ntdll path entirely."

  - indicator: "Disk vs memory ntdll.dll byte mismatch"
    source: memory-scan
    confidence: high
    relevant_to: [T-016]
    description: "Comparing the in-memory ntdll.dll .text section against the on-disk C:\\Windows\\System32\\Ntdll.dll file exposes any byte-level modifications introduced by EDR hooks. SEC670 identifies the disk file as the validation source and the methodology as 'search for bytes that should not be there'."
    bypassed_by: "EDRs that hook via trampoline allocation rather than inline patching may not produce a disk-vs-memory delta on the ntdll .text itself; the trampoline lives in a separate allocation."

  - indicator: "Sysmon Event ID 19/20/21 — WMI Event Filter, Consumer, and Binding creation"
    source: sysmon
    confidence: medium
    relevant_to: []
    description: "SEC670 identifies Sysmon as the primary detection tool for WMI-based attacks, catching Event Filters (__EventFilter), Event Consumers (__EventConsumer subclasses like ActiveScriptEventConsumer), and the __FilterToConsumerBinding that links them. Determining whether an event is benign notification or malicious requires analyst categorization."
    bypassed_by: "not discussed"

  - indicator: "AppCertDlls registry key modification"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-017]
    description: "Modifications to HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls register as registry-write events in the Windows Security log under object-access auditing and can be captured by Sysmon Event ID 12/13. SEC670 notes this requires Admin privileges and a reboot, so the write itself is high-signal."
    bypassed_by: "not discussed"

  - indicator: "IFEO registry value creation under Image File Execution Options"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Creation of a subkey under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<target>.exe with GlobalFlag, Debugger, or SilentProcessExitMonitor values is detectable via Sysmon Event ID 12 (RegistryEvent) or 13 (RegistryValueSet). SEC670 notes these require Admin/SYSTEM, narrowing the legitimate-origin population."
    bypassed_by: "not discussed"

  - indicator: "Call stack for a syscall does not originate from ntdll.dll"
    source: kernel-callback
    confidence: medium
    relevant_to: [T-001, T-002]
    description: "SEC670 notes that while direct syscalls evade userland hooks, kernel-mode components may still detect calls not originating from ntdll.dll — the return address on the stack at syscall time is the giveaway. This motivates the indirect-syscall variant that jumps into ntdll to execute the syscall instruction."
    bypassed_by: "Indirect syscalls dispatch the syscall instruction from inside ntdll, making the return address appear legitimate; the SEC670 material presents this as the operational fix."

sigma_ideas:
  - title: "Hooked Ntdll Stub — jmp at Function Start"
    logsource: memory-scan
    condition_summary: "Memory scan of ntdll.dll .text section where any Nt* function begins with bytes E9 (jmp rel32) or EB (jmp short) instead of the canonical stub prologue (mov r10, rcx on x64 / nop nop nop nop nop mov edi, edi on 32-bit)."

  - title: "Disk-vs-Memory ntdll.dll Hash Mismatch"
    logsource: memory-scan
    condition_summary: "Hash of the in-memory ntdll.dll .text section does not match the hash of C:\\Windows\\System32\\Ntdll.dll .text section."

  - title: "AppCertDlls Registry Value Written"
    logsource: sysmon
    condition_summary: "Sysmon Event ID 13 where TargetObject ends with \\Session Manager\\AppCertDlls\\<name> and EventType is SetValue."

  - title: "IFEO GlobalFlag or Debugger Value Created"
    logsource: sysmon
    condition_summary: "Sysmon Event ID 12 with TargetObject matching HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*.exe\\(GlobalFlag|Debugger|SilentProcessExitMonitor)."

  - title: "WMI Event Filter/Consumer/Binding Creation"
    logsource: sysmon
    condition_summary: "Sysmon Event ID 19, 20, or 21 indicating creation of __EventFilter, __EventConsumer, or __FilterToConsumerBinding in the root\\subscription or root\\default namespace."
```

### Operational Chains

```yaml
chains:
  - name: "Halo's Gate SSN Recovery"
    description: "Recover an SSN for a hooked ntdll syscall stub by walking neighbors."
    steps:
      - technique: T-004
        role: "PEB walker resolves ntdll.dll base from PEB.Ldr; locates the target Nt* function's virtual address."
      - technique: T-002
        role: "Inspect the stub's first bytes; if hooked (no mov r10, rcx; mov eax, SSN), walk to the previous or next Nt* stub in ntdll's sorted SSN layout."
      - technique: T-002
        role: "Read the unhooked neighbor's SSN, add or subtract the index offset, derive the target SSN."
      - technique: T-001
        role: "Dispatch the syscall using the recovered SSN via a direct or indirect stub, skipping the hooked ntdll stub entirely."
    notes: "SEC670 emphasizes that this works because SSNs in ntdll are laid out in numerical order; it does not require repairing the hook, preserving operational stealth. Requires ntdll to retain at least one unhooked neighbor stub adjacent to the target."

  - name: "NTDLL Unhook via Disk Validation"
    description: "Restore hooked ntdll bytes by overwriting from the on-disk file."
    steps:
      - technique: T-016
        role: "Enumerate ntdll.dll exports and locate each Nt* function in the in-memory image."
      - technique: T-016
        role: "Compare each stub's first bytes against the canonical prologue; flag stubs that deviate as hooked."
      - technique: T-016
        role: "Open C:\\Windows\\System32\\Ntdll.dll on disk, locate the corresponding function RVA, read the original bytes."
      - technique: T-016
        role: "Overwrite the in-memory hooked stub with the disk bytes, optionally via NtProtectVirtualMemory to flip RWX temporarily."
    notes: "SEC670 notes this is most useful when cleaning up an area of interest to restore intended function behavior. The disk file is the validation source. Operation does not bypass kernel-mode telemetry — it only defeats userland inspection hooks. Sysinternals and other integrity scanners perform the inverse comparison to detect that unhooking occurred."

  - name: "Indirect Syscall Stack-Spoof Chain"
    description: "Dispatch a syscall that bypasses both userland hooks and kernel call-stack origin checks."
    steps:
      - technique: T-004
        role: "Resolve ntdll base and locate a syscall; ret gadget inside ntdll .text."
      - technique: T-002
        role: "Recover SSN via Hell's or Halo's Gate."
      - technique: T-016
        role: "Spoof the call stack so frames appear to originate from legitimate ntdll callers."
      - technique: T-001
        role: "Jump into the ntdll gadget to execute the syscall instruction, leaving the return address inside ntdll."
    notes: "SEC670 explicitly motivates indirect syscalls as the response to kernel-mode detection that direct syscalls fail against — the call stack must show ntdll as the origin. Stack spoofing is the additional layer the material mentions in passing but does not detail mechanistically."

  - name: "Reflective DLL Injection into Target Process"
    description: "Manually map a DLL into a target process without invoking the Windows loader."
    steps:
      - technique: "shellcode staging"
        role: "Allocate RWX region in the target process via NtAllocateVirtualMemory (or section mapping variant)."
      - technique: T-013
        role: "Write the source DLL image plus the reflective loader stub into the region."
      - technique: T-013
        role: "Reflective loader resolves its own base, applies relocations, fixes imports, calls DllMain, and registers no entry in the PEB loader list."
    notes: "SEC670 emphasizes that RDI's value is stealth — the DLL never appears in tools that enumerate the PEB's InLoadOrderModuleList. The trade-off is that the manually mapped image has no on-disk backing module, exposing it to memory scanners that flag unbacked executable regions (VadS nodes)."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "appcert-dll-persistence"
    title: "AppCert DLLs as a Persistence Layer"
    kind: proposed-technique
    description: "SEC670 documents the AppCertDlls registry mechanism that injects a DLL into any process calling CreateProcess-family APIs or WinExec. This is a distinct persistence vector from COM hijack, schtask, NTFS EA, TLS callback, and PhantomPersist in T-017 — it triggers on host activity rather than on schedule or boot. It requires Admin + reboot to install. The vault currently has no card covering this, and it would complement the five-layer persistence stack."
    would_relate_to: [T-017]
    source_units: ["unit 2"]
    tags: [persistence, appcert, registry, dll-injection, proposed]

  - id: "ifeo-silent-process-exit-persistence"
    title: "IFEO GlobalFlag and Silent Process Exit as Persistence Primitives"
    kind: proposed-technique
    description: "SEC670 devotes multiple units to IFEO GlobalFlag and Silent Process Exit as abuse targets. The vault's T-017 persistence suite does not document IFEO as a layer. These primitives are gated on Admin/SYSTEM and produce per-process triggers distinct from COM hijack and schtask. Worth a dedicated card or a T-017 extension documenting programmatic setup via the IFEO registry subtree."
    would_relate_to: [T-017]
    source_units: ["unit 7", "unit 8", "unit 9", "unit 10", "unit 11", "unit 12", "unit 13", "unit 14"]
    tags: [persistence, ifeo, globalflag, silent-process-exit, gflags, proposed]

  - id: "sddl-service-hiding-tradecraft"
    title: "SDDL-Based Service Hiding"
    kind: proposed-technique
    description: "SEC670 documents a real-world SDDL string crafted by Joshua Wright that denies standard query rights to Interactive Users, Service Users, and Built-in Administrators while preserving SYSTEM access, effectively hiding a service from sc query and similar enumeration. The vault does not currently cover ACL-based service hiding. Programmatic implementation via SetSecurityDescriptorControl and SetNamedSecurityInfo is also covered. This is distinct from the persistence mechanism itself — it is a stealth layer applied on top."
    would_relate_to: [T-017]
    source_units: ["unit 3", "unit 4", "unit 5"]
    tags: [tradecraft, sddl, service-hiding, acl, security-descriptor, proposed]

  - id: "32-bit-hot-patch-prologue-coverage"
    title: "32-bit Wow64 Hot-Patch Prologue and MOV EDI, EDI Hook Detection"
    kind: coverage-gap
    description: "The vault's T-016 NTDLL unhook documentation is implicitly x64-centric. SEC670 devotes a unit to the 32-bit MOV EDI, EDI hot-patch prologue and the five-NOP padding that precedes 32-bit functions, explaining how this layout enables inline jmp rel32 hook installation and how the byte signature identifies hooked vs unhooked stubs on Wow64. The vault lacks explicit 32-bit hook detection coverage; a concept node or extension to T-016 would surface this."
    would_relate_to: [T-016]
    source_units: ["unit 39", "unit 40"]
    tags: [32-bit, wow64, hot-patch, mov-edi-edi, hook-detection, coverage-gap]

  - id: "direct-vs-indirect-syscall-callstack-detection"
    title: "Kernel Call-Stack Origin Check Defeating Direct Syscalls"
    kind: cross-source-convergence
    description: "Multiple SEC670 units converge on the point that direct syscalls bypass userland hooks but fail against kernel-mode components that verify the syscall's call stack originates from ntdll. This motivates indirect syscalls as the layered response. The vault's T-001 RecycledGate implements indirect syscalls but does not document the kernel-side detection rationale. Worth surfacing as the operational reason RecycledGate exists over plain direct syscall stubs."
    would_relate_to: [T-001, T-016]
    source_units: ["unit 26", "unit 27", "unit 28", "unit 29"]
    tags: [direct-syscalls, indirect-syscalls, kernel-detection, call-stack, convergence]

  - id: "win32u-gui-syscall-hook-coverage"
    title: "win32u.dll GUI Syscall Hook Layer"
    kind: coverage-gap
    description: "SEC670 distinguishes between ntdll (Native) and win32u (GUI) syscall layers and notes that EDRs hook both, including functions like NtUserOpenClipboard. The vault's T-016 NTDLL unhook documentation does not address win32u.dll. An operator unhooking only ntdll will miss GUI-syscall hooks and remain visible to the EDR for windowing-related calls. Worth extending T-016 to enumerate win32u as a second hook surface."
    would_relate_to: [T-016]
    source_units: ["unit 23", "unit 24", "unit 25"]
    tags: [win32u, gui-syscalls, hook-surface, coverage-gap, edr]

  - id: "vx-underground-av-artifacts-catalog"
    title: "VX-Underground AntiVirus Artifacts Catalog as Reference"
    kind: emerging-tradecraft
    description: "SEC670 cites the VX-Underground 'AntiVirus Artifacts' whitepaper series (first, second, third editions) as the canonical catalog of which Nt* APIs each EDR vendor hooks and in which module. The vault does not reference this catalog. Adding it as a reference node would let operators consult the catalog when planning unhook scope for a specific EDR target rather than reverse-engineering hooks from scratch."
    would_relate_to: [T-016, T-001, T-002]
    source_units: ["unit 23", "unit 24"]
    tags: [reference, vx-underground, av-artifacts, edr-catalog, emerging]
```