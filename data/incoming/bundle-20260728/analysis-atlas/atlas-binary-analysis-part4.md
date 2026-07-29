## Synthesis Summary

This batch of SANS SEC670 material covers PE file format internals (IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR, PE32+ optional header), Windows thread object architecture (ETHREAD/KTHREAD/TEB and their address-space placement), the CONTEXT structure and instruction-pointer redirection for thread hijacking, classic process injection variants (process hollowing, PE injection, SetWindowsHookEx-based DLL injection, QueueUserApc), Windows service management APIs (CreateService, QueryServiceStatusEx, QueryServiceConfig, ChangeServiceConfig) for persistence, OpenProcessToken for access-token manipulation, named-pipe creation, and UACMe-based UAC bypass research. The material maps to T-004 (PEB walker — the TEB/PEB structure relationship is foundational), T-007 (process injection suite — process hollowing, PE injection, thread hijacking, APC injection all live here), T-013 (remaining injection methods — ClassicDLLInjection, APCInjection, ThreadHijacker are explicitly named labs), T-017 (persistence via Windows services), and T-021/T-023 (UAC bypass research via UACMe). The gap the material fills is operational: it explains why thread-context manipulation works at the context-switch level, what the PE export/import directory structures physically look like (so PEB walking and module stomping become readable), how the service control manager APIs compose into a persistence primitive, and how SetWindowsHookEx targets GUI applications specifically. All 40 units are on-theme; none are skipped.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "teb-peb-pointer"
    target: T-004
    type: enables
    rationale: "SEC670 states the TEB is the only thread object accessible in process address space and contains ProcessEnvironmentBlock pointer — PEB walker reads this pointer to locate loaded modules without calling any API."
  - source: "thread-context-manipulation"
    target: T-013
    type: enables
    rationale: "SEC670 walk-through of Thread Hijacker lab: GetThreadContext/SetThreadContext modify the Rip register in the CONTEXT structure to redirect execution to shellcode in the target process."
  - source: "thread-context-manipulation"
    target: T-007
    type: concept_link
    rationale: "Thread hijacking is listed alongside APCInjection and ClassicDLLInjection as a Section 3 lab technique feeding into the broader injection suite."
  - source: "queue-user-apc-api"
    target: T-013
    type: enables
    rationale: "SEC670 covers QueueUserApc as the API to queue an APC to a user thread — APCInjection is Lab 3.3 in the course roadmap."
  - source: "setwindowshookex-injection"
    target: T-013
    type: alternative_to
    rationale: "Unit review answer identifies SetWindowsHookEx() as the API for DLL injection into GUI applications, presenting it as an alternative to CreateRemoteThread-based injection."
  - source: "windows-service-api-set"
    target: T-017
    type: enables
    rationale: "SEC670 services module covers CreateService, ChangeServiceConfig, and QueryServiceStatusEx as the API surface for installing and managing a Windows service as a persistence mechanism."
  - source: "openprocesstoken-api"
    target: T-021
    type: concept_link
    rationale: "OpenProcessToken is presented in the SEC670 escalation module alongside TokenThief and UACBypass labs — token manipulation as a privilege-escalation primitive that complements UAC bypass."
  - source: "pe-export-directory"
    target: T-004
    type: enables
    rationale: "SEC670 covers IMAGE_EXPORT_DIRECTORY (AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals) — PEB walker traverses this structure to resolve exported function addresses by name hash."
  - source: "pe-import-descriptor"
    target: T-013
    type: concept_link
    rationale: "SEC670 describes IMAGE_IMPORT_DESCRIPTOR (OriginalFirstThunk/ILT, FirstThunk/IAT, ForwarderChain) — relevant to PE injection which must process imports of the injected PE image inside the host process."
  - source: "process-hollowing-steps"
    target: T-013
    type: concept_link
    rationale: "SEC670 walk-through describes process hollowing as create-suspended-process, open replacement file, allocate memory, copy headers and sections — the canonical hollowing variant in the remaining-methods card."
  - source: "pe-injection-technique"
    target: T-013
    type: alternative_to
    rationale: "SEC670 explicitly contrasts PE injection with process hollowing: instead of replacing the original PE image, it adds a second PE image inside the target process, requiring no shellcode knowledge."
```

### Concept Nodes

```yaml
concepts:
  - id: "pe-export-directory"
    name: "IMAGE_EXPORT_DIRECTORY"
    category: windows-structure
    description: "The PE export directory is located at DataDirectory index 0 and contains NumberOfFunctions, NumberOfNames, and three RVA arrays: AddressOfFunctions, AddressOfNames, and AddressOfNameOrdinals. Function-name lookup walks AddressOfNames, finds the matching index, uses AddressOfNameOrdinal to get the ordinal, and indexes into AddressOfFunctions for the RVA. This is the structure PEB walkers traverse when resolving APIs by hash."
    relevant_to: [T-004, T-006]
    tags: [pe, exports, module-resolution, image-structures]

  - id: "pe-import-descriptor"
    name: "IMAGE_IMPORT_DESCRIPTOR"
    category: windows-structure
    description: "An array at DataDirectory index 1 describing each imported DLL. Each entry has OriginalFirstThunk (Import Lookup Table, ILT — pre-binding RVAs to function names/ordinals), FirstThunk (IAT — overwritten by the loader with resolved addresses), TimeDateStamp (0 unbound, -1 bound), ForwarderChain, and Name (RVA to DLL string). The loader walks ILT entries, resolves each function, and writes the result into the corresponding IAT slot."
    relevant_to: [T-013, T-006]
    tags: [pe, imports, iat, loader, image-structures]

  - id: "ethread-kthread-teb"
    name: "ETHREAD / KTHREAD / TEB Thread Object Hierarchy"
    category: windows-structure
    description: "ETHREAD embeds KTHREAD as its Tcb (thread control block) and holds kernel-only fields like CreateTime and StartAddress. Both ETHREAD and KTHREAD reside in system (kernel) address space. The TEB is the only structure accessible from user mode; it embeds NT_TIB (ExceptionList, StackBase, StackLimit), ClientId, and a pointer to the ProcessEnvironmentBlock. Inspectable via dt nt!_ethread and dt nt!_teb in WinDbg."
    relevant_to: [T-004, T-007, T-013]
    tags: [threads, windows-internals, teb, peb, kernel-objects]

  - id: "thread-context-structure"
    name: "CONTEXT Structure and Context Switching"
    category: os-internal
    description: "Each thread has a unique CONTEXT structure saved when its quantum ends or a higher-priority thread preempts it. The processor swaps these saved contexts in and out on every thread switch. On x64 the CONTEXT includes DWORD64 Rip (instruction pointer). GetThreadContext retrieves the structure for a suspended thread; SetThreadContext writes a modified one back. Modifying Rip redirects the thread's next execution to an arbitrary address — the basis of thread hijacking."
    relevant_to: [T-013, T-007]
    tags: [thread-context, context-switch, rip, getthreadcontext, setthreadcontext]

  - id: "thread-creation-internal-flow"
    name: "Windows Thread Creation Internal Flow (CreateThread to PspCreateThread)"
    category: os-internal
    description: "CreateThread converts parameters to flags, populates Client ID and TEB address into an attribute list, determines local vs remote target, and calls CreateRemoteThread which initializes the new thread object and invokes PspCreateThread. Threads are created initially suspended and later resumed to be scheduled. The same PspCreateThread path serves both local and remote thread creation."
    relevant_to: [T-007, T-013]
    tags: [thread-creation, pspcreatethread, windows-internals]

  - id: "queue-user-apc-api"
    name: "QueueUserApc"
    category: os-internal
    description: "QueueUserApc takes an APC_FUNC pointer, a thread handle, and a ULONG_PTR data argument, returning DWORD. It queues a user-mode APC to the specified thread. The APC fires only when the target thread enters an alertable wait state. The signature is DWORD QueueUserApc(APC_FUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData). Used by APCInjection (Lab 3.3 in SEC670)."
    relevant_to: [T-013, T-012, T-008]
    tags: [apc, queueuserapc, injection, alertable-wait]

  - id: "process-hollowing-steps"
    name: "Process Hollowing Step Sequence"
    category: attack-pattern
    description: "The SEC670 walk-through sequence: (1) create a new suspended process (e.g., notepad.exe as the decoy), (2) open the replacement file (evil.exe), (3) allocate memory in the suspended process, (4) copy PE headers and sections from evil.exe into the allocated memory, (5) fix imports/relocations as needed, (6) redirect execution to the replacement entry point, (7) resume the thread. Differs from PE injection in that the original image is replaced rather than augmented."
    relevant_to: [T-013, T-007]
    tags: [process-hollowing, injection, suspended-process, pe-copying]

  - id: "pe-injection-technique"
    name: "PE Injection (Non-Hollowing)"
    category: attack-pattern
    description: "Instead of replacing the original PE image as in hollowing, PE injection adds a second PE image inside the target process so the process holds two PE images simultaneously. The walk-through: OpenProcess on target (e.g., explorer.exe), VirtualAllocEx for the second image, copy PE header info and sections, apply .reloc relocations for the new base address, then CreateRemoteThread pointing at the injected image's entry point. Requires no shellcode — entirely C/C++ and Windows APIs."
    relevant_to: [T-013, T-007]
    tags: [pe-injection, virtualallocex, createremotethread, relocations]

  - id: "setwindowshookex-injection"
    name: "SetWindowsHookEx DLL Injection (GUI Targets)"
    category: attack-pattern
    description: "SetWindowsHookExA adds a hook procedure to the Windows hook chain and returns an HHOOK. When targeting GUI applications, a hook type such as WH_CBT or WH_GETMESSAGE forces the target process to load the DLL containing the hook procedure, achieving injection without CreateRemoteThread. Per the SEC670 unit review, SetWindowsHookEx() is the canonical API for injecting DLLs into GUI applications specifically because of this forced-load behavior."
    relevant_to: [T-013, T-007]
    tags: [setwindowshookex, dll-injection, gui, hook-chain]

  - id: "windows-service-api-set"
    name: "Windows Service Control Manager API Set"
    category: os-internal
    description: "The service persistence API surface: CreateService/CreateServiceA creates an SC_HANDLE-bound service entry; QueryServiceStatusEx (params: hService, InfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded) returns runtime status; QueryServiceConfig returns the QUERY_SERVICE_CONFIG (binary path, start type, account); ChangeServiceConfig modifies an installed service. lpBinaryPathName accepts full executable path plus command-line arguments; lpServiceStartName sets the run-as account; lpdwTagId is kernel-driver-only."
    relevant_to: [T-017]
    tags: [scm, services, persistence, createservice, queryserviceconfig]

  - id: "service-main-function"
    name: "Service Main Entry Point (EvilMain Pattern)"
    category: attack-pattern
    description: "A service-hosting executable implements VOID WINAPI ServiceMain(...) as its entry when launched by the SCM. SEC670's EvilMain code snippet demonstrates the minimal pattern: the SCM spawns the binary with service arguments, ServiceMain initializes the service, registers the control handler, and runs the payload body. This is the execution model that makes service-based persistence produce a running implant on boot."
    relevant_to: [T-017]
    tags: [scm, servicemain, persistence, payload-execution]

  - id: "openprocesstoken-api"
    name: "OpenProcessToken and Access Token Theft"
    category: os-internal
    description: "OpenProcessToken returns a handle to a process's access token and has a BOOL return type. The TokenThief lab in SEC670 pairs this with token duplication to escalate local privileges by stealing a token from a higher-privilege process and applying it to the attacker's process. Part of the escalation module that also covers UACBypass via UACMe."
    relevant_to: [T-021, T-023]
    tags: [token-manipulation, openprocesstoken, privilege-escalation, tokenthief]

  - id: "create-named-pipe-api"
    name: "CreateNamedPipe"
    category: os-internal
    description: "CreateNamedPipe creates a named pipe and returns a HANDLE. Named pipes provide an IPC channel between processes on the same machine or across the network. In an offensive context, named pipes are used for implant-to-implant IPC, C2 relay endpoints, and impersonation (a connecting client's token can be captured via ImpersonateNamedPipeClient)."
    relevant_to: []
    tags: [named-pipes, ipc, orphan, handles]

  - id: "uacme-fusion-scandirectory"
    name: "UACMe FusionScanDirectory"
    category: attack-pattern
    description: "The UACMe project's FusionScanDirectory function uses RtlSecureZeroMemory, FindFirstFile, and FindNextFile to scan the current directory for fusion-loadable DLLs. This is the auto-elevated DLL search path exploitation pattern: Windows auto-elevated binaries search the application directory for DLLs and load them with elevated privileges, allowing a planted DLL to execute at high integrity. Part of the SEC670 UACBypass-Research lab."
    relevant_to: [T-021, T-023]
    tags: [uac-bypass, uacme, dll-search-order, autoelevation]

  - id: "binary-patching"
    name: "Binary Patching"
    category: attack-pattern
    description: "Binary patching modifies compiled binaries to achieve results not intended by the original code. In an offensive context this includes patching security checks out of binaries, modifying CFG bitmap entries, hot-patching ntdll syscall stubs to restore unhooked bytes, and editing PE headers. SEC670 presents it as a general capability in the Red Team Tools module."
    relevant_to: [T-016]
    tags: [binary-patching, pe-editing, orphan]

  - id: "pe32-plus-magic"
    name: "PE32+ Optional Header Magic"
    category: windows-structure
    description: "The optional header magic value identifies the PE subformat: 0x10B indicates PE32 (32-bit), 0x20B indicates PE32+ (64-bit), and 0x00B is unused/invalid. PEB walkers and PE parsers branch on this value to choose between 32- and 64-bit field layouts. Mistakenly parsing a PE32+ binary with PE32 offsets corrupts the optional header field interpretation."
    relevant_to: [T-004, T-006]
    tags: [pe, optional-header, pe32-plus, magic-value]
```

### Detection Insights

```yaml
detection:
  - indicator: "CreateRemoteThread with start address outside any loaded module's .text section"
    source: etw
    confidence: high
    relevant_to: [T-007, T-013]
    description: "Thread hijacking and classic DLL injection both terminate in a CreateRemoteThread call whose start address points to unbacked memory or the injected PE's entry point inside the host process. ETW-TI surfaces the cross-process thread creation with the anomalous start address."
    bypassed_by: "not discussed"

  - indicator: "SetWindowsHookEx with WH_CBT or WH_GETMESSAGE targeting a foreign process"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-013, T-007]
    description: "SetWindowsHookEx installing a hook procedure whose DLL path is not a known system module generates an event in the Windows security log when SeAuditPrivilege is enabled. The hook DLL is forced into the target process address space on the next GUI message, observable as an out-of-band module load."
    bypassed_by: "not discussed"

  - indicator: "Process created in suspended state followed by WriteProcessMemory to its image region"
    source: etw
    confidence: high
    relevant_to: [T-013, T-007]
    description: "Process hollowing sequence (CREATE_SUSPENDED + NtUnmapViewOfSection + NtWriteVirtualMemory to the hollowed region + ResumeThread) is detectable via ETW-TI process-image-write events. The image content written does not match the original on-disk binary."
    bypassed_by: "not discussed"

  - indicator: "CreateService with lpBinaryPathName outside System32 or Program Files"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-017]
    description: "Service creation events (4688 with CreateService.exe, or Sysmon EID 13 for registry write to HKLM\\System\\CurrentControlSet\\Services) where the binary path points to a non-standard directory (user-writable location, temp folder, user profile) is a strong persistence indicator."
    bypassed_by: "not discussed"

  - indicator: "VirtualAllocEx with PAGE_EXECUTE_READWRITE in a remote process followed by CreateRemoteThread"
    source: sysmon
    confidence: high
    relevant_to: [T-013, T-007]
    description: "Sysmon EID 8 (CreateRemoteThread) correlated with EID 10 (ProcessAccess) and EID 18 (PipeEvent) reveals the classic injection pattern. PE injection specifically allocates with PAGE_EXECUTE_READWRITE to hold the second PE image."
    bypassed_by: "not discussed"

  - indicator: "OpenProcessToken with TOKEN_DUPLICATE access on a SYSTEM process"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-021, T-023]
    description: "Event 4663 (object access) on a token object with access mask including TOKEN_DUPLICATE (0x0008) when the caller is not a system service and the target is winlogon.exe or lsass.exe indicates TokenThief-style token theft."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Remote Thread Start Address in Unbacked Memory"
    logsource: etw
    condition_summary: "ETW-TI ThreadCreate event where StartAddress is not within any loaded module's virtual address range in the target process"
  - title: "Service Creation with Non-Standard Binary Path"
    logsource: windows-security
    condition_summary: "Event 4697 or Sysmon EID 13 where ImagePath does not start with C:\\Windows\\System32\\ or C:\\Program Files\\"
  - title: "CreateRemoteThread following VirtualAllocEx"
    logsource: sysmon
    condition_summary: "EID 8 CreateRemoteThread within 5 seconds of EID 10 ProcessAccess with granted access including PROCESS_VM_OPERATION from the same source process to the same target"
  - title: "SetWindowsHookEx Cross-Process Hook Installation"
    logsource: windows-security
    condition_summary: "Event 4663 on a hook object type with the source process different from the eventual hook-target process"
```

### Operational Chains

```yaml
chains:
  - name: "Thread Hijacking Injection Chain"
    description: "Redirect an existing thread in a remote process to execute injected shellcode by overwriting its CONTEXT.Rip"
    steps:
      - technique: T-013
        role: "Open target process (e.g., notepad.exe) and obtain handle to one of its threads"
      - technique: T-013
        role: "VirtualAllocEx PAGE_EXECUTE_READWRITE in target process; write shellcode"
      - technique: T-013
        role: "SuspendThread on the target thread handle"
      - technique: T-013
        role: "GetThreadContext to read CONTEXT; set Rip to the shellcode address; SetThreadContext to commit"
      - technique: T-013
        role: "ResumeThread — the hijacked thread begins executing at the shellcode address"
    notes: "SEC670 Lab 3.4 ThreadHijacker. Requires SeDebugPrivilege for cross-process thread handle access. The hijacked thread's original stack and TEB remain valid, which avoids some of the threadless-injection detection surface."

  - name: "Process Hollowing Chain"
    description: "Replace the image of a suspended decoy process with a replacement PE to execute under the decoy's identity"
    steps:
      - technique: T-014
        role: "CreateProcess with CREATE_SUSPENDED on a decoy binary (notepad.exe) to obtain a process handle and main thread in suspended state"
      - technique: T-013
        role: "Open the replacement file (evil.exe); read its PE headers and section data"
      - technique: T-013
        role: "Unmap or allocate memory in the suspended process; copy replacement PE headers and sections to the allocated base"
      - technique: T-013
        role: "Apply relocations against the new base address and fix the IAT for the host's import set"
      - technique: T-013
        role: "SetThreadContext to point Rip at the replacement entry point; ResumeThread"
    notes: "SEC670 Lab walkthrough (hproc.exe / notepad.exe / evil.exe). The decoy process retains its original ImagePathName in PEB unless explicitly rewritten, producing a path-mismatch detection surface."

  - name: "PE Injection Chain (Non-Hollowing)"
    description: "Inject a second PE image into a running process without replacing the original"
    steps:
      - technique: T-013
        role: "OpenProcess on target (e.g., explorer.exe) with PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD"
      - technique: T-013
        role: "VirtualAllocEx in the target with PAGE_EXECUTE_READWRITE sized to the injected PE image"
      - technique: T-013
        role: "WriteProcessMemory copies PE header and section data into the allocated region"
      - technique: T-013
        role: "Process the .reloc section against the new base address; walk IMAGE_IMPORT_DESCRIPTOR array and resolve the injected PE's imports in the host's address space"
      - technique: T-013
        role: "CreateRemoteThread with start address = injected PE entry point"
    notes: "SEC670 Section 20 walk-through. No shellcode needed. The host process now has two mapped PE images — a module-list scan will show the injected image as unbacked executable private memory unless additional module-list linking is performed."

  - name: "Windows Service Persistence Chain"
    description: "Install a service-hosting implant binary as a Windows service for boot-time or trigger-start persistence"
    steps:
      - technique: T-017
        role: "OpenSCManager with SC_MANAGER_CREATE_SERVICE access"
      - technique: T-017
        role: "CreateServiceA with lpBinaryPathName = full implant path, dwStartType = SERVICE_AUTO_START, lpServiceStartName = LocalSystem"
      - technique: T-017
        role: "Service binary's ServiceMain (EvilMain) initializes the implant when the SCM launches it"
      - technique: T-017
        role: "ChangeServiceConfig post-install to adjust start type, dependencies, or recovery actions"
    notes: "SEC670 Section 20 services module. lpBinaryPathName accepts appended command-line arguments. lpdwTagId is reserved for kernel-driver class services. Service-start account choice (LocalSystem vs NetworkService vs specific user) determines the implant's privilege level and network credential presentation."

  - name: "APC Injection Chain (QueueUserApc)"
    description: "Queue a user-mode APC to a thread in the target process that executes when the thread enters an alertable wait"
    steps:
      - technique: T-013
        role: "OpenThread on target thread with THREAD_SET_CONTEXT access"
      - technique: T-013
        role: "VirtualAllocEx + WriteProcessMemory to place the APC payload in the target process"
      - technique: T-013
        role: "QueueUserApc(pfnAPC, hThread, dwData) — APC_FUNC pointer addresses the payload"
      - technique: T-013
        role: "Target thread enters an alertable wait (SleepEx, WaitForSingleObjectEx with ALERTABLE) — the APC dispatches"
    notes: "SEC670 Lab 3.3 APCInjection. The APC silently fails to dispatch if the target thread never enters an alertable wait. Process injection suites that target alertable threads (e.g., Early Bird on a suspended process being created) avoid this requirement."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "service-based-persistence-as-distinct-technique"
    title: "Windows Service-Based Persistence as a Distinct Persistence Layer"
    kind: proposed-technique
    description: "SEC670 dedicates an entire services module (CreateService, QueryServiceStatusEx, QueryServiceConfig, ChangeServiceConfig, ServiceMain pattern) to service-based persistence. The vault's T-017 persistence suite currently lists COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not surface SCM service creation as a distinct layer despite the service binary's ServiceMain being a structurally different execution model from schtask or COM. This would merit its own sub-technique entry given the prevalence of services in real-world red team persistence."
    would_relate_to: [T-017]
    source_units: ["unit 32", "unit 33", "unit 34", "unit 35", "unit 36", "unit 37"]
    tags: [persistence, services, scm, coverage-gap]

  - id: "named-pipe-ipc-channel"
    title: "Named Pipes as an Implant IPC and C2 Relay Channel"
    kind: coverage-gap
    description: "SEC670 introduces CreateNamedPipe as a HANDLE-returning primitive. The vault covers NT sockets (T-022) and peer relay (T-022) but does not explicitly document named pipes as an IPC channel for implant-to-implant communication, parent-child implant handoff, or token impersonation via ImpersonateNamedPipeClient. Named pipes are operationally distinct from sockets because they integrate with Windows token impersonation."
    would_relate_to: [T-022, T-023]
    source_units: ["unit 38"]
    tags: [named-pipes, ipc, orphan, token-impersonation]

  - id: "token-theft-privilege-escalation"
    title: "Access Token Theft (TokenThief Pattern)"
    kind: proposed-technique
    description: "SEC670's escalation module includes the TokenThief lab pairing OpenProcessToken with token duplication for privilege escalation. The vault's T-021/T-023 UAC bypass coverage addresses auto-elevation but does not document the broader token-theft primitive (open a SYSTEM token on winlogon.exe, duplicate it, assign to the implant's primary token, AdjustTokenPrivileges). This is a distinct escalation capability separate from UAC bypass and would merit its own card."
    would_relate_to: [T-021, T-023]
    source_units: ["unit 30", "unit 31"]
    tags: [token-theft, privilege-escalation, tokenthief, openprocesstoken]

  - id: "uacme-dll-search-order-hijack"
    title: "UACMe Auto-Elevation DLL Search-Order Hijack"
    kind: cross-source-convergence
    description: "SEC670's UACBypass-Research lab uses the UACMe project's FusionScanDirectory function (RtlSecureZeroMemory, FindFirstFile, FindNextFile) to enumerate the application directory of an auto-elevated binary for a plantable DLL. This is the same auto-elevation pattern referenced by the vault's T-021/T-023 UAC bypass entries. Cross-source convergence with MalDev Academy and CRTO both covering UAC bypass via UACMe suggests the vault should document this specific UAC bypass variant explicitly rather than treating UAC bypass as a single monolithic capability."
    would_relate_to: [T-021, T-023]
    source_units: ["unit 39"]
    tags: [uac-bypass, uacme, dll-search-order, autoelevation, convergence]

  - id: "binary-patching-as-standalone-capability"
    title: "Binary Patching as a Standalone Offensive Capability"
    kind: coverage-gap
    description: "SEC670 lists binary patching ('modifying binaries to achieve results') as a discrete capability in the Red Team Tools module. The vault references patching implicitly inside T-016 (NTDLL unhook, AMSI patch, ETW patch) but does not document binary patching as a general technique covering CFG bitmap editing, hot-patching live PE images in memory, modifying EAT entries to redirect function resolution, or stripping security cookie checks. A general binary-patching concept would tie the existing patching references together."
    would_relate_to: [T-016]
    source_units: ["unit 40"]
    tags: [binary-patching, pe-editing, coverage-gap]

  - id: "gui-application-hook-injection-distinction"
    title: "GUI Application Hook Injection as a Distinct Injection Variant"
    kind: proposed-technique
    description: "SEC670 explicitly identifies SetWindowsHookEx as the API for injecting DLLs into GUI applications specifically, distinct from CreateRemoteThread-based injection. The vault's T-013 remaining methods lists callback, fiber, Early Bird, PE loader, etc. but does not surface SetWindowsHookEx as a named variant. The mechanism (forced DLL load on the next GUI message processing) produces a different module-load pattern than CreateRemoteThread injection and has different detection characteristics."
    would_relate_to: [T-013, T-007]
    source_units: ["unit 26", "unit 27", "unit 28"]
    tags: [setwindowshookex, gui-injection, dll-injection, proposed-technique]
```