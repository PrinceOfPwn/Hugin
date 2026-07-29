## Synthesis Summary

This batch maps most directly to T-002 (Hell's/Halo's/Tartarus Gate + FreshyCalls), T-004 (PEB Walker), T-001 (RecycledGate), and T-016 (EDR Evasion Suite, specifically the NTDLL unhook and PEB-walk material). The SANS SEC670 Book 5 material covers IAT and inline hooking mechanics at the byte level, the three syscall "Gates" (Heaven's, Hell's, Halo's) including the Wow64 32-bit-to-64-bit transition via `wow64cpu.dll`, NTDLL `.text`-section restoration via both a "Fresh Copy" (file-mapping approach using `CreateFileA`/`CreateFileMapping`/`MapViewOfFile`) and a "Suspended Copy" (clean process spawn with `CREATE_SUSPENDED`), trampoline infrastructure for round-trip hook execution, and an overview of AV detection engines (static, dynamic, scan) as the defensive landscape these techniques operate against. All 40 units are on-theme; none skipped. The knowledge gap this fills is the byte-level rationale for why each unhook and gate technique works (PE IAT location via `DataDirectory`, the `MOV EDI, EDI` 2-byte hot-patch NOP, the `mov r10, rcx; mov eax, SSN` stub pattern, the `jmp 0xFB (-5)` short-jump prologue-hook signature, and why SSNs are sequential in ntdll enabling Halo's neighbor-walk) — context that the Rust source files alone do not make explicit.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: T-004
    target: T-002
    type: requires
    rationale: "Hell's Gate locates ntdll by walking PEB via __readgsqword(0x60) and traversing InMemoryOrderModuleList — the PEB walker (T-004) is the resolution primitive T-002 depends on."
  - source: T-016
    target: T-002
    type: enhances
    rationale: "Restoring ntdll's .text section (T-016 NTDLL unhook) produces unhooked syscall stubs, which lets Hell's Gate (T-002) reliably read the 0xB8 opcode and the SSN immediately after; on a hooked stub Hell's Gate alone fails."
  - source: concept-halos-gate
    target: concept-hells-gate
    type: alternative_to
    rationale: "Halo's Gate addresses Hell's Gate's failure mode when the target stub is already hooked by walking neighboring stubs to infer the SSN, exploiting the fact that syscall IDs are stored in sequential order in ntdll."
  - source: concept-heavens-gate
    target: concept-wow64-prologue-hotpatch
    type: requires
    rationale: "Heaven's Gate depends on the Wow64 transition layer (ntdll.Wow64Transition → wow64cpu.dll) that 32-bit processes use to enter 64-bit mode for syscalls; the same prologue/hot-patch mechanics (MOV EDI, EDI; short JMP) apply when hooking or unhooking in that environment."
  - source: concept-edr-userland-hooking
    target: T-002
    type: counters
    rationale: "EDR userland hooks (inline or IAT) on ntdll syscall stubs defeat naive direct NT API calls; the Gates (T-002) exist specifically to bypass this by invoking syscalls without going through the hooked stub path."
  - source: concept-inline-hooking
    target: concept-trampoline
    type: requires
    rationale: "An inline hook modifies the first bytes of the target function with a JMP; without a trampoline that preserves and re-executes the displaced original bytes, the hook handler cannot return to the original function without infinite recursion."
  - source: concept-iat-hooking
    target: concept-inline-hooking
    type: alternative_to
    rationale: "IAT hooking and inline hooking serve the same operational purpose (intercepting API calls) but target different memory: IAT overwrites function pointers in the import table, inline overwrites the function prologue bytes."
  - source: concept-ntdll-fresh-copy-unhook
    target: concept-ntdll-suspended-copy-unhook
    type: alternative_to
    rationale: "Both restore a clean ntdll .text section; Fresh Copy maps ntdll.dll from C:\\Windows\\System32 via file-mapping APIs, while Suspended Copy spawns a fresh CREATE_SUSPENDED process and copies its pristine in-memory ntdll syscall table."
  - source: concept-edr-userland-hooking
    target: T-001
    type: detects
    rationale: "Inline/IAT hooks give the EDR visibility into the call order and arguments of NT APIs invoked through ntdll; T-001 (RecycledGate indirect syscalls) exists to route around this visibility by jumping to an ntdll gadget that issues the syscall without touching the hooked stub."
  - source: T-002
    target: T-001
    type: chains_to
    rationale: "SSN resolution (T-002) produces the syscall number that RecycledGate's indirect-dispatch stub (T-001) then invokes via an ntdll-resident gadget; resolution precedes dispatch in the operational sequence."
```

### Concept Nodes

```yaml
concepts:
  - id: "concept-iat-hooking"
    name: "IAT (Import Address Table) Hooking"
    category: edr-mechanism
    description: "IAT hooking overwrites the function pointer entries in the PE import data directory (one of 16 DataDirectory entries) so that calls to an imported function route to an attacker- or EDR-controlled handler. The IAT is normally read-only and the loader resolves it at load time; hooking requires VirtualProtect to flip the page to PAGE_READWRITE, overwriting the pointer, then restoring prior protections. Unlike inline hooking, IAT hooks only intercept calls routed through the import table, not calls resolved dynamically via GetProcAddress or PEB walking."
    relevant_to: [T-016]
    tags: [hooking, iat, pe-headers, edr, evasion]

  - id: "concept-inline-hooking"
    name: "Inline (Prologue) Hooking"
    category: edr-mechanism
    description: "Inline hooking patches the first bytes of a target function with a jump instruction to a handler, redirecting execution before the original prologue runs. On 32-bit the patch uses a 5-byte JMP rel32 (E9 xx xx xx xx) preceded by a 2-byte short JMP (EB F9) over the MOV EDI, EDI hot-patch slot. On 64-bit a MOV RAX, imm64 followed by JMP RAX pattern is used because a single JMP cannot encode a 64-bit absolute target. Detours and EasyHook are the canonical implementations. EDRs use this on ntdll syscall stubs to inspect arguments before the syscall executes."
    relevant_to: [T-016]
    tags: [hooking, inline, detours, edr, evasion]

  - id: "concept-trampoline"
    name: "Hook Trampoline"
    category: attack-pattern
    description: "A trampoline is a small code stub that contains the original bytes displaced by an inline hook, followed by a jump back to the byte immediately after the hook location in the original function. When the hook handler needs to invoke the real function it calls the trampoline, which executes the displaced prologue and returns control to the original function body past the patched region. Without a trampoline, calling the hooked function from inside the hook handler recurses infinitely because the hook JMP fires again. The number of bytes the trampoline must preserve depends on the length of the patched instructions, not a fixed count, because x86 instructions are variable-length."
    relevant_to: [T-016]
    tags: [hooking, trampoline, inline-hook, edr]

  - id: "concept-edr-userland-hooking"
    name: "EDR Userland Hooking Surface"
    category: edr-mechanism
    description: "EDRs inject a DLL into monitored processes that installs inline or IAT hooks on high-value ntdll syscall stubs (NtAllocateVirtualMemory, NtMapViewOfSection, NtWriteVirtualMemory, NtCreateThreadEx, NtProtectVirtualMemory, etc.). The hook handler inspects arguments and call order before deciding whether to pass, modify, or block the call. Userland hooks are the cheapest interception layer for the EDR but are entirely bypassable from the process itself because the hook code and the hooked bytes both live in user-mode memory the process can read, write, and avoid."
    relevant_to: [T-001, T-002, T-016]
    tags: [edr, hooking, userland, evasion]

  - id: "concept-hells-gate"
    name: "Hell's Gate SSN Resolution"
    category: attack-pattern
    description: "Hell's Gate dynamically resolves syscall service numbers (SSNs) at runtime by walking the PEB to find ntdll, locating the target Nt* export, and reading the SSN out of the stub's mov eax, imm32 instruction. The technique is position-independent and does not rely on hardcoded syscall IDs, which would break across Windows versions. The check `(*(PBYTE)TargetFunction + 3) == 0xB8` validates that the stub's fourth byte is the mov opcode, confirming the SSN follows. Hell's Gate fails if the stub is already inline-hooked because the 0xB8 byte is no longer at offset +3."
    relevant_to: [T-002, T-004]
    tags: [syscall, ssn, hells-gate, evasion]

  - id: "concept-halos-gate"
    name: "Halo's Gate Hook-Aware SSN Resolution"
    category: attack-pattern
    description: "Halo's Gate extends Hell's Gate to handle hooked stubs. Because SSNs in ntdll are stored in numerical order across consecutive stubs, if the target stub's 0xB8 byte is missing (hooked), the technique walks neighboring stubs forward or backward, reads their SSNs, and infers the target SSN by positional arithmetic. The instruction sequence is captured in the off_hooked pattern: repeatedly call off_hooked on near_syscall neighbors until a valid SSN region is found, then offset to the target. This avoids the need to unhook the stub before resolving its SSN."
    relevant_to: [T-002, T-016]
    tags: [syscall, ssn, halos-gate, evasion, hook-bypass]

  - id: "concept-heavens-gate"
    name: "Heaven's Gate Wow64 Transition"
    category: attack-pattern
    description: "Heaven's Gate is the mechanism by which a 32-bit (Wow64) process on a 64-bit Windows system transitions to 64-bit code to issue native syscalls. The 32-bit code jumps to ntdll.Wow64Transition, which redirects via a far jmp (0x33 selector) to wow64cpu.dll in 64-bit mode, where the syscall is issued directly. Because 32-bit ntdll is mapped alongside 64-bit ntdll in Wow64 processes, a 32-bit implant can use this transition to invoke 64-bit syscall stubs that bypass any 32-bit-mode hooks. EDRs that only hook the 32-bit ntdll have no visibility into calls routed through the 64-bit stub via Heaven's Gate."
    relevant_to: [T-002]
    tags: [wow64, heavens-gate, syscall, 32bit-64bit, evasion]

  - id: "concept-wow64-prologue-hotpatch"
    name: "Wow64 Function Prologue Hot-Patch Slot"
    category: os-internal
    description: "32-bit Windows functions conventionally begin with MOV EDI, EDI, a 2-byte NOP that serves as a hot-patch slot. An inline hook replaces this with a 2-byte short JMP (EB F9, jump −5) that lands in the 5 bytes of padding preceding the function, where the E9 rel32 jump to the hook handler is installed. The pattern nop nop nop nop nop / mov edi, edi / push ebp / mov ebp, esp appears in non-hooked functions; the hooked variant shows jmp rel32 (E9 xx xx xx xx) preceded by jmp 0xFB (−5) (EB F9). Scanning for these byte patterns in ntdll identifies inline-hooked stubs."
    relevant_to: [T-016]
    tags: [wow64, prologue, hot-patch, hook-detection, x86]

  - id: "concept-ntdll-fresh-copy-unhook"
    name: "Fresh Copy NTDLL .text Restoration"
    category: attack-pattern
    description: "The Fresh Copy unhook obtains a pristine ntdll from C:\\Windows\\System32\\ntdll.dll on disk and copies its entire .text section over the in-memory ntdll .text, displacing any EDR-installed inline hooks. The API sequence is CreateFileA → CreateFileMapping → MapViewOfFile → locate NT headers via the DOS stub and PE header → locate .text section via SectionHeader → memcpy the section bytes over the live ntdll .text. The on-disk copy is considered trustworthy because EDRs typically hook the in-memory stubs, not the on-disk file, although an operator could in theory patch on-disk ntdll to defeat this validation source."
    relevant_to: [T-016]
    tags: [unhook, ntdll, fresh-copy, file-mapping, evasion]

  - id: "concept-ntdll-suspended-copy-unhook"
    name: "Suspended Copy NTDLL Syscall Table Restoration"
    category: attack-pattern
    description: "The Suspended Copy unhook spawns a new process via CreateProcess with CREATE_SUSPENDED. Because the new process has just been initialized by the loader but not yet had EDR DLLs injected (or even if injected, the ntdll .text is pristine at the suspend point), the operator locates the ntdll .text section in the suspended process, extracts the syscall table, and copies it into the hooked process. The suspended process is then either discarded or used as the injection target. This avoids disk I/O on ntdll.dll that the Fresh Copy method incurs."
    relevant_to: [T-016, T-015]
    tags: [unhook, ntdll, suspended-process, syscall-table, evasion]

  - id: "concept-pe-data-directory-iat"
    name: "PE DataDirectory and Import Address Table"
    category: windows-structure
    description: "The PE header's optional header contains an array of 16 DataDirectory entries. Index 1 (IMAGE_DIRECTORY_ENTRY_IMPORT) points to the import descriptor; the IAT itself is a parallel array of function pointers that the loader fixes up at load time. Each IAT entry holds the resolved address of an imported function after load. Modifying an IAT entry redirects all calls routed through that import without modifying the target function's body, which is why IAT hooking is less invasive but also less comprehensive than inline hooking."
    relevant_to: [T-016]
    tags: [pe-headers, iat, datadirectory, windows-structure]

  - id: "concept-syscall-stub-mov-r10-rax"
    name: "x64 Syscall Stub Byte Pattern"
    category: os-internal
    description: "64-bit ntdll syscall stubs follow the pattern mov r10, rcx; mov eax, SSN; test byte ptr [...], 01; jne ...; syscall; ret. The mov eax, imm32 instruction encodes the SSN at offset +3 in the stub (opcode 0xB8 followed by the 4-byte SSN). Hell's Gate checks for the 0xB8 byte at this offset to validate the SSN is readable. Inline hooks overwrite this region — commonly with mov rax, imm64; jmp rax — destroying the SSN's discoverable position and triggering the Halo's Gate fallback path."
    relevant_to: [T-002, T-016]
    tags: [syscall-stub, ntdll, ssn, x64, byte-pattern]

  - id: "concept-av-detection-engines"
    name: "AV Detection Engine Types"
    category: defense-mechanism
    description: "Antivirus products decompose detection into three engine types. The static engine performs signature matching against files and in-memory buffers without executing the sample. The dynamic engine executes samples in a virtualized container (sandbox) and observes behavior including API call sequence, file and registry modifications, and network activity. The scan engine provides on-demand or on-access scanning against a signature database. EDRs extend this with kernel-mode telemetry and behavioral analytics layered on top of the AV engines. Evasion techniques must defeat multiple engines simultaneously because no single bypass covers static signatures, dynamic sandbox heuristics, and kernel callbacks."
    relevant_to: [T-016, T-020]
    tags: [av, detection-engines, static, dynamic, sandbox]

  - id: "concept-syswhispers3"
    name: "Syswhispers3 SSN Stub Generator"
    category: attack-pattern
    description: "Syswhispers3 is a tool that generates header, source, and MASM assembly files implementing syscall stubs with multiple bypass modes: WoW64 stubs, egg-hunter SSN resolution (searching ntdll for an 0xB8-byte egg pattern), direct syscall jumps in both WoW64 and x64 modes, and direct syscall jumps to random syscall numbers as a jitter against per-SSN detection. Visual Studio projects must enable MASM build support to compile the generated .asm files. Syswhispers1, 2, and 3 represent progressive generations adding more evasion modes over the original direct-syscall implementation."
    relevant_to: [T-002, T-001]
    tags: [syswhispers, ssn, syscall, masm, tooling]
```

### Detection Insights

```yaml
detection:
  - indicator: "Bytes at ntdll syscall stub prologue differ from mov r10, rcx; mov eax, SSN"
    source: memory-scan
    confidence: high
    relevant_to: [T-016, T-002]
    description: "A scanner reads the first 8 bytes of every Nt* export in the in-memory ntdll and compares against the expected mov r10, rcx; mov eax, imm32 pattern. Stubs whose first bytes match mov rax, imm64; jmp rax (inline hook) or whose +3 byte is not 0xB8 are flagged as hooked. Conversely, an EDR detecting unhooking looks for the inverse: a process whose in-memory ntdll .text matches the on-disk ntdll .text exactly, which indicates the EDR's hooks have been wiped."
    bypassed_by: "Halo's Gate does not unhook — it reads neighboring stubs to infer the SSN, leaving the hook in place and avoiding the unhook signature. Suspended Copy and Fresh Copy restore the bytes but the restoration itself generates a different signature (write to ntdll .text)."

  - indicator: "VirtualProtect call targeting an IAT region with PAGE_READWRITE"
    source: etw
    confidence: medium
    relevant_to: [T-016]
    description: "IAT hooking requires flipping the normally read-only IAT page to writable before overwriting a function pointer. The Microsoft-Windows-Kernel-Memory provider emits events for VirtualProtect calls; an EDR correlating VirtualProtect on an address inside any module's IAT range with a subsequent write to that address can flag IAT hook installation. EDRs use this same pattern themselves, complicating attribution."
    bypassed_by: "not discussed"

  - indicator: "CreateFileA on C:\\Windows\\System32\\ntdll.dll followed by CreateFileMapping and MapViewOfFile"
    source: sysmon
    confidence: medium
    relevant_to: [T-016]
    description: "Sysmon Event ID 11 (FileCreate) or 15 (FileCreateStreamHash) does not directly fire on read-only opens, but Sysmon Event ID 7 (ImageLoad) captures ntdll.dll loads and Event ID 10 (ProcessAccess) captures cross-process handle operations. The combination of opening on-disk ntdll, mapping it, and copying bytes into the live ntdll .text is anomalous process behavior. EDRs with telemetry on MapViewOfFile callers can flag this pattern as a fresh-copy unhook attempt."
    bypassed_by: "Suspended Copy unhook avoids touching on-disk ntdll entirely, removing the CreateFile/MapViewOfFile telemetry at the cost of spawning a suspended process."

  - indicator: "Process created with CREATE_SUSPENDED then terminated without ever resuming"
    source: windows-security-log
    confidence: low
    relevant_to: [T-016, T-015]
    description: "Event ID 4688 (process creation) with the CREATE_SUSPENDED flag in the input parameters, paired with the spawned process exiting shortly after creation without ever generating a main-thread activity event, is consistent with a Suspended Copy unhook that harvests ntdll .text and discards the helper. Some EDRs treat short-lived suspended-then-killed processes as suspicious."
    bypassed_by: "not discussed"

  - indicator: "Static signature matching on shellcode or payload bytes"
    source: memory-scan
    confidence: high
    relevant_to: [T-020, T-016]
    description: "The AV static engine scans file and memory buffers against a signature database. Known shellcode templates, encoding schemes (IPv4/UUID/MAC encoders), and loader scaffolds have static signatures. A buffer matching a signature in process memory triggers a detection regardless of whether the process executes the buffer."
    bypassed_by: "not discussed (unit 40 only enumerates the engine types; bypass tactics are not covered in this batch)"

sigma_ideas:
  - title: "NTDLL .text Section Overwrite via Fresh Copy"
    logsource: sysmon
    condition_summary: "Process opens C:\\Windows\\System32\\ntdll.dll with read attributes, calls MapViewOfFile, then issues NtProtectVirtualMemory or WriteProcessMemory targeting the address range of ntdll.dll's .text section in its own process."
  - title: "Short-Lived Suspended Process Spawn"
    logsource: windows-security
    condition_summary: "Process creation event with CREATE_SUSPENDED creation flag where the process exits within 5 seconds and no thread was ever resumed, by a parent process that is not a known debugger or service host."
  - title: "IAT Page Protections Flipped to Writable"
    logsource: etw
    condition_summary: "VirtualProtect ETW event where the target address falls within an IAT range of any loaded module and the requested protection includes PAGE_READWRITE or PAGE_EXECUTE_READWRITE."
```

### Operational Chains

```yaml
chains:
  - name: "Fresh Copy NTDLL Unhook"
    description: "Restore a pristine ntdll .text section to displace EDR inline hooks before issuing syscalls."
    steps:
      - technique: T-004
        role: "Walk PEB via gs:[0x60] to locate the in-memory ntdll base address and .text section bounds."
      - technique: T-016
        role: "Open C:\\Windows\\System32\\ntdll.dll, create a file mapping, map a view, locate the on-disk .text section via NT headers."
      - technique: T-016
        role: "memcpy the on-disk .text over the in-memory .text, restoring unhooked stubs."
      - technique: T-002
        role: "Resolve SSNs from the now-clean stubs using Hell's Gate byte validation."
    notes: "Material notes the on-disk file is treated as a trustworthy validation source; an operator could patch on-disk ntdll to defeat this but the batch does not elaborate. MapViewOfFile telemetry on ntdll.dll is a detection surface."

  - name: "Suspended Copy NTDLL Unhook"
    description: "Spawn a pristine process and harvest its unhooked ntdll syscall table."
    steps:
      - technique: T-015
        role: "CreateProcess with CREATE_SUSPENDED to spawn a process whose ntdll has not yet been hooked by the EDR DLL."
      - technique: T-016
        role: "Locate ntdll .text in the suspended process and extract the syscall table."
      - technique: T-016
        role: "Copy the syscall table into the hooked process, displacing inline hooks."
      - technique: T-002
        role: "Resolve SSNs from the restored table."
    notes: "Avoids disk I/O on ntdll.dll that the Fresh Copy chain incurs, at the cost of a visible suspended process spawn."

  - name: "Halo's Gate SSN Resolution on a Hooked Stub"
    description: "Resolve an SSN without unhooking when the target stub is already inline-hooked."
    steps:
      - technique: T-004
        role: "Walk PEB to locate ntdll and the target Nt* export address."
      - technique: T-002
        role: "Check the +3 byte for 0xB8 (Hell's Gate validation); if absent, the stub is hooked."
      - technique: T-002
        role: "Walk neighboring stubs forward and backward via off_hooked, reading their SSNs."
      - technique: T-002
        role: "Infer the target SSN by positional arithmetic from the nearest unhooked neighbor."
      - technique: T-001
        role: "Dispatch the syscall indirectly via an ntdll-resident gadget using the resolved SSN."
    notes: "Material attributes this to Renorth's blog and emphasizes that SSNs are stored in sequential order in ntdll, which is the property Halo's Gate exploits."

  - name: "Heaven's Gate Wow64 Syscall from 32-bit Implant"
    description: "Issue 64-bit syscalls from a 32-bit process to bypass 32-bit-mode ntdll hooks."
    steps:
      - technique: "wow64 transition via ntdll.Wow64Transition"
        role: "32-bit code executes jmp to ntdll.Wow64Transition."
      - technique: "far jmp 0x33 to wow64cpu.dll"
        role: "Transition from 32-bit code segment to 64-bit code segment inside wow64cpu.dll."
      - technique: "64-bit syscall stub"
        role: "Execute the mov r10, rcx; mov eax, SSN; syscall; ret sequence in 64-bit mode, bypassing any 32-bit ntdll hooks."
    notes: "Material notes 32-bit and 64-bit ntdll are both mapped in Wow64 processes; EDRs that hook only 32-bit ntdll have no visibility into calls routed through the 64-bit stub."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "vault-gap-heavens-gate"
    title: "Heaven's Gate Wow64 32-to-64-bit Transition"
    kind: coverage-gap
    description: "SEC670 dedicates multiple units (14–17) to Heaven's Gate as a distinct syscall evasion primitive: 32-bit Wow64 processes jumping to 64-bit code via ntdll.Wow64Transition and wow64cpu.dll to issue syscalls that bypass 32-bit-mode ntdll hooks. The vault's T-002 card covers Hell's/Halo's/Tartarus Gate but does not document the Heaven's Gate Wow64 transition path as a distinct mode. The two are operationally different — Hell's Gate resolves an SSN from a 64-bit stub, Heaven's Gate transitions an entire code path between execution modes. Worth adding as a sub-technique of T-002 or its own card."
    would_relate_to: [T-002, T-001]
    source_units: ["unit 14", "unit 15", "unit 16", "unit 17"]
    tags: [wow64, heavens-gate, syscall, 32bit-64bit, coverage-gap]

  - id: "vault-gap-syswhispers3-tooling"
    title: "Syswhispers3 as Reference SSN Tooling"
    kind: coverage-gap
    description: "SEC670 references Syswhispers3 (units 32, 33) as the canonical external tool for generating syscall stubs with multiple evasion modes: WoW64 stubs, egg-hunter SSN resolution, direct syscall jumps in WoW64 and x64, and direct syscall jumps to random syscalls as jitter. The vault's T-002 and T-001 cards implement equivalent functionality in pure Rust but do not document Syswhispers3 as the practitioner-side reference implementation or map which Syswhispers3 mode corresponds to which vault dispatch mode. Documenting the mapping would help operators translate between the vault's Rust implementations and the broader C/C++ tradecraft ecosystem."
    would_relate_to: [T-002, T-001, T-006]
    source_units: ["unit 32", "unit 33"]
    tags: [syswhispers, tooling, masm, ssn, coverage-gap]

  - id: "proposed-trampoline-infrastructure"
    title: "Hook Trampoline as Standalone Primitive"
    kind: proposed-technique
    description: "SEC670 units 22 and 23 cover trampolines as the infrastructure that makes inline hooks non-reentrant: a stub that executes the displaced original bytes and jumps back to the original function past the hook. The vault's T-016 EDR Evasion Suite covers unhooking but does not document the trampoline pattern as a primitive the implant itself might use for its own hooking needs (e.g., IAT camouflage, argument spoofing, KiUserException StepOver interactions all benefit from trampoline infrastructure). A standalone T-NNN for trampoline construction — preserving displaced instruction semantics under variable-length x86 decoding — would unify several existing card internals."
    would_relate_to: [T-016, T-013]
    source_units: ["unit 22", "unit 23"]
    tags: [trampoline, hooking, infrastructure, proposed-technique]

  - id: "cross-source-unhook-method-typology"
    title: "NTDLL Unhook Method Typology"
    kind: cross-source-convergence
    description: "SEC670 units 24–28 enumerate three distinct unhook methods with concrete API sequences: byte-level patch (search-and-replace), Fresh Copy (file-mapping restore of entire .text section), and Suspended Copy (clean process spawn to harvest syscall table). The vault's T-016 card documents NTDLL unhook but the source-code-centric view does not surface the three-method typology as a decision tree (detection surface vs. operational cost vs. robustness). Surfacing this typology in the card would help operators select the unhook variant appropriate to the target EDR's telemetry posture."
    would_relate_to: [T-016]
    source_units: ["unit 24", "unit 25", "unit 26", "unit 27", "unit 28"]
    tags: [unhook, ntdll, typology, cross-source-convergence]
```