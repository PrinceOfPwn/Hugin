## Synthesis Summary

This batch of 40 SANS SEC670 units (Book 1/2 — Windows Tool Development) maps thinly to the HUGIN vault: T-013 (Remaining Methods — thread hijacking, via Unit 5), T-016 (EDR Evasion Suite — NTDLL unhook and CIG/ACG, via Units 8 and 36), with Heaven's Gate (Unit 7) and the WldpQueryDynamicCodeTrust / Device Guard API (Unit 36) surfacing on-theme concepts not directly covered by an existing T-NNN card. The bulk of the batch covers foundational x86/x64 calling conventions, Windows data types, and basic Create*/Find* APIs — programming fundamentals rather than offensive tradecraft — and is off-theme. Approximately 36 units were skipped as foundational C/C++ and Windows API tutorial content; the remaining ~4 units contribute OS internals knowledge the source code alone does not surface: the explicit API sequence used to restore a clean NTDLL `.text` section via `CreateFileA` → `CreateFileMapping` → `MapViewOfFile` → `memcpy`, the requirement that thread hijacking modify the CONTEXT structure (not thread state or priority), and the existence of `WldpQueryDynamicCodeTrust` as the user-mode query for Device Guard dynamic-code trust decisions.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "ntdll-file-mapping-restore"
    target: T-016
    type: concept_link
    rationale: "Unit 8 explicitly describes the CreateFileA + CreateFileMapping + MapViewOfFile sequence to obtain a fresh .text copy of ntdll on disk and memcpy it over tampered in-memory sections, which is the NTDLL unhook technique catalogued under T-016."

  - source: "thread-context-structure"
    target: T-013
    type: requires
    rationale: "Unit 5 review answer states that thread hijacking requires modifying the Thread context (CONTEXT structure), not thread state or priority — the operational requirement for the thread hijack methods under T-013."

  - source: "wldp-device-guard-dynamic-code-trust"
    target: T-016
    type: detects
    rationale: "Unit 36 describes WldpQueryDynamicCodeTrust as the API EDR/Device Guard uses to evaluate whether in-memory dynamic code is trusted by policy — directly relevant to the ACG/CIG evasion material in T-016."

  - source: T-016
    target: "wldp-device-guard-dynamic-code-trust"
    type: counters
    rationale: "The T-016 EDR evasion suite includes ACG/CIG policy toggling; the Device Guard dynamic-code trust query (WldpQueryDynamicCodeTrust per Unit 36) is the policy gate these techniques must defeat for in-memory shellcode to execute."

  - source: "heavens-gate-transition"
    target: T-004
    type: concept_link
    rationale: "Unit 7 describes 32-bit code transitioning to 64-bit mode via ntdll.dll offset, relevant to T-004 (PEB Walker) and cross-bitness syscall/NT API resolution scenarios on WOW64 — same cross-bitness boundary that PEB walking must handle."

# material supports 5 edges; the remaining 35 units are foundational programming content (calling conventions, basic types, Create* API enumerations) without explicit sequencing relationships to vault techniques.
```

### Concept Nodes

```yaml
concepts:
  - id: "thread-context-structure"
    name: "CONTEXT Structure for Thread Hijacking"
    category: windows-structure
    description: "The Windows CONTEXT structure holds the register state of a thread at a given point (including RIP/RSP, segment registers, and FP state). Thread hijacking requires suspending the target thread via GetThreadContext, mutating the RIP member to redirect execution to shellcode, and committing the change via SetThreadContext. The SANS material explicitly frames this as the construct that must be modified — distinguishing hijack from thread-priority or thread-state manipulation."
    relevant_to: [T-013]
    tags: [thread-context, thread-hijack, windows-internals, getthreadcontext]

  - id: "ntdll-file-mapping-restore"
    name: "NTDLL .text Restoration via File Mapping"
    category: attack-pattern
    description: "A clean copy of ntdll.dll's .text section can be restored by opening the on-disk ntdll.dll with CreateFileA, mapping it into memory with CreateFileMapping + MapViewOfFile, locating the PE header and .text section bounds, and memcpy-ing the fresh bytes over the in-memory (potentially hooked) .text region. This neutralizes userland ntdll hooks placed by EDR without copying from another process or relying on a known-clean image."
    relevant_to: [T-016]
    tags: [ntdll, unhook, file-mapping, evasion, edr-evasion]

  - id: "wldp-device-guard-dynamic-code-trust"
    name: "WldpQueryDynamicCodeTrust and Device Guard Dynamic Code Trust"
    category: edr-mechanism
    description: "WldpQueryDynamicCodeTrust is the user-mode API to query whether the Windows Defender Device Guard (WDAC) policy trusts a given in-memory dynamic-code image. The function accepts either a fileHandle or a baseImage+imageSize pair (mutually exclusive, enforced via _When_ annotations). Code that fails this trust query cannot execute under policies that enforce CIG/ACG semantics — making it a key gating mechanism the T-016 ACG/CIG material must contend with."
    relevant_to: [T-016]
    tags: [wdac, device-guard, cig, acg, dynamic-code, edr-mechanism]

  - id: "heavens-gate-transition"
    name: "Heaven's Gate 32-to-64 Bit Transition"
    category: attack-pattern
    description: "A 32-bit (WOW64) process can transition into 64-bit code by jumping through the Heaven's Gate selector (the 0x33 segment selector in the WOW64 transition stub area of ntdll.dll). This allows 32-bit code to invoke the 64-bit syscall stubs directly, bypassing the 32-bit ntdll wrappers that are typically easier for EDR to hook. The technique is on-theme but not currently mapped to a vault card."
    relevant_to: []
    tags: [orphan, heavens-gate, wow64, syscall, edr-bypass, cross-bitness]
```

### Detection Insights

```yaml
detection:
  - indicator: "Mapped view of C:\\Windows\\System32\\ntdll.dll opened from a non-system process for READ access"
    source: kernel-callback
    confidence: low
    relevant_to: [T-016]
    description: "The NTDLL restore sequence described in Unit 8 opens the on-disk ntdll.dll with CreateFileA and maps a view via CreateFileMapping/MapViewOfFile. An EDR ObRegisterCallbacks callback or file minifilter observing this exact sequence from an untrusted process is a heuristic indicator of NTDLL unhooking activity."
    bypassed_by: "not discussed"

  - indicator: "WldpQueryDynamicCodeTrust call from an untrusted process querying non-image-backed memory"
    source: behavioral
    confidence: medium
    relevant_to: [T-016]
    description: "Unit 36 notes that WldpQueryDynamicCodeTrust is used to determine whether in-memory dynamic code is trusted by Device Guard policy. A process actively invoking this API to probe its own dynamic-code regions is a behavioral signal of payload code attempting to validate its execution context under WDAC."
    bypassed_by: "not discussed"

  - indicator: "Thread with modified RIP pointing into non-image-backed memory"
    source: memory-scan
    confidence: medium
    relevant_to: [T-013]
    description: "Unit 5 establishes that thread hijack requires modifying the Thread context (CONTEXT). After SetThreadContext commits a hijacked RIP, the target thread's instruction pointer resolves to shellcode that has no module backing — a memory-scan indicator (unbacked executable region now in the thread's active path)."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "NTDLL File Mapping from Non-System Process"
    logsource: sysmon
    condition_summary: "Sysmon EID 11 (FileCreate) or EID 1 (ProcessCreate) cross-referenced with a CreateFile mapping open of ntdll.dll from a process whose image path is not under System32 or WinSxS"
  - title: "WldpQueryDynamicCodeTrust API Call Telemetry"
    logsource: etw
    condition_summary: "ETW Microsoft-Windows-Wldp (or related WDAC provider) event for WldpQueryDynamicCodeTrust invocation supplying a baseImage pointer with no corresponding on-disk file backing"
```

### Operational Chains

```yaml
chains:
  - name: "NTDLL .text Restoration via On-Disk File Mapping"
    description: "Restores a clean (unhooked) ntdll .text section to the current process, removing userland EDR hooks before invoking NT syscalls directly."
    steps:
      - technique: "CreateFileA(ntdll.dll, READ)"
        role: "Obtain a handle to the on-disk ntdll.dll"
      - technique: "CreateFileMapping(hNtdll, READ_ONLY | SEC_IMAGE)"
        role: "Create a section object backed by the on-disk ntdll"
      - technique: "MapViewOfFile + locate NtHeader + .text bounds"
        role: "Map a view and resolve the fresh .text section's RVA and size"
      - technique: T-016
        role: "memcpy the fresh .text bytes over the in-memory hooked .text region, restoring clean syscall stubs"
    notes: "Unit 8 enumerates this sequence explicitly. No timing constraints discussed; relies on the on-disk ntdll.dll matching the running build version or the bytes will mismatch the in-memory image header layout."

  - name: "Device Guard Trust Probe Before Shellcode Execution"
    description: "Queries Device Guard dynamic-code trust for a candidate shellcode buffer before attempting execution, choosing an execution path that matches the trust decision."
    steps:
      - technique: "Stage shellcode in PAGE_READWRITE memory"
        role: "Prepare candidate payload region"
      - technique: "WldpQueryDynamicCodeTrust(baseImage, imageSize)"
        role: "Query WDAC trust state for the staged region"
      - technique: T-016
        role: "If untrusted, engage CIG/ACG policy evasion or module-stomp/backed-image technique before flipping to PAGE_EXECUTE_READ"
    notes: "Implied by Unit 36's framing of WldpQueryDynamicCodeTrust as the trust query for in-memory dynamic code. Material does not describe the explicit post-query evasion step — vault T-016 supplies that."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "heavens-gate-wow64-syscall-bridge"
    title: "Heaven's Gate (WOW64 32→64 Bit Syscall Bridge)"
    kind: proposed-technique
    description: "Unit 7 references the Heaven's Gate technique for 32-bit processes transitioning to 64-bit code space via ntdll.dll offset. The vault's syscall dispatch cards (T-001 RecycledGate, T-002 Hells/Halo/Tartarus, T-003 VEH Gate, T-006 Phantom Stubs) all assume 64-bit execution. Heaven's Gate would merit a distinct T-NNN card or a coverage note on the existing dispatch cards: it is a deployment-context technique (32-bit payload) that fundamentally changes which ntdll syscall stubs are visible and hookable."
    would_relate_to: [T-001, T-002, T-004]
    source_units: ["unit 7"]
    tags: [heavens-gate, wow64, syscall, cross-bitness, proposed-technique]

  - id: "coverage-gap-wdac-dynamic-code-trust-query"
    title: "WDAC Dynamic Code Trust Query (WldpQueryDynamicCodeTrust) Coverage Gap"
    kind: coverage-gap
    description: "Unit 36 documents the WldpQueryDynamicCodeTrust API as the user-mode query for Device Guard dynamic-code trust — a direct mechanism to detect whether a candidate payload region would survive CIG/WDAC enforcement before execution. The T-016 card touches ACG/CIG policy toggling but does not document the trust-query API itself, which is the operational pre-flight check an implant would run before committing to a dynamic-code execution path."
    would_relate_to: [T-016]
    source_units: ["unit 36"]
    tags: [wdac, device-guard, cig, acg, coverage-gap, dynamic-code]

  - id: "coverage-gap-ntdll-restore-api-sequence"
    title: "NTDLL Restore via On-Disk File Mapping — Explicit API Sequence"
    kind: coverage-gap
    description: "Unit 8 documents the exact CreateFileA → CreateFileMapping → MapViewOfFile → NtHeader lookup → .text memcpy sequence for restoring a fresh ntdll. The vault's ntdll_unhook_inject.rs and ntdll_unhook.rs implement the technique, but the source alone does not surface why this specific sequence (rather than copying from another process, or KnownDlls) is operationally preferred: it requires no cross-process handle, no SCM interaction, and uses only on-disk bytes that match the running build. A short operational note attached to T-016 documenting the alternative NTDLL restore sources (on-disk vs KnownDlls vs suspended-process injection) and their tradeoffs would close this gap."
    would_relate_to: [T-016]
    source_units: ["unit 8"]
    tags: [ntdll, unhook, file-mapping, coverage-gap]

  - id: "cross-source-convergence-thread-context-hijack-requirement"
    title: "Thread Hijack Requires CONTEXT Modification — Cross-Course Convergence"
    kind: cross-source-convergence
    description: "Unit 5's review answer (thread hijack requires modifying Thread context, not thread state or priority) is a foundational formulation of the thread-hijack primitive. The vault's T-013 waiting_thread_hijack_ref.rs implements the technique; the SANS framing clarifies the operational invariant at the API level (GetThreadContext → mutate RIP → SetThreadContext) that the source code does not comment on. This convergence between SEC670 didactic framing and vault source reinforces that the CONTEXT structure is the canonical manipulation target across all thread-hijack variants."
    would_relate_to: [T-013]
    source_units: ["unit 5"]
    tags: [thread-hijack, context-structure, cross-source-convergence]
```