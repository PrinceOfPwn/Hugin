Let me analyze the task. I need to produce a HUGIN technique card for T-027: KUSER_SHARED_DATA: Direct-Read System Information Primitive.

Key inputs:
1. Cluster spec: T-027, category `discovery`, tier `A`, member notes: `lgtm:kuser-shared-data-info-source`, `lgtm:kuser-shared-data-sysinfo-primitive`, would_relate_to: ['T-023', 'T-016', 'T-020']
2. Related T-NNN cards: T-016 (EDR Evasion), T-020 (Anti-Analysis), T-023 (Client Capabilities)
3. Matching source files: 
   - `src/dark_crystal/crates/core/src/experimental/evasion/veh/def.rs` — this is VEH gate definitions (PEB structures, etc.). It does NOT implement KUSER_SHARED_DATA reads. It has a PEB struct but no KUSER_SHARED_DATA usage. Not an implementation.
   - `src/dark_crystal/crowd/src/chain.rs` — the chain orchestrator. It uses `get_own_image_base` via gs:[0x60] PEB read, but does not touch KUSER_SHARED_DATA (0x7FFE0000). Not an implementation.
   - `src/dark_crystal/crowd/src/persist/ntfs_ea.rs` — NTFS EA persistence. Not related.
   
   So: no current implementation in the HUGIN source. I must verify: grep mentally for KUSER_SHARED_DATA or 0x7FFE0000 in provided files — none of them reference 0x7FFE0000. So `source_file: none`, `crate: none`.

4. Atlas material:
   - atlas-binary-analysis-part2.md units 21-23: KUSER_SHARED_DATA as "Undocumented Method", same VA in almost every process, holds large number of elements, VA 0x7FFE0000. Also units 16-20 about GetVersionEx, GetNativeSystemInfo, SYSTEM_INFO members (dwPageSize, lpMinimumApplicationAddress, lpMaximumApplicationAddress, dwActiveProcessorMask, dwNumberOfProcessors).
   - atlas-recon-part3.md units 15-16: OS Info bootcamp challenge — GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo, BONUS: KUSER_SHARED_DATA.

MITRE ATT&CK: The technique is about gathering system information. Best fit: T1082 (System Information Discovery). That's the single best-fit ID. Secondary could be T1497 (Virtualization/Sandbox Evasion) since TickCount/time checks can be used for anti-analysis, but let me not overreach. The notes mention "bypasses syscall-based EDR hooks" and "detection-free enumeration primitive". T1082 is the primary. Maybe no secondary, or T1033? No — the material is about OS version, tick count, processor counts, system time, NtSystemRoot. That's T1082 System Information Discovery. I'll use T1082 as primary. For secondary, possibly T1497.003 (time-based sandbox evasion via TickCount) — but the material doesn't explicitly say that. The rule says: "mitre_secondary: [<additional ATT&CK IDs if the technique spans multiple, or omit the line>]". I'll omit it or include T1497. The cluster spec tags mention 'anti-edr', 'evasion'. The notes relate to T-020 (anti-analysis). TickCount/InterruptTime are commonly used for timing checks, but the material doesn't explicitly state anti-sandbox use. I'll omit mitre_secondary to be safe. Actually, reading KUSER_SHARED_DATA for TickCount to detect sandboxes is well-established, but the rule says don't fabricate. The material describes it as sysinfo source. I'll go with just T1082.

Category: `discovery` per the spec. Tier: A per spec.

Frontmatter:
- id: T-027
- name: KUSER_SHARED_DATA Direct-Read System Information (4-8 words: "KUSER_SHARED_DATA Direct-Read System Information" = 4 words if we count KUSER_SHARED_DATA as one. Or "Direct-Read System Information via KUSER_SHARED_DATA". Let me pick something readable: "KUSER_SHARED_DATA Direct-Read System Information Primitive" — 5 words. Good.)
- category: discovery
- tier: A
- crate: none
- source_file: none
- mitre: T1082
- tags: 5-10 kebab-case: [kuser-shared-data, sysinfo, direct-read, fixed-va, user-mode-mapping, hook-bypass, discovery, timing-source]
- origin: atlas-synthesis
- member_notes: [lgtm:kuser-shared-data-info-source, lgtm:kuser-shared-data-sysinfo-primitive]

H1: `# KUSER_SHARED_DATA Direct-Read System Information — Fixed-VA Kernel-Mapped Page for Hook-Free Enumeration`

Sections:

## Summary
3-5 sentences. What it does: reads a kernel-maintained read-only page at fixed VA 0x7FFE0000, which is mapped into every user-mode process; provides OS version, NtSystemRoot, TickCount, InterruptTime, timer resolution, processor features — without any API call or syscall. Operator use: sysinfo gathering with zero userland hook surface. Detection surface: essentially none in userland telemetry; only memory-content heuristics or behavioral correlation.

## Mechanism
Numbered steps:
1. Locate the page: hardcoded VA 0x7FFE0000 (x64; 0x7FFE0000 also on x86; note ARM64 differs — I know it's 0x7FFE0000 on x86/x64. For WOW64 there's also a 32-bit mapping. The material says "Same VA in almost every process".) — no handle, no section open.
2. Read fields directly by offset from the page base: e.g., NtMajorVersion (0x26C), NtMinorVersion (0x270), NtBuildNumber (0x260)... wait, I need to be careful about offsets. Known offsets for x64 KUSER_SHARED_DATA on Win10/11:
   - TickCountLowDeprecated: 0x0
   - TickCountMultiplier: 0x4
   - InterruptTime: 0x8 (KSYSTEM_TIME)
   - SystemTime: 0x14 (KSYSTEM_TIME)
   - TimeZoneBias: 0x20
   - ImageNumberLow: 0x2C
   - ImageNumberHigh: 0x2E
   - NtSystemRoot: 0x30 (WCHAR[260])
   - MaxStackTraceDepth: 0x238
   - CryptoExponent: 0x23C
   - TimeZoneId: 0x240
   - LargePageMinimum: 0x244
   - NtProductType: 0x264 (enum NT_PRODUCT_TYPE)
   - ProductTypeIsValid: 0x268
   - NtMajorVersion: 0x26C
   - NtMinorVersion: 0x270
   - ProcessorFeatures: 0x274 (BOOLEAN[64])
   - Reserved1: 0x2B4
   - Reserved3: 0x2B8
   - TimeSlip: 0x2BC
   - AlternativeArchitecture: 0x2C0
   - AltArchitecturePad: 0x2C4
   - SystemExpirationDate: 0x2C8
   - SuiteMask: 0x2D0
   - KdDebuggerEnabled: 0x2D4
   - NXSupportPolicy: 0x2D5
   - ActiveConsoleId: 0x2D8
   - DismountCount: 0x2DC
   - ComPlusPackage: 0x2E0
   - LastSystemRITEventTickCount: 0x2E4
   - NumberOfPhysicalPages: 0x2E8
   - SafeBootMode: 0x2EC
   - TickCount: 0x320 (KSYSTEM_TIME) on newer versions; TickCountQuad: 0x330... Actually let me be careful. On Windows 10 x64:
     - TickCount: 0x320 (KSYSTEM_TIME)
     - Cookie: 0x330
     - ConsoleSessionForegroundProcessId: 0x338
   
   Hmm, I should not fabricate precise offsets unless confident. Well-established ones I'm confident about for x64 Win10/11:
   - 0x000 TickCountLowDeprecated
   - 0x004 TickCountMultiplier
   - 0x008 InterruptTime (KSYSTEM_TIME)
   - 0x014 SystemTime (KSYSTEM_TIME)
   - 0x020 TimeZoneBias (KSYSTEM_TIME)
   - 0x02C ImageNumberLow (USHORT)
   - 0x02E ImageNumberHigh (USHORT)
   - 0x030 NtSystemRoot (WCHAR[260])
   - 0x238 MaxStackTraceDepth
   - 0x23C CryptoExponent
   - 0x240 TimeZoneId
   - 0x244 LargePageMinimum
   - 0x264 NtProductType
   - 0x268 ProductTypeIsValid
   - 0x26C NtMajorVersion
   - 0x270 NtMinorVersion
   - 0x274 ProcessorFeatures[64]
   - 0x2D4 KdDebuggerEnabled
   - 0x2EC SafeBootMode
   - 0x2E8 NumberOfPhysicalPages
   - 0x320 TickCount (KSYSTEM_TIME on Win10+)
   - 0x330 Cookie (encode pointer cookie? actually it's the system call cookie... On Win10, at 0x330 there's "Cookie". Hmm.)
   
   Known documented: NtBuildNumber? No — KUSER_SHARED_DATA doesn't have NtBuildNumber... Actually it does not. Version info: NtMajorVersion/NtMinorVersion only. Build number isn't in KUSER_SHARED_DATA (PEB has OSBuildNumber). I'll avoid claiming build number.

   QPC bypass: QPC bypass: QueryPerformanceCounter on modern Windows reads... actually QPC uses KUSER_SHARED_DATA? No — that's not right either. GetTickCount reads TickCountLow * multiplier from KUSER_SHARED_DATA (that's the well-known "GetTickCount doesn't syscall" fact). GetSystemTimeAsFileTime reads SystemTime from KUSER_SHARED_DATA. Those are well-established facts.

   Also KdDebuggerEnabled at 0x2D4 — used by anti-debug. NtSystemRoot at 0x30. SafeBootMode at 0x2EC.

   The system prompt says I can rely on "Well-established Windows internals documentation (Windows Internals 7ed, MSDN, ntdll headers)". KUSER_SHARED_DATA offsets are well-established. I'll include the offsets I'm confident about and note they are stable for the listed fields across Win10/11 x64.

3. Read version/product: NtMajorVersion/NtMinorVersion/NtProductType/ProductTypeIsValid → OS version and workstation-vs-server determination without GetVersionEx/RtlGetVersion.
4. Read NtSystemRoot wide string (offset 0x30) → Windows directory path without GetWindowsDirectory/GetSystemWindowsDirectory.
5. Read timing fields: InterruptTime, SystemTime, TickCount (KSYSTEM_TIME triples: LowPart, High1Time, High2Time) → tick count and system time without GetTickCount64/GetSystemTimeAsFileTime.
6. Read processor/system fields: NumberOfPhysicalPages, ImageNumberLow/High, ProcessorFeatures, SuiteMask, NXSupportPolicy, ActiveConsoleId.
7. Optional anti-analysis checks: KdDebuggerEnabled (0x2D4) and SafeBootMode (0x2EC).
8. KSYSTEM_TIME read protocol: read High1Time, LowPart, High2Time, retry if High1Time != High2Time (for 64-bit atomicity on 32-bit; on 64-bit aligned reads are atomic).

Also: how Win32 APIs consume it — GetTickCount returns TickCountLowDeprecated * TickCountMultiplier >> 24? The actual formula: GetTickCount = (ULONG)((TickCountMultiplier * TickCountLow) >> 24). Well-established. GetSystemTimeAsFileTime reads SystemTime from the shared page. This demonstrates the page is the underlying source the APIs read — direct reads are equivalent to the API call.

## OS Internals Context
- The page: kernel virtual address 0xFFFFF78000000000 (x64) mapped read-only into user space at 0x7FFE0000 in every process. Set up by the memory manager at boot (MmInitSystem / mapping via the page tables; the user mapping is created for each process address space). Same physical page shared system-wide — one global copy, mapped RO in userland, RW in kernel.
- Kernel updates fields: clock interrupt handler updates InterruptTime/SystemTime/TickCount; version fields are fixed at boot; KdDebuggerEnabled reflects KD state.
- Why it needs no syscall: the mapping is established before process creation completes; it's part of the address space template. Reading it is a plain memory load — no transition, no syscall, no ntdll code path, hence no userland inline hooks or syscall monitoring see it.
- Kernel/user boundary: userland sees a snapshot updated by the kernel asynchronously. KSYSTEM_TIME structure: LowPart, High1Time, High2Time — the High1/High2 pair allows readers on 32-bit to detect a tear mid-update.
- Wow64: on WOW64 processes the page is also mapped at 0x7FFE0000 (same VA). Material says "Same VA in almost every process".
- Relation to PEB: PEB.ReadOnlySharedMemoryBase points to the same page? Actually PEB has ReadOnlySharedMemoryBase field which historically pointed to... Hmm. In the def.rs PEB struct provided, there's `read_only_shared_memory_base` field. Historically PEB->ReadOnlySharedMemoryBase pointed to 0x7FFE0000 on XP-era. On modern Windows this field is not populated that way (it's used differently). I should be careful. The well-established way is the hardcoded constant. Windows code itself (kernel32/ntdll) uses the hardcoded address 0x7FFE0000 (SharedUserData symbol). I'll mention the fixed VA as the canonical access method, which matches the material ("Same VA in almost every process").
- GetTickCount implementation detail: reads 0x7FFE0000 (TickCountLowDeprecated at 0x0) and TickCountMultiplier at 0x4: `return (NtGetTickCount64-ish) (ULONG)(((UInt64)TickCountMultiplier * TickCountLow) >> 24)`. Well-established reverse-engineered fact. I can include the multiplier formula.
- EDR angle: userland hooks intercept at ntdll/Win32 API level; direct reads never reach those. ETW providers for API calls don't fire. Syscall telemetry (ETW-TI / kernel callbacks) sees nothing because no syscall occurs.
- Version differences: material doesn't discuss version differences beyond "almost every process". KdDebuggerEnabled exists since... I'll keep to fields I'm confident exist on Win10/11.

## Key Implementation Details
No implementation. Check the provided files:
- veh/def.rs — defines PEB, LoaderDataTableEntry, etc. for the VEH gate. No KUSER_SHARED_DATA references. Not an implementation.
- crowd/src/chain.rs — chain orchestration; uses gs:[0x60] PEB read for own image base; no 0x7FFE0000. Not an implementation.
- persist/ntfs_ea.rs — EA persistence. Not an implementation.
So write the "No current implementation" paragraph + describe what an implementation would look like: a small module defining a `#[repr(C)] KUSER_SHARED_DATA` struct with the needed fields at exact offsets, `const SHARED_USER_DATA: *const KUserSharedData = 0x7FFE0000 as _;`, volatile reads via `core::ptr::read_volatile` for timing fields, KSYSTEM_TIME tear-check loop, helper fns: `os_version()`, `system_root()`, `tick_count()`, `interrupt_time()`, `kd_debugger_enabled()`. Feature-gated under `discovery` or used by sysinfo_collect / anti-analysis modules.

## Why It Matters
- T-023 lists sysinfo collection via APIs; this card documents the zero-API primitive that removes the hook surface entirely.
- T-004 (PEB Walker) is a different fixed-structure read; KUSER_SHARED_DATA is a distinct info source (note 1 says distinct from PEB walking).
- Operational gap: gathering OS version, system root, tick counts during recon and during time-based checks without touching ntdll exports or triggering syscall-based EDR monitoring.

## Detection Considerations
The material doesn't cover detection explicitly. The notes say "bypasses userland hooks and syscall monitoring" / "reduces EDR hook surface". I can describe:
- Telemetry sources: none of the standard ones observe it — no ETW provider, no Sysmon event, no kernel callback fires for a plain user-mode read of this page (kernel sees no event; it's just memory access). But rule 4 says don't invent detections. The instruction for Detection Considerations: "Detection surface the training material describes for this technique... If the material does not cover detection for this technique, write: 'Training material does not discuss detection for this technique.' Do not invent detections."
  
  The material/notes DO make claims: "Bypasses userland hooks and syscall monitoring", "detection-resistant primitive", "reduces EDR hook surface". So I can document that the notes describe it as bypassing userland hooks and syscall monitoring, and that the training material does not describe specific detection telemetry for it. I'll structure: Telemetry sources — training material describes the technique as invisible to userland API hooks and syscall monitoring; no ETW/Sysmon source is discussed. Bypass options — the technique is itself the bypass (relative to API-based enumeration). Residual artifacts — none described in material; the read leaves no handles, files, or registry traces (I can state this carefully as it's inherent and the notes call it detection-free).

  I think a careful formulation: state what the material claims (hook/syscall-monitoring bypass), note that no concrete telemetry sources or detection logic are discussed in the material, and list residual artifacts as none per the material's characterization. Avoid inventing specific EDR product detections.

## Related Techniques
would_relate_to from cluster spec: ['T-023', 'T-016', 'T-020']. Also note 1 lists would_relate_to T-004 and T-020. The system prompt says "Only reference cards from the would_relate_to list or that you find explicitly discussed in the related T-NNN cards provided." The member notes explicitly relate to T-004. The cluster spec's would_relate_to is ['T-023', 'T-016', 'T-020'], but member note 1 says would_relate_to T-004, T-020. The instruction says "Only reference cards from the `would_relate_to` list or that you find explicitly discussed in the related T-NNN cards provided." T-004 is in the member notes' would_relate_to — I think it's justifiable since the notes explicitly reference T-004. The spec's own consolidated would_relate_to list is ['T-023', 'T-016', 'T-020']. I'll include T-023, T-016, T-020, and T-004 (justified by member note 1's explicit relation and the atlas note text explaining the distinction from PEB walking).

Relationships:
- T-023 Client Capabilities — T-023's System Info Collection gathers host details via APIs for the HELLO message; KUSER_SHARED_DATA is the direct-read alternative that removes the API surface.
- T-016 EDR Evasion — the direct read is itself an evasion primitive: no ntdll hook or syscall monitor observes it, complementing T-016's unhooking/patching approaches by avoiding the hooked path entirely.
- T-020 Anti-Analysis — fields like KdDebuggerEnabled and the timing fields (TickCount/InterruptTime) serve as zero-syscall inputs to debugger/sandbox checks documented in T-020's suite. Careful: does the material tie KUSER_SHARED_DATA to anti-analysis? Note tags include 'anti-edr', 'evasion'. Note 1 relates to T-020. I'll phrase it as: complements T-020's checks by providing the same system inputs (time, debugger state) without API calls that sandboxes instrument. Hmm — KdDebuggerEnabled use is well-established Windows internals. I'll mention it as the documented field.
- T-004 PEB Walker — both are fixed-structure userland reads requiring no API; T-004 resolves modules via PEB/LDR, T-027 reads kernel-published system values from the shared page. The note explicitly frames it as distinct from PEB walking.

## References
- Atlas material: atlas-binary-analysis-part2.md (units 21-23), atlas-recon-part3.md (units 15-16)
- MITRE ATT&CK: T1082 https://attack.mitre.org/techniques/T1082/
- LGTM notes: lgtm:kuser-shared-data-info-source, lgtm:kuser-shared-data-sysinfo-primitive
- Public references: MSDN KUSER_SHARED_DATA structure documentation (documented since it became public in WDK headers). Also Geoff Chappell's KUSER_SHARED_DATA analysis is a known public reference but not named in the material — the rule says "do not invent references" — public references should be ones "named in the atlas material". The material names no public tools/blogs for this. I can reference the WDK/MSDN `KUSER_SHARED_DATA` documentation as "well-established Windows internals documentation" — hmm, the references section template says "Public references: <optional — original tool authors, blog posts, papers named in the atlas material; do not invent references>". The atlas material doesn't name any. But referencing MSDN documentation of KUSER_SHARED_DATA is factual, not invented — the structure is publicly documented by Microsoft in ntddk.h. I think it's acceptable to cite "Microsoft WDK ntddk.h — KUSER_SHARED_DATA structure definition" as a public reference since it's a real, verifiable documentation source and the system prompt explicitly allows "Well-established Windows internals documentation (Windows Internals 7ed, MSDN, ntdll headers)" as claim sources. I'll cite MSDN/ntddk.h and Windows Internals 7ed.

## Source Reference
"No current implementation. See atlas material and MITRE reference for public tooling."

Wait — actually the template says: `<If no source: "No current implementation. See atlas material and MITRE reference for public tooling.">`. And in Key Implementation Details, write the exact sentence: `**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in <source language/tool>.` — the source language here is C (the training material is C-centric; SEC670 uses C). So "See the atlas material for reference implementations in C."

Also, I need to double check the word count: minimum 800 words body, target 1200-1800.

Frontmatter tags (5-10 kebab-case): [kuser-shared-data, fixed-va, direct-read, sysinfo-discovery, timing-source, hook-bypass, syscall-free, kernel-mapped-page] — that's 8.

mitre: T1082. 

Let me double-check "category" enum: `discovery` is in the enum. Yes.

crate: none. source_file: none. Wait — crate enum is `dark_crystal|client_rust|none`. Since no implementation: none. Hmm, but should crate be the crate where it *would* live? The template says `crate: dark_crystal|client_rust|none` — with no implementation, `none` is right.

Now let me carefully draft the Mechanism steps:

1. Obtain the page base as a compile-time constant: `0x7FFE0000`. The mapping is present at process start on x86 and x64 (including WOW64); no enumeration, handle, or API call is required to locate it. The material emphasizes "Same VA in almost every process".
2. Read OS version fields at fixed offsets: NtMajorVersion (0x26C), NtMinorVersion (0x270), NtProductType (0x264), ProductTypeIsValid (0x268) — replaces GetVersionEx/RtlGetVersion/GetProductInfo.
3. Read NtSystemRoot (0x30, WCHAR[260]) — replaces GetWindowsDirectory/GetSystemWindowsDirectory.
4. Read processor fields: ImageNumberLow/High (0x2C/0x2E), ProcessorFeatures (0x274, 64 bytes), NumberOfPhysicalPages (0x2E8), SuiteMask (0x2D0), NXSupportPolicy (0x2D5).
5. Read timing triples: InterruptTime (0x8), SystemTime (0x14), TickCount (0x320) as KSYSTEM_TIME {LowPart, High1Time, High2Time}; on 64-bit aligned 64-bit reads are atomic; portable code loops on High1Time != High2Time.
6. Compute GetTickCount-equivalent: (TickCountLowDeprecated[0x0] * TickCountMultiplier[0x4]) >> 24 — the same arithmetic kernel32!GetTickCount performs against this page.
7. Read system-state flags: KdDebuggerEnabled (0x2D4), SafeBootMode (0x2EC), ActiveConsoleId (0x2D8).
8. Consume values directly in recon output or as inputs to timing checks — no ntdll export, syscall stub, or Win32 import is exercised.

For offsets — let me verify a few against well-established ntddk layout (x64):
- 0x000 TickCountLowDeprecated ✓
- 0x004 TickCountMultiplier ✓
- 0x008 InterruptTime ✓
- 0x014 SystemTime ✓
- 0x020 TimeZoneBias ✓
- 0x02C ImageNumberLow ✓
- 0x02E ImageNumberHigh ✓
- 0x030 NtSystemRoot[260] ✓ (0x30 + 520 bytes = ends 0x238)
- 0x238 MaxStackTraceDepth ✓
- 0x23C CryptoExponent ✓
- 0x240 TimeZoneId ✓
- 0x244 LargePageMinimum ✓
- 0x248 AitSamplingValue / 0x24C AppCompatFlag / 0x250 RNGSeedVersion / 0x258 GlobalValidationRunlevel / 0x25C TimeZoneBiasStamp
- 0x260 NtBuildNumber ✓ — yes! NtBuildNumber IS at 0x260 in the Windows 10+ ntddk.h KUSER_SHARED_DATA. Let me recall: 

```c
typedef struct _KUSER_SHARED_DATA {
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    volatile KSYSTEM_TIME InterruptTime;
    volatile KSYSTEM_TIME SystemTime;
    volatile KSYSTEM_TIME TimeZoneBias;
    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;
    WCHAR NtSystemRoot[260];
    ULONG MaxStackTraceDepth;
    ULONG CryptoExponent;
    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG AitSamplingValue;
    ULONG AppCompatFlag;
    ULONGLONG RNGSeedVersion;
    ULONG GlobalValidationRunlevel;
    LONG TimeZoneBiasStamp;
    ULONG NtBuildNumber;
    NT_PRODUCT_TYPE NtProductType;
    BOOLEAN ProductTypeIsValid;
    BOOLEAN Reserved0[1];
    USHORT NativeProcessorArchitecture;
    ULONG NtMajorVersion;
    ULONG NtMinorVersion;
    BOOLEAN ProcessorFeatures[64];
    ...
```

So on Win10+ WDK: NtBuildNumber at 0x260, NtProductType at 0x264, ProductTypeIsValid at 0x268, NativeProcessorArchitecture at 0x26A, NtMajorVersion at 0x26C, NtMinorVersion at 0x270, ProcessorFeatures at 0x274. ✓ These are the documented WDK offsets for Windows 10/11 x64. 

- 0x2D0 SuiteMask ✓
- 0x2D4 KdDebuggerEnabled ✓
- 0x2D5 NXSupportPolicy ✓ (0x2D5)
- 0x2D8 ActiveConsoleId ✓
- 0x2DC DismountCount
- 0x2E0 ComPlusPackage
- 0x2E4 LastSystemRITEventTickCount
- 0x2E8 NumberOfPhysicalPages ✓
- 0x2EC SafeBootMode ✓
- 0x320 TickCount (KSYSTEM_TIME) ✓ — actually 0x2F0 is "TscQpcData"... union VirtualizationFlags at 0x2ED, then 0x2F0... let me recall Win10 1607+: 0x2F0 "Reserved12[2]"... Hmm. The Win10 WDK:

```c
    BOOLEAN SafeBootMode;            // 0x2EC
    union {
        UCHAR VirtualizationFlags;
        ...
    };                               // 0x2ED
    UCHAR Reserved12[2];             // 0x2EE
    ULONG SharedDataFlags;           // 0x2F0
    ULONG DataFlagsPad[1];           // 0x2F4
    ULONGLONG TestRetInstruction;    // 0x2F8
    LONGLONG QpcFrequency;           // 0x300
    ULONG SystemCall;                // 0x308
    ...
    ULONGLONG SystemCallPad[2];      // 0x310?
    volatile KSYSTEM_TIME TickCount; // 0x320
    ULONG Cookie;                    // 0x330? actually Cookie at 0x330
```

Yes: TickCount at 0x320, Cookie at 0x330, ConsoleSessionForegroundProcessId at 0x338. And QpcFrequency at 0x300 (Win10+). I'm fairly confident on 0x320 TickCount and 0x330 Cookie for Win10 1607+. I'll cite the main ones and avoid the riskier ones. Actually QpcFrequency at 0x300 — I'm reasonably confident this was added in Win10 (used by QueryPerformanceCounter to avoid syscall in some cases). To be safe I'll mention only fields I'm sure of: TickCount 0x320.

For "page size, tick count, processor counts" — note 1 mentions "page size, tick count, processor counts, system time, NtSystemRoot". Page size: KUSER_SHARED_DATA has... hmm, PAGE_SIZE isn't a field; there's LargePageMinimum (0x244). Basic page size (4KB) is constant for the architecture; GetSystemInfo reports it. The note says the page provides "page size" — maybe via LargePageMinimum, or the note is loosely describing SYSTEM_INFO-like values. I'll present LargePageMinimum and frame it accurately. Processor counts: NumberOfPhysicalPages is physical pages (RAM), not processor count. Processor *counts* aren't directly in KUSER_SHARED_DATA (active processor count isn't a classic field; Win11 added... there's "ActiveProcessorCount"? Hmm — actually Windows 11 22H2+ has new fields but I won't claim). The note's characterization is loose; I'll document the actual fields and map them to what the notes claim where accurate. I should be careful: the note says the page holds "page size, tick count, processor counts, system time, NtSystemRoot". I can say: the notes characterize the contents as including page-size, tick-count, processor, system-time, and system-root values; the documented WDK layout provides the following concrete fields... and list real ones (ImageNumberLow/High, ProcessorFeatures, NumberOfPhysicalPages, LargePageMinimum). That stays truthful.

MM_SYSTEMSIZE? No. Ok.

Also GetSystemTimeAsFileTime reads SystemTime directly from SharedUserData on modern Windows — well-established. GetTickCount reads TickCountLowDeprecated*multiplier — well-established on legacy; on Win10 GetTickCount64 reads TickCount KSYSTEM_TIME (0x320). I'll present both as established facts.

Also: kernel-side VA 0xFFFFF78000000000 (x64). That's well-established (KI_USER_SHARED_DATA constant in WDK as 0xFFFFF78000000000). ✓ 

User-mode SharedUserData symbol in ntdll points to 0x7FFE0000. ✓

KdDebuggerEnabled at 0x2D4 used by anti-debug checks (alternative to PEB.BeingDebugged / CheckRemoteDebuggerPresent) — well-established.

Timing: KSYSTEM_TIME tear-check loop is the documented read protocol in WDK comments. ✓

Now the "OS Internals Context" section:
- The mapping: created by the memory manager; one physical page, kernel VA 0xFFFFF78000000000 RW, user VA 0x7FFE0000 RO, mapped into every process address space. Set up during system initialization; inherited by all processes because it's part of the system-wide address space layout (the page tables for this region are shared/process-inherited).
- The kernel's clock interrupt routine (KeUpdateSystemTime / KeUpdateRunTime at CLOCK2_LEVEL) updates InterruptTime, SystemTime, TickCount; HAL updates... I'll keep to: updated by the kernel's timer interrupt path.
- Because the page is read-only from userland, writes fault (STATUS_ACCESS_VIOLATION).
- No syscall boundary crossing: pure load instruction → no ETW-TI syscall events, no kernel callbacks, no userland inline hooks (they live in ntdll), no VEH-mediated gates involved.
- KSYSTEM_TIME structure and the High1/High2 protocol (documented in WDK: on 32-bit, read High1Time, LowPart, High2Time, loop until High1Time==High2Time; on 64-bit the volatile 64-bit aligned read is atomic).
- WOW64: same VA; wow64 processes see the same page (ImageNumberLow reflects native machine type? Actually ImageNumberLow is the native machine; there's NativeProcessorArchitecture field at 0x26A on Win10+).
- Material's framing: "Undocumented Method" slide — note the structure is now publicly documented in ntddk.h (Microsoft made it public), though SEC670 presents it as undocumented method in the course context.
- Relation to APIs: GetTickCount, GetSystemTimeAsFileTime, RtlGetVersion (partially — RtlGetVersion reads PEB OSMajorVersion fields; hmm. Actually RtlGetVersion reads from PEB, not KUSER_SHARED_DATA. GetVersionEx similar. But the version fields in KUSER_SHARED_DATA mirror the same values). I'll be careful: I'll say the version fields mirror what RtlGetVersion reports (values sourced from the same kernel globals) without claiming RtlGetVersion reads the page. GetNativeSystemInfo populates SYSTEM_INFO from kernel globals, several of which are also published in the page.

- QPC: QueryPerformanceCounter on Win10+ reads QpcFrequency from the page (0x300) — I'll skip unless confident. I'm fairly confident Win10 added QpcFrequency at 0x300 and QPC uses it with the TestRetInstruction/rdtsc path. This is well-established in reverse-engineering literature (the "QPC no longer syscalls on Win10" change). I could include a brief mention. I'll include it cautiously as "on Windows 10 and later, QueryPerformanceCounter computes its result in user mode using QpcFrequency (offset 0x300) published in this page, avoiding a syscall in the common path" — this is well-documented (Geoff Chappell, various RE writeups). Given the system prompt allows well-established Windows internals documentation, I'll include it briefly.

Hmm, but I want to be careful not to overload with claims beyond the material. The system prompt explicitly encourages OS internals depth beyond the material, sourced from established documentation. Good.

- The def.rs file provided contains a PEB struct with `read_only_shared_memory_base` field. Historically (XP/2003), PEB.ReadOnlySharedMemoryBase pointed at the shared data page region... Actually ReadOnlySharedMemoryBase at PEB+0x4C (x86) pointed to 0x7F6F0000 (the read-only shared heap used by csrss) — NOT KUSER_SHARED_DATA. So I should NOT claim PEB points to KUSER_SHARED_DATA. The canonical access is the hardcoded constant. I'll note the access method is the hardcoded VA, which is how ntdll itself references it (SharedUserData).

Detection Considerations section:
- Telemetry sources: Training material characterizes the read as bypassing userland hooks and syscall monitoring. No ETW provider fires (no event is generated by a memory load), no Sysmon event covers it, kernel callbacks (process/thread/image/load-object) don't observe it. GUID: not applicable / not documented in material.
- Bypass options: the technique is itself the bypass — the operator substitutes direct reads for GetProductInfo/GetWindowsDirectory/GetComputerName/GetNativeSystemInfo calls (the four APIs the recon material lists).
- Residual artifacts: none — no handles opened, no files or registry keys touched, no network traffic. Memory-scanners could in principle flag the hardcoded 0x7FFE0000 constant in a binary's .rdata/.text, but the material doesn't discuss that. I'll say the material does not discuss static signatures.

I must include the fallback line if detection isn't covered: The material partially covers it (the notes characterize detection posture). I'll write the three bullets with material-traceable content and end with a note that concrete telemetry/detection logic is not discussed in the material.

Actually, re-reading the template: "If the material does not cover detection for this technique, write: 'Training material does not discuss detection for this technique.'" The notes DO discuss the detection posture (bypass claims). So I'll write the three subsections grounded in the notes, and be explicit that no concrete provider/Sysmon coverage is documented.

Why It Matters: 
- Fills the gap between T-023 (sysinfo via APIs) and T-004 (PEB walking for modules): this is a third fixed-structure info source, distinct in content (kernel-published runtime state rather than loader structures).
- Bypass surface: every alternative enumeration path (Win32 API, NT API, WMI, registry) traverses code that EDRs instrument; this one traverses none.
- It's a building block: version gating for payload selection, system root for path construction, tick/time for anti-sandbox timing, KdDebuggerEnabled for anti-debug — all from one page with zero API surface.

Mechanism section should name the actual fields/offsets — that's the concrete value of the card.

Word count target: I'll aim ~1300-1500 words.

H1 format: `# <Technique Name> — <One-Line Purpose>`. 
`# KUSER_SHARED_DATA Direct-Read System Information — Fixed-VA Kernel-Mapped Page Enumeration Without API Calls`

Frontmatter name: "KUSER_SHARED_DATA Direct-Read System Information" (4 words).

Let me also double check banned words list: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable. Avoid "essentially", "at its core", "interestingly", "worth noting", "the key insight", "it is important to note", "as you can see", "but wait". No exclamation marks. Third person. 

Also careful with the phrase "textbook" — the system prompt uses it in quotes for Key Implementation Details ("deviations from the 'textbook' implementation") — but since there's no implementation, I use the no-implementation template.

Tags check (5-10 kebab-case): 
- kuser-shared-data
- fixed-va
- direct-read
- sysinfo-discovery
- timing-source
- hook-bypass
- syscall-free
- kernel-mapped-page
That's 8. Good.

mitre_secondary: I'll include T1497.003? The notes don't explicitly tie to sandbox evasion timing. Hmm. Note 1 tags: ['kuser-shared-data', 'info-source', 'evasion', 'kernel', 'proposed-technique']; note 2 tags include 'anti-edr'. would_relate_to T-020 (anti-analysis). The card will mention KdDebuggerEnabled and timing fields as inputs to anti-analysis — that's traceable to well-established internals + the notes' T-020 relation. T1497.003 is "Virtualization/Sandbox Evasion: Time Based Evasion". I think it's defensible but the primary is clearly T1082. The instruction: pick single best-fit for mitre; secondary optional. I'll add mitre_secondary: [T1497.003] since the timing-field reads directly feed time-based sandbox checks and the notes explicitly relate to T-020. Hmm, rule: "mitre_secondary: [<additional ATT&CK IDs if the technique spans multiple, or omit the line>]". The technique as documented in the material is discovery; the anti-analysis use is an application. I'll include T1497.003 as secondary — justified by note relations to T-020 and the KdDebuggerEnabled/timing field content. Actually, to be conservative and strictly material-driven... The note 1 tags include 'evasion'; would_relate_to T-004, T-020. I'll include it. It's a real ID.

Now — one more consideration on the member notes' would_relate_to T-004: the system prompt rule 9 says only reference cards from the would_relate_to list or explicitly discussed in related T-NNN cards provided. The member notes (part of the cluster spec input) explicitly list T-004 in would_relate_to. The consolidated spec list is ['T-023', 'T-016', 'T-020']. The "would_relate_to" in the spec header is the authoritative list, but the member notes' own would_relate_to fields are also part of the input and explicitly name T-004. I'll include T-004 as a fourth relation since note 1 explicitly justifies it ("distinct from PEB walking"). This is well-justified, not speculative.

Let me now write the card.

Mechanism steps (numbered, concrete):

1. Reference the page through the architecture constant 0x7FFE0000. The mapping exists before the first user-mode instruction runs (established during address-space creation), so no enumeration step is required. ntdll exports the same address as the `SharedUserData` symbol; operator code can hardcode the constant.
2. Read the version block: NtMajorVersion at 0x26C, NtMinorVersion at 0x270, NtBuildNumber at 0x260, NtProductType at 0x264, ProductTypeIsValid at 0x268 (ntddk.h layout, Windows 10/11). Substitutes for GetVersionEx / RtlGetVersion / GetProductInfo.
3. Read NtSystemRoot at 0x30 (WCHAR[260], NUL-terminated) — the absolute path of the Windows directory. Substitutes for GetWindowsDirectory / GetSystemWindowsDirectory.
4. Read processor and memory fields: ImageNumberLow/ImageNumberHigh (0x2C/0x2E, native machine type), NativeProcessorArchitecture (0x26A), ProcessorFeatures (0x274, 64-byte boolean array indexed by PF_* constants), NumberOfPhysicalPages (0x2E8, RAM sizing), LargePageMinimum (0x244), SuiteMask (0x2D0).
5. Read the timing triples: InterruptTime (0x8), SystemTime (0x14), TimeZoneBias (0x20), TickCount (0x320) — each a volatile KSYSTEM_TIME { LowPart, High1Time, High2Time }. On x64 an aligned 64-bit load is atomic; portable code applies the documented read protocol (High1Time → LowPart → High2Time, retry on High1Time != High2Time).
6. Derive the GetTickCount value locally: (TickCountLowDeprecated at 0x0 × TickCountMultiplier at 0x4) >> 24 — the identical arithmetic kernel32!GetTickCount performs against this page; GetSystemTimeAsFileTime likewise copies SystemTime (0x14) from the page. Direct reads therefore return values identical to the API family they replace.
7. Read system-state flags: KdDebuggerEnabled (0x2D4), SafeBootMode (0x2EC), ActiveConsoleId (0x2D8), NXSupportPolicy (0x2D5). KdDebuggerEnabled supplies a debugger check that does not traverse PEB or call CheckRemoteDebuggerPresent.
8. Consume the values in-place. No ntdll export is called, no syscall stub executes, no Win32 import is touched; the only machine instructions are loads against a read-only mapping.

OS Internals Context:

- Mapping mechanics: single physical page; kernel RW mapping at 0xFFFFF78000000000 (KI_USER_SHARED_DATA), user RO mapping at 0x7FFE0000 in every process. Same physical page system-wide → every process sees the same values. Mapped by the memory manager during system initialization and inherited into each address space.
- Update path: kernel timer interrupt processing (KeUpdateSystemTime/KeUpdateRunTime) rewrites InterruptTime, SystemTime, TickCount on each clock tick; static fields (version, system root, suite mask) written once at boot; KdDebuggerEnabled tracks KD state.
- Why invisible to userland instrumentation: inline hooks live in ntdll/kernelbase code; syscall-based monitoring (ETW-TI syscall events, kernel-mode syscall hooking, PatchGuard-sensitive SSDT approaches) observes ring transitions. A load from 0x7FFE0000 executes neither hooked code nor a syscall — it is a page-table-resolved memory access indistinguishable from reading a constant.
- Write protection: user-mode writes to the page raise STATUS_ACCESS_VIOLATION (page is RO in the user page tables); the kernel writes through its own RW mapping.
- WOW64: the page is mapped at the same VA for WOW64 processes; ImageNumberLow reports the native machine and NativeProcessorArchitecture distinguishes the native architecture, so WOW64 readers can detect the 32-bit-on-64-bit condition.
- Version mirroring: the version fields are the same globals RtlGetVersion reports; GetNativeSystemInfo's SYSTEM_INFO members (dwPageSize, dwNumberOfProcessors, processor architecture — the recon material's documented targets) are populated from the same kernel state the page publishes (the atlas notes characterize the page as carrying page-size, tick-count, processor, system-time, and NtSystemRoot values).
- QPC note: on Windows 10+, QueryPerformanceCounter completes in user mode in the common path, using QpcFrequency (0x300) published in this page — another instance of Windows itself using the page to avoid syscalls. (I'll include this as established.)
- The training material labels the method "Undocumented" (SEC670 slide) although Microsoft now ships the full structure definition in ntddk.h; the operational property the course emphasizes is the fixed VA and the breadth of fields ("holds large number of elements").

Key Implementation Details:
- No current implementation. The three grep-matched files don't implement: veh/def.rs (PEB/loader structs for VEH gate — no KUSER_SHARED_DATA), chain.rs (reads PEB via gs:[0x60] for own image base — PEB, not the shared page), ntfs_ea.rs (persistence, unrelated).
- Describe implementation sketch: repr(C) struct with explicit offsets/padding or a field-offset approach; `const SHARED_USER_DATA: usize = 0x7FFE00_00`; read_volatile for KSYSTEM_TIME fields; tear-check loop; helpers os_version(), nt_system_root(), tick_count64(), interrupt_time(), kd_debugger_enabled(); no imports → zero IAT entries (ties into T-021/IAT-camouflage posture... no, don't relate to T-021, not in list). Integration point: client_rust/src/sysinfo_collect.rs (T-023 HELLO message) and crowd anti-analysis modules (T-020) as a drop-in replacement for the API calls.

Why It Matters (2-4 sentences).

Detection Considerations:
- Telemetry sources: The material frames the primitive as bypassing userland hooks and syscall monitoring entirely. Consistent with that framing: a plain load instruction produces no ETW event, no Sysmon event, and triggers no kernel callback (process/thread/image/object callbacks all observe object operations, not memory reads). No ETW provider GUID applies; none is documented in the material.
- Bypass options: the technique is the bypass — it substitutes for GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo (the four APIs the recon material prescribes) plus GetVersionEx/GetTickCount-family calls. No additional hardening is documented.
- Residual artifacts: the material describes no residual artifacts; the read opens no handles, creates no files or registry keys, and emits no network traffic. Static artifacts (the 0x7FFE0000 immediate embedded in the binary) are not discussed in the material.

Hmm — "no kernel callback" — object callbacks ObRegisterCallbacks observe handle operations; memory reads are not observed. That's a factual statement of Windows internals, acceptable.

Related Techniques:
- T-023 Client Capabilities Suite — System Info Collection module gathers host data via API calls for the HELLO message; this primitive is the zero-API substitute for the OS/architecture/system-root fields.
- T-016 EDR Evasion Suite — T-016 removes visibility from hooked API paths (unhooking, StepOver, stack spoofing); T-027 removes the path itself for enumeration — no hook exists on a memory read, so no unhooking is needed.
- T-020 Anti-Analysis Suite — T-020's anti-VM/timing checks call timing and system APIs; KdDebuggerEnabled (0x2D4), InterruptTime/TickCount, and SafeBootMode from the page provide the same check inputs without API calls that sandboxes instrument.
- T-004 PEB Walker — the other fixed-structure, import-free enumeration primitive in the vault; T-004 walks loader structures (modules/exports), T-027 reads kernel-published runtime state. Member notes frame KUSER_SHARED_DATA as a distinct info source warranting separate treatment.

References:
- atlas-binary-analysis-part2.md (units 21–23; also units 16–20 for the GetVersionEx/GetNativeSystemInfo API family the page replaces)
- atlas-recon-part3.md (units 15–16 — OS Info bootcamp: GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo, BONUS: KUSER_SHARED_DATA)
- MITRE ATT&CK T1082 (System Information Discovery) — https://attack.mitre.org/techniques/T1082/
- LGTM notes
- Public references: Microsoft WDK ntddk.h — KUSER_SHARED_DATA structure definition (public since Windows 10 WDK). Windows Internals, 7th ed. — shared data page coverage. The atlas material names no specific public tooling for this primitive.

Source Reference: No current implementation. See atlas material and MITRE reference for public tooling.

Let me double-check offsets once more (x64, Win10/11 ntddk.h):
- 0x000 TickCountLowDeprecated ✓
- 0x004 TickCountMultiplier ✓
- 0x008 InterruptTime (12 bytes) ✓
- 0x014 SystemTime ✓
- 0x020 TimeZoneBias ✓
- 0x02C ImageNumberLow ✓
- 0x02E ImageNumberHigh ✓
- 0x030 NtSystemRoot[260] → ends at 0x30+0x208=0x238 ✓
- 0x238 MaxStackTraceDepth ✓
- 0x23C CryptoExponent ✓
- 0x240 TimeZoneId ✓
- 0x244 LargePageMinimum ✓
- 0x248 AitSamplingValue
- 0x24C AppCompatFlag
- 0x250 RNGSeedVersion (8 bytes)
- 0x258 GlobalValidationRunlevel
- 0x25C TimeZoneBiasStamp
- 0x260 NtBuildNumber ✓
- 0x264 NtProductType ✓
- 0x268 ProductTypeIsValid ✓
- 0x269 Reserved0[1]
- 0x26A NativeProcessorArchitecture ✓
- 0x26C NtMajorVersion ✓
- 0x270 NtMinorVersion ✓
- 0x274 ProcessorFeatures[64] → ends 0x2B4 ✓
- 0x2B4 Reserved1
- 0x2B8 Reserved3
- 0x2BC TimeSlip
- 0x2C0 AlternativeArchitecture
- 0x2C4 BootId (Win10+)... (AltArchitecturePad on some versions)
- 0x2C8 SystemExpirationDate (8 bytes)
- 0x2D0 SuiteMask ✓
- 0x2D4 KdDebuggerEnabled ✓
- 0x2D5 NXSupportPolicy ✓ (MitigationPolicies on newer)
- 0x2D8 ActiveConsoleId ✓
- 0x2DC DismountCount
- 0x2E0 ComPlusPackage
- 0x2E4 LastSystemRITEventTickCount
- 0x2E8 NumberOfPhysicalPages ✓
- 0x2EC SafeBootMode ✓
- 0x2ED VirtualizationFlags
- 0x2F0 SharedDataFlags
- 0x2F8 TestRetInstruction (8)
- 0x300 QpcFrequency (8) ✓ (Win10+)
- 0x308 SystemCall
- 0x320 TickCount (KSYSTEM_TIME) ✓
- 0x330 Cookie... hmm, on some builds Cookie is at 0x330. I won't cite Cookie.
- 0x338 ConsoleSessionForegroundProcessId

I'm confident in all offsets I plan to cite. On 32-bit (x86), layout is same through most of these (offsets identical for the fields listed — yes, the structure is layout-compatible for these fields on x86 too; KSYSTEM_TIME is 12 bytes on both; ULONGLONG alignment differs... RNGSeedVersion at 0x250 on x86? Alignment of ULONGLONG on x86 is 8 in this context since it's packed by the compiler with 8-byte alignment for ULONGLONG even on x86? Actually on x86, ULONGLONG default alignment is 8 (MSVC aligns 64-bit ints to 8 even on x86 in structs). Yes — MSVC uses 8-byte alignment for ULONGLONG on x86 as well. So offsets match. Good. I'll note offsets are for the ntddk.h layout current on Windows 10/11 and stable across x86/x64 for the cited fields.

GetTickCount formula: kernel32!GetTickCount = (ULONG)(((ULONG64)KUSER_SHARED_DATA.TickCountMultiplier * KUSER_SHARED_DATA.TickCountLowDeprecated) >> 24). Established RE fact. ✓ GetSystemTimeAsFileTime copies SystemTime with the tear-check. ✓ GetTickCount64 on Win10: reads TickCount KSYSTEM_TIME at 0x320 and computes... GetTickCount64 ≈ (TickCount * TickCountMultiplier... something) — hmm, actually GetTickCount64 on modern Windows: ((TickCountQuad-related) — it computes ((UInt64)TickCount * TickCountMultiplier) >> 24? I recall GetTickCount64 = ((TickCount * Multiplier) >> 24) using the 0x320 TickCount... Not 100%. I'll avoid specifying GetTickCount64's formula and just cite GetTickCount's, which I'm sure of.

QpcFrequency at 0x300: established (Win10 1607+). QPC user-mode path: on systems where the TSC is invariant, QPC computes from rdtsc * QpcFrequency-ish without syscall. I'll phrase carefully: "on Windows 10 and later, QueryPerformanceCounter can complete in user mode using QpcFrequency (offset 0x300) published in this page" — this is well-established RE. Keep it one sentence.

Kernel VA: 0xFFFFF78000000000 — established (KI_USER_SHARED_DATA). ✓

Also mention: page also contains Cookie (encode pointer) used by ntdll pointer-encoding — skip.

The material says "Same VA in almost every process" — I'll quote/paraphrase that in Mechanism step 1.

Now — one more check on the "Key Implementation Details" no-implementation template sentence: `**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in <source language/tool>.` → source language: C (SEC670 examples are C). I'll say "in C". Then one paragraph describing the implementation sketch. I must also verify the matched files and state the verification: I'll add a sentence noting the grep-matched files (veh/def.rs, chain.rs, ntfs_ea.rs) were reviewed and do not implement direct reads of 0x7FFE0000. Good — that demonstrates verification.

Length check: I'll write it out and estimate. Should land ~1300-1500 words. Fine.

One more style check: avoid "notable", avoid "it is important to note". Avoid first person. Avoid rhetorical questions. 

Title: `# KUSER_SHARED_DATA Direct-Read System Information — Hook-Free Enumeration From a Fixed Kernel-Mapped Page`

Summary first sentence standalone: "KUSER_SHARED_DATA is a kernel-maintained read-only page mapped at the fixed virtual address 0x7FFE0000 into every Windows user-mode process, and reading it directly yields OS version, system root path, tick counts, and system time without invoking any API or syscall."

Then 3-4 more sentences.

Let me write the final card now.

Frontmatter:

```yaml
---
id: T-027
name: KUSER_SHARED_DATA Direct-Read System Information
category: discovery
tier: A
crate: none
source_file: none
mitre: T1082
mitre_secondary: [T1497.003]
tags: [kuser-shared-data, fixed-va, direct-read, sysinfo-discovery, timing-source, hook-bypass, syscall-free, kernel-mapped-page]
origin: atlas-synthesis
member_notes: [lgtm:kuser-shared-data-info-source, lgtm:kuser-shared-data-sysinfo-primitive]
---
```

Hmm, do I keep mitre_secondary? The card body does discuss KdDebuggerEnabled + timing as anti-analysis inputs (traceable to note 1's would_relate_to T-020 and the established field semantics). T1497.003 is Time Based Evasion. I think T1497.001 (System Checks) might fit better for KdDebuggerEnabled... but debugger checks are T1622 (Debugger Evasion). The time-based checks via TickCount → T1497.003. I'll keep [T1497.003]. Actually — to be maximally defensible, maybe just omit. The core technique is discovery. But the notes explicitly frame it with 'evasion'/'anti-edr' tags and T-020 relation... I'll keep T1497.003 as secondary since the timing-field read for sandbox timing checks is a documented use in the card. Fine.

Word-count: I'll count roughly as I write. Aim 1400.

Also — format of Related Techniques per template: "- **T-NNN Name** — <one-line explanation>". 

References section:
- Atlas material: atlas-binary-analysis-part2.md, atlas-recon-part3.md
- MITRE ATT&CK: T1082 — https://attack.mitre.org/techniques/T1082/
- LGTM notes: lgtm:kuser-shared-data-info-source, lgtm:kuser-shared-data-sysinfo-primitive
- Public references: Microsoft WDK ntddk.h KUSER_SHARED_DATA definition; Windows Internals 7th ed. (shared data page). The atlas material names no tool authors or blogs for this primitive.

Source Reference: "No current implementation. See atlas material and MITRE reference for public tooling."

Writing now. I need to make sure the "Mechanism" numbered steps are concrete and not padded — 8 steps is right.

Also mention in OS Internals: the SEC670 slide deck presents it under the heading "Undocumented Method" and quizzes the VA (units 21–23); unit 15/16 of recon material frames it as a BONUS sysinfo target alongside the four documented APIs.

In OS Internals I should also cover: the page is one of a small set of fixed user-mode mappings; reading requires no privileges; works from any integrity level including low-IL/sandboxed contexts (AppContainer can read it too — the mapping is present in all processes). That's a useful operator fact: no privilege requirement.

Also kernel/user boundary: values are a snapshot — the kernel updates asynchronously; readers must tolerate torn reads on 32-bit (hence KSYSTEM_TIME protocol) and must not cache time values.

Version differences: field offsets stable across Win10/11 for cited fields; structure grows at the tail across releases, never reorders — established characteristic (Microsoft appends). I'll state that offsets for the cited fields are stable from Windows 10 through Windows 11 per the ntddk.h layout.

Okay. Writing final output. Body word count — let me make sure each section is substantive. I'll draft carefully.