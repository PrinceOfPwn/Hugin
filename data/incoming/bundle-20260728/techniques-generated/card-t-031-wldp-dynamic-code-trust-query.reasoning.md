Let me analyze the inputs carefully.

The cluster spec assigns:
- T-031
- Canonical name: WldpQueryDynamicCodeTrust: Device Guard Dynamic Code Trust Check
- Category: edr-evasion
- Tier: A
- would_relate_to: T-016, T-013, T-006
- member_notes: ['lgtm:wldp-dynamic-code-trust-query', 'lgtm:wldp-dynamic-code-trust-edr-mechanism']

Member notes:
1. `lgtm:wldp-dynamic-code-trust-query` from atlas-exploit-dev-part16, unit 13 — WldpQueryDynamicCodeTrust as a pre-flight check for ACG/WDAC before committing to allocation.
2. `lgtm:wldp-dynamic-code-trust-edr-mechanism` from atlas-exploit-dev-part6, units 19, 20 — WldpQueryDynamicCodeTrust as documented EDR mechanism; the mutual-exclusion _When_ contract on fileHandle vs baseImage; explains why MEM_IMAGE-backed execution (T-006) is operationally necessary under strict WDAC.

Source files provided:
- runner.rs (core) — doesn't implement WldpQueryDynamicCodeTrust. No match.
- chain.rs (crowd) — doesn't implement WldpQueryDynamicCodeTrust. No match.
- edo_dead_drop.rs — irrelevant. No match.

So: no current implementation in source. `crate: none`, `source_file: none`.

Atlas material:
- part16 unit 13: WldpQueryDynamicCodeTrust API — grabs a value to figure out if the specified in-memory dynamic code is trusted by Device Guard policy. _When_() expressions: if fileHandle is not NULL, then baseImage better be NULL, and vice versa. First _When_ indicates fileHandle optional when baseImage is not NULL; second indicates fileHandle read-only and required when baseImage is NULL (truncated).
- part6 units 19-20: same content, unit 19 is the slide visual showing C code for QueryDynamicCodeTrust with `HANDLE fileHandle` visible; unit 20 has the same text as part16 unit 13.

So the material gives me:
- API name: WldpQueryDynamicCodeTrust
- Purpose: query whether in-memory dynamic code is trusted by Device Guard policy
- Parameters seen: fileHandle (HANDLE), baseImage, imageSize
- Mutual exclusion contract: fileHandle XOR baseImage — exactly one must be non-NULL
- SAL annotations with _When_ expressions

What do I know from established Windows documentation (which I can use per rule 4 — "well-established Windows internals documentation")?

WldpQueryDynamicCodeTrust is exported by wldp.dll (Windows Lockdown Policy). Signature (documented in wldp.h, Windows 10 SDK):

```c
HRESULT WINAPI WldpQueryDynamicCodeTrust(
    _When_(baseImage == NULL, _In_) HANDLE fileHandle,
    _When_(fileHandle == NULL, _In_reads_bytes_(imageSize)) PVOID baseImage,
    _In_ ULONG imageSize
);
```

Returns S_OK if trusted. It checks the code integrity policy (WDAC) via the CI (Code Integrity) subsystem — ci.dll in kernel. The trust decision comes from the active WDAC policy (SiPolicy.p7b in EFI System Partition, or the policy at C:\Windows\System32\CodeIntegrity\). Device Guard includes both WDAC (Windows Defender Application Control) and HVCI (Hypervisor-protected Code Integrity).

The two modes:
- fileHandle mode: pass an open handle to a file on disk; the API evaluates the file's signature against the policy.
- baseImage mode: pass an in-memory buffer (the image bytes) plus imageSize; the API evaluates the in-memory image. Note: for in-memory code, the policy check happens against the content — if the buffer is not a properly signed PE, it fails under a strict WDAC policy that doesn't allow unsigned code.

The dynamic code trust check corresponds to what happens when a process with dynamic code restrictions (ACG — Arbitrary Code Guard, SetProcessMitigationPolicy with ProhibitDynamicCode) or when a WDAC policy with the "Dynamic Code Security" / UMCI (user-mode code integrity) enforcement encounters code that is not backed by a properly signed image.

Operational context per the notes:
- Note 1: pre-flight check before executing injected code/hollowed modules/manually-loaded binaries. Branch on policy state without triggering a block. Cheaper than a failed NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE) under ACG. Actually under ACG, NtAllocateVirtualMemory with PAGE_EXECUTE_* fails with STATUS_DYNAMIC_CODE_BLOCKED (0xC0000604). I can state that ACG blocks dynamic code allocation; STATUS_DYNAMIC_CODE_BLOCKED is the status code — that's established NT status documentation. I should be careful: the material doesn't name the status code. But it's well-established (winnt.h / ntstatus.h: STATUS_DYNAMIC_CODE_BLOCKED 0xC0000604). Rule 4 allows well-established Windows internals documentation. I'll include it with care.

- Note 2: documents it as the named defensive mechanism (kernel-side code-integrity decision API) that MEM_IMAGE-backed stubs (T-006) and module overloading (T-013) are designed to satisfy. Under strict WDAC, code must come from a signed image — hence SEC_IMAGE-backed execution is operationally necessary.

Related cards:
- T-006 Phantom Stubs: MEM_IMAGE-backed syscall stubs via SEC_IMAGE mapping of version.dll — satisfies the "signed image backing" requirement.
- T-013 Remaining injection: module stomping, module overloading — shellcode runs from MEM_IMAGE backed by Microsoft-signed DLLs (chakra.dll, xpsservices.dll). Vectored overloading similarly.
- T-016 EDR evasion suite: ACG policy (ProhibitDynamicCode flag via NtSetInformationProcess class 52 — that's ProcessMitigationPolicy; actually class 52 in the T-016 card is ProcessSignaturePolicy... let me check: T-016 says "ProcessSignaturePolicy via NtSetInformationProcess (class 52). MicrosoftSignedOnly flag → EDR cannot inject its DLL. Also supports ACG (Arbitrary Code Guard): ProhibitDynamicCode flag"). So T-016 applies ACG as an evasion (to block EDR's own injected dynamic code), while T-031 is the query side for an implant operating in an environment where ACG/WDAC may be applied against it.

MITRE mapping: what's the best-fit ATT&CK ID? Options:
- T1620 Reflective Code Loading — no, this is a query.
- T1497 Virtualization/Sandbox Evasion — no.
- T1518.001 Security Software Discovery — plausible: discovering security policy state.
- T1622 Debugger Evasion — no.
- T1562.001 Impair Defenses: Disable or Modify Tools — it's not impairing; it's querying.
- T1033? No.

The technique is a policy/environment query enabling adaptive execution — closest is T1518.001 (Security Software Discovery) since Device Guard/WDAC state is a security control. ATT&CK does list discovering whether specific security mechanisms are enabled under T1518.001. Alternatively T1057? No. Some map ACG/WDAC checks to T1518.001. I'll use T1518.001 as primary. Secondary: T1562.001 (Impair Defenses: Disable or Modify Tools) — since the broader context is bypassing WDAC/ACG; and possibly T1620 (Reflective Code Loading) because the technique informs reflective loading decisions. I'll include mitre_secondary: [T1562.001] — adaptive tradecraft to impair/evade defenses. Hmm, actually rule says pick the single best-fit for `mitre`, and secondary if it spans multiple. T1518.001 is the best fit for the query itself. The secondary could be T1562.001 (evasion context). I could also consider T1055 (process injection context) but T1518.001 + T1562.001 seems right.

Category: edr-evasion per spec. Tier: A.

Frontmatter:
```yaml
---
id: T-031
name: WldpQueryDynamicCodeTrust Dynamic Code Trust Check
category: edr-evasion
tier: A
crate: none
source_file: none
mitre: T1518.001
mitre_secondary: [T1562.001]
tags: [wdac, acg, device-guard, dynamic-code, policy-query, code-integrity, wldp, pre-flight, adaptive-execution]
origin: atlas-synthesis
member_notes: ['lgtm:wldp-dynamic-code-trust-query', 'lgtm:wldp-dynamic-code-trust-edr-mechanism']
---
```

Name should be 4-8 words: "WldpQueryDynamicCodeTrust Dynamic Code Trust Check" = 5 words. Good.

Now the body.

# WldpQueryDynamicCodeTrust — Pre-Flight Device Guard Trust Query for Dynamic Code

## Summary
3-5 sentences. First sentence standalone.

WldpQueryDynamicCodeTrust is a user-mode API exported by wldp.dll that returns the active Device Guard/WDAC code-integrity policy's trust decision for a candidate piece of dynamic code without executing it. Implants call it as a pre-flight check before allocating executable memory or reflectively loading a module, branching to MEM_IMAGE-backed execution paths when the policy would block unsigned in-memory code. The query accepts either a file handle or an in-memory image buffer (mutually exclusive per the SAL _When_ contract) and returns the policy verdict as an HRESULT. Primary detection surface: the call itself is observable (API monitoring, ETW), but it generates far less telemetry than a failed NtAllocateVirtualMemory under ACG.

## Mechanism
Numbered steps:
1. Resolve WldpQueryDynamicCodeTrust from wldp.dll (load library or GetProcAddress).
2. Choose query mode — fileHandle (on-disk candidate) XOR baseImage (in-memory bytes + imageSize). The mutual exclusion: if fileHandle non-NULL, baseImage must be NULL and vice versa.
3. Prepare the candidate: for in-memory, a pointer to the would-be image/shellcode buffer and its size.
4. Call the API; it forwards to the code integrity subsystem for policy evaluation against the active WDAC policy.
5. Interpret HRESULT: S_OK = trusted by policy; failure = code would be blocked.
6. Branch: if blocked, select MEM_IMAGE-backed techniques (T-006 phantom stubs, T-013 module overloading) rather than raw RWX allocation.

## OS Internals Context
- wldp.dll (Windows Lockdown Policy) — user-mode front end for the code integrity policy engine; same DLL hosts WldpIsDynamicCodePolicyEnabled (hmm — careful. WldpIsDynamicCodePolicyEnabled exists in wldp.h too, but is it in the material? No. I should only mention APIs I'm confident exist. WldpIsDynamicCodePolicyEnabled is real and documented in wldp.h. But rule: material is authority; well-established docs allowed. I can mention it briefly but must be accurate. Actually to be safe, keep focus on WldpQueryDynamicCodeTrust; mentioning related exports like WldpIsDynamicCodePolicyEnabled is well-established (it's in the Windows SDK wldp.h). I'll mention it briefly.)
- Code Integrity: kernel side is ci.dll; policy file SiPolicy.p7b. The trust evaluation for dynamic/in-memory code is what ACG (ProhibitDynamicCode mitigation) and WDAC UMCI enforce. Under ACG, NtAllocateVirtualMemory requesting execute protection for non-image-backed memory fails with STATUS_DYNAMIC_CODE_BLOCKED (0xC0000604), and NtProtectVirtualMemory transitions to execute are blocked; only MEM_IMAGE pages can be executable.
- WDAC with user-mode code integrity (UMCI): unsigned or non-policy-compliant binaries/DLLs can't load; dynamic code must originate from signed images — hence SEC_IMAGE-backed stubs.
- The _When_ contract: from material — fileHandle optional when baseImage != NULL; fileHandle read-only and required when baseImage == NULL; symmetric for baseImage.
- Distinction between the query (no state change, no allocation) and the enforcement point (memory manager + CI at allocation/protect time).
- HVCI note: under HVCI, the kernel-mode CI runs in VTL1; user query still goes through the same policy decision. Careful — material doesn't discuss HVCI. Device Guard = WDAC + HVCI is well-established. I can mention Device Guard branding covers WDAC and that the query exposes the policy decision; keep HVCI mention minimal and accurate.

## Key Implementation Details
No current implementation. State that. Then describe what an implementation would look like: resolve wldp.dll via PEB walker / LoadLibraryW, GetProcAddress, call with baseImage pointing at candidate payload bytes + size, branch on HRESULT; integrate into chain dispatch (e.g., InjectionMethod selection in chain.rs-style FSM) so Auto mode prefers phantom stubs/module overloading when untrusted. One paragraph.

Also note: the provided runner.rs/chain.rs/edo_dead_drop.rs do not implement this technique — I verified. I won't list them as implementing; I'll state no current implementation. Should I explicitly say the grep-matched files don't implement it? The template says write the standard sentence. I can add that the matched files (runner.rs, chain.rs, edo_dead_drop.rs) were reviewed and do not call WldpQueryDynamicCodeTrust. That's accurate verification reporting.

## Why It Matters
The vault documents ACG/WDAC as something to apply (T-016 Block-DLL/ACG policy) and MEM_IMAGE-backed execution as a workaround (T-006, T-013), but nothing documents the policy-introspection primitive that tells the implant which world it's in. This is the branch condition: it converts an environment probe into a deterministic technique-selection decision without paying the telemetry cost of a blocked allocation. Also names the defensive mechanism those techniques are designed to satisfy — gives operators the reference point for why MEM_IMAGE backing is operationally necessary rather than stylistic.

## Detection Considerations
Material: "The query itself is observable but is far cheaper than a failed NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE) under ACG." So:
- Telemetry: API monitoring/ETW on wldp.dll call (provider GUID not documented in material); EDR usermode hooks on wldp.dll exports possible.
- Residual artifacts: loading wldp.dll into a process that has no legitimate reason (module load telemetry, Sysmon image load Event ID 7 — hmm, Sysmon event 7 is image load; that's well-established. But rule says don't invent Sysmon event IDs. Sysmon Event ID 7 = Image Loaded is well-established documentation. I'll say Sysmon image-load events without pinning the ID, or state ID 7 carefully. Rule 4 says don't fabricate Sysmon event IDs — Sysmon 7 is genuinely Image Loaded; I'm confident. I'll include it.)
- Bypass: material says the query is the cheap alternative; avoid repeated probing; resolving via direct calls. Keep to material: "the query itself is observable but far cheaper than a failed allocation."

## Related Techniques
- T-016 EDR Evasion Suite — documents ACG/CIG policy application (Block-DLL, ProhibitDynamicCode via NtSetInformationProcess); T-031 is the query-side complement that reads the same policy state the T-016 mitigations write/enforce.
- T-006 Phantom Stubs — MEM_IMAGE-backed stubs exist precisely because dynamic-code trust policy blocks non-image executable memory; T-031 is the probe that tells the operator whether that backing is required.
- T-013 Remaining Injection Methods — module stomping/overloading run shellcode from MEM_IMAGE backed by Microsoft-signed DLLs; the trust query determines whether these image-backed paths are mandatory on the target.

## References
- Atlas material: atlas-exploit-dev-part16.md (unit 13), atlas-exploit-dev-part6.md (units 19-20)
- MITRE: T1518.001 https://attack.mitre.org/techniques/T1518/001/
- LGTM notes: lgtm:wldp-dynamic-code-trust-query, lgtm:wldp-dynamic-code-trust-edr-mechanism
- Public references: MSDN wldp.h documentation (WldpQueryDynamicCodeTrust). The material is SANS SEC670 Book 1. I can cite "SANS SEC670 Red Teaming Tools Book 1 — SAL annotations module" as the atlas source. Public reference: Microsoft wldp.h header documentation.

## Source Reference
No current implementation. See atlas material and MITRE reference for public tooling.

Length: target 1200-1800 words. Let me write carefully, no banned words. Banned: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable. Banned phrases: "but wait", "interestingly", "worth noting", "the key insight", "it is important to note", "as you can see", "essentially", "at its core". Avoid "It's a pretty cool function!" (that's in the material — I won't quote it; it's fanboy-ish).

Careful about STATUS_DYNAMIC_CODE_BLOCKED value 0xC0000604 — that is well-established. Under ACG, allocation of executable memory fails; also note ACG is per-process mitigation set via SetProcessMitigationPolicy(ProcessDynamicCodePolicy) / NtSetInformationProcess class 52 (ProcessMitigationPolicy). T-016 card says class 52 — I'll reference the T-016 card for that instead of asserting a class number myself. Actually the T-016 card says "ProcessSignaturePolicy via NtSetInformationProcess (class 52)" — I'll reference T-016's description without re-asserting class numbers.

WldpQueryDynamicCodeTrust signature from wldp.h:

```
HRESULT
WldpQueryDynamicCodeTrust(
    _When_(baseImage == NULL, _In_) HANDLE fileHandle,
    _When_(fileHandle == NULL, _In_reads_bytes_(imageSize)) PVOID baseImage,
    _In_ ULONG imageSize
);
```

I'm confident in this signature. The material confirms: fileHandle optional when baseImage non-NULL; required/read-only when baseImage NULL; mutual exclusion. And parameters fileHandle, baseImage, imageSize named in the cluster description and note 2 ("fileHandle vs. baseImage"). imageSize appears in the consolidated description ("imageSize" mentioned in note 1? Let me check: note 1 mentions fileHandle, baseImage... The consolidated description doesn't mention imageSize; the cluster spec Note 2 says "mutual-exclusion _When_ contract on fileHandle vs. baseImage". atlas unit 13 (part16) says "parameters like fileHandle, baseImage, and imageSize." Yes — part16 unit 13: "define conditional requirements for parameters like fileHandle, baseImage, and imageSize." Good, imageSize is grounded in material.

Return value: HRESULT; S_OK when trusted. The material says "grab a value to figure out if the specified in-memory dynamic code is trusted by Device Guard policy." The exact success semantics (S_OK = trusted) is documented MSDN behavior. I'm confident.

Where does the evaluation happen? WldpQueryDynamicCodeTrust in wldp.dll calls into the code integrity library; for in-memory images it validates the signature against the active CI policy. Device Guard policy stored in SiPolicy.p7b (well-established: C:\Windows\System32\CodeIntegrity\SiPolicy.p7b for single-policy format; EFI System Partition \EFI\Microsoft\Boot\SiPolicy.p7b historically). I'll mention SiPolicy.p7b as the policy blob; keep it accurate: WDAC policies are binary (.p7b) deployed to CodeIntegrity folder. Good.

Also relevant: under WDAC with UMCI, even in-memory .NET / dynamic code generation is constrained; .NET uses WldpQueryDynamicCodeTrust internally? Actually — well-established: the CLR calls WldpQueryDynamicCodeTrust to decide whether JIT-generated code is permitted under WDAC (this is documented behavior; WDAC supports managed code via this API; WldpQueryDynamicCodeTrust was introduced for "dynamic code" scenarios like .NET JIT and script engines). I recall Microsoft docs: "WldpQueryDynamicCodeTrust function (wldp.h) — Queries if the specified in-memory dynamic code is trusted by the Device Guard policy." And .NET/CLR uses it. I'm fairly confident the CLR uses it for dynamic methods. I'll state that script engines/JITs are the legitimate consumers, which is why the API exists — that's accurate framing and documented in MSDN remarks (the API exists so applications that generate dynamic code can check trust). Keep it brief.

Mechanism steps (operator usage):
1. Resolve wldp.dll and the export.
2. Decide query form: (a) fileHandle — open handle to a file containing the candidate image (used when the code exists on disk), or (b) baseImage+imageSize — pointer to the in-memory bytes the implant intends to execute.
3. Call; API evaluates against the Device Guard/WDAC policy. For baseImage mode, the buffer is treated as an image and its signature/policy compliance is evaluated as CI would at load time.
4. HRESULT verdict: S_OK trusted; otherwise untrusted → would be blocked.
5. Branch technique selection: raw RWX/RX private-memory execution only when trusted or when no policy; fall back to SEC_IMAGE-backed execution (T-006, T-013 module overloading) when untrusted.
6. Optionally re-query after environmental changes? Don't add suggestions — no variant ideas. Keep mechanism to what the technique IS. The mechanism of the technique = the pre-flight query and branch. Fine.

Also mention the "without triggering execution" aspect: no allocation, no protection change, no thread creation — the decision comes back before any enforceable action occurs. That's in the consolidated description ("Returns policy decision without triggering execution").

Word budget: Summary ~130, Mechanism ~250, OS Internals ~450, Key Impl ~200, Why ~100, Detection ~150, Related ~100, References ~60, Source ref ~30 → ~1470. Good.

Careful with rule: "Do not invent detections" — if material doesn't cover detection, write the single line. But material DOES cover detection minimally ("The query itself is observable but is far cheaper than a failed NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE) under ACG"). So I build the section around that, adding telemetry-source framing carefully: wldp.dll module load (Sysmon ID 7 image load — established), ETW/API monitoring of the export — I'll phrase as "API monitoring and ETW-based API tracing can observe the call; GUID not documented in material." Bypass options: material says use the query instead of triggering the block — the query is itself the reduced-observability option. Residual artifacts: wldp.dll loaded in the process module list (if not already loaded — on Windows 10+ wldp.dll is commonly loaded in many processes? Actually wldp.dll is loaded by apps that use Device Guard APIs; it may already be present. I'll say: if the DLL was not previously mapped, the load leaves a module entry in the PEB loader lists — that's factual).

Hmm, careful about asserting Sysmon Event ID 7: I'm confident Sysmon event 7 is "Image loaded". Well-established. Include.

ETW for WLDP: there is a Microsoft-Windows-WLDP ETW provider (Microsoft-Windows-WLDP/Debug and Operational channels exist in Event Viewer under Applications and Services Logs → Microsoft → Windows → WLDP). This is well-established. GUID not memorized — write "GUID not documented in material."

Frontmatter tags: 5-10 kebab-case: [wdac, device-guard, dynamic-code-trust, policy-query, acg, code-integrity, pre-flight-check, adaptive-execution, wldp]. That's 9. Good.

mitre_secondary: [T1562.001] — Impair Defenses: Disable or Modify Tools? Hmm. T1562.001 is about impairing defensive tools. The query enables evasion of defenses. Actually better secondary might be T1055 (process injection) since the check gates injection technique selection, or T1620 Reflective Code Loading. But the notes frame it as EDR-mechanism/policy discovery. T1518.001 primary is solid. Secondary T1562.001 is defensible since WDAC/ACG bypass planning falls under impair defenses... Alternatively omit secondary. The cluster description: "Implants use this as pre-flight check before executing injected code... enables adaptive technique selection." I'll use mitre_secondary: [T1562.001] with reasoning that the broader behavior is defense evasion. Hmm, but is that the closest? ATT&CK T1562.001 examples include disabling/blocking security tooling; probing policy to evade could fit "Impair Defenses" loosely. Another candidate: T1082 System Information Discovery? No, it's security software specifically. T1518.001 covers "Security Software Discovery" including checks for specific protections (e.g., "checks for the presence of application control/whitelisting"). I'm confident T1518.001 is right. For secondary I'll include T1055 since the check exists to select injection paths — actually the spec says secondary only if the technique spans multiple. The query + adaptive injection spans discovery and injection. I'll keep secondary minimal: [T1562.001]. Hmm... Let me reconsider: which is more defensible? The notes' tags: 'wdac','acg','dynamic-code','policy-query','pre-flight' and 'edr-mechanism'. The primary behavior = discovery of security policy → T1518.001. I'll omit secondary to avoid overreach? The template allows omitting. But spanning: the technique's purpose is defense evasion planning. I think T1562.001 is acceptable as secondary. Actually, "Impair Defenses" is for actions that weaken/disable defenses — a passive query doesn't impair. Better secondary: none, or T1620 (Reflective Code Loading) since it's the pre-flight for reflective loads. Reflective code loading is the execution technique, not the query. I'll omit mitre_secondary. Hmm — but wait: adaptive selection of MEM_IMAGE-backed injection to evade WDAC could be T1218? No. Keep it clean: only primary T1518.001. Decision: omit mitre_secondary.

Now double-check frontmatter name length: "WldpQueryDynamicCodeTrust Dynamic Code Trust Check" — 5 words. Good.

h1: `# WldpQueryDynamicCodeTrust — Pre-Flight Device Guard Trust Query for Dynamic Code`

Write the card now. Ensure no banned words. Check "robust" — avoid. "clean" — avoid (careful: "clean stubs" appears in other cards but I won't use). "notable" avoid. Don't use "essentially", "worth noting", "interestingly".

OS Internals Context content plan:
- wldp.dll = Windows Lockdown Policy DLL, user-mode stub for the Device Guard code-integrity policy engine; exports WldpQueryDynamicCodeTrust (and related WLDP functions).
- Two Device Guard pillars: WDAC (configurable code integrity policy) and HVCI (memory integrity). The query surfaces the WDAC/CI decision; HVCI relevance is that kernel CI policy evaluation is enforced even for user-mode dynamic code. Keep brief.
- Policy blob: SiPolicy.p7b under C:\Windows\System32\CodeIntegrity (and multiple-policy format GUID-named .p7b/.cip files). The active policy determines UMCI enforcement.
- Enforcement points the query fronts: ACG per-process mitigation (ProcessDynamicCodePolicy / ProhibitDynamicCode) — when set, the memory manager rejects executable protections on non-image-backed pages: NtAllocateVirtualMemory with PAGE_EXECUTE* fails STATUS_DYNAMIC_CODE_BLOCKED (0xC0000604); NtProtectVirtualMemory to execute on MEM_PRIVATE likewise blocked. Only MEM_IMAGE (SEC_IMAGE-backed) pages may hold executable code.
- WDAC UMCI: unsigned in-memory images fail trust; the in-memory buffer passed via baseImage is evaluated as CI would evaluate a file image — signature and policy rule evaluation over the buffer content.
- The _When_ contract details from material: fileHandle optional when baseImage != NULL; required + read-only (_In_) when baseImage == NULL; symmetric. Exactly one of the two identifies the code to evaluate: a file object (kernel can page it, has an identity/signature on disk) vs. raw bytes with explicit size.
- Legitimate consumers: runtimes that generate code at runtime (JIT/script engines) use the query to decide whether generated code may execute — this is why the API exists in user mode at all, and why calling it is not inherently anomalous. Careful: is that documented? MSDN remarks for WldpQueryDynamicCodeTrust... The function's documented purpose: "Queries if the specified in-memory dynamic code is trusted by the Device Guard policy. This function is used by applications that generate dynamic code (such as .NET) to determine whether the code is permitted to run under the active policy." I recall this is roughly accurate — .NET uses it. I'll phrase: "documented consumers are runtimes that emit code at execution time; the API exists so those runtimes can conform to policy rather than be terminated by it." Reasonable.
- Kernel boundary: the call itself stays in user mode as far as the caller is concerned (wldp.dll internally consults CI); no memory is allocated, no protection flipped, no thread created — the decision returns before any enforceable action. The enforcement happens later at MM/CI when the implant actually allocates/maps executable memory. Material says "Returns policy decision without triggering execution."

Careful about claiming wldp.dll calls ci.dll directly via syscall — I shouldn't assert the internal call path (whether it RPCs or syscalls). Say: "wldp.dll is the user-mode front end; the policy evaluation is performed by the code-integrity subsystem (CI) using the active WDAC policy." Safe.

Mechanism section steps:
1. Load/resolve wldp.dll + WldpQueryDynamicCodeTrust export (dynamic resolution to keep IAT clean — careful "clean" banned word; use "to avoid a static import entry").
2. Select query form per mutual exclusion: fileHandle for an on-disk candidate, or baseImage+imageSize for the in-memory buffer the implant intends to execute.
3. For in-memory pre-flight: pass pointer to the would-be payload image bytes and imageSize; fileHandle NULL.
4. API evaluates the buffer against the active Device Guard/WDAC code-integrity policy and returns the verdict as HRESULT — S_OK when trusted.
5. No state changes occur: no allocation, protection change, section creation, or thread — the verdict is returned before any enforceable action (per material: "returns policy decision without triggering execution").
6. Branch on verdict: trusted/absent policy → proceed with direct execution path; untrusted → select MEM_IMAGE-backed execution (SEC_IMAGE section from a signed DLL — T-006 phantom stubs, T-013 module overloading) instead of private-memory RWX, avoiding a blocked NtAllocateVirtualMemory.

Key Implementation Details:
Standard line + verification note + one-paragraph description of what an implementation would look like in crowd: a small module resolving wldp.dll via the existing PEB walker/DJB2 resolution (T-004 style per resolve.rs), calling baseImage mode against the decrypted payload buffer pre-FASE 4, and feeding the verdict into InjectionMethod Auto selection (phantom/overload when untrusted). Mention the reviewed files (runner.rs, chain.rs, edo_dead_drop.rs) contain no reference to WldpQueryDynamicCodeTrust or wldp.dll.

Detection Considerations:
- Telemetry: the call observable via API monitoring/ETW tracing of wldp.dll export; Microsoft-Windows-WLDP event channel exists (GUID not documented in material); Sysmon Event ID 7 (image load) records wldp.dll mapping if not already loaded; EDR user-mode hooks may interpose the export.
- Bypass options per material: the query is the low-cost alternative — "far cheaper than a failed NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE) under ACG"; single query vs. repeated trial allocations.
- Residual artifacts: wldp.dll entry in PEB loader lists if newly mapped; no memory allocations, threads, handles (in baseImage mode) left behind.

Also should I mention that in fileHandle mode a handle to the candidate file must be opened (file access telemetry)? That's accurate and derived from the contract. Brief.

Related Techniques: 3 entries as planned.

References:
- atlas-exploit-dev-part16.md (unit 13); atlas-exploit-dev-part6.md (units 19-20)
- MITRE T1518.001 URL
- LGTM notes both
- Public: Microsoft wldp.h / WldpQueryDynamicCodeTrust documentation (MSDN). SANS SEC670 Book 1 is the atlas origin — that's the atlas material line. Public references optional: "Microsoft Learn — WldpQueryDynamicCodeTrust (wldp.h)" is named in material? The material is SANS slides describing the API. The API is documented publicly by Microsoft; citing Microsoft documentation is safe.

Source Reference: no current implementation sentence.

Word count check at end. Let me draft.

Draft:

---

```yaml
---
id: T-031
name: WldpQueryDynamicCodeTrust Dynamic Code Trust Check
category: edr-evasion
tier: A
crate: none
source_file: none
mitre: T1518.001
tags: [wdac, device-guard, dynamic-code-trust, policy-query, acg, code-integrity, pre-flight-check, adaptive-execution, wldp]
origin: atlas-synthesis
member_notes: [lgtm:wldp-dynamic-code-trust-query, lgtm:wldp-dynamic-code-trust-edr-mechanism]
---
```

# WldpQueryDynamicCodeTrust — Pre-Flight Device Guard Trust Query for Dynamic Code

## Summary

WldpQueryDynamicCodeTrust is a user-mode API exported by wldp.dll that returns the active Device Guard / WDAC code-integrity policy's trust verdict for a candidate piece of dynamic code without executing it. The API accepts either a handle to a file containing the candidate image or a pointer to in-memory bytes plus a size — the two are mutually exclusive — and answers whether that code would be permitted to run under the current policy. Implants use it as a pre-flight check before allocating executable memory or reflectively loading a module, converting an unknown environment into a deterministic branch: raw private-memory execution when the policy permits it, MEM_IMAGE-backed execution when it does not. The primary detection surface is the call itself (API monitoring, module-load telemetry), which the training material characterizes as far cheaper in observability than a failed NtAllocateVirtualMemory under Arbitrary Code Guard.

## Mechanism

1. Resolve wldp.dll and the WldpQueryDynamicCodeTrust export at runtime. Dynamic resolution avoids a static import-table entry advertising Device Guard introspection.
2. Select the query form. The SAL contract enforces mutual exclusion: if fileHandle is non-NULL then baseImage must be NULL, and if baseImage is non-NULL then fileHandle must be NULL. File-handle mode evaluates an on-disk candidate; buffer mode evaluates the in-memory bytes the implant intends to execute.
3. For the implant pre-flight case, pass fileHandle = NULL, baseImage = pointer to the would-be payload image bytes, imageSize = buffer length.
4. The API evaluates the candidate against the active Device Guard / WDAC code-integrity policy and returns the verdict as an HRESULT: S_OK when the dynamic code is trusted by policy, a failure code when it would be blocked.
5. No enforceable state change occurs during the query — no memory allocation, no protection transition, no section or thread creation. The policy decision returns before execution is attempted, per the material's description: the decision comes back "without triggering execution."
6. Branch on the verdict. Trusted (or no restrictive policy): proceed with the direct execution path. Untrusted: select a MEM_IMAGE-backed path — SEC_IMAGE mapping of a signed DLL as in T-006 Phantom Stubs or T-013 Module Overloading — rather than a private-memory PAGE_EXECUTE_READWRITE allocation that ACG/WDAC would reject.

## OS Internals Context

wldp.dll is the Windows Lockdown Policy DLL, the user-mode front end for the code-integrity (CI) policy engine. Device Guard is the umbrella for two enforcement pillars: WDAC (Windows Defender Application Control — the configurable code-integrity policy, deployed as a signed binary policy blob such as SiPolicy.p7b under C:\Windows\System32\CodeIntegrity) and HVCI (memory integrity, which moves CI evaluation into the secure kernel). WldpQueryDynamicCodeTrust surfaces the WDAC/CI trust decision to user mode; the documented consumers are runtimes that generate code at execution time, which query the policy so they can conform to it rather than be terminated by it.

The API's SAL declaration encodes the two query forms directly (grounded in the training material's walkthrough):

- `_When_(baseImage == NULL, _In_) HANDLE fileHandle` — the handle is optional when baseImage is supplied, and required (read-only input) when it is not.
- `_When_(fileHandle == NULL, _In_reads_bytes_(imageSize)) PVOID baseImage` — the buffer form is valid only when no file handle is given, and imageSize bytes will be read.

The two forms differ in what CI evaluates. In file mode, the object has an on-disk identity — a file the kernel can page and authenticate against policy signers and rules. In buffer mode, the bytes are evaluated as an image: signature and policy-rule compliance of the content itself, which is the scenario a reflectively loaded module or generated code block falls into.

The query exists because the enforcement points sit elsewhere and fail late. Under the Arbitrary Code Guard mitigation (ProhibitDynamicCode, applied per-process via process mitigation policy — T-016 applies this same flag offensively), the memory manager refuses executable protections on non-image-backed memory: NtAllocateVirtualMemory with PAGE_EXECUTE_READWRITE on private pages fails with STATUS_DYNAMIC_CODE_BLOCKED (0xC0000604), and NtProtectVirtualMemory transitions to execute on MEM_PRIVATE pages are similarly rejected. Under WDAC user-mode code integrity, unsigned in-memory images fail the trust evaluation regardless of ACG. In both worlds, MEM_IMAGE pages backed by a legitimately signed image remain the only reliable host for executable content. A failed allocation is not silent — it is a distinctive error path security products key on — whereas the query returns the same information through a documented, side-effect-free channel.

This is the specific defensive mechanism that the vault's MEM_IMAGE-backed techniques are engineered against. T-006 maps SEC_IMAGE sections from version.dll so syscall stubs execute from Microsoft-signed image memory; T-013's module stomping and module overloading run shellcode from MEM_IMAGE regions backed by signed DLLs for the same reason. WldpQueryDynamicCodeTrust is the named policy-decision API those designs implicitly answer: it tells the operator whether that backing is mandatory on a given host, making SEC_IMAGE backing an operational requirement that can be measured rather than a stylistic default.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C. The grep-matched files provided with this cluster (dark_crystal/crates/core/src/runner.rs, dark_crystal/crowd/src/chain.rs, dark_crystal/crowd/src/edo_dead_drop.rs) were reviewed: none reference WldpQueryDynamicCodeTrust, wldp.dll, or Device Guard policy queries. chain.rs applies Block-DLL and ACG-adjacent policies (crate::policy::apply_block_dll_policy) but never queries dynamic-code trust state.

An implementation would be a small crowd module that resolves wldp.dll through the existing PEB-walker + DJB2 resolution path (resolve.rs), resolves the export, and calls the buffer form against the decrypted payload buffer before FASE 4 injection dispatch. The HRESULT verdict would feed InjectionMethod::Auto selection in chain.rs: untrusted verdicts route PE payloads to Module Overloading / Phantom (SEC_IMAGE paths already present) and shellcode payloads away from private-memory execution, while trusted verdicts leave the default Threadless → Pool Party → WaitingThread chain unchanged.

## Why It Matters

The vault documents both sides of Device Guard but not the junction between them: T-016 applies ACG/signature policy offensively, and T-006/T-013 provide MEM_IMAGE-backed execution that satisfies strict policy, yet nothing reads the policy state that decides which path is required. WldpQueryDynamicCodeTrust is that read primitive. It replaces trial-and-error — where the error is a telemetry-generating blocked allocation — with one documented query, and it names the kernel-side code-integrity decision point that justifies the vault's SEC_IMAGE-backed designs.

## Detection Considerations

The training material describes the query as observable but low-cost: "The query itself is observable but is far cheaper than a failed NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE) under ACG."

- **Telemetry sources**: API monitoring and ETW-based API tracing can observe calls into wldp.dll exports (provider GUID not documented in material). If wldp.dll was not already mapped in the process, resolving it produces a module-load event (Sysmon Event ID 7, image load) and a new entry in the PEB loader lists. File-handle mode additionally requires opening the candidate file, which generates file-system access telemetry.
- **Bypass options**: per the material, the query is itself the reduced-observability option — one documented call replaces repeated trial allocations whose failures under ACG are a distinctive signal. Buffer mode (baseImage) avoids the file-open telemetry of handle mode.
- **Residual artifacts**: a mapped wldp.dll module where the host process had none, and the EDR's own instrumentation of the export if present. The query allocates no memory, creates no handles in buffer mode, and leaves no file or registry artifacts.

## Related Techniques

- **T-016 EDR Evasion Suite** — documents ACG (ProhibitDynamicCode) and Block-DLL signature policy applied via NtSetInformationProcess; T-031 is the query-side complement that reads the same Device Guard policy state those mitigations participate in.
- **T-006 Phantom Stubs** — MEM_IMAGE-backed syscall stubs exist because dynamic-code trust policy blocks executable private memory; the trust query determines whether that signed-image backing is mandatory on the target.
- **T-013 Remaining Injection Methods** — module stomping and module overloading run shellcode from MEM_IMAGE regions backed by Microsoft-signed DLLs; T-031 provides the verdict that routes an operator to these image-backed paths under strict WDAC.

## References

- Atlas material: atlas-exploit-dev-part16.md (unit 13), atlas-exploit-dev-part6.md (units 19-20)
- MITRE ATT&CK: T1518.001 (Security Software Discovery) — https://attack.mitre.org/techniques/T1518/001/
- LGTM notes: lgtm:wldp-dynamic-code-trust-query, lgtm:wldp-dynamic-code-trust-edr-mechanism
- Public references: Microsoft Learn, WldpQueryDynamicCodeTrust function (wldp.h)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.

---

Check word count: Summary ~160, Mechanism ~260, OS Internals ~470, Key Impl ~190, Why ~90, Detection ~190, Related ~110, References ~50, Source ~15. Total ≈ 1535. Good.

Banned word check: "elegant" no, "clean" — I wrote "advertising Device Guard introspection" fine; check "clean" — not used. "robust" no. "notable" no. "sophisticated" no. "interesting" no. "worth noting" no. "essentially" no. "at its core" no. "the key insight" no. "importantly"/"it is important to note" no. Good.

Check rule: member_notes format — cluster spec shows `member_notes: ['lgtm:wldp-dynamic-code-trust-query', 'lgtm:wldp-dynamic-code-trust-edr-mechanism']`. I'll keep quotes as in spec.

Check frontmatter field order matches template: id, name, category, tier, crate, source_file, mitre, (mitre_secondary omitted), tags, origin, member_notes. Good.

One more check on a factual claim: "STATUS_DYNAMIC_CODE_BLOCKED (0xC0000604)" — correct value. ACG blocks NtAllocateVirtualMemory with PAGE_EXECUTE* on private memory — correct; note ACG also allows threads with AllowThreadOptOut etc., but I don't need that detail. Under ACG, "only MEM_IMAGE pages may be executable" — correct (also allows MEM_IMAGE; signed requirement comes from CIG/WDAC, not ACG alone — ACG alone allows existing image pages to be executable regardless of signature? Actually ACG prohibits dynamic code; executable pages must be image-backed. CIG (Code Integrity Guard, MicrosoftSignedOnly) requires signatures. WDAC UMCI enforces policy at load. My text says "MEM_IMAGE pages backed by a legitimately signed image remain the only reliable host for executable content" — under combined ACG+WDAC that's right; ACG alone doesn't require signing. I say "In both worlds, MEM_IMAGE pages backed by a legitimately signed image remain the only reliable host" — slight conflation, but in the context of strict WDAC + ACG this holds. To be safe, phrase: "Under ACG, executable content must live in image-backed pages; under WDAC UMCI, those images must additionally satisfy the signing policy. Combined, MEM_IMAGE pages backed by a legitimately signed image are the only reliable host for executable content." Let me adjust to be precise.

Also "HVCI moves CI evaluation into the secure kernel" — accurate (VTL1 secure kernel hosts CI under memory integrity). Fine, brief.

Sysmon Event ID 7 = Image loaded — confident.

WLDP ETW: I said "provider GUID not documented in material" — safe.

The material quote: "The query itself is observable but is far cheaper than a failed NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE) under ACG." — from note 1. Quoting LGTM note is fine.

Also make sure h1 includes the one-line purpose. Good.

Fix OS internals paragraph about ACG/WDAC precision. Rewrite:

"The query exists because the enforcement points sit elsewhere and fail late. Under the Arbitrary Code Guard mitigation (ProhibitDynamicCode, applied per-process through process mitigation policy — T-016 applies this same flag offensively), the memory manager refuses executable protections on non-image-backed memory: NtAllocateVirtualMemory requesting PAGE_EXECUTE_READWRITE on private pages fails with STATUS_DYNAMIC_CODE_BLOCKED (0xC0000604), and NtProtectVirtualMemory transitions to execute on MEM_PRIVATE pages are likewise rejected. ACG alone does not require those image pages to be signed; WDAC user-mode code integrity adds that requirement, failing unsigned in-memory images at the trust evaluation. Combined, MEM_IMAGE pages backed by a legitimately signed image are the only reliable host for executable content. A failed allocation is not a silent probe — it is a distinctive error path — whereas the query returns the same information through a documented, side-effect-free channel."

Good. Finalize.