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
member_notes: ['lgtm:wldp-dynamic-code-trust-query', 'lgtm:wldp-dynamic-code-trust-edr-mechanism']
---

# WldpQueryDynamicCodeTrust — Pre-Flight Device Guard Trust Query for Dynamic Code

## Summary

WldpQueryDynamicCodeTrust is a user-mode API exported by wldp.dll that returns the active Device Guard / WDAC code-integrity policy's trust verdict for a candidate piece of dynamic code without executing it. The API accepts either a handle to a file containing the candidate image or a pointer to in-memory bytes plus a size — the two are mutually exclusive — and answers whether that code would be permitted to run under the current policy. Implants use it as a pre-flight check before allocating executable memory, executing injected code, or manually loading a module, converting an unknown environment into a deterministic branch: private-memory execution when the policy permits it, MEM_IMAGE-backed execution when it does not. The primary detection surface is the call itself (API monitoring, module-load telemetry), which the training material characterizes as far cheaper in observability than a failed NtAllocateVirtualMemory under Arbitrary Code Guard.

## Mechanism

1. Resolve wldp.dll and the WldpQueryDynamicCodeTrust export at runtime. Dynamic resolution avoids a static import-table entry advertising Device Guard introspection.
2. Select the query form. The SAL contract enforces mutual exclusion on the first two parameters: if fileHandle is non-NULL then baseImage must be NULL, and if baseImage is non-NULL then fileHandle must be NULL. File-handle mode evaluates an on-disk candidate; buffer mode evaluates in-memory bytes.
3. For the implant pre-flight case, pass fileHandle = NULL, baseImage = pointer to the would-be payload image bytes, imageSize = buffer length.
4. The API evaluates the candidate against the active Device Guard / WDAC code-integrity policy and returns the verdict as an HRESULT: S_OK when the dynamic code is trusted by policy, a failure code when it would be blocked.
5. No enforceable state change occurs during the query — no memory allocation, no protection transition, no section or thread creation. The policy decision returns before execution is attempted; per the cluster description, the API "returns policy decision without triggering execution."
6. Branch on the verdict. Trusted (or no restrictive policy present): proceed with the direct execution path. Untrusted: select a MEM_IMAGE-backed path — an SEC_IMAGE mapping of a signed DLL as in T-006 Phantom Stubs or T-013 Module Overloading — rather than a private-memory PAGE_EXECUTE_READWRITE allocation that ACG/WDAC would reject.

## OS Internals Context

wldp.dll is the Windows Lockdown Policy DLL, the user-mode front end for the code-integrity (CI) policy engine. Device Guard is the umbrella for two enforcement pillars: WDAC (Windows Defender Application Control — the configurable code-integrity policy, deployed as a signed binary policy blob such as SiPolicy.p7b under C:\Windows\System32\CodeIntegrity) and HVCI (memory integrity, which moves CI evaluation into the secure kernel). WldpQueryDynamicCodeTrust surfaces the WDAC/CI trust decision to user mode. The documented consumers are runtimes that generate code at execution time — JIT and scripting engines — which query the policy so they can conform to it rather than be terminated by it. The API exists so that dynamic-code producers have a sanctioned way to ask before they act.

The API's SAL declaration encodes the two query forms directly, as the training material walks through:

- `_When_(baseImage == NULL, _In_) HANDLE fileHandle` — the handle is optional when baseImage is supplied, and required (read-only input) when it is not.
- `_When_(fileHandle == NULL, _In_reads_bytes_(imageSize)) PVOID baseImage` — the buffer form is valid only when no file handle is given, and imageSize bytes will be read from it.

The two forms differ in what CI evaluates. In file mode, the object has an on-disk identity — a file the kernel can page and authenticate against policy signers and rules. In buffer mode, the bytes are evaluated as an image in their own right: signature and policy-rule compliance of the content, which is the scenario a reflectively loaded module or generated code block falls into.

The query matters because the enforcement points sit elsewhere and fail late. Under the Arbitrary Code Guard mitigation (ProhibitDynamicCode, applied per-process through process mitigation policy — T-016 applies this same flag offensively against EDR DLL injection), the memory manager refuses executable protections on non-image-backed memory: NtAllocateVirtualMemory requesting PAGE_EXECUTE_READWRITE on private pages fails with STATUS_DYNAMIC_CODE_BLOCKED (0xC0000604), and NtProtectVirtualMemory transitions to execute on MEM_PRIVATE pages are likewise rejected. ACG alone does not require image pages to be signed; WDAC user-mode code integrity adds that requirement, failing unsigned in-memory images at the trust evaluation. Combined, MEM_IMAGE pages backed by a legitimately signed image are the only reliable host for executable content. A blocked allocation is not a silent probe — it is a distinctive error path security products key on — whereas the query returns the same information through a documented, side-effect-free channel.

This is the specific defensive mechanism that the vault's MEM_IMAGE-backed techniques are engineered against. T-006 maps SEC_IMAGE sections from version.dll so syscall stubs execute from Microsoft-signed image memory; T-013's module stomping and module overloading run shellcode from MEM_IMAGE regions backed by signed DLLs (chakra.dll, xpsservices.dll) for the same reason. WldpQueryDynamicCodeTrust is the named policy-decision API those designs implicitly answer: it tells the operator whether signed-image backing is mandatory on a given host, turning SEC_IMAGE execution from a stylistic default into a measured operational requirement.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C. The grep-matched files provided with this cluster (dark_crystal/crates/core/src/runner.rs, dark_crystal/crowd/src/chain.rs, dark_crystal/crowd/src/edo_dead_drop.rs) were reviewed: none reference WldpQueryDynamicCodeTrust, wldp.dll, or Device Guard policy queries. chain.rs applies Block-DLL policy (`crate::policy::apply_block_dll_policy`) but never reads dynamic-code trust state.

An implementation would be a small crowd module that resolves wldp.dll through the existing PEB-walker + DJB2 hash resolution path (resolve.rs), resolves the export, and calls the buffer form against the decrypted payload buffer before FASE 4 injection dispatch. The HRESULT verdict would feed `InjectionMethod::Auto` selection in chain.rs: an untrusted verdict routes PE payloads to Module Overloading or Phantom (SEC_IMAGE paths already present) and routes shellcode payloads away from private-memory execution, while a trusted verdict leaves the default Threadless → Pool Party → WaitingThread chain unchanged.

## Why It Matters

The vault documents both sides of Device Guard but not the junction between them: T-016 applies ACG and signature policy offensively, and T-006/T-013 provide MEM_IMAGE-backed execution that satisfies strict policy, yet nothing reads the policy state that decides which path is required. WldpQueryDynamicCodeTrust is that read primitive. It replaces trial-and-error — where the error is a telemetry-generating blocked allocation — with a single documented query, and it names the kernel-side code-integrity decision point that justifies the vault's SEC_IMAGE-backed designs.

## Detection Considerations

The training material describes the query as observable but low-cost: "The query itself is observable but is far cheaper than a failed NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE) under ACG."

- **Telemetry sources**: API monitoring and ETW-based API tracing can observe calls into wldp.dll exports (provider GUID not documented in material). If wldp.dll was not already mapped in the process, resolving it produces a module-load event (Sysmon Event ID 7, image load) and a new entry in the PEB loader lists. File-handle mode additionally requires opening the candidate file, which generates file-system access telemetry.
- **Bypass options**: per the material, the query is itself the reduced-observability option — one documented call replaces repeated trial allocations whose failure under ACG is a distinctive signal. Buffer mode (baseImage) avoids the file-open telemetry of handle mode.
- **Residual artifacts**: a mapped wldp.dll module in a process that had none, and whatever instrumentation an EDR has placed on the export. The query allocates no memory, creates no handles in buffer mode, and leaves no file or registry artifacts.

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