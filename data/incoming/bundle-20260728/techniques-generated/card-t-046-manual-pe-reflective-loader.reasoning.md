Let me analyze the inputs carefully.

The cluster spec assigns:
- T-046
- Name: Manual PE Loader and Reflective DLL Injection (sRDI)
- Category: process-injection
- Tier: A
- would_relate_to: T-013, T-007
- member_notes: lgtm:srdi-as-distinct-technique, lgtm:proposed-manual-pe-loader-technique-card, lgtm:proposed-technique-manual-pe-loading

Now, source files provided: chain.rs, edo_tensei.rs, payload_cfg.rs. None of these is pe_loader.rs itself. But the file manifest in the system context says `dark_crystal/crowd/src/pe_loader.rs` exists with role "Reflective PE loader". The provided source files (chain.rs, edo_tensei.rs, payload_cfg.rs) reference pe_loader:

- chain.rs: `InjectionMethod::ReflectivePe` variant with comment "Reflective PE: manual PE mapping in-process without LoadLibrary". Dispatches to `crate::pe_loader::PE::run(payload.clone())`. Also `reflective_pe: bool` config toggle with comment "Reflective PE Loader — manual PE mapping without LoadLibrary".
- edo_tensei.rs: `parse_injection_method` maps "reflective_pe" | "pe_loader" to InjectionMethod::ReflectivePe.
- payload_cfg.rs: `REFLECTIVE_PE: bool = false` constant.

T013's card says: "Reflective PE Loader (S tier) — Source: crowd/src/pe_loader.rs — Full manual PE mapping: headers, sections, relocations, imports, TLS callbacks — Module never appears in PEB (invisible to NtQueryInformationProcess, toolhelp) — Handles both EXE and DLL entry points."

So the actual implementation file pe_loader.rs is NOT included in my inputs. Only files that *reference* it. Per rule 8: "If a .rs file is in your inputs, do not assume it implements the technique just because it hit a keyword grep." The included files don't implement the technique — chain.rs dispatches to it, edo_tensei.rs maps strings to the enum, payload_cfg.rs holds a toggle. However, the file manifest (system context) explicitly lists `dark_crystal/crowd/src/pe_loader.rs` with role "Reflective PE loader" mapped to T007-process-injection. And T-013's card (provided as input) states the source is `crowd/src/pe_loader.rs` with specific capabilities.

So what should source_file be? The rule says: "source_file must be a real path (verified from included files) or exactly none". Hmm — "verified from included files". The pe_loader.rs file is referenced in the included chain.rs (calls `crate::pe_loader::PE::run`), and the manifest lists it. I can verify that chain.rs's ReflectivePe dispatch path calls `crate::pe_loader::PE::run(payload.clone())` — that's a direct reference from an included file to the implementing module. The manifest confirms the file exists at `dark_crystal/crowd/src/pe_loader.rs`. So source_file: dark_crystal/crowd/src/pe_loader.rs is justified — it's a real path verified through the manifest and referenced by included code. But I should be careful: I have NOT seen pe_loader.rs's contents. I cannot describe its internal functions. I can describe the dispatch plumbing (chain.rs InjectionMethod::ReflectivePe, payload_cfg REFLECTIVE_PE toggle, edo_tensei mapping) and state what T-013 documents about it, but I should be explicit that the implementing file itself was not included in this input set, so I cannot verify its internal implementation details beyond what the calling code and T-013 card document.

Actually, let me re-read rule 8 and the Key Implementation Details section spec:

"If matching Rust source is included in your inputs AND you verified it implements this technique: Reference the file path and specific functions..."

The matching source files here are chain.rs, edo_tensei.rs, payload_cfg.rs. Do any of them implement the primary mechanism (manual PE mapping)? No. chain.rs calls into pe_loader but doesn't implement the loader. So per the explicit test: "for the file to count as an implementation of this technique, at least ONE function in it must implement the primary mechanism the card describes." None of the included files implement manual PE loading themselves.

But wait — the file manifest (system context, not "included files" per se, but it IS in my system context) lists pe_loader.rs. The instructions say "Matching source files (src/**/*.rs, optional) — Rust source files from the HUGIN implant that a keyword grep matched to this technique's terms." The grep matched chain.rs, edo_tensei.rs, payload_cfg.rs — because they mention "reflective_pe" and "pe_loader". The actual implementation file wasn't matched/included (odd, but that's the input).

Decision: In Key Implementation Details, I'll state that the included source files contain the dispatch plumbing but not the loader itself; the implementing file `dark_crystal/crowd/src/pe_loader.rs` is referenced by `chain.rs` (`crate::pe_loader::PE::run`) and documented in T-013, but its internals were not part of this input set, so verification is limited to the call sites. That's honest. For source_file frontmatter: the manifest lists pe_loader.rs as a real path, and it's directly referenced by included code. I think setting `source_file: dark_crystal/crowd/src/pe_loader.rs` is correct and verifiable via the manifest. The rule says "verified from included files" — the manifest is in my system context as part of the vault, and chain.rs (included) references `crate::pe_loader::PE::run`. Combined, this verifies the path exists. I'll use it but note in Key Implementation Details that the loader file itself was not included, so internal function-level description is not possible.

Hmm, actually, let me be more careful. False attribution is worse. Is there any risk pe_loader.rs doesn't implement this? T-013's card (provided) says: "Reflective PE Loader (S tier) - Source: crowd/src/pe_loader.rs - Full manual PE mapping: headers, sections, relocations, imports, TLS callbacks". That's an existing vault card explicitly attributing it. chain.rs calls `pe_loader::PE::run(payload)` requiring an MZ header. The manifest says role "Reflective PE loader". Three independent attestations. Attribution is safe.

Note T-013 lists it as "S tier" in its body, but the cluster spec proposes tier A for this card. The cluster spec is the primary directive — tier A. The T-013 "S tier" label is that card's own assessment of the loader; the clustering pass decided A for the standalone card. I'll use A per spec. I won't dwell on the discrepancy, though I could avoid mentioning it. Actually the spec says "Proposed tier: A" — use A.

Category: process-injection per spec. Although note 3 argues it's reusable beyond injection (in-memory plugin execution, staging). The spec says category process-injection as default; I could keep it since the enum doesn't have "loader" and the would_relate_to are both injection cards. Keep process-injection and explain in Why It Matters.

Crate: dark_crystal (pe_loader.rs is in dark_crystal/crowd). 

MITRE: Best fit. Manual PE loading / reflective DLL injection → T1620 "Reflective Code Loading". That's the precise ATT&CK technique for reflective loading. T1620: "Adversaries may reflectively load code into a process in order to conceal the execution of malicious payloads. Reflective loading involves allocating then executing payloads directly within the memory of the process, vice creating a thread or process backed by a file path on disk." Yes — T1620 is the canonical mapping for RDI/manual mapping. Secondary: T1055 (Process Injection) and maybe T1055.001 (DLL injection) — but T1620 is the primary. mitre_secondary: [T1055]. Also possibly T1027 (obfuscation) — no, keep T1055 as secondary. Actually T1106 (Native API)? Not needed. Keep [T1055].

Tags (5-10 kebab-case): manual-pe-loader, reflective-dll-injection, srdi, in-memory-execution, base-relocations, iat-resolution, tls-callbacks, peb-invisible, position-independent. That's 9. Good.

Atlas material grounding:
- part11 units 1-5: RDI walk-through steps (allocate heap buffer from file size; allocate buffer OptionalHeader.SizeOfImage; copy headers and sections; apply fixups and parse tables; call DllMain and return). sRDI: position-independent shellcode loader; target DLL doesn't need RDI compilation; GetProcAddressR custom helper; Bootstrap + RDI + Existing DLL + User-Data layout; full PE loader supporting section permissions and TLS callbacks; Nick Landers (monoxgas) credited.
- part11 units 8-9: custom loader rationale — memory-only execution, no disk footprint, pull PE over a socket and execute.
- part11 unit 12-13: Implementation — MZ check at offset 0x00; FileHeader.Machine == x64; process PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS64, PIMAGE_FILE_*, PIMAGE_OPTIONAL_*, PIMAGE_SECTION_*; process PIMAGE_DATA_DIRECTORY; build IAT, EAT; base relocations; kick off OptionalHeader.AddressOfEntryPoint.
- part20 unit 5: same implementation content (MZ validation, x64 machine check, headers, data dirs, IAT/EAT, relocs, entry point dispatch).
- part20 unit 21: RDI definition — DLL manually mapped into target's VAS; full path never written; "we are now the system loader"; stealthier; must reimplement LoadLibrary functionality.
- part5 unit 31: "manually load an image into memory" as last-resort capability alongside re-implementing API hooks, C2 callbacks, shellcode execution; used when stealth desired / basic techniques fail.

Detection material: The atlas doesn't discuss detection for this technique specifically. part5 unit 31 mentions stealth motivation. part20 unit 21 mentions avoiding the DLL path appearing on disk / loaded modules lists (that's an evasion property, not detection). T-013 says module never appears in PEB (invisible to NtQueryInformationProcess, toolhelp). I can describe residual artifacts carefully: private memory allocations (MEM_PRIVATE) with RX/RWX, unbacked executable pages — but is that "inventing detection"? Rule: "If the material does not cover detection for this technique, write: Training material does not discuss detection for this technique. Do not invent detections." The material does touch on stealth properties (not in PEB, no file path). I can frame those as the evasion side. For detection surface, the material is silent — I should say so, and I can note the general telemetry implication only insofar as the material states: RDI avoids the full DLL path being written and avoids loaded-module lists. I'll keep detection section honest: state material doesn't discuss detection; describe the stealth properties documented (no PEB entry, no on-disk path, bypasses LoadLibrary telemetry implicitly since LoadLibrary isn't called — careful: ETW-TI etc. is not in material). Better to strictly say material doesn't discuss detection, then list what the material says about stealth/no-artifacts as "residual artifacts" framing: absence of PEB LDR entry; memory is privately allocated (heap buffer per the RDI walk-through — actually the material says "Allocate heap buffer from file size; Allocate buffer OptionalHeader.SizeOfImage"). Heap-backed executable memory is a detectable artifact in general knowledge, but stating that specific detection (pe-sieve finding executable heap) might be inventing. I'll say: material does not discuss detection; the technique's documented stealth properties are absence of DLL path on disk and absence from loaded-module lists; HUGIN T-013 documents PEB invisibility. Residual artifact per material: the loaded image resides in buffers allocated by the loader (heap/private memory per the RDI walk-through steps). That's descriptive, not a detection claim.

Mechanism steps — synthesize from material:
1. Validate MZ signature at offset 0x00.
2. Read e_lfanew from DOS header → locate NT headers (the material says "process all headers... PIMAGE_DOS_HEADER; PIMAGE_NT_HEADERS64" — e_lfanew itself is standard Windows knowledge, fine).
3. Validate FileHeader.Machine == x64 (IMAGE_FILE_MACHINE_AMD64 0x8664 — value is standard).
4. Allocate buffer of OptionalHeader.SizeOfImage (material: "Allocate buffer OptionalHeader.SizeOfImage"); RDI walk-through also mentions allocating heap buffer from file size for the raw bytes.
5. Copy headers (SizeOfHeaders) then each section per PIMAGE_SECTION_HEADER (PointerToRawData → VirtualAddress, SizeOfRawData).
6. Apply base relocations if actual base != OptionalHeader.ImageBase: walk IMAGE_DIRECTORY_ENTRY_BASERELOC blocks; for x64 apply IMAGE_REL_BASED_DIR64 delta fixups (T-013's vectored overloading mentions DIR64/HIGHLOW types; the DIR64 type for x64 is standard knowledge).
7. Process data directories (PIMAGE_DATA_DIRECTORY): build import table — for each IMAGE_IMPORT_DESCRIPTOR, load dependency DLL and resolve thunks (by name via hint/name or ordinal) writing resolved addresses into the IAT (FirstThunk). Material says "build the tables; IAT, EAT, etc."
8. EAT construction — for exports? Material says build IAT, EAT. The EAT building is presumably for the loaded module's own exports so the loader can resolve them (sRDI's GetProcAddressR walks the EAT). I'll describe GetProcAddressR as sRDI's custom export-resolution helper that parses the loaded module's EAT in place.
9. Set section permissions (sRDI supports section permissions — part11 unit 3/4: "complete PE loader supporting section permissions and TLS callbacks").
10. Execute TLS callbacks (material mentions TLS callback support for sRDI; T-013 documents TLS callbacks in pe_loader.rs).
11. Dispatch entry point: call OptionalHeader.AddressOfEntryPoint — DllMain for DLLs (DLL_PROCESS_ATTACH) vs EXE entry; part11 unit 1: "Call DllMain and return". part11 unit 12/13: distinguish DllMain vs WinMain entry signatures ("identifying entry point signatures for DLLs versus EXEs" per unit 13 summary).

sRDI specifics: loader converted to position-independent shellcode; target DLL need not be compiled with RDI support; layout = Bootstrap + RDI shellcode + Existing DLL + User-Data; bootstrap locates the embedded DLL and transfers control to the loader shellcode; GetProcAddressR helper.

OS Internals Context:
- What the Windows loader (Ldr) does that must be replicated: the OS loader in ntdll (LdrpInitializeProcess path / LdrLoadDll) normally handles mapping SEC_IMAGE, relocations, import resolution, TLS, and registers the module in PEB LDR lists (InLoadOrder/InMemoryOrder/InInitializationOrderModuleList via LDR_DATA_TABLE_ENTRY). Manual loader skips registration → module absent from the three lists (T-013 says invisible to toolhelp/NtQueryInformationProcess).
- SEC_IMAGE vs private memory: manual loaders copy into VirtualAlloc'd MEM_PRIVATE memory, not NtCreateSection(SEC_IMAGE) mapped views; VAD shows MEM_PRIVATE, not backed by file on disk. (Standard internals; material says "allocate buffer" — heap buffer per walk-through; I can state the distinction carefully as Windows internals knowledge.)
- Relocation internals: .reloc blocks, page RVA + entries, type/offset nibble split, DIR64 adds 64-bit delta.
- Import resolution: normally Ldr snaps IAT via LdrpSnapThunk; manual loader must call LoadLibrary-equivalent (or map dependencies itself) and write function addresses to FirstThunk array; delay-load not covered by material — don't mention.
- TLS: IMAGE_TLS_DIRECTORY, TlsCallbacks array executed before entry point — OS loader invokes them via LdrpCallTlsInitializers; manual loader must call them explicitly.
- Exception directory (note 2 mentions exception directory as a loader responsibility: ".pdata" — for x64, RtlAddFunctionTable / RtlInstallFunctionTableCallback needed for SEH to work in manually mapped code; note 2 explicitly lists "relocations, imports, TLS callbacks, exception directory" as OS-loader behaviors to replicate. I can mention IMAGE_DIRECTORY_ENTRY_EXCEPTION / .pdata RUNTIME_FUNCTION registration via RtlAddFunctionTable — that's standard and the note references exception directory.)
- sRDI position independence: no absolute addresses; resolves own location via RIP-relative or call/pop; bootstrap+user-data layout.

Key Implementation Details:
- Included files: chain.rs (InjectionMethod::ReflectivePe dispatch → crate::pe_loader::PE::run(payload.clone()); validates MZ before dispatch; ReflectivePe handled by run(); also reflective_pe bool config gate), edo_tensei.rs ("reflective_pe"|"pe_loader" string mapping), payload_cfg.rs (REFLECTIVE_PE const).
- Implementing file dark_crystal/crowd/src/pe_loader.rs not included; per manifest role "Reflective PE loader"; T-013 documents it as full manual mapping (headers, sections, relocations, imports, TLS callbacks), PEB-invisible, EXE+DLL entry handling.
- Note: no sRDI-style shellcode bootstrap, no GetProcAddressR in what I can verify — state that the HUGIN implementation is the in-process loader form (RDI-style), and sRDI shellcode form is documented in material but not verified in source.

Why It Matters: fills gap — T-013 folds "PE Loader" into one line of an 8-technique card; this is reusable primitive beyond injection (in-memory plugin execution, staging, loading EXEs which many injection methods can't handle); bypasses LoadLibrary/Ldr telemetry path and PEB module enumeration that Module Stomping/Overloading alternatives still touch (Module Overloading uses SEC_IMAGE mapping of a legit DLL — different artifact); gives fine-grained control (relocations, permissions, TLS). Note 3's argument: standalone capability, last-resort per SEC670.

Related Techniques:
- T-013 (Additional Injection Methods) — contains the one-line "Reflective PE Loader" entry; this card expands it. Also T-013's vectored overloading handles DIR64/HIGHLOW relocs as a related but different approach.
- T-007 (Pool Party) — hmm, would_relate_to includes T-007. Relationship: T-007 is the injection execution primitive that can deliver/execute code in a remote process; a manual PE loader can be the payload staged into the target by such methods. The member notes relate manual loading to T-007 because T-007 is the process-injection card family head. I'll phrase: T-007 Pool Party — execution primitive for shellcode in a remote process; the manual loader is what runs after delivery when the payload is a full PE rather than raw shellcode. That's justifiable from note 3 ("underpins in-memory execution of plugins... beyond injection" and would_relate_to lists T-007).

References:
- Atlas: atlas-exploit-dev-part11.md, atlas-exploit-dev-part20.md, atlas-exploit-dev-part5.md
- MITRE: T1620 https://attack.mitre.org/techniques/T1620/
- LGTM: the three IDs
- Public references: Nick Landers (monoxgas) sRDI — named in part11 unit 4 key cues ("Nick Landers (monoxgas)"). I can cite monoxgas/sRDI.

Source Reference: dark_crystal/crowd/src/pe_loader.rs (referenced by chain.rs dispatch; file not included in input set) + call sites in chain.rs (InjectionMethod::ReflectivePe arms in run/run_with_shellcode/inject paths), payload_cfg.rs REFLECTIVE_PE, edo_tensei.rs parse_injection_method.

Frontmatter:
```yaml
---
id: T-046
name: Manual PE Loader and Reflective DLL Injection (sRDI)
category: process-injection
tier: A
crate: dark_crystal
source_file: dark_crystal/crowd/src/pe_loader.rs
mitre: T1620
mitre_secondary: [T1055]
tags: [manual-pe-loader, reflective-loading, srdi, in-memory-execution, base-relocations, iat-resolution, tls-callbacks, peb-invisible, position-independent]
origin: atlas-synthesis
member_notes: ['lgtm:srdi-as-distinct-technique', 'lgtm:proposed-manual-pe-loader-technique-card', 'lgtm:proposed-technique-manual-pe-loading']
---
```

Name length: "Manual PE Loader and Reflective DLL Injection (sRDI)" — the template says 4-8 words human readable name. That's ~8 words. Fine. H1: "# Manual PE Loader and Reflective DLL Injection (sRDI) — In-Memory Image Loading Without the OS Loader".

Length: target 1200-1800 words body. Let me draft thoroughly.

Banned words check: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable. Banned phrases: "but wait", "interestingly", "worth noting", "the key insight", "it is important to note", "as you can see", "essentially", "at its core". Avoid all.

Careful with "textbook" — the template itself uses "textbook" in quotes in the instructions ("deviations from the 'textbook' implementation"). Rule bans the word. I'll avoid it: say "deviations from the implementation the material describes".

Now write the card.

Summary (3-5 sentences): Manual PE loader replicates OS loader responsibilities — header/section mapping, base relocations, import resolution, TLS callbacks, entry-point dispatch — to execute a DLL or EXE entirely from memory without LoadLibrary or an on-disk image. sRDI variant converts the loader itself into position-independent shellcode so any DLL can be reflectively loaded without being compiled for RDI, exposing helpers like GetProcAddressR. Operator use: pull PE over C2 and execute with no disk artifact and no PEB module entry. Detection surface: material doesn't cover; primary surface in general is... keep to material: absence from module lists.

Mechanism — numbered, concrete:
1. Obtain raw PE bytes (file read, network download, or embedded); validate 'MZ' (0x4D 0x5A) at offset 0.
2. Follow e_lfanew (offset 0x3C) to NT headers; check FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 (0x8664) for x64.
3. Allocate destination buffer of OptionalHeader.SizeOfImage (SEC670 walk-through: "Allocate buffer OptionalHeader.SizeOfImage"; also an initial heap buffer sized from file size to stage raw bytes).
4. Copy SizeOfHeaders bytes of headers, then walk PIMAGE_SECTION_HEADER array: copy each section's PointerToRawData/SizeOfRawData to base+VirtualAddress.
5. Compute relocation delta = actual base − OptionalHeader.ImageBase; if nonzero and IMAGE_DIRECTORY_ENTRY_BASERELOC present, walk IMAGE_BASE_RELOCATION blocks and apply fixups (x64: IMAGE_REL_BASED_DIR64; 32-bit HIGHLOW noted in T-013 vectored overloading).
6. Process data directories: for IMAGE_DIRECTORY_ENTRY_IMPORT, walk descriptors, load each dependency DLL (LoadLibrary or recursively manual-map), resolve each thunk by hint/name or ordinal via the dependency's EAT, write resolved VA into FirstThunk (IAT).
7. Build/walk export table (IMAGE_DIRECTORY_ENTRY_EXPORT) — needed so the loaded module's own exports can be resolved afterward; sRDI exposes this as GetProcAddressR.
8. Apply per-section memory permissions from section characteristics (sRDI described as "complete PE loader supporting section permissions and TLS callbacks").
9. If IMAGE_DIRECTORY_ENTRY_TLS present, execute each callback in the TlsCallbacks array before entry.
10. (x64 exception directory — from note 2: exception directory registration as loader responsibility; register RUNTIME_FUNCTION via RtlAddFunctionTable — that's established Windows API, safe.)
11. Dispatch to OptionalHeader.AddressOfEntryPoint — DllMain(hinstDLL, DLL_PROCESS_ATTACH, ...) for DLLs, main/WinMain-style entry for EXEs; material: "Call DllMain and return"; "kick off main OptionalHeader.AddressOfEntryPoint".

sRDI layout: Bootstrap + loader shellcode (RDI) + existing DLL bytes + User-Data; bootstrap runs first, locates embedded DLL, passes to loader; loader is PIC; GetProcAddressR; target DLL need not be RDI-compiled.

OS Internals:
- Ldr role: ntdll loader (LdrLoadDll/Ldrp*): creates SEC_IMAGE section via NtCreateSection, maps view, snaps IAT, applies relocs (usually already applied by kernel for SEC_IMAGE? — actually for SEC_IMAGE the kernel applies relocations at map time via MiRelocateImage; hmm, careful. For normal DLL loads, kernel maps the image section and applies relocations if needed (MiRelocateImage), then user-mode Ldr snaps imports, runs TLS, and links LDR_DATA_TABLE_ENTRY into the three PEB lists. Manual loader replicates user-mode portion and skips registration. I'll describe accurately but conservatively: kernel handles SEC_IMAGE mapping and fixups for the standard path; manual loader does its own copying and fixups into private memory.)
- PEB LDR lists: InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList; manual mapping never inserts LDR_DATA_TABLE_ENTRY → toolhelp32 Module32First/Next and NtQueryInformationProcess don't see it (per T-013).
- VAD: destination is MEM_PRIVATE (VirtualAlloc/HeapAlloc) not MEM_IMAGE — contrasts with Module Overloading (T-013) which maps SEC_IMAGE of a signed DLL.
- Relocation format: blocks of IMAGE_BASE_RELOCATION {VirtualAddress, SizeOfBlock}, 16-bit entries high nibble type low 12 offset; DIR64 = 10.
- Import snapping: FirstThunk overwritten with resolved addresses; ILT vs IAT; ordinal imports (IMAGE_ORDINAL_FLAG64).
- TLS: IMAGE_TLS_DIRECTORY64, AddressOfCallBacks null-terminated array, invoked by OS loader via LdrpCallTlsInitializers normally; manual loader must invoke with DLL_PROCESS_ATTACH.
- .pdata exception registration: RtlAddFunctionTable for x64 SEH; without it, exceptions in the manually mapped image unwind into nowhere (crash). Note 2 lists exception directory — good.
- Position independence for sRDI: RIP-relative addressing, no absolute VA references; resolves API via PEB walk/hash — but careful, material only says "everything is converted to position independent shellcode" and GetProcAddressR custom function. Keep to that.

Key Implementation Details: as planned. Mention chain.rs lines conceptually: `InjectionMethod::ReflectivePe` arm in run() and run_with_shellcode() and inject_fsm? In inject_fsm the ReflectivePe is in the `_ => {}` catch-all "handled by run()". The dispatch validates MZ (payload[0]==0x4D && payload[1]==0x5A), wraps call in stack_spoof::spoof_caller(), calls `crate::pe_loader::PE::run(payload.clone())`, then goto_cleanup with no PID (in-process technique). Config: `reflective_pe: bool` in ChainConfig (default false), `REFLECTIVE_PE` const in payload_cfg.rs (auto-generated by crowd_builder.py), edo_tensei parse maps "reflective_pe"|"pe_loader". T-013 documents pe_loader.rs capabilities. State that pe_loader.rs internals not included in this input set; description of internal functions limited to call-site verification. No sRDI shellcode bootstrap or GetProcAddressR verified in source — HUGIN implements the RDI-style in-process loader form.

Why It Matters: 2-4 sentences.

Detection: material silent → state it. Document stealth properties from material: no DLL full path written, absent from loaded-module lists; T-013: invisible to NtQueryInformationProcess/toolhelp. Residual: image lives in loader-allocated buffers (heap/private per walk-through) — describe as documented allocation behavior. Bypass options: material doesn't discuss operator bypass measures; the technique itself is the bypass relative to LoadLibrary-based loading.

Related Techniques:
- T-013 Additional Injection Methods — folds reflective PE loading into a single line; this card expands the loader responsibilities it names; T-013's Vectored Overloading entry documents the alternative SEC_IMAGE-backed approach (DIR64/HIGHLOW reloc handling) that keeps a signed-DLL backing instead of private memory.
- T-007 Pool Party — remote execution primitive delivering shellcode into a target's thread pool; the manual loader is the complement for when the staged payload is a full PE: T-007-class methods execute the loader, the loader maps the PE. Justify from member notes' would_relate_to and note 3 (loader underpins in-memory execution beyond injection).

References: atlas parts 11, 20, 5; MITRE T1620; LGTM IDs; monoxgas sRDI (named in atlas part11 unit 4).

Source Reference: pe_loader.rs path + call sites; note implementing file not included in input.

Word count: aim ~1300-1600.

Write it now, careful with banned words. Also no rhetorical questions, no first person, no "Consider also".

Double-check YAML: tags 9 items, kebab-case ok: manual-pe-loader, reflective-loading, srdi, in-memory-execution, base-relocations, iat-resolution, tls-callbacks, peb-invisible, position-independent. "srdi" is fine.

mitre_secondary: [T1055] — format as YAML list.

One more consideration: the H1 format "# <Technique Name> — <One-Line Purpose>". Use "# Manual PE Loader and Reflective DLL Injection (sRDI) — In-Memory Image Execution Without the OS Loader".

Section: OS Internals Context — ensure someone with Win Internals knowledge learns something: focus on (a) division of labor kernel vs user loader for SEC_IMAGE vs manual; (b) LDR_DATA_TABLE_ENTRY registration skip; (c) VAD MEM_PRIVATE vs MEM_IMAGE implications; (d) .reloc entry encoding and DIR64; (e) TLS callback invocation contract (reason=DLL_PROCESS_ATTACH before entry); (f) .pdata/RtlAddFunctionTable for x64 unwind; (g) sRDI bootstrap layout and why PIC avoids needing the target DLL to be RDI-aware.

Detection section: "Training material does not discuss detection for this technique." Then add what material documents as evasion properties. The template says if material doesn't cover detection write that line — I'll write it and then list documented stealth/residual items clearly framed as such. The template asks for telemetry/bypass/residual bullets; I can structure: "The training material does not discuss detection for this technique." followed by the documented artifact-avoidance claims from the material and the T-013 card. That's within rules.

Now produce final output. Single markdown file, no preamble.