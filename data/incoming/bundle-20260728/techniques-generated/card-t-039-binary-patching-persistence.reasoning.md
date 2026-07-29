Let me analyze the inputs carefully.

The cluster spec asks for T-039: On-Disk Binary Patching for Persistence and Evasion, category `persistence`, tier `B`.

Member notes:
1. `lgtm:proposed-binary-patching-technique` — from atlas-exploit-dev-part22, unit 17. SEC670 introduces binary patching as a distinct module with objectives and benefits. Code-cave shellcode insertion, import-table patching, resource-section modification. Trade: signed-binary cave availability, detection via signature mismatch.
2. `lgtm:proposed-technique-binary-patching-persistence` — from atlas-methodology-part8, units 16-22. SEC670 Section 4 lists Binary Patching as distinct persistence topic alongside Registry Keys, Services, IFEO, WMI Event Subscriptions. In-place modification of binary files on disk to insert persistent execution hooks. Distinct from module stomping (in memory) and proxy DLL planting (adds new files).
3. `lgtm:on-disk-patching-system-dlls` — from atlas-post-exploit-part11, unit 19. On-disk patching of system binaries (potentially Ntdll.dll and signature-scanning binaries) as persistence surviving reboot, unlike in-memory unhooking. Cascading risks: system instability, faster detection by file integrity monitoring, harder to undo.

would_relate_to: T-017, T-006, T-021.

Source files provided:
- `src/dark_crystal/crowd/src/byovd.rs` — BYOVD driver loading. Does NOT implement binary patching. It force-deletes files via a vulnerable driver. Not this technique.
- `src/dark_crystal/crowd/src/chain.rs` — the chain orchestrator. Does it implement on-disk binary patching? Let me check. It has many injection methods, persistence via `crate::persist::install_all`. The persistence layer 4 is TLS Callback Injection which "Modifies third-party DLL on disk to add TLS callback" — that's in `persist/tls_cb.rs` which is NOT included in the inputs. chain.rs itself just calls `crate::persist::install_all(&persist_cfg)`. So chain.rs does not itself implement binary patching — it references the persistence module. The actual on-disk PE modification (TLS callback) lives in `dark_crystal/crowd/src/persist/tls_cb.rs`, which is not provided. 

Per rule 8: for a file to count as implementation, at least ONE function in it must implement the primary mechanism the card describes. The primary mechanism here is on-disk PE file modification (code-cave insertion, import patching, resource modification, section extension). Neither byovd.rs nor chain.rs implements that. chain.rs references TLS callback persistence indirectly via persist module, but the file itself doesn't implement PE modification.

However, T-017's card documents Layer 4: TLS Callback Injection in `persist/tls_cb.rs` which "Modifies third-party DLL on disk to add TLS callback... Extends last PE section to fit stub + TLS directory + callback array... pure PE modification". That IS on-disk binary patching, implemented in the HUGIN source — but the source file isn't provided to me. The file manifest lists `src/persist/tls_cb.rs` with role "TLS callback persistence". 

Hmm — the question is what to put in `source_file`. Rule: `source_file` must be a real path (verified from included files) or exactly `none`. The included files are byovd.rs, chain.rs, payload_cfg.rs. None of these implement on-disk binary patching. So I should write `source_file: none` and in Key Implementation Details note that no current implementation in the provided source implements the general technique, but acknowledge the closest existing implementation: T-017 Layer 4 (TLS callback injection in `dark_crystal/crowd/src/persist/tls_cb.rs`) which is documented in the T-017 card provided. The T-017 card is provided as input, so I can reference it as an existing card fact. I need to be careful: rule says source_file must be verified from included files. tls_cb.rs is not included, but it IS referenced in the T-017 card and the file manifest in system context. The manifest is in my system context and lists `src/persist/tls_cb.rs`. 

Let me re-read rule 8 and the Key Implementation Details instructions: "If matching Rust source is included in your inputs AND you verified it implements this technique". The matching source files included are byovd.rs and chain.rs (and payload_cfg.rs). None implement the primary mechanism. So: "No current implementation in the HUGIN source" — but wait, that's not quite accurate either, since T-017 Layer 4 does PE modification. The honest framing: no *dedicated/general* implementation of on-disk binary patching exists in the provided source set; the nearest implementation is the TLS-callback PE modifier documented under T-017 (`persist/tls_cb.rs`), which performs a specific instance of on-disk PE modification (section extension + TLS directory insertion) rather than general code-cave/import patching.

For frontmatter: `crate: dark_crystal`, `source_file: none`. Actually should crate be `none` if source_file is none? The template says crate: dark_crystal|client_rust|none. Given the closest implementation lives in dark_crystal (crowd is part of dark_crystal per manifest — "dark_crystal/crowd"), I'd say `crate: dark_crystal` with source_file: none... Hmm, but the pairing in existing cards: T-017 has crate: dark_crystal, source_file: dark_crystal/crowd/src/persist/mod.rs. For T-039, since no source implements the general technique, safest is `crate: none, source_file: none`. But I could argue dark_crystal since tls_cb.rs is a specific instance. The cluster spec says tier B, category persistence. I'll go with `crate: none, source_file: none` to be strictly honest, then explain in Key Implementation Details. Actually — wait. Let me reconsider. The system prompt says crate must be dark_crystal|client_rust|none. If there's a partial/specific implementation in dark_crystal (tls_cb.rs, verified via T-017 card + file manifest), I could set crate: dark_crystal and source_file: none... that's inconsistent. Better: `crate: none`, `source_file: none`, and in Key Implementation Details state clearly that no general-purpose implementation exists in the provided source, note the TLS-callback instance under T-017, and describe what an implementation would look like.

Hmm, but actually, is that right? Let me check chain.rs more carefully for anything that modifies PE files on disk... Searching: `herpaderp` writes a decoy file to disk then overwrites it — but that's process herpaderping (T-010), writing a new file and racing content, not patching an existing binary. `self_delete` — ADS rename. `drop_driver` in byovd.rs writes a new driver file. Nothing patches an existing PE in place on disk. Correct — no implementation in provided files.

payload_cfg.rs — just config constants. Not an implementation.

Now the atlas material:

atlas-exploit-dev-part22 unit 17: "SEC670 introduces binary patching as a distinct module with stated objectives and benefits... Define binary patching, Discuss benefits of binary patching." Page 21 of some book. Excerpt: "Objectives Our objectives for this module are: Define binary patching Discuss benefits of binary patching".

atlas-methodology-part8 units 16-22: Table of contents showing Section 4: "In Memory Execution 13, Dropping to Disk 20, Binary Patching 26, Registry Keys 39, Services Revisited 47, Lab 4.1: PersistentService 67, Port Monitors 74, Lab 4.2: Sauron 79, IFEO 90, Lab 4.3: IFEOPersisto 97, WMI Event Subscriptions 114". Unit 20: "In this module, we will discuss what binary patching is and how we can leverage it for persistence on target."

atlas-post-exploit-part11 unit 19: The key unit. Excerpt from Book 4 (Persistence Die Another Day), page 24: "On-Disk Patching — Should survive reboots; cascading effect. Are files on disk better protected from patching than their memory mapped image? Is there a way to undo your changes if you accidentally break something with your patch? Could you render a system unstable if you patch system files? Could you get caught faster by patching files on disk? On-Disk Patching: There might come a time when you would have to patch the file as it resides on the file system. If you have the proper permissions, you might be able to patch the binaries that offer signature scanning for..." (truncated — "binaries that offer signature scanning for" presumably AV/EDR).

So material-grounded facts:
- Binary patching is a distinct SEC670 Section 4 module (page 20/26 of Book 4), listed alongside Registry Keys, Services, Port Monitors, IFEO, WMI Event Subscriptions as persistence topics.
- Purpose: leverage for persistence on target.
- On-disk patching survives reboots (vs in-memory).
- Patching files on disk has cascading effect/risk.
- Risks posed as questions: undo-ability, system instability when patching system files, faster detection by patching files on disk.
- Requires proper permissions.
- Targets include "binaries that offer signature scanning" (AV/EDR binaries) and potentially Ntdll.dll (from note 3 — note 3 says "potentially including Ntdll.dll and signature-scanning binaries").
- Note 1 adds: code-cave shellcode insertion, import-table patching, resource-section modification as the sub-techniques; signed-binary cave availability; detection via signature mismatch.
- Note 2 adds: distinct from module stomping (in-memory) and proxy DLL planting (new files).

Related cards:
- T-017 (Five-Layer Persistence): Layer 4 TLS Callback Injection modifies third-party DLL on disk, extends last PE section to add TLS callback — a specific instance of on-disk binary patching. T-039 generalizes.
- T-006 (Phantom Stubs): maps SEC_IMAGE sections from signed version.dll; relates via signed-binary usage. Note 1's would_relate_to includes T-006. Relationship: both leverage signed Microsoft binaries to give malicious code a trusted backing, but T-006 does it in memory (MEM_IMAGE mapping) while T-039 modifies the file at rest.
- T-021 (Crypto & Obfuscation): shellcode encoding formats — the shellcode inserted into a code cave can be encoded with T-021's formats; T-021 covers obfuscation of content, T-039 covers placement into existing PE. Note 1 relates to T-021.

MITRE: best fit? Options:
- T1554 (Compromise Host Software Binary) — "Adversaries may modify host software binaries to establish persistent access to systems." That's the best fit for on-disk binary patching persistence. Yes, T1554 is exactly this.
- Secondary: T1574 (Hijack Execution Flow) maybe, or T1027 (Obfuscated Files or Information) for the evasion side, or T1036? T1554 is the primary. mitre_secondary could include T1027 (evasion through modification of signature-scan targets) — actually the evasion angle is patching AV/signature-scanning binaries, which is T1562.001 (Impair Defenses: Disable or Modify Tools)? Hmm. Note 3's would_relate_to is T-016 (EDR evasion suite). Patching signature-scanning binaries = impair defenses → T1562.001. I'll use mitre: T1554, mitre_secondary: [T1027, T1562.001]. Let me be careful not to invent. T1554 Compromise Host Software Binary is real: https://attack.mitre.org/techniques/T1554/. T1027 Obfuscated Files or Information is real. T1562.001 Disable or Modify Tools is real. The spec consolidated description says "Persistence through modification of application logic at rest; evasion through modification of signature-scan targets." So both secondaries justified. Keep it to those two.

Tags: 5-10 kebab-case: [binary-patching, code-cave, pe-modification, persistence, on-disk, signature-mismatch, import-patching, file-integrity]. That's 8.

Tier: B (proposed). Category: persistence.

Now section content plan:

**Summary**: 3-5 sentences. On-disk binary patching modifies PE files at rest — code caves, import tables, resources, or added sections — to embed persistent execution hooks or to neuter security tooling. Survives reboot unlike in-memory unhooking. SEC670 Section 4 treats it as a distinct persistence topic alongside registry keys, services, IFEO, WMI. Primary detection surface: Authenticode signature mismatch and file integrity monitoring.

**Mechanism**: numbered steps. Need to be careful to ground in material + established PE format knowledge (allowed: "Well-established Windows internals documentation"). Steps:

1. Target selection: identify a binary that is executed by something else on a schedule/trigger — a frequently-loaded third-party DLL, a service binary, or a security-product binary (signature-scanning binaries named in material). Material says "patch the binaries that offer signature scanning" for AV bypass, and third-party DLLs for persistence.
2. Permission check: proper permissions required (material). Files under System32 require admin + TrustedInstaller ownership handling (that's established Windows knowledge — I should be careful. The material says "If you have the proper permissions". I can mention that system binaries are owned by TrustedInstaller and protected by WRP — that's well-established Windows internals. OK.)
3. Read and parse the PE: locate IMAGE_DOS_HEADER (e_magic MZ, e_lfanew), NT headers, section table — atlas-exploit-dev-part22 units 1 covers IMAGE_DOS_HEADER fields; unit 4 covers PE parsing for loader requirements.
4. Choose insertion strategy:
   a. Code cave: find slack space (runs of 0x00/0xCC between section raw data and its declared size), write PIC shellcode stub, redirect execution (entry point or hooked call) to the cave.
   b. Import table patching: add or modify an IMAGE_IMPORT_DESCRIPTOR to force-load an attacker DLL, or patch an IAT thunk.
   c. Resource section modification: embed payload in .rsrc, modify code to extract/execute.
   d. Section extension: extend the last section's SizeOfRawData/VirtualSize and append stub (this is what T-017 Layer 4 does for TLS callbacks — verified from T-017 card).
5. Update header fields: SizeOfImage, section characteristics (add IMAGE_SCN_MEM_EXECUTE/IMAGE_SCN_MEM_WRITE as needed), checksum field if targeted by naive integrity checks (the CheckSum field in optional header — established knowledge; but material doesn't mention it. I should be careful. I'll keep header fixups to what's needed: section sizes, characteristics, entry point. The T-017 card says "Extends last PE section to fit stub + TLS directory + callback array" — so directory updates too.)
6. Write back to disk, preserving timestamps if desired (material doesn't say; skip or keep minimal — better skip ungrounded details).
7. Result: next load of the binary executes the inserted logic; persists across reboot.

**OS Internals Context**:
- Authenticode: signature covers the file image as hashed per the Authenticode spec (excluding the CheckSum field, security directory entry, and the certificate blob itself). Modifying any byte in .text invalidates the signature → signature mismatch detection (note 1). Explorer/driver loading signature checks, but note: Windows does NOT re-verify Authenticode on LoadLibrary for user-mode DLLs by default — signature mismatch is detected by tools (sigcheck, Sysmon? no) not by the loader. Established knowledge: user-mode DLL loading does not enforce signature; Code Integrity applies to kernel drivers and processes with Code Integrity policy. This is important "specific internals surface".
- Memory-mapped image vs file on disk: material asks "Are files on disk better protected from patching than their memory mapped image?" — SEC_IMAGE sections are backed by the file; page-out writes go... actually SEC_IMAGE pages are copy-on-write when modified (PAGE_WRITECOPY semantics from T-006). The file on disk is protected by ACLs/WRP; the mapped image is protected by page protections + COW. Discuss.
- WRP (Windows Resource Protection): system files owned by TrustedInstaller; Administrators get read/execute only. Patching Ntdll.dll on disk requires taking ownership/ACL modification — loud. Established Windows knowledge.
- KnownDlls: Ntdll.dll is a KnownDll — mapped from a named section created at boot from the on-disk image. Patching the file on disk affects the section only after reboot (KnownDlls sections are created at boot). Actually KnownDlls object directory sections are created during boot from the files; a patched ntdll.dll on disk would be picked up on next boot via smss creating the section. That's the "survives reboot / requires reboot" nuance. Well-established internals.
- Cascading risk: patching system binaries risks instability (material); bad patch → every process loading that DLL crashes → boot failure potential for ntdll (every user process maps ntdll).
- PE structure specifics: code caves exist because SectionAlignment (4096) vs FileAlignment (512) rounding leaves slack between raw data end and section end; signed binaries (note 1: "signed-binary cave availability") — Microsoft-signed DLLs often have caves from alignment padding.

**Key Implementation Details**: No current implementation in provided source. Note that the nearest is T-017 Layer 4 (`dark_crystal/crowd/src/persist/tls_cb.rs`) which performs a specific on-disk PE modification (last-section extension, TLS directory + callback array insertion, PIC x64 stub with OpenEventA mutex check). This card documents the general technique. Describe what a general implementation would look like: PE parser (crowd already has pe.rs parsing per manifest? manifest says crates/core/src/pe.rs "PE header parsing"), cave scanner, PIC stub, header fixups, backup copy for undo.

Careful with rule 3 — no suggestions/variant ideas. But the template explicitly instructs: "If no source implements this technique... Then briefly describe what an implementation would look like (data structures, syscalls, roughly one paragraph)." That's allowed — it's part of the template.

**Why It Matters**: Distinct from T-016 (in-memory NTDLL unhook — dies at reboot), distinct from module stomping (in-memory), distinct from proxy DLL (new file). Fills the gap of persistence-through-modification rather than persistence-through-new-artifact. Also doubles as evasion by patching signature-scanning binaries. Earns own card because SEC670 lists it as a standalone module and the operational tradeoffs (undo, instability, FIM exposure) differ from every existing persistence layer.

**Detection Considerations**:
- Telemetry: Authenticode signature mismatch (note 1: detection via signature mismatch) — sigcheck, Get-AuthenticodeSignature; file integrity monitoring (note 3: faster detection by file integrity monitoring); Sysmon? Material does not name Sysmon event IDs — do not invent. I can say FIM tools (e.g., Windows itself has no built-in FIM for system files except WRP/SFC; sfc /scannow verifies system file hashes against the component store — established Windows knowledge, WRP). Windows Defender/AV on-access scanning of modified binaries. The material asks "Could you get caught faster by patching files on disk?" — yes, because disk artifacts persist for scanners.
- Bypass: material implies preferring third-party binaries over system files (unit 19 mentions third-party binaries in key cues: "n_t_d_l_l_dot_dll, third-party binaries"); patching targets not covered by WRP avoids SFC detection. Material states the risks as open questions — I'll present them as the documented trade-offs.
- Residual artifacts: modified file hash, broken signature, changed file size (for section extension), backup files if operator keeps them, ACL/ownership changes on WRP-protected files (well-established).

Careful: "If the material does not cover detection for this technique, write..." — material DOES cover detection partially (signature mismatch in note 1, FIM in note 3). Good.

**Related Techniques**:
- T-017 Five-Layer Persistence — Layer 4 (TLS callback) is a specific instance of on-disk PE modification; T-039 is the general primitive; the resilience model differs (T-017 monitor reinstalls, T-039 has no reinstall logic).
- T-006 Phantom Stubs — both exploit trust in signed Microsoft binaries; T-006 in memory via SEC_IMAGE mapping, T-039 at rest via file modification.
- T-021 Crypto & Obfuscation — supplies shellcode encodings (IPv4/IPv6/MAC/UUID/words) usable for the inserted stub; obfuscation complements placement.
- Note 3's would_relate_to is T-016, but the spec's would_relate_to list is T-017, T-006, T-021. Rule 9: only reference cards from the would_relate_to list or explicitly discussed in related cards provided. T-016 is not in the provided related cards (only T-006, T-017, T-021 were provided). The spec's would_relate_to is [T-017, T-006, T-021]. So stick to those three. Hmm — but the in-memory unhooking comparison is central to note 3. I can mention the in-memory unhook contrast in Why It Matters without a formal Related Techniques link... Actually rule 9 says only reference cards from the list or that I find explicitly discussed in the related T-NNN cards provided. T-016 is not provided. I'll keep Related Techniques to the three, but I can mention "in-memory NTDLL restoration (documented in T-016)" — no, restraint. I'll phrase Why It Matters generically: "in-memory unhooking documented elsewhere in the vault" — better to just say in-memory unhooking without linking, or... The instruction says cross-references section only. In body prose, mentioning the concept of in-memory unhooking is fine without a T-NNN link. I'll avoid the T-016 link in Related Techniques but may reference the concept.

Hmm, actually let me re-read: "Only reference cards from the `would_relate_to` list or that you find explicitly discussed in the related T-NNN cards provided." Note 3 explicitly discusses T-016's content ("T-016 documents NTDLL .text restoration (in-memory unhooking) but does not document the on-disk equivalent"). The member notes are part of the cluster spec input. The spirit is don't invent relationships. The T-016 relationship is explicit in the input material (note 3). But the spec's would_relate_to for the card is ['T-017', 'T-006', 'T-021']. Task instruction #3: "Cross-reference the T-NNN cards in `would_relate_to` = ['T-017', 'T-006', 'T-021'] in your Related Techniques section." Safest: include the three required, and I could add T-016 since note 3 explicitly relates it. But T-016's card text isn't provided, so I can't describe it precisely... Note 3 describes it: "T-016 documents NTDLL .text restoration (in-memory unhooking)". That's enough for a one-line relationship. The system prompt says "Only reference cards from the would_relate_to list or that you find explicitly discussed in the related T-NNN cards provided. Do not invent relationships." T-016 is not in the would_relate_to list and not in provided cards. Strictly, leave it out. I'll mention in-memory unhooking conceptually in Why It Matters/Detection without a formal link. Actually — mentioning "the vault's EDR evasion suite (T-016)" in body text would violate restraint? The rule targets the Related Techniques section. To be safe I'll keep T-016 out entirely and phrase as "in-memory NTDLL unhooking".

**References**:
- Atlas: atlas-exploit-dev-part22.md, atlas-methodology-part8.md, atlas-post-exploit-part11.md
- MITRE: T1554 URL https://attack.mitre.org/techniques/T1554/
- LGTM notes: the three IDs
- Public references: SEC670 Book 4 "Persistence: Die Another Day" (named in atlas material). That's named in material, fine.

**Source Reference**: "No current implementation. See atlas material and MITRE reference for public tooling." Plus mention tls_cb.rs as nearest? The template for no-source says exactly: "No current implementation. See atlas material and MITRE reference for public tooling." I can add a line about the nearest implementation being T-017's tls_cb.rs. I think that's accurate and useful, grounded in the T-017 card + file manifest. I'll write: "No current implementation in the provided source. The nearest existing implementation is the TLS-callback PE modifier in `dark_crystal/crowd/src/persist/tls_cb.rs`, documented under T-017 Layer 4."

Word count target: 1200-1800 body words. Let me draft with enough depth.

Frontmatter:
```yaml
---
id: T-039
name: On-Disk Binary Patching for Persistence and Evasion
category: persistence
tier: B
crate: none
source_file: none
mitre: T1554
mitre_secondary: [T1027, T1562.001]
tags: [binary-patching, code-cave, pe-modification, on-disk-persistence, signature-mismatch, import-table, resource-section, file-integrity]
origin: atlas-synthesis
member_notes: ['lgtm:proposed-binary-patching-technique', 'lgtm:proposed-technique-binary-patching-persistence', 'lgtm:on-disk-patching-system-dlls']
---
```

Wait — mitre format: "T####[.###] — pick the single best-fit". T1554 good.

Name in h1: "On-Disk Binary Patching — Persistent Execution Hooks in Files at Rest" or similar one-line purpose.

Now write the body.

Mechanism steps (numbered, concrete):

1. Select target binary. Two target classes named in the material: third-party binaries/DLLs loaded by applications or the OS on a predictable trigger (persistence), and "binaries that offer signature scanning" — security-product executables (evasion). Selection criteria: the file must be executed or loaded after the patch without operator action (service binary, DLL in a load path, logon-triggered executable).
2. Obtain write access. The material conditions the technique on "proper permissions". For files under %SystemRoot%\System32, the ACL grants full control to TrustedInstaller and read/execute to Administrators — patching requires ownership and ACL modification. Third-party installs under Program Files or per-user locations frequently grant the installing user write access.
3. Parse the PE on disk. Read IMAGE_DOS_HEADER, verify e_magic = 0x5A4D, follow e_lfanew to the NT headers, walk IMAGE_SECTION_HEADER table. (atlas-exploit-dev-part22 units 1, 4: PE parsing as loader prerequisite.)
4. Choose an insertion strategy:
   - Code cave: scan sections for slack bytes. Because FileAlignment (typically 0x200) rounds each section's raw data, the tail of a section on disk is frequently zero padding; larger caves appear in signed Microsoft binaries from alignment padding. Write position-independent stub into the cave and repoint a call site, the AddressOfEntryPoint, or an IAT-invoked function to the cave.
   - Import table: add an IMAGE_IMPORT_DESCRIPTOR naming an attacker-controlled DLL so the loader maps it at load time; or overwrite a FirstThunk entry to redirect one imported call.
   - Resource section: write payload into .rsrc (raw resource data has no alignment-driven execution constraints) and patch code to locate it via FindResource/LoadResource and execute.
   - Section extension: grow the last section's SizeOfRawData and VirtualSize, append stub plus any new data directory content (T-017 Layer 4 uses this variant for a TLS directory + callback array).
5. Fix up headers: update SizeOfImage if section virtual extents changed, set IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ on a section made executable, add/repoint the relevant data directory entry (import, TLS, resource), adjust AddressOfEntryPoint when entry-point redirection is used.
6. Write modified image back in place, replacing the original file. (Undo requires an original copy — the material explicitly asks "Is there a way to undo your changes if you accidentally break something with your patch?")
7. Execution occurs on next natural load — reboot, service start, application launch, or DLL load. The hook survives reboot because the file itself carries the modification.

OS Internals Context:
- Authenticode and signature mismatch: signature covers file content excluding checksum field and security directory; any .text/section modification invalidates it. Loader doesn't enforce for user-mode DLLs — LoadLibrary maps without signature verification; enforcement exists for kernel drivers (Code Integrity) and processes with ProcessSignaturePolicy. So a patched user-mode binary still loads and executes — detection is by external verification (sigcheck, Get-AuthenticodeSignature, FIM), not by the loader refusing. This is the specific internals surface: the patch is *tolerated by the loader but visible to verifiers*.
- Mapped image vs file: a DLL loaded normally is backed by an SEC_IMAGE section; writes to its pages trigger copy-on-write, so in-memory patching never touches the file. The material frames the inverse question — whether files on disk are better protected than their mapped images — and the answer in practice is that disk files are guarded by ACLs/WRP while mapped images are guarded by page protection and COW; bypassing one says nothing about the other. On-disk patch + reboot = every process gets the patched image via the section.
- KnownDlls/ntdll: ntdll.dll is registered in the KnownDlls object directory; smss creates the section at boot from the on-disk file. A patched ntdll.dll on disk propagates to every user-mode process after reboot — both the payoff (universal unhook/persistence) and the cascading instability risk (a bad patch crashes every process; ntdll corruption can render the system unbootable). Material: "Could you render a system unstable if you patch system files?" and "cascading effect".
- WRP: system files verified by SFC against component store hashes; modification is both harder (ownership) and more detectable (sfc /scannow, CBS logs) — do I mention SFC? It's established Windows knowledge; the material mentions "faster detection by file integrity monitoring". SFC/WRP is the canonical FIM for system files. I'll mention briefly as established context.
- Version differences: material doesn't discuss version differences. Skip or one line.

Key Implementation Details:
- Provided source files (byovd.rs, chain.rs, payload_cfg.rs) verified: none implements in-place PE modification on disk. byovd.rs drops a new driver file and force-deletes files via IOCTL; chain.rs orchestrates injection/persistence and calls persist::install_all; payload_cfg.rs is constants.
- Nearest implementation: T-017 Layer 4 in dark_crystal/crowd/src/persist/tls_cb.rs (documented in T-017 card): modifies a third-party DLL on disk, extends last section to fit PIC x64 stub + TLS directory + callback array, stub checks OpenEventA mutex.
- What a general implementation would look like: reuse PE parser, cave scanner over section raw data (0x00/0xCC runs ≥ stub size), PIC stub with mutex-style re-entry guard, header fixup (SizeOfImage, characteristics, directory), original-file backup for undo. One paragraph per template.

Why It Matters: 2-4 sentences. Fills gap: persistence by modification-at-rest rather than new artifact. Survives reboot unlike in-memory unhooking; no registry key/task/service entry for Autoruns to enumerate — the trigger is the normal loading of an existing binary. Trade-offs (undo, instability, FIM) are distinct from every T-017 layer. Also the only vault entry covering offensive modification of security-product binaries.

Detection Considerations:
- Telemetry: Authenticode signature mismatch (note 1); FIM (note 3: faster detection); SFC/WRP for system files (established); the material's rhetorical "Could you get caught faster by patching files on disk?" — yes because the artifact is at rest and scanned repeatedly.
- Bypass options per material: prefer third-party binaries (unit 19 key cues: "third-party binaries") over WRP-protected system files; keep patches minimal. Material does not give more bypass detail — I'll say so implicitly by limiting.
- Residual artifacts: modified file content/hash, invalidated signature, changed file size when sections are extended, ownership/ACL changes on protected files, operator backup copies.

Related Techniques: the three.

References:
- Atlas material: atlas-exploit-dev-part22.md (unit 17), atlas-methodology-part8.md (units 16-22), atlas-post-exploit-part11.md (unit 19)
- MITRE: T1554 URL
- LGTM: three IDs
- Public: SANS SEC670 Book 4 "Persistence: Die Another Day" (binary patching module, pp. 20-26 per methodology atlas units)

Banned words check: avoid "elegant", "textbook" (banned!), "notable", "key insight", "worth noting", "essentially". Careful — "textbook" appears in the template instructions ("textbook implementation") but I must not use it in output. 

Word count: aim ~1300-1500 body words. Let me write it.

Also h1 format: `# <Technique Name> — <One-Line Purpose>`: `# On-Disk Binary Patching — Persistence and Evasion via PE Modification at Rest`.

Double-check frontmatter name: "On-Disk Binary Patching for Persistence and Evasion" (canonical). h1 can shorten.

Let me now count and ensure Mechanism is concrete with named structures: IMAGE_DOS_HEADER.e_magic/e_lfanew, IMAGE_SECTION_HEADER, SizeOfRawData, VirtualSize, SizeOfImage, AddressOfEntryPoint, IMAGE_IMPORT_DESCRIPTOR, FirstThunk, IMAGE_SCN_MEM_EXECUTE, .rsrc, TLS directory (IMAGE_DIRECTORY_ENTRY_TLS — established name), FindResource/LoadResource (material mentions resource-section modification; FindResource is the standard API — established).

One more check on claims about KnownDlls: ntdll.dll is indeed a KnownDll; KnownDlls sections are created at boot by smss.exe under \KnownDlls. Established Windows Internals 7ed knowledge. Fine.

Authenticode hashing exclusions: the CheckSum field, the Certificate Table entry in the data directory, and the Attribute Certificate Table itself are excluded from the hash. Established. Fine.

User-mode LoadLibrary not verifying signatures: correct — Windows loader does not validate Authenticode for regular DLL loads; CI.dll validates kernel drivers; ProcessSignaturePolicy/Block-DLL (T-016 mentions Block-DLL policy) restricts to signed binaries when set. I'll mention that processes with a signature policy would refuse an unsigned/invalid patched DLL — good tie-in, but careful: Block-DLL (ProcessSignaturePolicy / PROCESS_CREATION_MITIGATION_POLICY... actually the "Block-DLL" in HUGIN refers to ProcessSignaturePolicy requiring Microsoft-signed). Established enough: SetProcessMitigationPolicy ProcessSignaturePolicy with MicrosoftSignedOnly. A patched system DLL would fail signature validation and be blocked from loading into such processes. That's a real, precise internals interaction. Include one line.

Now write the card. Ensure ≥800 words body; target 1200-1800. Draft mentally with sufficient density.

Summary draft:
"On-disk binary patching modifies a PE file at rest — inserting shellcode into code caves, patching the import table, altering the resource section, or extending a section — so that the binary's normal loading path executes attacker logic on every subsequent launch. SEC670 treats binary patching as a standalone persistence module in Section 4, alongside registry keys, services, port monitors, IFEO, and WMI event subscriptions, and frames its central benefit as survival across reboots, in contrast to in-memory hooking and unhooking which die with the process or the OS. The same primitive serves defense evasion when the target is a security product: the material names 'binaries that offer signature scanning' as patch candidates. The primary detection surfaces are Authenticode signature mismatch and file integrity monitoring, both of which the material flags as the technique's cost."

Good. Now write everything out.