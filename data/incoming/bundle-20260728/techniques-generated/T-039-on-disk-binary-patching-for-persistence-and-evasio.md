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

# On-Disk Binary Patching — Persistence and Evasion via PE Modification at Rest

## Summary

On-disk binary patching modifies a PE file at rest — inserting shellcode into code caves, patching the import table, altering the resource section, or extending a section — so that the file's normal load path executes attacker logic on every subsequent launch without any new artifact being created. SEC670 treats binary patching as a standalone persistence module in Section 4 ("Persistence: Die Another Day"), listed alongside registry keys, services, port monitors, IFEO, and WMI event subscriptions, and frames its central benefit as survival across reboots — in contrast to in-memory hooking and unhooking, which die with the process or the OS. The same primitive serves defense evasion when the target is a security product: the material names "binaries that offer signature scanning" as patch candidates, including system DLLs such as Ntdll.dll. The primary detection surfaces are Authenticode signature mismatch and file integrity monitoring, both of which the material identifies as the technique's inherent cost.

## Mechanism

1. **Select the target binary.** Two target classes appear in the material: third-party binaries and DLLs loaded by applications or the OS on a predictable trigger (persistence), and "the binaries that offer signature scanning" — security-product executables and libraries (evasion). The selection criterion is that the file must be loaded or executed after the patch without further operator action: a service binary, a DLL in an application's load path, or a logon-triggered executable.
2. **Obtain write access.** The material conditions the technique on having "the proper permissions." Files under `%SystemRoot%\System32` carry ACLs that grant full control to TrustedInstaller and read/execute to Administrators; patching them requires an ownership and ACL change first. Third-party binaries under `Program Files` or per-user install locations frequently grant the installing user or Administrators direct write access, making them the lower-friction target class.
3. **Parse the PE on disk.** Read `IMAGE_DOS_HEADER`, verify `e_magic` is `0x5A4D` ("MZ"), follow `e_lfanew` to the NT headers, and walk the `IMAGE_SECTION_HEADER` table. The atlas material presents PE format parsing as a loader prerequisite skill — the same parsing drives patch-site selection.
4. **Choose an insertion strategy.** The cluster notes name three, plus one verified in the existing vault:
   - **Code-cave shellcode insertion.** Because `FileAlignment` (typically 0x200) rounds each section's raw data, the tail of a section on disk is frequently zero padding; signed Microsoft binaries often carry additional alignment slack. Write a position-independent stub into the cave, then repoint a call site, an IAT-invoked function, or `AddressOfEntryPoint` to the cave.
   - **Import-table patching.** Add an `IMAGE_IMPORT_DESCRIPTOR` naming an attacker-controlled DLL so the loader maps it whenever the binary loads, or overwrite a `FirstThunk` entry to redirect a single imported call.
   - **Resource-section modification.** Embed a payload as raw resource data in `.rsrc` and patch code to retrieve it via `FindResource`/`LoadResource` and execute it.
   - **Section extension.** Grow the final section's `SizeOfRawData` and `VirtualSize` and append the stub plus any new data-directory content. T-017 Layer 4 uses this variant to append a TLS directory and callback array to a third-party DLL.
5. **Fix up the headers.** Update `SizeOfImage` when section virtual extents change, set `IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ` on any section made executable, add or repoint the relevant data-directory entry (import, TLS, resource), and adjust `AddressOfEntryPoint` when entry-point redirection is used.
6. **Write the modified image back in place**, replacing the original file. The material poses undo-ability as an open operational question — "Is there a way to undo your changes if you accidentally break something with your patch?" — which in practice means retaining a copy of the original bytes before overwriting.
7. **Wait for natural load.** Execution occurs on the next reboot, service start, application launch, or DLL load of the patched file. The hook persists because the file itself carries the modification; no registry key, task, or service entry is required.

## OS Internals Context

The internals surface that defines this technique is the gap between what the Windows loader enforces and what external verifiers check. Authenticode signs the file image as hashed per the signing specification, which excludes the `CheckSum` field, the security-directory entry, and the embedded certificate blob itself; any modification to `.text`, the section table, or appended data invalidates the signature. However, the user-mode loader does not verify Authenticode when mapping a DLL — `LoadLibrary` and the SEC_IMAGE section creation path map the file without consulting its signature. A patched binary therefore still loads and executes normally. Signature enforcement exists only in specific lanes: kernel drivers pass through Code Integrity, and processes holding a `ProcessSignaturePolicy` mitigation (Microsoft-signed-only) refuse to load DLLs whose signatures fail — meaning a patched system DLL will be rejected by exactly those hardened processes while loading everywhere else. Detection is thus deferred to verifiers outside the load path: signature-checking tools and file integrity monitors.

The material frames a second internals question directly: "Are files on disk better protected from patching than their memory mapped image?" The two are protected by different mechanisms. A normally loaded DLL is backed by an SEC_IMAGE section; writes to its pages trigger copy-on-write, so in-memory patching never propagates to the file and evaporates at reboot or reload. The file at rest is guarded by ACLs and, for system binaries, Windows Resource Protection, which verifies system files against component-store hashes. Defeating one layer says nothing about the other — but the on-disk layer is the only one whose effect survives a reboot, which is the property the material identifies as the reason to accept its risks.

Ntdll.dll illustrates the cascading profile the material warns about. Ntdll is a KnownDll: at boot, smss.exe creates the `\KnownDlls\ntdll.dll` section from the on-disk file, and every user-mode process maps that section. A patched on-disk ntdll therefore propagates to every process after the next reboot — the payoff for persistent unhooking or AV blinding — but a malformed patch has the symmetric effect: every process mapping the corrupted image misbehaves or crashes, and corruption severe enough to break process initialization renders the system unbootable. The material summarizes this as "Should survive reboots; cascading effect" and asks whether patching system files could render the system unstable — it can, and the blast radius scales with how early and how widely the target loads.

## Key Implementation Details

**No current implementation in the HUGIN source.** The source files matched to this cluster were verified and do not implement the technique: `dark_crystal/crowd/src/byovd.rs` drops a new driver file and force-deletes EDR files via IOCTL (file creation and deletion, not in-place modification), `dark_crystal/crowd/src/chain.rs` orchestrates injection and delegates persistence to `persist::install_all` without itself touching on-disk PE content, and `payload_cfg.rs` holds compile-time constants. This card documents the technique for future implementation; the atlas material presents it in C/C++ terms within SEC670's tool-development labs.

The nearest existing implementation is T-017 Layer 4 in `dark_crystal/crowd/src/persist/tls_cb.rs`, which performs one specific instance of on-disk binary patching: it modifies a third-party DLL on disk, extends the last PE section to fit a PIC x64 stub plus a TLS directory and callback array, and has the stub check a mutex via `OpenEventA` before executing. A general implementation would reuse a PE parser to locate cave runs (0x00/0xCC slack of at least stub size within section raw data), a position-independent stub with a re-entry guard of the same style, header fixup for `SizeOfImage`, section characteristics, and the relevant data directory, and an original-bytes backup to answer the undo question the material raises.

## Why It Matters

This technique earns its own card because it is the only vault entry covering persistence by *modification of an existing artifact at rest* rather than creation of a new one: module stomping and function stomping operate in memory, proxy DLL loading plants a new file, and every T-017 layer except TLS-callback registers a new trigger (COM entry, EA, task, restart registration). It is also the on-disk counterpart to in-memory NTDLL unhooking — the material explicitly contrasts the two on reboot survival — and the only entry covering offensive modification of security-product binaries to disable signature scanning. Its operational trade-offs (undo difficulty, system instability, heightened file-integrity exposure) are distinct from every existing persistence layer, which is why SEC670 grants it a standalone module.

## Detection Considerations

- **Telemetry sources**: The material names two directly. First, signature mismatch: any content change invalidates the patched file's Authenticode signature, exposing the modification to signature-verification tooling even though the loader itself tolerates it. Second, file integrity monitoring: the material asks "Could you get caught faster by patching files on disk?" and answers by implication — a modified file at rest is re-scanned on every AV pass and FIM sweep, whereas an in-memory patch is only observable during the process lifetime. For WRP-protected system files, integrity verification against component-store hashes provides a third channel.
- **Bypass options**: The material's guidance is target selection rather than concealment: prefer third-party binaries over system files, avoiding WRP coverage, ownership changes, and the cascading instability risk entirely. It presents no byte-level stealth measures for the patch itself.
- **Residual artifacts**: modified file content and hash, an invalidated digital signature, changed file size when a section is extended, ACL and ownership modifications if a protected system file was targeted, and any operator-retained backup copy of the original binary.

## Related Techniques

- **T-017 Five-Layer Persistence with Resilience Monitor** — Layer 4 (TLS callback injection) is a specific, implemented instance of on-disk binary patching (last-section extension on a third-party DLL); T-039 documents the general primitive and its additional variants (code cave, import table, resource section) that T-017 does not use.
- **T-006 Phantom Stubs** — both techniques derive cover from Microsoft-signed binaries, but in opposite domains: T-006 maps a signed DLL via SEC_IMAGE to give in-memory syscall stubs a MEM_IMAGE backing, while T-039 modifies a signed file at rest and thereby breaks the signature T-006 relies on.
- **T-021 Cryptography and Obfuscation** — supplies the shellcode encodings (IPv4, IPv6, MAC, UUID, dictionary-word formats) applicable to the stub inserted into a cave or appended section; T-021 governs how inserted content is encoded, T-039 governs where it is placed.

## References

- Atlas material: atlas-exploit-dev-part22.md (unit 17), atlas-methodology-part8.md (units 16–22), atlas-post-exploit-part11.md (unit 19)
- MITRE ATT&CK: T1554 Compromise Host Software Binary — https://attack.mitre.org/techniques/T1554/
- LGTM notes: lgtm:proposed-binary-patching-technique, lgtm:proposed-technique-binary-patching-persistence, lgtm:on-disk-patching-system-dlls
- Public references: SANS SEC670, Book 4 "Persistence: Die Another Day" — Binary Patching module (named in the atlas material)

## Source Reference

No current implementation. The nearest existing implementation is the TLS-callback PE modifier in `dark_crystal/crowd/src/persist/tls_cb.rs`, documented under T-017 Layer 4. See atlas material and the MITRE reference for the technique's public treatment.