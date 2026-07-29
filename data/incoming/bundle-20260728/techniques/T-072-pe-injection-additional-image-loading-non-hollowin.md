---
id: T-072
name: 'PE Injection: Additional Image Loading (Non-Hollowing)'
category: process-injection
tier: B
crate: none
source_file: none
mitre: T1055.002
tags: [pe-injection, additive-injection, non-hollowing, process-injection, manual-mapping, remote-image-load, memory-execution]
origin: atlas-synthesis
member_notes: [lgtm:pe-injection-additional-image-card]
---

# PE Injection: Additional Image Loading (Non-Hollowing) — Load a Second PE into a Live Process

## Summary

PE Injection, as distinguished from process hollowing in SEC670, loads an additional PE image into a target process without unmapping or replacing the original executable. The technique exploits the fact that Windows places no constraint on how many PE-formatted images a process address space may contain — only the loader-maintained module lists track the "official" set. Operators use it when the host process must remain intact and functional: the original binary stays mapped, its entry point and sections unmodified, while the injected image executes alongside it. The primary detection surface is the coexistence of two executable code regions in one process, where the second is either MEM_PRIVATE memory containing PE structure or MEM_IMAGE memory absent from the PEB loader lists.

## Mechanism

1. Open the target process via NtOpenProcess with PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_VM_READ, plus an execution right (PROCESS_CREATE_THREAD for a new thread, or thread suspend/set-context rights for hijack-based entry).
2. Parse the payload PE locally: read IMAGE_NT_HEADERS64 to obtain OptionalHeader.SizeOfImage, SizeOfHeaders, ImageBase, AddressOfEntryPoint, and the data directories; walk the section table following the optional header.
3. Allocate memory in the target with NtAllocateVirtualMemory, size equal to SizeOfImage, MEM_COMMIT | MEM_RESERVE. The base is wherever the allocator places it — unlike hollowing, there is no requirement to land at the payload's preferred ImageBase, because the host image already occupies its own base.
4. Write the PE headers (SizeOfHeaders bytes) to the remote base via NtWriteVirtualMemory.
5. For each IMAGE_SECTION_HEADER, copy RawSize bytes from PointerToRawData to remote_base + VirtualAddress.
6. Apply base relocations: compute delta = remote_base − OptionalHeader.ImageBase, walk the IMAGE_DIRECTORY_ENTRY_BASERELOC blocks, and patch each IMAGE_REL_BASED_DIR64 entry in the remote image.
7. Resolve imports: walk IMAGE_DIRECTORY_ENTRY_IMPORT descriptors. For system DLLs, per-boot ASLR guarantees identical bases across processes, so addresses resolved locally (via export-table walking) are valid in the target; write them into the remote IAT at FirstThunk. Non-system dependencies require either a remote LoadLibraryW bootstrap call or recursive manual mapping.
8. Process TLS callbacks and delay-load descriptors if the payload requires them; shellcode-grade payloads typically skip this.
9. Set final per-section memory protections with NtProtectVirtualMemory (RW for .data, RX for .text), then NtFlushInstructionCache on any pages transitioned from writable to executable.
10. Trigger execution at remote_base + AddressOfEntryPoint, either by creating a thread (NtCreateThreadEx) or by redirecting an existing thread (CONTEXT modification or APC).
11. Leave the host image untouched: no NtUnmapViewOfSection, no PEB.ImageBaseAddress rewrite, no loader-list modification. The host resumes or continues normally.

## OS Internals Context

The loader tracks legitimately loaded images through three doubly-linked lists in the PEB (InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList), each entry an LDR_DATA_TABLE_ENTRY. A manually mapped PE never receives an entry and is therefore invisible to EnumProcessModules and to any consumer of the loader lists — but also to legitimate unloaded-image bookkeeping, which is precisely the anomaly memory scanners look for. The memory classification determines the specific tell: an image delivered through NtAllocateVirtualMemory lives in MEM_PRIVATE pages and trips private-executable-memory heuristics; an image delivered through NtCreateSection with SEC_IMAGE followed by NtMapViewOfSection is MEM_IMAGE but unbacked by a loader entry, and requires the payload to exist as a file object (on disk, in an ADS, or in a delete-pending state — the delivery tricks documented in T-009 and T-010).

Relocations are mandatory in the additive case. Hollowing reuses the host's preferred base, so a payload with a stripped .reloc directory can work if written at that base; additive injection lands at an arbitrary ASLR-assigned address, so DIR64 fixups must be applied or the payload must be position-independent. Import resolution relies on the Windows per-boot ASLR model: kernel32, ntdll, and user32 load at identical bases in every process until reboot, making locally resolved export addresses directly usable in the remote IAT for system modules only.

The structural contrast with hollowing (bundled under T-013) defines the detection tradeoff. Hollowing unmaps the suspended host's image, writes the payload at the same base, and patches PEB.ImageBaseAddress — producing one image whose on-disk path no longer matches in-memory content. Additive injection produces a fully consistent host plus a second, unlisted code region. The hollowed-process heuristic (image path/base mismatch, modified original entry point) never fires; instead the two-image presence and loader-list inconsistency are the observable artifacts.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would assemble existing HUGIN components: the header/section parsing and relocation logic from `src/dark_crystal/crowd/src/pe_loader.rs` (currently used for in-process reflective loading), retargeted to a remote process via RecycledGate-routed NtAllocateVirtualMemory/NtWriteVirtualMemory calls; system-DLL import patching using addresses resolved by the T-002/T-050 walkers; and execution through `waiting_thread.rs` context redirection or `early_cascade.rs` APC dispatch rather than a new thread. None of the three source files provided with this cluster (browser_session.rs, fsm.rs, waiting_thread.rs) implement additive remote PE loading.

## Why It Matters

The vault's T-013 enumerates hollowing among the remaining injection methods but does not distinguish the additive variant, which SEC670 treats as a separate technique with a different operational profile: the host process remains stable and observable, there is no suspended-process window during setup, and the payload image can be re-entered after its first execution completes. The detection profile is correspondingly different — no image-path mismatch heuristic applies, and defenders must instead catch the loader-list-inconsistent image or the cross-process write sequence. Separating the two prevents operators from reasoning about one with the other's tradeoffs.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 8 (CreateRemoteThread) if execution uses a new thread; Sysmon Event ID 10 (ProcessAccess) for the handle acquisition; ETW Threat Intelligence cross-process NtAllocateVirtualMemory / NtWriteVirtualMemory / NtProtectVirtualMemory chains. Kernel image-load callbacks (PsSetLoadImageNotifyRoutine) do not fire for the private-memory variant because no SEC_IMAGE section backed by a real file is created by the loader.
- **Bypass options**: deliver the image as SEC_IMAGE from a legitimately named file (sacrificing the fileless property), stomp the DOS/NT headers after relocation and import resolution complete, reuse an existing thread for execution to avoid Sysmon 8, and encrypt sections between periods of use.
- **Residual artifacts**: the payload pages persist for the host's lifetime and are recoverable by memory acquisition; if SEC_IMAGE-backed, the backing file path or its delete-pending state is a disk-side artifact.

## Related Techniques

- **T-013 Remaining Injection Methods** — hollowing, the subtractive counterpart: same remote-image-writing mechanics, opposite treatment of the host image.
- **T-046 Manual PE Loader and Reflective DLL Injection** — the in-process analogue; identical parsing/relocation/import mechanics applied to the loader's own address space rather than a remote target.

## References

- Atlas material: atlas-exploit-dev-part19.md
- MITRE ATT&CK: [T1055.002 — Process Injection: Portable Executable Injection](https://attack.mitre.org/techniques/T1055/002/)
- LGTM notes: lgtm:pe-injection-additional-image-card

## Source Reference

No current implementation. Closest substrate for a future implementation: `src/dark_crystal/crowd/src/pe_loader.rs` (local PE mapping), `src/dark_crystal/crowd/src/mapping_inject.rs` (remote section mapping), `src/dark_crystal/crowd/src/waiting_thread.rs` (execution trigger).