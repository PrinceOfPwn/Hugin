---
id: T-069
name: DLL Export Mechanics as Injection Prerequisite
category: process-injection
tier: C
crate: none
source_file: none
mitre: T1055.001
tags: [dll-exports, declspec-dllexport, def-file, export-table, dllmain, loader-resolution, injection-prerequisite]
origin: atlas-synthesis
member_notes: [lgtm:dll-export-for-injection-surface]
---

# DLL Export Mechanics as Injection Prerequisite — How Export Table Construction Enables DLL-Based Injection

## Summary

DLL export table construction determines which entry points an injected module exposes to the loader and to any remote invoker after it maps into a target process. SEC670 presents DLL construction with exported functions as a direct enabler of process injection: the export surface is what makes a DLL callable after `LoadLibrary` completes, whether invocation happens through `DllMain`, a remote thread pointed at an export, or an export-address hijack. The choice of export method — `__declspec(dllexport)`, a module-definition `.def` file, or `extern "C"` linkage — controls name decoration, ordinal assignment, and whether loader-side resolution via `GetProcAddress` by name or ordinal succeeds at all. This card documents that prerequisite layer rather than a standalone offensive capability. The primary detection surface is module-load telemetry combined with export-name and export-count heuristics applied to the loaded image.

## Mechanism

1. The linker emits an `IMAGE_EXPORT_DIRECTORY` into the PE and stores its RVA and size in `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]` (index 0) of the optional header. The size field matters: it bounds the region in which EAT entries are interpreted as forwarder strings.
2. `__declspec(dllexport)` marks a symbol at compile time; the linker converts the mark into an Export Address Table (EAT) entry. Under C++ linkage the exported name carries the decorated form (`?Func@@YAHXZ`-style); adding `extern "C"` yields the undecorated name on x64.
3. A `.def` file `EXPORTS` section gives explicit control: the export name, the ordinal (`@N`), the `NONAME` attribute (ordinal-only export, no name string emitted), `PRIVATE`, and `DATA` for exporting variables. The linker `/EXPORT:name` flag is a third equivalent path.
4. The resulting directory contains three parallel arrays: `AddressOfFunctions` (EAT, RVAs of code), `AddressOfNames` (name pointer table, RVAs of ASCII strings), and `AddressOfNameOrdinals` (word indices mapping name position to EAT slot). `NumberOfFunctions` counts EAT entries; `NumberOfNames` counts named entries only.
5. When the loader maps the DLL — locally or inside a remote process via `LoadLibrary`/`LdrLoadDll` — it resolves the DLL's own imports, runs TLS callbacks, then calls `DllMain(DLL_PROCESS_ATTACH)` while holding the loader lock.
6. `GetProcAddress` resolves an export by binary-searching the sorted name table, indexing the ordinal array with the found position, and returning `ImageBase + EAT[index]`. Ordinal-based resolution subtracts `Base` from the ordinal and indexes the EAT directly, bypassing the name table entirely.
7. If the returned RVA falls inside the export directory's address range, it is a forwarder string (`NTDLL.RtlAllocHeap`-form) and the loader recursively loads and resolves the target.
8. Injection linkage, classic form: `CreateRemoteThread` (or `NtCreateThreadEx`) started on `LoadLibraryA`/`LdrLoadDll` with the DLL path executes `DllMain` in the target; the export table is what makes any *subsequent* step possible.
9. Injection linkage, export-invocation form: after the module maps, the operator resolves an export (by name or ordinal, remotely via `GetProcAddress` on a duplicated module handle or by parsing the export directory out-of-process) and redirects execution onto it — via a second remote thread, an APC, a thread-context hijack, or a callback registration.
10. Threadless injection (T-008) inverts the relationship: it patches the first bytes of a chosen *export* in an already-loaded module and self-restores, so the export table of the *victim* DLL is the targeting data.

## OS Internals Context

The PE specification requires the name pointer table to be sorted alphabetically; the loader's `LdrpFindExportedName` performs a binary search over it, so an unsorted table produces resolution failures that appear random to the caller. Ordinal-only exports created with `NONAME` shrink the string surface — the name table simply omits the entry while the EAT slot remains live — and `Base` (the ordinal bias, typically 1) defines the mapping between caller-supplied ordinals and EAT indices.

Name decoration is ABI-visible. On x86, `stdcall` exports acquire `_name@N` decoration and `GetProcAddress("name")` fails unless the `.def` file or a `#pragma comment(linker, "/EXPORT:...")` alias provides the undecorated alias. On x64 the single calling convention means `extern "C"` names are exported undecorated. C++ mangling makes exports unreachable by predictable string, which is sometimes desired and sometimes fatal depending on the invocation plan.

`DllMain` executes under `LdrpLoaderLock`. Inside it the module must not call `LoadLibrary`, must not call `GetProcAddress` on not-yet-initialized dependencies, and must not block on a thread it creates (thread initialization itself needs the loader lock — joining deadlocks the process). This contract is the principal reason export-invocation patterns exist: work performed from a separately-invoked export runs outside loader lock and may allocate, load further modules, and synchronize freely. Reflective loaders (T-046) replicate the loader's job manually and still must respect the same sequencing — their convention is to export a well-known entry (historically `ReflectiveLoader`) plus `DllMain`, so the export mechanics question does not disappear when the OS loader is bypassed; it is reimplemented.

WOW64 introduces a second consideration: a 32-bit DLL's exports are resolved by the 32-bit loader with 32-bit decoration rules, and architecture-mismatched modules cannot be loaded into a 64-bit process at all, which constrains which export surfaces a cross-architecture injection plan can use.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would be a build-side concern rather than a runtime module: a `cdylib` crate producing the payload DLL, exports declared with `#[no_mangle] pub extern "system" fn` (equivalent to `extern "C"` undecorated naming), optionally a build script emitting a minimal export surface with a single entry point (e.g., one `Run` export) so that loader-side resolution has exactly one target. A more aggressive variant would strip the name table entirely (ordinal-only, the `NONAME` equivalent) and hard-code the ordinal into the injector, removing export strings from memory scans at the cost of self-inflicted resolution complexity.

## Why It Matters

Every DLL-family injection method catalogued under T-013, the threadless export hijack of T-008, and the reflective loading of T-046 presuppose a correctly constructed export table; a malformed directory yields loader failure (`STATUS_INVALID_IMAGE_FORMAT`, error 0xC000007B) or an unresolvable entry point at the worst possible moment. The export surface also defines the detection surface: names, counts, and ordinals are static features visible to any scanner that parses the image. Documenting the mechanics as a prerequisite card prevents the details from being duplicated, shallowly, across every consuming technique card.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 7 (ImageLoaded) captures the DLL mapping into the target; ETW `Microsoft-Windows-Kernel-ImageLoad` and Threat-Intelligence providers expose module loads including remote-initiated ones. Static scanners parse `IMAGE_EXPORT_DIRECTORY` and flag anomalies: export names inconsistent with the DLL's claimed identity, single-export binaries, name/ordinal table mismatches.
- **Bypass options**: ordinal-only (`NONAME`) exports to remove name strings; export sets that mimic the legitimate DLL being impersonated; minimizing `DllMain` work so that module-load-time behavior matches benign DLLs; reflective loading to avoid the on-disk image entirely.
- **Residual artifacts**: the DLL file on disk for non-reflective variants, `InLoadOrderModuleLists` entries in the target PEB unless deliberately unlinked (see T-016), Prefetch and Amcache/ShimCache records of the module path.

## Related Techniques

- **T-013 Remaining Injection Methods** — callback, fiber, and PE-loader variants that consume a constructed DLL export surface as their invocation target.
- **T-008 Threadless Injection** — hijacks an export's first bytes in an already-loaded module; requires precise export-table parsing of the victim DLL.
- **T-046 Manual PE Loader and Reflective DLL Injection (sRDI)** — reimplements loader-side export resolution manually rather than relying on `GetProcAddress`.

## References

- Atlas material: atlas-exploit-dev-part14.md
- MITRE ATT&CK: T1055.001 — Dynamic-link Library Injection (https://attack.mitre.org/techniques/T1055/001/)
- LGTM notes: lgtm:dll-export-for-injection-surface

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.