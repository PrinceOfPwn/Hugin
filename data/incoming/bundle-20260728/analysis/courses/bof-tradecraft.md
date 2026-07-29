---
id: RTO-bof-tradecraft
name: BOF Tradecraft
source: Red Team Ops / Zero-Point Security
category: winapi
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-023]
tags: [bof, beacon-object-file, cobalt-strike, aggressor-script, pic, position-independent-code, windows-api, in-beacon-execution]
---

# BOF Tradecraft — Training Reference

## TL;DR
This module is the introductory chapter of Zero-Point Security's "BOF Tradecraft" course, covering Beacon Object File (BOF) design and development in C/C++. The actual operational content in this chunk is limited to the course description and learning objectives — no hands-on techniques, code, or procedures are presented yet. Operators should treat this as a roadmap document: it identifies what the *full* course covers (BOF format, Windows API integration, Cobalt Strike Aggressor integration, open-source BOF porting, and PIC/BOF hybrid long-running tasks) so you know where to look when the operational chapters are ingested.

## Key Concepts
1. **Beacon Object File (BOF) Format** — A compiled-and-linked COFF object file loaded directly into the beacon's process memory by the Cobalt Strike `beacon-loader`. No standalone executable, no PE headers — just relocatable code parsed and resolved by the beacon's internal linker. Vault T-023 references BOF execution as a client capability but does not document the COFF format or relocation model — this course is the canonical source for that knowledge.
2. **Windows API via `Beacon*` / `BeaconData*` family** — BOFs cannot link against `kernel32.lib`/`ntdll.lib` directly. They use the `BeaconGetProcAddress`, `BeaconGetSpawnTo`, `BeaconDataParse`, `BeaconPrintf`, etc. APIs exposed by the beacon's `beacon.h` header to resolve Win32/NT APIs at runtime and to read arguments passed from the operator console. Vault T-023 uses BOF execution but assumes the resolution contract is already implemented by the loader.
3. **Aggressor Script Integration** — BOFs are wired into the operator UI via Aggressor (`alias`, `bexecute_assembly`, `bdangerous` opcodes, `bof_*` helpers). This is the operator-facing surface — without an Aggressor entry, the BOF cannot be invoked from the CS console. The vault has no equivalent operator-UI integration layer (client_rust uses its own protocol, see T-019/T-022).
4. **Porting Open-Source Tools to BOF** — Discipline of converting existing C/C++ tools (e.g., standalone EXEs) into COFF objects that meet the BOF contract: position-independent, no CRT, single-threaded, minimal heap, no TLS, no PE imports. The vault's T-023 has a BOF executor but does not document the *porting* methodology.
5. **PIC + BOF Hybrid Long-Running Tasks** — The advanced/off-the-beaten-path topic: combining Position-Independent Code (PIC) with BOF semantics to create tasks that run inside the beacon process beyond a single `bof_run` invocation. This directly overlaps with the vault's T-023 "in-beacon-process tasks" capability and is the area with the highest leverage for cross-reference.
6. **Cross-Platform Dev Environment** — Course expects both Linux (cross-compile via `x86_64-w64-mingw32-gcc` + `mingw-w64`) and Windows (MSVC `cl.exe` + `link.exe` with `/NOLOGO /DLL /NOENTRY /MACHINE:X64`-style flags producing COFF) toolchains. The vault's `dark_crystal` is Rust-only and does not directly produce BOFs — operators writing new BOFs against vault-loaded implants need this toolchain knowledge.

## Operational Techniques

### BOF Project Lifecycle (per course outline)
- **What**: A staged workflow from "understand the format" → "use WinAPI" → "integrate via Aggressor" → "port existing tools" → "extend open-source BOF toolkits" → "PIC hybrid long-runners".
- **When to use**: Any engagement where the implant is Cobalt Strike (or a CS-protocol-compatible C2 like Havoc, Nighthawk, Sliver-with-BOF-runner) and the operator needs single-execution tooling that does not spawn a child process.
- **How** (per course description, no code in this chunk):
  1. Write C/C++ source against `beacon.h` API contract (`BeaconPrintf`, `BeaconDataParse`, `BeaconGetProcAddress`, etc.).
  2. Compile to COFF object file (`.obj` on MSVC, `.o` on MinGW).
  3. Define Aggressor alias that wraps `bdangerous` + `barch` + `bexecute_assembly`/`bof_*` invocation.
  4. Load `.cna` in CS → invoke alias → beacon's internal loader resolves symbols, applies relocations, calls `go` entrypoint.
  5. BOF returns control to beacon; beacon frees the COFF memory region.
- **Vault link**: T-023 (Client Capabilities) — vault's BOF executor consumes pre-built COFFs over the wire protocol. The vault *executes* BOFs but does not *author* them; this course fills the authoring gap.
- **Tool/code**: `beacon.h` (CS SDK header), `mingw-w64`, `cl.exe`/`link.exe`, Aggressor `.cna` scripts. Specific compiler/linker flags are not in this chunk.
- **OPSEC**: BOFs are attractive because they execute in-process with no child process spawn — no `CreateProcess` ETW event, no `__provider_signature__` syscall telemetry beyond what the BOF itself does. Risk: beacon process will appear anomalous if the BOF makes high-volume API calls (e.g., `LDAP` queries, WMI) without OPSEC wrappers. Mitigations: short-lived execution, free memory on return, avoid calling APIs that produce per-event ETW (e.g., prefer `Ldap_search_s` style over `ADSI`).

### PIC + BOF Hybrid Long-Running Task (advanced topic per syllabus)
- **What**: Extending the BOF model past single-invocation semantics so that PIC-loaded code persists in the beacon process and continues tasking across multiple operator check-ins.
- **When to use**: Tasks too expensive to re-issue every check-in (long poll sockets, in-process keyloggers, in-process SOCKS relays, in-process beacon chaining). Also when spawning a child process is OPSEC-unacceptable.
- **How**: Not detailed in this chunk — the syllabus lists it as the final "off the beaten path" project. Operationally, the pattern is: allocate RWX/RW region inside the beacon, copy PIC blob in, install a beacon-compat callback (sleep hook, timer, or thread) that yields control to the PIC, route further tasking to the PIC via the operator protocol rather than re-executing `bof_run`.
- **Vault link**: T-023 — the vault's client_rust is a long-running implant and uses BOF execution as one capability; the PIC-hybrid pattern is conceptually how an operator would embed a sub-implant inside a CS beacon. T-019 (Network Suite) peer relay (juubi) and SOCKS5 (kamui) modules are the vault-side equivalent of "in-beacon long-running tasks" but implemented natively in Rust rather than as PIC.
- **Tool/code**: Not provided in this chunk.
- **OPSEC**: Highest OPSEC risk profile in the course. Persistent in-process code means beacon memory is non-volatile across check-ins — scanners that compare beacon image regions against disk will flag the resident PIC blob. Mitigations: load PIC into a region backed by a legitimate module (module stomping — vault T-013/T-009), use Ekko-style (T-005) encryption between callbacks, unhook on completion.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `beacon.h` | CS-provided BOF API header; defines `Beacon*` family (output, data parsing, API resolution, token, spawn-to). | Header itself has no OPSEC impact; calls made through resolved APIs inherit those APIs' telemetry. |
| `cl.exe` + `link.exe` (MSVC) | Produces 64-bit COFF `.obj` files for BOF use. | Compile-time only; no on-target footprint. Use `/O1` for size, suppress CRT linkage. |
| `x86_64-w64-mingw32-gcc` (MinGW-w64) | Cross-compile BOFs from Linux. | Cross-compile workflow enables dev on operator's preferred OS; produced COFFs are equivalent to MSVC output. Watch for mingw-specific CRT dependencies (`__main`, `_initterm`) that must be stubbed. |
| Aggressor (`.cna`) | Operator-UI glue: `alias`, `bexecute_assembly`, `bdangerous`, argument marshalling to BOF. | Aggressor activity is logged in the team server's `aggressor.log` — treat as audit trail. |
| Cobalt Strike team server | Hosts BOFs and serves them to beacons on request. | BOF objects are stored on the team server filesystem — recoverable on team-server compromise. |
| Havoc / Nighthawk / Sliver | Non-CS C2 frameworks with BOF-runner compatibility. | BOFs authored per CS contract are largely portable; framework-specific `beacon.h` equivalents must be checked for divergence (`Beacon*` API surface is not standardized). |

## Gaps & Extensions

**What the vault covers that this training does not (in this chunk):**
- T-023 documents an in-process BOF executor inside client_rust that fetches COFF objects over the C2 protocol and executes them — the vault implements the *runtime*; this course (per syllabus) implements the *authoring*.
- T-019 (Network Suite) covers in-beacon long-running tasks (SOCKS5 `kamui`, peer relay `juubi`, HTTP long-poll `http_poll_transport`) that the course only gestures at as the "advanced PIC hybrid" topic.
- T-005 (Ekko ROP Sleep), T-001 (RecycledGate), T-002 (VEH Gate), T-003 (Halo's/Tartarus) — syscall/sleep obfuscation primitives the course does not cover but which a BOF author needs to be aware of when BOFs make sensitive syscalls (the BOF inherits the beacon's syscall posture; a beacon using direct syscalls will route BOF-triggered NT calls through them, while a beacon using Win32 will expose the BOF's calls to userland hooking).

**What this training covers that the vault does not:**
- COFF format internals, relocation tables, symbol resolution contract — foundational to *authoring* BOFs; the vault only *consumes* them.
- Aggressor script integration — the vault has no operator-UI layer (its protocol is binary, see T-019 `protocol.rs`).
- Cross-platform dev toolchain specifics (MSVC vs MinGW COFF emission differences, CRT-free linking).
- Methodology for *porting* existing open-source tools to BOF format — this is high-value operational knowledge absent from the vault.

**Specific high-leverage areas to ingest from subsequent chapters (not in this chunk):**
- The exact `Beacon*` API surface and semantics.
- COFF section types (`.text`, `.data`, `.rdata`, `.bss`, `.pdata`, `.xdata`) and how the beacon's loader handles each.
- Relocation record format (`IMAGE_REL_AMD64_REL32`, `IMAGE_REL_AMD64_ADDR64`, etc.) and limitations.
- Aggressor argument-marshalling format (binary blob: `<int32 arg-count> <arg-type> <arg-data>...`).
- The PIC + BOF hybrid implementation pattern — this is the single most valuable chapter for vault cross-reference, since it would let operators embed vault's `dark_crystal` loader chain inside a CS beacon rather than as a separate payload.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| BOF format / COFF authoring | T-023 Client Capabilities (BOF execution) | Vault consumes BOFs; training teaches how to author them. Complementary, non-overlapping. |
| `Beacon*` API runtime resolution | T-004 PEB Walker | Different concerns: `Beacon*` resolves APIs inside the beacon process via the CS-provided resolver; PEB Walker (T-004) resolves modules via `gs:[0x60]` for direct syscall pipelines. A BOF could in principle use PEB-walk resolution if it wanted to bypass the beacon's API resolution, but this is non-idiomatic. |
| Aggressor script operator UI | (none) | Vault has no operator-UI layer — protocol is binary operator→implant. Gap to acknowledge. |
| Porting open-source tools to BOF | T-013 Remaining Methods (Reflective PE loader, callback exec, fiber exec) | Both involve executing externally-supplied code in-process, but BOFs are a tighter, beacon-coupled contract vs. the vault's general-purpose loaders. |
| PIC + BOF hybrid long-running tasks | T-022 Network Suite (long-poll, peer relay, SOCKS5); T-023 client_rust long-running FSM | Conceptual parallel: both implement "in-implant long-running task". Vault implements natively in Rust; course describes how to achieve the same inside a CS beacon using PIC. The hybrid pattern is how an operator would *bridge* vault-loaded dark_crystal with CS-loaded BOFs. |
| Cross-compile toolchain (MinGW/MSVC) | (none — vault is Rust-only) | Toolchain gap. Operators bridging BOF authoring with the vault need to maintain a separate C/C++ toolchain alongside `cargo`. |
| CRT-free, single-threaded, no-TLS constraint | T-020 Anti-Analysis (IAT camouflage), T-016 EDR Evasion (PE stomping) | Vault's evasion suite has analogous "minimize footprint" concerns but applied to full PEs, not COFFs. The discipline transfers. |
| Beacon memory region as execution substrate | T-008 Threadless Injection, T-013 Module Stomping | Threadless/Module Stomp load code into existing module memory; BOF loads into beacon-process heap. Both are "in-process non-PE-backed execution" — operators should recognize them as the same class of technique. |

---

**Note on chunk coverage**: This chunk contains only the course welcome/disclaimer and course description. The operational chapters (BOF format internals, WinAPI integration, Aggressor scripting, porting methodology, PIC hybrid) are *not present* in this batch. The above document is a roadmap — it identifies what the full course covers and how each topic relates to the vault, but does not extract specific commands, code, or procedures because none are present in the source material. When subsequent chunks are ingested, this document should be extended with the actual technique steps, exact `Beacon*` API signatures, compiler/linker flag values, and Aggressor argument-marshalling format.