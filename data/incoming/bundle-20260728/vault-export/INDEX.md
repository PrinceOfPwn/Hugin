# Technique Index

## Syscalls & API Resolution
- [T-001: RecycledGate](techniques/T001-recycled-gate.md) — Indirect syscalls via ntdll gadget (S tier)
- [T-002: Hell's/Halo's/Tartarus Gate + FreshyCalls](techniques/T002-hells-halo-tartarus-gate.md) — 4-stage SSN resolution cascade including Zw* RVA sort (S tier)
- [T-003: VEH Syscall Gate](techniques/T003-veh-gate.md) — HW breakpoint mediated syscalls (S tier)
- [T-004: PEB Walker](techniques/T004-peb-walker.md) — Manual module resolution via gs:[0x60] (A tier)
- [T-006: Phantom Stubs](techniques/T006-phantom-stubs.md) — MEM_IMAGE backed syscall stubs (A tier)

## Sleep Obfuscation
- [T-005: Ekko ROP Sleep](techniques/T005-ekko-rop-sleep.md) — 6-frame ROP chain PE encryption (S tier)

## Process Injection (14 methods)
- [T-007: Pool Party](techniques/T007-pool-party.md) — Thread pool manipulation (S tier)
- [T-008: Threadless](techniques/T008-threadless-injection.md) — Export hijack, self-restoring (A tier)
- [T-009: Process Ghosting](techniques/T009-process-ghosting.md) — Delete-pending file execution (S tier)
- [T-010: Process Herpaderping](techniques/T010-process-herpaderping.md) — File content race (A tier)
- [T-011: Dirty Vanity](techniques/T011-dirty-vanity.md) — Process reflection (A tier)
- [T-012: Early Cascade](techniques/T012-early-cascade.md) — Pre-LdrInitializeThunk APC (S tier)
- [T-013: Remaining Methods](techniques/T013-remaining-injection.md) — Hollowing, Hypnosis, WaitingThread, Mapping, Module/Func Stomp, Overloading, Vectored Overloading, Callback, Fiber, Early Bird, PE Loader
- [T-014: NtCreateUserProcess](techniques/T014-nt-create-user-process.md) — Direct NT process creation (S tier)
- [T-015: PPID Spoofing](techniques/T015-ppid-spoofing.md) — Parent PID manipulation (S tier)

## EDR Evasion (12 techniques)
- [T-016: EDR Evasion Suite](techniques/T016-edr-evasion.md) — AMSI, ETW, stack spoofing (basic + advanced multi-frame), PEB unlink, NTDLL unhook, Block-DLL, ACG, handle blocking, KiUserException StepOver, arg spoofing, proxy DLL, PE stomping

## Persistence (5 layers + 2 engines)
- [T-017: Five-Layer Persistence](techniques/T017-persistence-suite.md) — COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist + resilience monitor
- [T-018: Edo Tensei](techniques/T018-edo-tensei.md) — Polymorphic technique-stack resurrection
- [T-019: Edo Dead Drop](techniques/T019-edo-dead-drop.md) — Autonomous C2 (Google Translate, blockchain, steganography)

## Anti-Analysis
- [T-020: Anti-Analysis Suite](techniques/T020-anti-analysis.md) — Anti-VM (10 checks), API hammering (FPU/SIMD), IAT camouflage, self-deletion, Kaguya LOtL, WinHTTP download, diagnostic test harness

## Cryptography & Obfuscation
- [T-021: Crypto & Obfuscation](techniques/T021-crypto-obfuscation.md) — String obfuscation proc macro, AES-GCM+zstd, Ethereum TX signing, shellcode encoding (IPv4/IPv6/MAC/UUID/words), UAC bypass

## Networking & Protocol
- [T-022: Network Suite](techniques/T022-networking.md) — SOCKS5, HVNC, VNC/RFB, malleable C2, multi-chain vault, peer relay, HTTP poll, NT sockets, BYOVD

## Client Capabilities
- [T-023: Client Capabilities](techniques/T023-client-capabilities.md) — BOF execution, keylogger, browser hook, UAC bypass, screen capture, H.264 encoding, dirty rect, input blocker, recon, exfil, UI automation, clipboard, sysinfo, credential harvest, HTML overlay (WebView2 phishing), Win32 overlay (WDA_EXCLUDEFROMCAPTURE), cursor hider

---

## Cross-Cutting
- [Architecture Overview](architecture/overview.md) — System design, protocol, execution flow
- [Dependency Map](architecture/dependency-map.md) — Cargo features, crate dependencies
- [Rust Patterns](patterns/rust-patterns.md) — RAII guards, OnceLock singletons, DJB2, FFI patterns
- [MITRE ATT&CK Mapping](references/mitre-mapping.md) — Full technique-to-ATT&CK mapping

## Stats
- **82+ techniques** documented across 23 technique cards
- **2 crates**: dark_crystal (dropper/loader) + client_rust (RAT/C2)
- **20+ Cargo feature gates** for minimal-footprint builds
- **15 injection methods**, **13 EDR evasion techniques**, **5 persistence layers**
- **4 SSN resolution stages**: FreshyCalls, Hell's Gate, Halo's Gate, Tartarus Gate
- **3 syscall dispatch modes**: RecycledGate, VEH Gate, Direct
