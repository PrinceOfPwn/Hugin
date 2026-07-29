# Cluster Spec — T-102: Position-Independent C Shellcode Build Pipeline and Discipline

- **T-NNN ID**: `T-102`
- **Canonical name**: Position-Independent C Shellcode Build Pipeline and Discipline
- **Proposed category**: `exploit-primitive`
- **Proposed tier**: `A`
- **Priority**: high — Four member notes from three atlas batches; fills a critical prerequisite gap for all shellcode-producing techniques.
- **would_relate_to**: ['T-013', 'T-020', 'T-021', 'T-016']

## Consolidated Description

SEC670 documents a complete methodology for producing position-independent shellcode
from C using Visual Studio compiler/linker settings: /GS- (no stack canary), /NODEFAULTLIB
(no CRT), /SUBSYSTEM:NATIVE, /NOENTRY (no default entry), custom entry point via
/ENTRY: flag, /SDL- (no security checks), and no C++ exceptions. The discipline requires
avoiding the heap (no malloc/new), avoiding external references (no imports resolved by
the loader), and avoiding the .data section (use stack-allocated constants or
runtime-resolved strings). Compiler intrinsics (__readgsqword, __readmsr) replace their
CRT-wrapped equivalents. The vault's T-020 (Anti-Analysis) and T-021 (Crypto &
Obfuscation) cover shellcode encoding formats (IPv4/IPv6/MAC/UUID/words) but do not
document the build pipeline that produces the raw shellcode bytes in the first place.
This card should be the prerequisite reference for all shellcode-emitting techniques.


## Member LGTM Notes (4)

### Note 1: Position-Independent C Shellcode Build Configuration
- id: `lgtm:pic-shellcode-build-config-coverage`
- origin: atlas-exploit-dev-part1
- would_relate_to: ['T-013', 'T-020']
- tags: ['shellcode', 'build-config', 'pic', 'visual-studio', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part1
**Would relate to:** T-013, T-020
**Source units:** unit 17

Unit 17 documents the full Visual Studio build configuration for compiling C into position-independent shellcode (/GS-, /NODEFAULTLIB, /SUBSYSTEM:NATIVE, /NOENTRY, custom entry point, /SDL-, no exceptions). The vault's shellcode is Rust-based and uses different toolchain flags, but operators who need to embed C-shellcode payloads (e.g., for tools like donut-style loaders or specific shellcode snippets) need this configuration. The vault's T-020 (Anti-Analysis Suite) and T-013 (shellcode execution) cards don't currently document the build configuration for producing the embedded shellcode blobs.

### Note 2: Position-Independent C Shellcode Build Pipeline
- id: `lgtm:pic-c-shellcode-build-pipeline`
- origin: atlas-exploit-dev-part13
- would_relate_to: ['T-021', 'T-016']
- tags: ['pic', 'shellcode', 'visual-studio', 'build-settings', 'intrinsics', 'crt-free']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part13
**Would relate to:** T-021, T-016
**Source units:** unit 25, unit 27, unit 28, unit 29, unit 30, unit 33, unit 34, unit 38

SEC670 units 25-39 document a complete methodology for producing PIC shellcode from C: Visual Studio linker/compiler settings (/GS-, /NODEFAULTLIB, /SUBSYSTEM:NATIVE, /NOENTRY, /MT, /SDL-, no exceptions), compiler intrinsics (#pragma intrinsic for memset/strcmp/__movsb), and the requirement to avoid .rdata string references. The vault's T-021 covers shellcode encoding formats and T-016 covers PE stomping, but neither documents the build-system configuration required to produce the raw PIC shellcode blob in the first place. This is a coverage gap because the build pipeline is a prerequisite for every shellcode-encoding technique in T-021.

### Note 3: Position-Independent C Shellcode with Compiler Intrinsics
- id: `lgtm:pic-c-shellcode-tradecraft`
- origin: atlas-exploit-dev-part19
- would_relate_to: ['T-021', 'T-020']
- tags: ['shellcode', 'pic', 'c', 'intrinsics', 'build-settings', 'visual-studio', 'emerging-tradecraft']

**Kind:** emerging-tradecraft
**Origin:** atlas-exploit-dev-part19
**Would relate to:** T-021, T-020
**Source units:** unit 31, unit 32, unit 33, unit 34, unit 37, unit 40

SEC670 documents a comprehensive approach to writing position-independent shellcode in C rather than assembly, covering PIC requirements (no external references, no data section references), compiler intrinsics (intrin.h, pragma intrinsic), and specific Visual Studio build settings (/NOENTRY, /NODEFAULTLIB, /GS-, /MT, /SUBSYSTEM:NATIVE, /SDL-). The vault's T-021 covers shellcode encoding (IPv4/IPv6/MAC/UUID/words) but does not document the shellcode authoring tradecraft itself — how to write self-contained PIC in a high-level language. This is foundational tradecraft that would enrich the shellcode development knowledge base.

### Note 4: Shellcode Position-Independence Discipline (No Heap, No External References)
- id: `lgtm:gap-shellcode-position-independence-discipline`
- origin: atlas-exploit-dev-part20
- would_relate_to: ['T-021', 'T-013']
- tags: ['shellcode', 'position-independence', 'heap', 'external-references', 'c-language']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part20
**Would relate to:** T-021, T-013
**Source units:** unit 1, unit 2

SEC670 explicitly identifies the heap and external references as elements to avoid when writing shellcode in C. The vault's T-021 (Crypto & Obfuscation) covers shellcode encoding formats (IPv4/IPv6/MAC/UUID/words) but does not document the C-language shellcode-authorship discipline that governs whether the resulting shellcode is genuinely position-independent. This is a foundational tradecraft gap — encoded shellcode that internally uses the heap or external references will fail in cross-process injection contexts.

---
Use `id: T-102`, canonical name above, and `member_notes: ['lgtm:pic-shellcode-build-config-coverage', 'lgtm:pic-c-shellcode-build-pipeline', 'lgtm:pic-c-shellcode-tradecraft', 'lgtm:gap-shellcode-position-independence-discipline']`.
Cross-reference `would_relate_to`: ['T-013', 'T-020', 'T-021', 'T-016'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.