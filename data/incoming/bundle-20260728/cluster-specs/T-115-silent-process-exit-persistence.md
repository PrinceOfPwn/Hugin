# Cluster Spec — T-115: SilentProcessExit Registry Persistence

- **T-NNN ID**: `T-115`
- **Canonical name**: SilentProcessExit Registry Persistence
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: medium — 2 member notes, named technique with dedicated lab exercise, fills a distinct event-driven gap
- **would_relate_to**: ['T-017']

## Consolidated Description

SilentProcessExit is a registry-driven persistence mechanism triggered when a monitored process terminates, using the GlobalFlag value in HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<binary>\GlobalFlag to enable silent process exit monitoring, and HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<binary>\ReportingMode and MonitorProcess values to specify the action on exit. SEC670's Lab 4.3 covers this as a paired variant of IFEO Debugger persistence — the Debugger value triggers on launch, SilentProcessExit triggers on termination. T-017's five-layer suite (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) does not document this mechanism. The GFlags-based enablement is shared with the IFEO Debugger variant, making the two operationally complementary for launch-and-exit coverage.


## Member LGTM Notes (2)

### Note 1: SilentProcessExit as a Persistence Vector
- id: `lgtm:silent-process-exit-persistence`
- origin: atlas-post-exploit-part13
- would_relate_to: ['T-017']
- tags: ['persistence', 'silent-process-exit', 'registry', 'process-termination']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part13
**Would relate to:** T-017
**Source units:** unit 1, unit 2, unit 3, unit 4, unit 5, unit 6

SEC670 identifies SilentProcessExit as a registry key for monitoring process termination. The vault's T-017 (Five-Layer Persistence) covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not explicitly document SilentProcessExit-based persistence. This is a distinct persistence vector where process exit events trigger configurable follow-up actions, operating on a different trigger mechanism than the existing five layers.

### Note 2: IFEO Persistence Coverage Gap
- id: `lgtm:ifeo-persistence-coverage-gap`
- origin: atlas-post-exploit-part17
- would_relate_to: ['T-017']
- tags: ['persistence', 'ifeo', 'debugger', 'silent-process-exit', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part17
**Would relate to:** T-017
**Source units:** unit 4, unit 5, unit 6, unit 7

SEC670 covers IFEO persistence in two variants — the Debugger process-start trigger and the SilentProcessExit variant — as a dedicated lab (Lab 4.3 IFEOPersisto). The HUGIN T-017 persistence card does not document IFEO as one of its five persistence layers. IFEO persistence is a high-prevalence, low-complexity persistence mechanism that would fit naturally alongside COM hijack and schtask in the persistence suite.

---
Use `id: T-115`, canonical name above, and `member_notes: ['lgtm:silent-process-exit-persistence', 'lgtm:ifeo-persistence-coverage-gap']`.
Cross-reference `would_relate_to`: ['T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.