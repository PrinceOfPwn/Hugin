# Cluster Spec — T-108: Registry Run/RunOnce Key Persistence

- **T-NNN ID**: `T-108`
- **Canonical name**: Registry Run/RunOnce Key Persistence
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: high — 3 member notes, most commonly used registry persistence key, cited APT usage
- **would_relate_to**: ['T-017']

## Consolidated Description

SEC670 review material explicitly identifies HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run as the most commonly used registry persistence key, with HKLM requiring administrator privileges. The RunOnce variant (...\RunOnce) executes its entries once and then deletes the value, providing single-shot persistence. T-017's five-layer persistence suite does not include Run/RunOnce despite their prevalence in real-world intrusions (SEC670 cites APT28, Emotet, APT39 as users of registry-based persistence). The HKCU\...\Run variant provides per-user persistence without elevation, making it accessible from medium-IL implant contexts. SEC670 devotes an entire module to registry-based persistence covering Run, RunOnce, RunOnceEx, and the distinction between HKLM (admin) and HKCU (user) scopes.


## Member LGTM Notes (3)

### Note 1: Registry Run Key Persistence Not in T-017 Layer Set
- id: `lgtm:gap-registry-run-key-persistence`
- origin: atlas-post-exploit-part14
- would_relate_to: ['T-017']
- tags: ['persistence', 'registry', 'run-key', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part14
**Would relate to:** T-017
**Source units:** unit 32, unit 33, unit 34, unit 35

SEC670 review questions explicitly identify the Run key as the most commonly used registry persistence key, but T-017's documented five layers do not include Run/RunOnce registry value persistence. This is the canonical Windows persistence primitive and predates the five layers T-017 covers. The vault should either add Run key as a sixth layer in T-017 or surface it as a separate technique card.

### Note 2: Registry Run/RunOnce Key Persistence
- id: `lgtm:registry-run-key-persistence-coverage-gap`
- origin: atlas-post-exploit-part16
- would_relate_to: ['T-017']
- tags: ['registry', 'run-key', 'persistence', 'coverage-gap', 'hklm']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part16
**Would relate to:** T-017
**Source units:** unit 35, unit 36, unit 37, unit 38

SEC670 Book 4 review material identifies `run` as the most commonly used registry key for persistence and notes HKLM Run-key modification requires Admin permissions. T-017 does not list Run/RunOnce registry persistence in its five-layer suite, even though it is one of the most established persistence vectors. The vault has schtask and COM hijack layers but no explicit registry Run-key technique, leaving a foundational persistence vector undocumented.

### Note 3: Registry Run/RunOnce/AppInit/AppCert Persistence Coverage Gap
- id: `lgtm:registry-persistence-coverage-gap`
- origin: atlas-post-exploit-part5
- would_relate_to: ['T-017']
- tags: ['persistence', 'registry', 'run-key', 'appinit', 'appcert', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part5
**Would relate to:** T-017
**Source units:** unit 32, unit 34, unit 36, unit 37, unit 38

SEC670 devotes an entire module to registry-based persistence covering Run keys, RunOnce/RunOnceEx, AppInit_DLLs, and AppCert DLLs, citing APT28, Emotet, APT39, CherryPicker, and T9000 as real-world users. The vault's T-017 Five-Layer Persistence card covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not include any registry-autostart technique. These four registry mechanisms are the most-used persistence methods per the material and would merit explicit T-NNN presence or expansion of T-017.

---
Use `id: T-108`, canonical name above, and `member_notes: ['lgtm:gap-registry-run-key-persistence', 'lgtm:registry-run-key-persistence-coverage-gap', 'lgtm:registry-persistence-coverage-gap']`.
Cross-reference `would_relate_to`: ['T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.