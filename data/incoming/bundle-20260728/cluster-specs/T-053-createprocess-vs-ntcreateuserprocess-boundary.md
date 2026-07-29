# Cluster Spec — T-053: CreateProcess vs NtCreateUserProcess Policy Boundary

- **T-NNN ID**: `T-053`
- **Canonical name**: CreateProcess vs NtCreateUserProcess Policy Boundary
- **Proposed category**: `discovery`
- **Proposed tier**: `B`
- **Priority**: low — Singleton methodology note, policy comparison rather than discrete offensive technique.
- **would_relate_to**: ['T-014', 'T-015', 'T-013', 'T-016']

## Consolidated Description

CreateProcess is Win32 wrapper including STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS for PPID spoofing. NtCreateUserProcess is direct NT path with different policy boundaries. Understanding both paths informs process creation strategy and policy interactions.

## Member LGTM Notes (1)

### Note 1: CreateProcess vs NtCreateUserProcess Policy Boundary
- id: `lgtm:createprocess-vs-ntcreateuserprocess-policy-boundary`
- origin: atlas-binary-analysis-part6
- would_relate_to: ['T-014', 'T-015', 'T-013', 'T-016']
- tags: ['createprocess', 'ntcreateuserprocess', 'ppid-spoofing', 'policy-boundary', 'win32-vs-nt', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part6
**Would relate to:** T-014, T-015, T-013, T-016
**Source units:** unit 16, unit 17, unit 19

The unit walks through CreateProcess as the Win32 wrapper, including STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as the Win32 path to PPID spoofing. The vault has T-014 NtCreateUserProcess and T-015 PPID Spoofing as separate cards but no explicit treatment of the policy boundary between the Win32 layer (which applies mitigation inheritance, block-dll policy, and parent-process validation) and the NT layer (which skips these). A proposed card documenting the policy delta would clarify when an operator should choose NT direct vs the Win32 wrapper.

---
Use `id: T-053`, canonical name above, and `member_notes: ['lgtm:createprocess-vs-ntcreateuserprocess-policy-boundary']`.
Cross-reference `would_relate_to`: ['T-014', 'T-015', 'T-013', 'T-016'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.