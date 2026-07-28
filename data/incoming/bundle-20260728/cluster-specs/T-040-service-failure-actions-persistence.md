# Cluster Spec — T-040: SERVICE_FAILURE_ACTIONS Crash-Triggered Persistence

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-040`
- **Canonical name**: SERVICE_FAILURE_ACTIONS Crash-Triggered Persistence
- **Proposed category**: `persistence`
- **Proposed tier**: `B`
- **Priority**: medium — 4 member notes, distinct SCM-native trigger mechanism, clear recovery/resilience purpose.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-017']

## Consolidated Description (from clustering)

SERVICE_FAILURE_ACTIONS persistence via ChangeServiceConfig2 to execute recovery command when service fails. Operators force service failure to trigger recovery action. Survives reboot; SCM-monitored. Distinct from service-binary-modification persistence; provides fail-safe resilience.

## Member LGTM Notes (4)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Service Failure Actions as Persistence
- **id**: `lgtm:service-failure-actions-persistence`
- **origin**: atlas-binary-analysis-part5
- **source_units**: ['unit 8']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'scm', 'service-failure-actions', 'registry', 'system']

**Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part5
**Would relate to:** T-017
**Source units:** unit 8

SEC670 unit 8 documents the SERVICE_FAILURE_ACTIONS structure used with ChangeServiceConfig2. Operators can install a malicious recovery command that the SCM executes when a service fails — including services that fail deliberately or are forced to fail. This is a persistence vector orthogonal to T-017's existing layers and survives reboots because the failure-action configuration is stored in the service's registry entry. The vault does not currently surface this as a persistence technique.

### Note 2: SERVICE_FAILURE_ACTIONS Persistence
- **id**: `lgtm:service-failure-actions-card`
- **origin**: atlas-post-exploit-part1
- **source_units**: ['unit 12', 'unit 31']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'services', 'failure-actions', 'proposed-card']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part1
**Would relate to:** T-017
**Source units:** unit 12, unit 31

SEC670 presents SERVICE_FAILURE_ACTIONS via ChangeServiceConfig2 as a persistence vector that triggers a configured command (e.g., 'ping C2') when a service fails, evading ImagePath-based detection while still executing on a recurring schedule. The vault's T-017 persistence suite does not list service failure actions as a layer. This would merit its own card or explicit sub-entry under T-017 because it has a distinct detection signature (failure-action command execution on service crash) and distinct operational prerequisites (existing service to modify).

### Note 3: SERVICE_FAILURE_ACTIONS Abuse for Crash-Triggered Persistence
- **id**: `lgtm:service-failure-actions-as-persistence`
- **origin**: atlas-post-exploit-part11
- **source_units**: ['unit 37', 'unit 38', 'unit 39']
- **would_relate_to**: ['T-017']
- **tags**: ['scm', 'service', 'failure-actions', 'change-service-config2', 'persistence-trigger']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part11
**Would relate to:** T-017
**Source units:** unit 37, unit 38, unit 39

SEC670 documents the SERVICE_FAILURE_ACTIONS structure (set via ChangeServiceConfig2) as a mechanism to execute a binary when a service 'fails' per SCM's contract (no SERVICE_STOPPED reported or non-zero Win32ExitCode). This is a distinct persistence trigger from schtask scheduling — it is event-driven on service crash and can be deliberately triggered by terminating the service abnormally. T-017 does not currently enumerate this as a persistence layer despite its operational utility and unique trigger surface.

### Note 4: Service Failure Action as Resilience Primitive
- **id**: `lgtm:proposed-service-failure-action-resilience`
- **origin**: atlas-post-exploit-part4
- **source_units**: ['unit 32', 'unit 33']
- **would_relate_to**: ['T-017']
- **tags**: ['service', 'failure-action', 'resilience', 'scm']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part4
**Would relate to:** T-017
**Source units:** unit 32, unit 33

The material surfaces that SERVICE_WIN32_OWN_PROCESS services can be configured with failure actions (restart on failure) as a fail-safe. This pairs naturally with T-017's resilience monitor (PhantomPersist) but is distinct: failure actions are SCM-native and survive reboots where userland monitor processes do not. A dedicated technique card covering failure-action chain configuration (restart → restart → run recovery binary) would complement the existing T-017 persistence suite with a kernel-mediated resilience layer.

---

## Your Task

Produce the technique card for **T-040** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-040` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-017'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:service-failure-actions-persistence', 'lgtm:service-failure-actions-card', 'lgtm:service-failure-actions-as-persistence', 'lgtm:proposed-service-failure-action-resilience']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.