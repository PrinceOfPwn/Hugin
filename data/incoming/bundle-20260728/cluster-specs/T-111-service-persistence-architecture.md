# Cluster Spec — T-111: Windows Service Architecture and Failure-Action Persistence

- **T-NNN ID**: `T-111`
- **Canonical name**: Windows Service Architecture and Failure-Action Persistence
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: high — Two member notes from different batches; documents a SYSTEM-privilege persistence mechanism with auto-restart resilience absent from T-017.
- **would_relate_to**: ['T-017']

## Consolidated Description

SEC670 documents the three-component Windows service architecture required to construct
a functional service: the main thread (calling StartServiceCtrlDispatcher with a
SERVICE_TABLE_ENTRY), the service thread (the actual ServiceMain callback), and the
control handler (registered via RegisterServiceCtrlHandler for
SERVICE_CONTROL_STOP/PAUSE/CONTINUE events). For persistence resilience, the
SERVICE_FAILURE_ACTIONS structure is set via ChangeServiceConfig2 with
SERVICE_CONFIG_FAILURE_ACTIONS, specifying SC_ACTION_RESTART with a delay (e.g., 60
seconds) — ensuring the service auto-restarts on failure and thus survives
termination. The vault's T-017 documents PhantomPersist with a 30-minute resilience
monitor but does not document the service architecture or the failure-action
mechanism. A card should document the service registration sequence (CreateService →
StartServiceCtrlDispatcher → RegisterServiceCtrlHandler → SetServiceStatus), the
ChangeServiceConfig2 failure-action API, and how the auto-restart creates a
self-healing persistence layer.


## Member LGTM Notes (2)

### Note 1: Service-Based Persistence Architecture Coverage
- id: `lgtm:windows-service-persistence-coverage`
- origin: atlas-exploit-dev-part18
- would_relate_to: ['T-017']
- tags: ['persistence', 'service', 'scm', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part18
**Would relate to:** T-017
**Source units:** unit 34

SEC670 Unit 34 documents the three-component service architecture (main thread, service thread, control handler via RegisterServiceCtrlHandler) required to construct a Windows service. The vault's T-017 persistence suite covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist — but does not surface a service-install persistence variant or the SCM-handler-registered-then-service-thread-runs-payload pattern. Service persistence is operationally distinct from schtask and survives reboots under a different SCM-controlled lifecycle.

### Note 2: Service Failure Actions for Persistence Resilience
- id: `lgtm:service-failure-actions-resilience`
- origin: atlas-exploit-dev-part19
- would_relate_to: ['T-017']
- tags: ['persistence', 'resilience', 'service-failure-actions', 'changeserviceconfig2', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part19
**Would relate to:** T-017
**Source units:** unit 19

SEC670 documents SERVICE_FAILURE_ACTIONS via ChangeServiceConfig2 as a mechanism to auto-restart services on failure, ensuring persistence survives termination. The vault's T-017 documents PhantomPersist with a 30-minute resilience monitor but does not cover the native Windows service failure action mechanism. This is a complementary resilience approach — service-level auto-restart is built into the SCM and does not require a separate monitor process.

---
Use `id: T-111`, canonical name above, and `member_notes: ['lgtm:windows-service-persistence-coverage', 'lgtm:service-failure-actions-resilience']`.
Cross-reference `would_relate_to`: ['T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.