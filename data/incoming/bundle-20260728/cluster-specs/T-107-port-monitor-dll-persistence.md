# Cluster Spec — T-107: Port Monitor DLL Persistence via AddMonitor

- **T-NNN ID**: `T-107`
- **Canonical name**: Port Monitor DLL Persistence via AddMonitor
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: high — Two member notes from different batches; documents a SYSTEM-privilege persistence mechanism absent from T-017.
- **would_relate_to**: ['T-017']

## Consolidated Description

SEC670 covers abusing the AddMonitor API (winspool.drv) to register a custom DLL as a
port monitor for persistence via the print spooler service (spoolsv.exe). The registered
DLL is loaded by spoolsv.exe at service startup, executing in SYSTEM privilege context.
The monitor entry persists in the registry under
HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors with the DLL path, and the spooler
service loads it on every restart. T-017's persistence suite (COM hijack, NTFS EA,
schtask, TLS callback, PhantomPersist) does not include this mechanism. Port monitor
persistence is distinct because it executes under the print spooler's SYSTEM context,
triggers on service start rather than user logon, and blends with legitimate printer
driver installation activity. The AddMonitor call itself is a privileged operation
requiring SeLoadDriverPrivilege.


## Member LGTM Notes (2)

### Note 1: Port Monitor DLL Persistence Coverage Gap
- id: `lgtm:port-monitor-persistence-gap`
- origin: atlas-exploit-dev-part10
- would_relate_to: ['T-017']
- tags: ['persistence', 'port-monitor', 'addmonitor', 'print-spooler', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part10
**Would relate to:** T-017
**Source units:** unit 21

SEC670 covers abusing the AddMonitor API to register a custom DLL as a port monitor for persistence via the print spooler service. T-017 does not document this mechanism. Port monitor persistence is a distinct entry point that executes in the spooler service context and survives reboots via registry storage under the print monitors key.

### Note 2: Port Monitor Persistence Coverage Gap
- id: `lgtm:port-monitor-persistence-coverage`
- origin: atlas-exploit-dev-part19
- would_relate_to: ['T-017']
- tags: ['persistence', 'port-monitor', 'addmonitor', 'spooler', 'system-privilege', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part19
**Would relate to:** T-017
**Source units:** unit 23, unit 24

SEC670 covers AddMonitor-based port monitor abuse as a SYSTEM-privilege persistence mechanism loaded by the print spooler service. The vault's T-017 persistence suite lists COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not include port monitor abuse. This is a well-known persistence vector with distinct registry and service-loading characteristics that would expand the persistence technique coverage.

---
Use `id: T-107`, canonical name above, and `member_notes: ['lgtm:port-monitor-persistence-gap', 'lgtm:port-monitor-persistence-coverage']`.
Cross-reference `would_relate_to`: ['T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.