---
id: T-061
name: Registry Watchdog for Situational Awareness and AV Detection
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1518.001
mitre_secondary: [T1012]
tags: [registry-watchdog, regnotifychangekeyvalue, situational-awareness, av-detection, event-driven, configuration-manager, edr-detection]
origin: atlas-synthesis
member_notes: [lgtm:registry-watchdog-situational-awareness]
---

# Registry Watchdog for Situational Awareness and AV Detection — Event-Driven Registry Change Monitoring

## Summary

Registry watchdog monitoring uses RegNotifyChangeKeyValue to receive event-driven notifications when targeted registry keys change, allowing an implant to detect AV and EDR product installation in real time without polling. The technique exploits the Windows Configuration Manager's notify-block mechanism, which signals a caller-supplied event object whenever a change matching a REG_NOTIFY_CHANGE_* filter occurs on a watched key or its subtree. SEC670 frames this as a situational-awareness primitive pointed at HKLM\SOFTWARE\Microsoft, where vendor product keys and Defender state changes surface during security-product installation. Because the watcher blocks on an event rather than enumerating the registry on a timer, its telemetry footprint is a fraction of any polling loop. The primary detection surface is the subsequent re-enumeration performed when the event fires, plus kernel registry callbacks that can observe the notification registration itself.

## Mechanism

1. Build a baseline. Enumerate the watch target — HKLM\SOFTWARE\Microsoft for AV vendor product keys and Defender state, and optionally HKLM\SYSTEM\CurrentControlSet\Services for EDR service and driver registrations — recording the known-good subkey set into an in-memory structure.
2. Open the target key with RegOpenKeyEx, requesting KEY_NOTIFY in addition to KEY_READ. KEY_NOTIFY (0x0010) is the access right that authorizes change-notification registration on the key handle.
3. Create a synchronization event via CreateEvent. Manual-reset versus auto-reset determines whether multiple waiters can observe a single signal.
4. Register the notification with RegNotifyChangeKeyValue, passing the key handle, bWatchSubtree set to TRUE to cover descendant keys, a filter mask composed of REG_NOTIFY_CHANGE_NAME (0x1, subkey addition or deletion), REG_NOTIFY_CHANGE_LAST_SET (0x4, value writes), and REG_NOTIFY_CHANGE_SECURITY (0x8, security-descriptor changes), the event handle, and fAsynchronous set to TRUE.
5. Block a dedicated watcher thread on the event with WaitForSingleObject. The thread consumes no CPU while waiting; no timer or polling loop exists.
6. On signal, re-enumerate the watched key and diff the result against the baseline. Classify newly appeared subkeys against a vendor list (AV and EDR product keys, uninstall entries) and feed the verdict to decision logic — suspend injection, trigger self-deletion, or activate an alternate persistence layer.
7. Re-register RegNotifyChangeKeyValue immediately after handling. Each registration is single-shot; failing to re-arm leaves the watcher blind to subsequent changes.
8. OR REG_NOTIFY_THREAD_AGNOSTIC (0x10000000) into the filter mask when the notification must survive the registering thread's lifetime, so any thread can wait on the event even after the original registrant exits.

## OS Internals Context

The registry is managed in kernel space by the Configuration Manager (Cm). Each open key is represented by a CM_KEY_BODY, and calls to NtNotifyChangeKey (the syscall behind RegNotifyChangeKeyValue) attach a notify block to that body describing the event to signal and the filter mask. When a modifying operation lands on the key — subkey creation, value write, security-descriptor change — Cm walks the attached notify blocks, matches the operation against each filter, and signals the associated event objects. The watch-subtree flag causes Cm to evaluate the filter against descendant key operations as well, which is what makes a single registration on HKLM\SOFTWARE\Microsoft sufficient to observe an entire vendor installation.

The REG_NOTIFY_CHANGE_* filter semantics are precise: REG_NOTIFY_CHANGE_NAME fires on subkey add or delete, REG_NOTIFY_CHANGE_ATTRIBUTES on key attribute changes, REG_NOTIFY_CHANGE_LAST_SET on any value write (the last-write timestamp on the key updates), and REG_NOTIFY_CHANGE_SECURITY on DACL/SACL modification. An AV installer writing its product key and configuration values trips NAME and LAST_SET filters; a service-installing EDR trips NAME on the Services key.

Thread affinity is the subtle contract. By default, a notification registration is bound to the calling thread: if that thread terminates, the Configuration Manager discards its pending notify blocks and the event never fires. REG_NOTIFY_THREAD_AGNOSTIC, available since Windows Vista, severs this binding — the notify block persists independently of any thread, and the event signals whenever the change occurs. For an implant whose worker threads are short-lived or whose watchdog thread might be torn down by a sleep-obfuscation cycle, the thread-agnostic flag is what makes the watcher durable.

The asynchronous mode contract also matters: with fAsynchronous TRUE and an event handle, the call returns immediately and the caller waits on the event. With fAsynchronous FALSE and a NULL event, RegNotifyChangeKeyValue itself blocks the calling thread until a matching change — usable but inflexible, and it occupies the thread for the entire watch duration.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would follow the existing codebase conventions: resolve NtOpenKey, NtNotifyChangeKey, NtEnumerateKey, and NtWaitForSingleObject through the DJB2-hash PEB walker and dispatch them via RecycledGate, avoiding the advapi32 registry thunks entirely. A dedicated watcher thread would own the event handle, maintain the baseline key set in a HashSet, and on each signal re-enumerate, diff, re-arm the notification, and publish a status word (e.g., an AtomicU32 product-detected flag) that other modules — persistence, injection dispatch, self-delete — consult before acting.

## Why It Matters

Every other AV/EDR detection approach in the vault is point-in-time: the implant checks for security products at startup and never learns about a product installed mid-operation. The registry watchdog converts security-product detection into a continuous signal with near-zero cost — one open key handle, one event, one blocked thread. That signal gates operational decisions: whether to proceed with a noisy injection, whether a persistence layer is likely to be quarantined on write, or whether the implant should self-delete before a newly installed EDR finishes initializing its kernel sensor.

## Detection Considerations

- **Telemetry sources**: The Microsoft-Windows-Kernel-Registry ETW provider logs registry operations at high volume and is rarely collected at scale; the watcher's registration and reads are a handful of events against it. Kernel sensors using CmRegisterCallbackEx can observe NtNotifyChangeKey registration itself, including the watched key path. Sysmon event IDs 12, 13, and 14 capture the installer's registry writes — the changes that trip the filter — but not the watch.
- **Bypass options**: Watching a parent key with subtree scope (one registration) generates less telemetry than per-vendor-key registrations. Performing the post-signal diff with direct NT enumeration avoids Win32 registry API hooks.
- **Residual artifacts**: No files or registry writes by the watcher itself. The open key handle and event handle exist for the watcher's lifetime and are visible in handle-table enumeration of the process.

## Related Techniques

- **T-017 Five-Layer Persistence** — the watchdog's install-detection signal gates persistence-layer decisions, such as holding off writes likely to be quarantined.
- **T-020 Anti-Analysis Suite** — Kaguya performs a one-shot EDR/AV inventory at startup; the registry watchdog supplies the continuous complement to that point-in-time check.

## References

- Atlas material: atlas-edr-evasion-part1.md
- MITRE ATT&CK: T1518.001 (https://attack.mitre.org/techniques/T1518/001/)
- LGTM notes: lgtm:registry-watchdog-situational-awareness

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.