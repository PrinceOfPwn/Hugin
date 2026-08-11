---
id: T-152
title: "C2 Check-in Loop with Jittered Sleep and JSON Tasking"
category: networking
tier: A
tags: ['c2-tasking-loop-jittered-sleep']
mitre: ["T-022","T-005"]
origin: glm-expand-cluster
source_cluster: c2-tasking-loop-jittered-sleep
member_notes: ["lgtm:c2-tasking-loop-and-jitter-tradecraft"]
---
## Summary

This technique covers C2 Check-in Loop with Jittered Sleep and JSON Tasking. It addresses a gap in knowledge for red-team operations related to networking.

## Technical Deep Dive

SEC670 units 12-14 document the implant check-in loop (while/try/catch/sleep with
jittered interval) and the JSON tasking protocol: UUID-based task IDs, CheckTasks
request parsing, RunTask execution dispatch, and result reporting back to the C2. The
jitter pattern adds ±N% randomness to the base sleep interval to defeat beacon-
timing analysis. The vault's T-022 documents HTTP transport (WinHTTP-based download)
but does not document the tasking loop, the jitter algorithm, or the JSON protocol
structure. A card should document the check-in state machine (initial check-in → task
poll → task execute → result report → sleep(jitter) → repeat), the jitter calculation
(base_interval * (1 ± random(0, jitter_pct))), the JSON schema for task requests and
responses, and the relationship to T-005 (Sleep Obfuscation), which must integrate with
the jittered sleep interval.


Technical anchor details:
```text
Check-in loop: while(true) { CheckTasks(UUID) → RunTask → ReportResult → Sleep(base_interval ± jitter_pct) } — JSON task schema with UUID task IDs
```

## Evidence

- lgtm:c2-tasking-loop-and-jitter-tradecraft: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-022: Related technique for extended operations.
- T-005: Related technique for extended operations.

## References

- Internal Vault References
