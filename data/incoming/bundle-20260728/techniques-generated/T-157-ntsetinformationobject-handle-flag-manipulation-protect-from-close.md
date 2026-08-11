---
id: T-157
title: "NtSetInformationObject Handle Flag Manipulation (Protect-from-Close)"
category: edr-evasion
tier: B
tags: ['ntsetinformationobject-handle-flags']
mitre: ["T-016"]
origin: glm-expand-cluster
source_cluster: ntsetinformationobject-handle-flags
member_notes: ["lgtm:gap-handle-flag-manipulation-via-ntsetinformationobject"]
---
## Summary

This technique covers NtSetInformationObject Handle Flag Manipulation (Protect-from-Close). It addresses a gap in knowledge for red-team operations related to edr-evasion.

## Technical Deep Dive

SEC670 unit 3 documents the handle table Entry bit fields — Lock, Inheritable, Audit,
and Protect-from-close — and explicitly names NtSetInformationObject with
ObjectHandleFlagInformation (class 0) as the API to manipulate the Protect-from-close
and Inheritable flags. The OBJECT_HANDLE_FLAG_INFORMATION structure contains two
BOOLEAN fields: Inherit (whether the handle is inherited by child processes) and
ProtectFromClose (whether CloseHandle on this handle returns ERROR_INVALID_HANDLE
instead of closing). Setting ProtectFromClose=1 prevents the handle from being closed,
which can be used to pin open handles to resources (e.g., a file handle to a deleted
file, preserving its data) or to prevent EDR from closing handles to monitored
resources. The vault's T-016 (NTAPI Hook Evasion) does not document this handle-
manipulation primitive. A card should document the OBJECT_HANDLE_FLAG_INFORMATION
structure, the NtSetInformationObject call, the detectability (ObjectHandleFlagInformation
is a rare information class), and operational scenarios for Protect-from-close.


Technical anchor details:
```text
NtSetInformationObject(ObjectHandleFlagInformation, class 0) with OBJECT_HANDLE_FLAG_INFORMATION {Inherit, ProtectFromClose} — ProtectFromClose=1 makes CloseHandle return ERROR_INVALID_HANDLE
```

## Evidence

- lgtm:gap-handle-flag-manipulation-via-ntsetinformationobject: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-016: Related technique for extended operations.

## References

- Internal Vault References
