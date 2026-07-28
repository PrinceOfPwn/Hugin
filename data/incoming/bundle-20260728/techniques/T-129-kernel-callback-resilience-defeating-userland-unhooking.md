---
id: T-129
name: Kernel-Callback Resilience Defeating Userland Unhooking
category: edr-evasion
tier: A
crate: none
source_file: none
mitre: T1562.001
mitre_secondary: [T1055, T1055.004, T1106, T1574.011]
tags: [kernel-callbacks, edr-evasion, unhooking-limitation, etw-ti, ppl-antimalware, process-notify, loadimage-notify, ob-callbacks, cm-callbacks, passive-level]
origin: atlas-synthesis
member_notes: ['lgtm:kernel-callback-resilience-metadata']
---

# Kernel-Callback Resilience Defeating Userland Unhooking — why T-016 alone is insufficient

## Summary

The T-016 card documents restoring `ntdll.dll` text to the on-disk image so userland hooks installed by EDR-injected DLLs become inert — but the same EDR vendors also register a constellation of **kernel-mode callbacks** that fire regardless of whether the user-mode stubs of `NtCreateThreadEx`, `NtWriteVirtualMemory`, or `NtMapViewOfSection` have been restored. These callbacks — `PsSetCreateProcessNotifyRoutineEx2`, `PsSetLoadImageNotifyRoutine` (and the `Ex` variant on Windows 10+), `PsSetCreateThreadNotifyRoutine`, `ObRegisterCallbacks` with `OB_PRE_OPERATION_HANDLER`, and `CmRegisterCallbackEx` — are invoked by the executive and the memory manager directly inside the syscall body, in the context of the calling thread, at `PASSIVE_LEVEL` IRQL. An operator who strips ntdll hooks and then issues `NtCreateThreadEx(hTargetProcess, …)` against a foreign process is still observed by the thread-notify callback in `PspCreateThread`, by the `ObRegisterCallbacks` pre-op that filtered `THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME` off the handle at `NtOpenThread` time, and by the Microsoft-Windows-Threat-Intelligence ETW provider's `ThreadCreate`/`SetThreadContext`/`QueueApc` events emitted from inside `nt!Mi*` and `nt!Ps*` bodies. The card enumerates each kernel callback surface, the structures it inspects, the exact operations that trigger each, and the operational evasions an operator can compose against each: existing-thread `CONTEXT` hijack to bypass thread-notify (trades for `SetThreadContext` TI), position-independent shellcode mapping to bypass image-load notify (trades for `PageAlloc`/`Protect` TI), and kernel-mode callback deregistration via signed-driver abuse to bypass everything at once. The vault's T-016 card documents the userland surface; this card documents what survives that operation.

## Mechanism

This card documents a **property of the Windows kernel** rather than an action the operator performs. The following sub-sections enumerate each kernel callback surface, the syscall body it sits inside, and what userland action triggers it.

### Variant 1: PsSetCreateProcessNotifyRoutineEx2 (process create/exit)

1. An EDR driver calls `PsSetCreateProcessNotifyRoutineEx2(NotifyRoutine, FALSE)` during `DriverEntry`, registering a `PCREATE_PROCESS_NOTIFY_ROUTINE_EX2` callback.
2. The callback is invoked twice per process creation: **Phase 1** (before the image section is mapped — `CreateInfo->FileOpenNameAvailable == TRUE`, `CreateInfo->ImageFileName` populated, the callback may set `CreateInfo->CreationStatus = STATUS_ACCESS_DENIED` to abort) and **Phase 2** (after `Mm` has committed the image section, `CreateInfo` populated with `CreationStatus` indicating `STATUS_SUCCESS`).
3. `PS_CREATE_NOTIFY_INFO` carries: `ParentProcessId` (`CLIENT_ID`), `CreatingThreadId` (`ClientId`, `Creator`), `ImageFileName` (`UNICODE_STRING` to the resolved image path), `CommandLine` (parsed from `RTL_USER_PROCESS_PARAMETERS` if available), `FileOpenNameAvailable`, and `CreationStatus`.
4. When an operator calls `NtCreateUserProcess` (or `CreateProcessW` → kernel32 → `NtCreateUserProcess`), the executive walks `PspCreateProcess` → `PspCallProcessNotifyRoutines` for every entry in the opaque `PspCreateProcessNotifyRoutine` array (an array of `EX_CALLBACK_ROUTINE_BLOCK` slots indexed by registration position).
5. EDR-side action: the callback runs in the creating thread's context at `PASSIVE_LEVEL`, the EDR can call `IoQueryFileDosDeviceName` to resolve the path, hash the image bytes, compare against cloud reputation, and ship the record to its user-mode service via `FltSendMessage` or a shared ring buffer.
6. **Blocking**: if the callback sets `CreateInfo->CreationStatus = STATUS_ACCESS_DENIED`, `PspCreateProcess` rolls back the `EPROCESS`, removes the entry from `PsActiveProcessHead`, decrements the `PspCidTable` reference, and returns `STATUS_ACCESS_DENIED` to the caller of `NtCreateUserProcess`. The process is never admitted to `PspCidTable`; no `NtCreateThreadEx` is issued; no image loads occur.
7. The userland hook on `NtCreateUserProcess` or `CreateProcessInternalW` is **redundant** for the EDR's detection. Stripping it (per T-016) does not silence the kernel callback.

### Variant 2: PsSetLoadImageNotifyRoutine / PsSetLoadImageNotifyRoutineEx (image load)

1. An EDR driver calls `PsSetLoadImageNotifyRoutine(NotifyRoutine)` to register a `PLOAD_IMAGE_NOTIFY_ROUTINE` callback.
2. The callback is invoked whenever the image loader (`nt!LdrpLoadDll` user-side, `nt!MiMapViewOfImageSection` kernel-side) maps a PE image. This includes: the process's primary image (`LoadReason = LoadReasonStaticDependency`), all implicit imports, `LoadLibraryEx` calls (`LoadReason = DynamicLoad`), and — critically — `ntdll.dll` itself during `LdrpInitializeProcess` Phase 0.
3. The `IMAGE_INFO` structure carries: `ImageBase` (the VA in the target process), `ImageSelector` (legacy, often zero on x64), `ImageSize` (the `OptionalHeader.SizeOfImage`), `ImageSectioned` (TRUE if the image was loaded from a section object — i.e., a real DLL rather than a manually-mapped blob), `ImageNumber`.
4. The `Ex` variant (`PsSetLoadImageNotifyRoutineEx`, Windows 10+) hands the callback an `IMAGE_INFO_EX` with the `ImageInfo` field set including `ParentProcessId` and a `Classification` field distinguishing kernel driver loads, primary user image, dependency loads, and `LoadImageInfoSet` enumeration.
5. Evasion implication: manually-mapped DLLs (reflective DLL injection, module stomping onto already-mapped image sections) **do not fire** this callback because no `LdrLoadDll`/`NtMapViewOfSection(SEC_IMAGE)` walk occurs. Conversely, a `SEC_IMAGE` mapping at any point in any process fires the callback — shellcode that calls `NtMapViewOfSection` with `SEC_IMAGE = 0x01000000` to load an embedded DLL is observed.
6. The callback fires in the mapping thread's context at `PASSIVE_LEVEL`. The image's `IMAGE_NT_HEADERS` are validated (`MiVerifyImageHeader`) before the callback runs, so a malformed PE will fail earlier.
7. **Operational nuance**: because `ntdll.dll` itself fires the callback during process init, an EDR can compare the loaded `ntdll.dll` bytes against the on-disk reference inside the callback. A T-016 unhook that has overwritten `ntdll.dll`'s `.text` is detectable from the kernel side by re-reading the in-memory image and diffing against `\SystemRoot\System32\ntdll.dll`.

### Variant 3: PsSetCreateThreadNotifyRoutine (thread create/exit)

1. An EDR driver calls `PsSetCreateThreadNotifyRoutine(NotifyRoutine)` registering a `PCREATE_THREAD_NOTIFY_ROUTINE`.
2. The callback is invoked on every thread creation and exit, in the context of the creating thread, at `PASSIVE_LEVEL`.
3. Parameters: `ProcessId`, `ThreadId`, `Create` (TRUE for create, FALSE for exit). The bare callback does not include the start address — the EDR follows up with `NtQueryInformationThread(ThreadQuerySetWin32StartAddress, …)` to recover `Win32StartAddress`.
4. The callback fires from `PspCreateThread` after `KeStartThread` has built the `KTHREAD`/`ETHREAD` and inserted it into the process's `EPROCESS.ThreadListHead`, but **before** `NtCreateThreadEx` returns to the caller. The EDR therefore observes a remote-thread injection before the injector sees its own `NtCreateThreadEx` return value.
5. `PspCreateThreadNotifyRoutine` is an array of up to 64 entries; multiple EDRs each take a slot. Sysmon's Event ID 8 (RemoteThreadCreate) is generated from this callback when `SourcePid != TargetPid`.
6. The callback cannot itself distinguish a `StartAddress` pointing at `LoadLibraryW` (legitimate-looking) from one pointing at `0x180001234` in a private-commit region (shellcode) — that distinction is the EDR's job via the same `ThreadQuerySetWin32StartAddress` query the userland hook would do.
7. **The userland hook on `NtCreateThreadEx` is irrelevant**: the kernel callback has already fired by the time the user-mode stub returns. T-016 unhooking makes zero difference.

### Variant 4: ObRegisterCallbacks (process / thread / desktop / file handles)

1. An EDR driver fills an `OB_CALLBACK_REGISTRATION`:

   ```
   OB_OPERATION_REGISTRATION ops[2];
   ops[0].ObjectType    = *PsProcessType;
   ops[0].Operations    = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
   ops[0].PreOperation = PreOpProcess;
   ops[0].PostOperation = PostOpProcess;

   ops[1].ObjectType    = *PsThreadType;
   ops[1].Operations    = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
   ops[1].PreOperation = PreOpThread;

   OB_CALLBACK_REGISTRATION reg = {
     .Version                   = OB_FLT_REGISTRATION_VERSION,
     .OperationRegistrationCount = 2,
     .OperationRegistration    = ops,
   };
   PVOID h;
   ObRegisterCallbacks(&reg, &h);
   ```

2. The pre-operation callback receives an `OB_PRE_OPERATION_INFORMATION` with `OperationParameters.CreateHandleInformation.DesiredAccess` (the mutable field the callback can shrink) and `.OriginalDesiredAccess` (the user's full request, read-only).
3. The EDR strips dangerous rights: for `*PsProcessType`, mask out `PROCESS_VM_READ = 0x0010 | PROCESS_VM_WRITE = 0x0020 | PROCESS_VM_OPERATION = 0x0008 | PROCESS_CREATE_THREAD = 0x0002 | PROCESS_SUSPEND_RESUME = 0x0800 | PROCESS_DUP_HANDLE = 0x0040`. For `*PsThreadType`, mask out `THREAD_SET_CONTEXT = 0x0010 | THREAD_SUSPEND_RESUME = 0x0002 | THREAD_SET_INFORMATION = 0x0020`.
4. Result: even with `SeDebugPrivilege` enabled, `NtOpenProcess(&h, PROCESS_VM_WRITE | PROCESS_VM_OPERATION, …)` against a protected target returns `STATUS_ACCESS_DENIED` — or, more commonly, succeeds but yields a handle whose `GrantedAccess` field in the `HANDLE_TABLE_ENTRY` is missing the requested rights. The subsequent `NtWriteVirtualMemory(h, …)` then returns `STATUS_ACCESS_DENIED` because theGrantedAccess lacks `PROCESS_VM_WRITE`.
5. The filter runs entirely in the kernel, inside `ObpPreCallCallbacks` invoked from `ObpCreateHandle`. No userland stub is involved.
6. Post-operation callback receives `OB_POST_OPERATION_INFORMATION` with `OperationStatus` — the EDR can log a denied handle open even when the userland stub returned an error to the caller. This is how EDRs produce "blocked attempted process open" telemetry without userland hooks.

### Variant 5: CmRegisterCallbackEx (registry)

1. An EDR driver calls `CmRegisterCallbackEx(Function, &Altitude, Context, &Cookie, &Version, NULL)` with an altitude string such as `"328010"` (Defender's altitude, in the FSFilter Anti-Malware range `"320000-329999"`).
2. The callback fires on every registry operation in the `REG_NOTIFY_CLASS` enum. Pre-side flavors of operational interest: `RegNtPreCreateKey`, `RegNtPreDeleteKey`, `RegNtPreSetValueKey`, `RegNtPreDeleteValueKey`, `RegNtPreRenameKey`, `RegNtPreRestoreKey`, `RegNtPreReplaceKey`, `RegNtPreLoadKey`, `RegNtPreUnloadKey`, `RegNtPreQueryMultipleValueKey`, `RegNtPreSetKeySecurity`.
3. The pre-op callback receives `REG_PRE_OPERATION_INFORMATION` with `Operation` (the `REG_NOTIFY_CLASS` enum value), `Object` (the key body), `PreInformation` (a pointer to the relevant `_REG_*_INFORMATION` structure — for `RegNtPreSetValueKey`, a `REG_SET_VALUE_KEY_INFORMATION` with `ValueName`, `ValueType`, `DataSize`, `ValueData`, `KeyHandle`).
4. EDRs block writes to: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image>\` (Debugger, GlobalFlag), `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BrowserHelperObjects`, `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\` keys' `StubPath`.
5. Returning `STATUS_ACCESS_DENIED` from the callback vetoes the write — `NtSetValueKey` returns `STATUS_ACCESS_DENIED` to the caller. Returning `STATUS_CALLBACK_BYPASS` lets the operation proceed without invoking lower-altitude callbacks.
6. T-016 unhooking (restoring the `NtSetValueKey` stub) does not affect this kernel callback. The userland stub is reached only after the kernel body has already invoked `CmpCallCallBacks`.
7. The hive transaction log (`*.LOG1`, `*.LOG2`, `*.LOGSTOR`) records every cell write committed by the configuration manager — even when the Cm callback permits the operation, the hive log captures it, and the EDR can parse the log to reconstruct changes the live callback did not see (rare, but a forensics surface).

### Variant 6: ETW Threat Intelligence (the modern final layer)

1. The Microsoft-Windows-Threat-Intelligence provider is a kernel-mode-only ETW provider registered during `nt!EtwpBootPhase1`. Events are emitted from inside the executive bodies of memory and process syscalls.
2. Subscription requires the subscriber's `EPROCESS.Protection` field to be `PsProtectedSignerAntimalware` (signer = 4 in the `_PS_PROTECTION` struct, set during `PspCreateProcess` based on the launcher's signature level). This is the PPL (Protected Process Light) Anti-Malware level, gated by the Microsoft ELAM (Early Launch Anti-Malware) certificate chain — a strict cross-signature chain that includes a Microsoft attestation.
3. Event classes emitted by the TI provider, dispatched from the noted kernel bodies:
   - `PageAlloc` — from `nt!MiAllocateVm` (the kernel body of `NtAllocateVirtualMemory`). Carries `ProcessId`, `VA`, `RegionSize`, `AllocationType`, `Protection` (e.g., `PAGE_EXECUTE_READWRITE = 0x40`).
   - `Protect` — from `nt!MiProtectVirtualMemory` (the kernel body of `NtProtectVirtualMemory`). Carries `ProcessId`, `VA`, `RegionSize`, `OldProtection`, `NewProtection`.
   - `ThreadCreate` / `ThreadExit` — from `nt!PspCreateThread` / `nt!PspExitThread`. Carries `ProcessId`, `ThreadId`, `StartAddress`.
   - `SetThreadContext` — from `nt!NtSetContextThread` body. Carries `ProcessId`, `ThreadId`, `ContextFlags` (which subset of the `CONTEXT` was modified).
   - `QueueApc` — from `nt!NtQueueApcThread` / `nt!NtQueueApcThreadEx` bodies. Carries `ProcessId`, `ThreadId`, `ApcRoutine` pointer.
   - `MapViewOfSection` — from `nt!MiMapViewOfSection`. Carries `ProcessId`, `SectionHandle`, `AllocationAttributes` (including `SEC_IMAGE = 0x01000000`), `ViewSize`, `BaseAddress`.
   - `WriteVirtualMemory` — from `nt!MiCopyVirtualMemory` (the kernel body of `NtWriteVirtualMemory`). Carries `ProcessId`, `TargetVA`, `Buffer`, `Size`.
4. These events fire **before** the syscall returns to user mode, in the calling thread's context. An operator who calls `NtAllocateVirtualMemory(hTargetProcess, &VA, …, PAGE_EXECUTE_READWRITE)` will emit a `PageAlloc` event with the target PID and `0x40` protection — even if every userland hook in the operator's process and the target's process is gone.
5. The combination of (kernel callback array) + (ETW-TI) + (ObRegisterCallbacks) means userland-only evasion is **fundamentally incomplete** against a PPL-protected EDR with TI subscription. The vault's T-016 card is necessary but no longer sufficient on Windows 10 1903+ where TI became widely adopted.

## OS Internals Context

### Process notify — `PspCreateProcess` internals

`PspCreateProcess` (`nt!PspCreateProcess`) is the executive function that materializes a new process. It allocates an `EPROCESS` from a lookaside list, inserts the new object into `PsActiveProcessHead` (a doubly-linked list anchored at `nt!PsActiveProcessHead`, joined via `EPROCESS.ActiveProcessLinks`), populates `EPROCESS.Peb` via `MmCreatePeb`, seeds the 15-byte `EPROCESS.ImageFileName` field (which is truncated — the full path lives in `EPROCESS.SeAuditProcessCreationInfo.ImageFileName`), and registers the new `KPROCESS` (`EPROCESS.Pcb`) with the scheduler via `KeInitializeProcess`.

After the new `EPROCESS` is built, `PspCreateProcess` calls `PspCallProcessNotifyRoutines(0)` (Phase 1) and `PspCallProcessNotifyRoutines(1)` (Phase 2). The walking code acquires `PspProcessNotifyLock`, iterates `PspCreateProcessNotifyRoutine` (an array of `EX_CALLBACK_ROUTINE_BLOCK` slots), dereferences each callback through `ObReferenceObjectSafe`, invokes it under exception protection (callback failures are swallowed by `KiDispatchException` and logged but not propagated). The Phase 1 `CreateInfo->CreationStatus` mutation path: if a callback sets `STATUS_ACCESS_DENIED`, `PspCreateProcess` rolls back the EPROCESS — `PsRemoveProcess` removes it from `PsActiveProcessHead`, decrements `PspCidTable` reference (the new `ProcessId` was reserved earlier from `PspCidTable` via `ExCreateHandle` on the CID table), and returns `STATUS_ACCESS_DENIED` to `NtCreateUserProcess`'s caller.

The `CreateInfo->CommandLine` field is populated by `PspGetProcessCommandLine`, reading from `RTL_USER_PROCESS_PARAMETERS` passed via `NtCreateUserProcess`'s `PS_ATTRIBUTE_LIST` — the same structure `RtlCreateProcessParametersEx` builds. The EDR therefore sees the same command line that `RtlGetProcessImageFileName` would later return, even if the caller never wrote the `PEB.ProcessParameters->CommandLine` pointer into the new process's `PEB`.

### Image-load notify — `MiMapViewOfImageSection` internals

When `NtMapViewOfSection` is invoked with `AllocationType = SEC_IMAGE = 0x01000000` (or the image is loaded implicitly via `LdrLoadDll` → `LdrpMapDllNtFileName` → `NtCreateSection(SEC_IMAGE)` → `NtMapViewOfSection`), the executive lands in `MiMapViewOfImageSection` inside `ntoskrnl.exe`. This routine builds a `VAD` (`MMVAD_SHORT` at the leaf for private allocations, or `MMVAD` with `Subsection` linkage for image-backed and pagefile-backed sections) and inserts it into the target process's `EPROCESS.VadRoot` AVL tree (rooted at `EPROCESS.VadRoot.BalancedRoot`).

After the VAD is committed but **before** the section's prototype PTEs have been faulted in, `MiMapViewOfImageSection` calls `PsCallImageNotifyRoutines`. This iterates `PspLoadImageNotifyRoutine` (an `EX_CALLBACK` array of up to 64 slots, same structure as the process-notify array), invokes each registered callback with `FullImageName` (resolved from the `_FILE_OBJECT.FileName` of the section's `CONTROL_AREA->FilePointer`), `ProcessId` (from `PsGetCurrentProcess()->Cid.UniqueProcess`), and `PIMAGE_INFO` filled with `ImageBase`, `ImageSize`, `ImageSectioned = TRUE`.

The callback therefore fires for every PE mapped by the image loader, including:
- The process's primary image in `LdrpInitializeProcess` Phase 2 (when the section is mapped before the loader's TLS callbacks run).
- All implicit imports in dependency-order DFS during `LdrpWalkImportDescriptor`.
- `LoadLibraryEx` calls with `LOAD_LIBRARY_AS_IMAGE` or default flags (those that go through the loader's `LdrLoadDll` path).
- The `ntdll.dll` image itself during `LdrpInitializeProcess` Phase 0 — meaning an EDR receives a load-image event for `ntdll` **before** any user code in the new process runs. A T-016 unhook that has overwritten `ntdll.dll`'s `.text` is detectable from the kernel side by re-reading the in-memory image (via the `ImageBase` passed to the callback) and diffing against `\SystemRoot\System32\ntdll.dll` on disk.

A manually-mapped DLL (the operator allocates RWX memory with `NtAllocateVirtualMemory`, copies the PE bytes, fixes imports and relocations) **does not fire** this callback because no section object is opened and no `MiMapViewOfImageSection` call is made. The cost: the manually-mapped image has no `LDR_DATA_TABLE_ENTRY` in the loader's `InLoadOrderModuleList` (so `GetModuleHandle` / `EnumProcessModules` won't return it), no `_SECTION`/`_CONTROL_AREA` is allocated, and the VAD is a regular `MMVAD_SHORT` with `Subsection = NULL` (private commit, not image-backed). This is the classic reflective-DLL-injection tradeoff: silent to image-notify, loud to `PageAlloc`/`Protect` TI events.

### Thread notify — `PspCreateThread` internals

`NtCreateThreadEx` walks into `PspCreateThread` (or `PspCreateThread` directly for system-thread creation). It allocates an `ETHREAD` (the `KTHREAD` is the first field, `ETHREAD.Tcb`), initializes it via `KeInitThread` (which builds the initial `KTRAP_FRAME`, copies the user-mode context into `KTHREAD.TrapFrame`, sets `KTHREAD.InitialStack`, `StackBase`, `KernelStack`), inserts the thread into `PspCidTable` via `ExCreateHandle` (which gives it a thread `HANDLE`), links it into `EPROCESS.ThreadListHead` (via `ETHREAD.ThreadListEntry`), and finally calls `KeReadyThread` to make it schedulable.

Right before `KeReadyThread`, `PspCreateThread` walks `PspCreateThreadNotifyRoutine` (an `EX_CALLBACK` array, same family as the process-notify array) and invokes each registered routine with `ProcessId`, `ThreadId`, `Create = TRUE`. On thread exit, `PspExitThread` walks the same array with `Create = FALSE`. The callback runs at `PASSIVE_LEVEL` in the calling thread's context, so an EDR can perform `NtQueryInformationThread(ThreadQuerySetWin32StartAddress, …)` (which reads `ETHREAD.Win32StartAddress`) to recover the user-mode start address — the same `StartAddress` value the operator passed to `NtCreateThreadEx`'s `StartRoutine` parameter.

If the operator's start routine is a shellcode stub at `0x180001234` inside a private-commit region (no image backing), the EDR can correlate that VA against the `PsSetLoadImageNotifyRoutine` record set: no image-load event for any image whose `[ImageBase, ImageBase+ImageSize)` range covers `0x180001234` means the start address is outside any registered image — a high-confidence IOC. The combination of thread-notify + image-notify data, joined on the start-address VA, is the basis for Sysmon Event ID 8's "StartAddress not backed by image" correlation.

### Object callbacks — `ObpCreateHandle` internals

The object manager's `ObpCreateHandle` is the central dispatch for handle creation. It is invoked from `ObOpenObjectByNamePointer`, `ObpOpenObjectName`, `ObDuplicateObject`, etc. Before performing the access check (`SeAccessCheck` against the object's security descriptor with the caller's token, modified by `ObpAdjustGrantedAttributes` for `OBJ_INHERIT`/`OBJ_KERNEL_HANDLE`/`OBJ_PROTECT_CLOSE`), `ObpCreateHandle` invokes `ObpPreCallCallbacks` if `OBJECT_TYPE.TypeInfo.SupportsObjectCallbacks == TRUE`.

The pre-callback walk iterates the `OB_CALLBACK` list registered against the `OBJECT_TYPE` of the target object (the list is anchored at `OBJECT_TYPE.CallbackList`, doubly-linked via `OB_CALLBACK.CallbackListEntry`). For each entry, it builds an `OB_PRE_OPERATION_INFORMATION` on the stack, populates `Object` (the raw object body, e.g., the `EPROCESS`), `OperationParameters.CreateHandleInformation.OriginalDesiredAccess` (the user's full request), and a copy of `DesiredAccess` that the callback may mutate.

The callback returns one of `OB_PREOP_SUCCESS` (proceed with possibly-modified `DesiredAccess`), `OB_PREOP_COMPLETE` (handle creation completed early — used for handle pre-create filters that bypass the access check entirely), or an NTSTATUS error to veto the operation. After the access check completes, the post-op callback runs with `OB_POST_OPERATION_INFORMATION` carrying `OperationStatus` and `GrantedAccess`.

A common EDR pre-op strips `PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME` from `OriginalDesiredAccess` when the calling process's image is on a blocklist or the target is a protected browser child process. The `SeAccessCheck` that follows now sees a reduced `DesiredAccess`. If the operator's requested rights include the stripped bits, `SeAccessCheck` succeeds but the resulting `HANDLE_TABLE_ENTRY.GrantedAccess` field lacks those bits. A subsequent `NtWriteVirtualMemory` against that handle returns `STATUS_ACCESS_DENIED` because theGrantedAccess lacks `PROCESS_VM_WRITE = 0x0020`.

This is the kernel-internal reason **unhooking `NtWriteVirtualMemory` does not restore the ability to write to foreign processes.** The kernel callback runs in `ObpCreateHandle` regardless of the userland `NtWriteVirtualMemory` stub.

### Registry callbacks — `CmCallback` internals

Registry callbacks are layered in the Configuration Manager. Each registered callback carries an **altitude** — a `UNICODE_STRING` whose numeric value is parsed into a 64-bit sort key. Altitudes are assigned by Microsoft per-driver; the FSFilter Anti-Malware altitude range is `"320000-329999"`. The Configuration Manager sorts callbacks by altitude so the highest-altitude driver sees the operation first.

The Configuration Manager intercepts every `NtSetValueKey`, `NtCreateKey`, `NtDeleteKey`, `NtDeleteValueKey`, `NtRenameKey`, `NtRestoreKey`, `NtReplaceKey`, `NtLoadKey`, `NtUnloadKey`, `NtSetKeySecurity` etc. inside the kernel body of the syscall (e.g., `CmSetValueKey` after `NtSetValueKey` validates parameters and acquires the KCB — Key Control Block — lock). The body invokes `CmpCallCallBacks` with the appropriate `REG_NOTIFY_CLASS` value, passing a pointer to the `*_INFORMATION` structure holding the operation's parameters (for `RegNtPreSetValueKey`, that's `REG_SET_VALUE_KEY_INFORMATION` with `ValueName`, `ValueType`, `DataSize`, `ValueData`, `KeyHandle`, `TxContext`).

A callback can return `STATUS_ACCESS_DENIED` to veto, `STATUS_CALLBACK_BYPASS` to let the call proceed without invoking lower-altitude callbacks, or `STATUS_SUCCESS` to let the chain continue. The hive transaction log files (`*.LOG1`, `*.LOG2`, and for newer Windows the `*.LOGSTOR` stream) record every cell write committed by the configuration manager — even when the Cm callback permits the operation, the hive log captures it, and an EDR can parse the log on boot to reconstruct changes the live callback did not see.

### ETW Threat Intelligence dispatch

The Microsoft-Windows-Threat-Intelligence provider is gated for subscribers by `EPROCESS.Protection == PsProtectedSignerAntimalware` (signer = 4 in the `_PS_PROTECTION` struct, which is a `USHORT` of `Type:3, Audit:1, Signer:4` bits set during `PspCreateProcess` based on the launcher's signature level). The provider is registered by `nt!EtwpBootPhase1` and emits events from inside the executive bodies of memory and process syscalls.

For example, `nt!NtAllocateVirtualMemory`'s kernel body `nt!MiAllocateVm` calls `EtwpTraceTiEvent` with `EVENT_TRACE_GROUP_TI = 'iTTm'` (or similar internal opcode) and a `PageAlloc` payload carrying `ProcessId`, `VA`, `RegionSize`, `AllocationType`, `Protection`. The trace is written to a kernel ring buffer that the PPL subscriber drains via `NtTraceEvent`/`EtwpNotificationDispatcher`. The subscriber sees the event before `NtAllocateVirtualMemory` returns to user mode.

The protection model is enforced by the kernel at the `EPROCESS.Protection` field — only processes with `PsProtectedSignerAntimalware` may subscribe to TI. `PsProtectedSignerAntimalware` is reserved for binaries with the Microsoft Anti-Malware ELAM certificate, gated by the `EarlyLaunchAntimalware` driver class and a strict code-signing chain that includes a Microsoft attestation cross-signature (this is enforced by `PsTestProtectedProcessIncompatibility` and the loader's `MiCheckSigningPolicy`). An operator cannot become a PPL Anti-Malware process without compromising Microsoft's signing infrastructure or repurposing an existing PPL Anti-Malware process.

The only way to fully evade TI is to be **inside the kernel** — either as a vulnerable-driver-abusing attacker who can patch `nt!EtwpTraceKernelEvent` or `nt!EtwTiLog*` dispatcher, or to find operations that don't emit TI events at all. The set of memory operations TI does **not** cover is shrinking each release; in Windows 11 23H2 builds, almost every write, alloc, protect, map, set-context, and queue-apc operation emits.

## Key Implementation Details

The operator's practical takeaway: **userland unhooking (T-016) restores the user-mode stubs but does not touch the kernel callback array.** The kernel callback array is per-`OBJECT_TYPE` / per-notification-class and persists for the lifetime of the registering driver. There is no userland API to deregister another driver's callback.

To **observe** which kernel callbacks are registered on a host, you cannot enumerate them directly — `PspCreateProcessNotifyRoutine`, `PspLoadImageNotifyRoutine`, `PspCreateThreadNotifyRoutine`, and `OBJECT_TYPE.CallbackList` are opaque kernel structures with no export to query them. Indirect probes:

1. Allocate a tiny RWX page in your own process with `NtAllocateVirtualMemory(hCurrent, …, PAGE_EXECUTE_READWRITE)`, then `NtProtectVirtualMemory(hCurrent, …, PAGE_READONLY)` and check if TI telemetry fires (visible in the EDR's console or Sysmon Event ID 18/19 — though Sysmon doesn't subscribe to TI, an EDR console will show the access).
2. Issue `NtOpenProcess(&h, PROCESS_VM_OPERATION, …)` against a PPL-protected browser child (e.g., `MicrosoftEdgeSH.exe` child of `msedge.exe`). If the returned handle's `GrantedAccess` (queryable via `NtQueryObject(ObjectHandleFlagInformation, …)` won't return this — you need `NtQueryInformationProcess` with the kernel's `GrantedAccess` field; in practice, attempt the subsequent `NtWriteVirtualMemory(h, …)` and observe `STATUS_ACCESS_DENIED`) lacks `PROCESS_VM_OPERATION = 0x0008`, an `ObRegisterCallbacks` pre-op is stripping rights.
3. Write a benign `Debugger = "C:\\Windows\\System32\\calc.exe"` value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\notepad.exe_honeypot\` — if the write returns `STATUS_ACCESS_DENIED`, a `CmRegisterCallbackEx` is filtering IFEO writes.

To **evade** each callback:

- **`PsSetCreateThreadNotifyRoutine`**: do not create new threads in the target. Use `NtSetContextThread` on an existing thread (suspend via `NtSuspendThread`, capture `CONTEXT` via `NtGetContextThread`, set `Rip` to the shellcode entry, resume via `NtResumeThread`). Tradeoff: `SetThreadContext` emits an ETW-TI `SetThreadContext` event. To bypass both thread-notify and `SetThreadContext` TI, walk the thread's user-mode stack frame by frame and write the return address via `NtWriteVirtualMemory` into the stack slot the suspended thread will pop when it returns from `NtWaitForSingleObject` (the `NtContinue`-based hijack pattern).
- **`PsSetLoadImageNotifyRoutine`**: do not load a PE. Run position-independent shellcode copied into pre-existing RWX memory (the `NtAllocateVirtualMemory`-allocated private-commit kind). Reflective DLL injection will be silent to the image-load callback but will trigger `PageAlloc` + `Protect` TI events if you allocate fresh memory.
- **`ObRegisterCallbacks`**: no userland bypass — open the handle before the EDR's driver registers (impossible at boot) or operate in-process without a foreign process handle (e.g., thread injection within the same process). Process-hollowing children inherit a fully-privileged handle from the parent before the EDR sees the child's first syscall — there is a brief window during `PspSetupUserProcessStack` where the parent's handle is fully privileged; this is exploited by process-hollowing variants that hand off the privileged handle via inheritance.
- **`CmRegisterCallbackEx`**: write directly to the hive file at `C:\Windows\System32\config\SYSTEM` after it's been unmapped (requires kernel-level hive editing — `NtSaveKeyEx` then file-replace then `NtLoadKey` on the next boot). Or use `NtRestoreKey` with a pre-crafted hive (but `RegNtPreRestoreKey` is observable). Or move persistence off the registry entirely — WMI subscriptions live in `\SystemRoot\System32\wbem\Repository\OBJECTS.DATA`, the Cm callback does not intercept them.
- **ETW Threat Intelligence**: cannot be evaded from userland against a PPL-subscribed EDR. Requires either kernel-mode tampering (driver unloading the provider or patching `EtwpTraceKernelEvent`) or restricting operations to those TI does not cover (a shrinking set).
- **Kernel-level bypass**: if you have a kernel-mode primitive (a signed-vulnerable driver like `iqvw64e.sys`, `RTCore64.sys`, `gdrv.sys` loaded via `NtLoadDriver` after BYOVD), you can call `PsRemoveLoadImageNotifyRoutine(routine)`, `PsSetCreateProcessNotifyRoutineEx2(routine, TRUE)` to deregister, `ObUnRegisterCallbacks(handle)` if you can locate the registration handle by walking `OBJECT_TYPE.CallbackList`, `CmUnRegisterCallback(cookie)`. TI cannot be easily deregistered because the provider is owned by `ntoskrnl.exe` itself — the only path is to patch `EtwpTraceKernelEvent` or unload the subscriber. Reference the vault's T-095-style kernel-callback-deregistration card for the kernel primitive path.

## Why It Matters

T-016 userland unhooking is the foundation of many evasion chains, but treating it as sufficient is the most common operator error. Modern EDRs (Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Elastic EDR, Bitdefender GravityZone) all register multiple kernel callbacks as their primary detection layer; the userland hooks are layered on top for telemetry enrichment (command-line capture, call-stack walking, parent-process correlation) rather than for primary detection. When an operator reads T-016, T-007, and T-013 in isolation, the unhooked stubs look like a green light; this card exists to make the kernel-observable ceiling explicit.

The card composes with T-016 (NTDLL Unhook) as the prerequisite that this card critiques, with T-007 (Process Injection) where injection-technique choice determines which callbacks fire, and with T-013 (Thread Hijack) where `CONTEXT`-based hijack avoids the `PsSetCreateThreadNotifyRoutine` trigger but exposes the `SetThreadContext` ETW-TI event — the operator trades one detection surface for another. The detection-engineering counterpart is the kernel-callback-deregistration primitive (a future card extending this card with the kernel-mode bypass path: `PsRemoveLoadImageNotifyRoutine`, `ObUnRegisterCallbacks`, `CmUnRegisterCallback`).

## Detection Considerations

- **Telemetry sources**: every operation that triggers a kernel callback leaves evidence in the EDR's telemetry store even if no userland hook fires. `NtCreateUserProcess` → process-notify callback → Sysmon Event ID 1 (ProcessCreate) and Security log 4688 (Audit Process Creation, when `Audit Process Creation` policy is enabled). `NtCreateThreadEx` → thread-notify callback → Sysmon Event ID 8 (RemoteThreadCreate) when target PID ≠ source PID. `NtMapViewOfSection(SEC_IMAGE)` → image-load callback → Sysmon Event ID 7 (ImageLoad). `NtOpenProcess(PROCESS_VM_WRITE)` against a protected target → object pre-op callback strips rights → no Sysmon event, but the EDR's own audit log shows the attempted open with the stripped `OriginalDesiredAccess`. `NtAllocateVirtualMemory` on a foreign process → ETW-TI `PageAlloc` event (only EDRs with PPL subscription see this; Sysmon does not subscribe to TI). `NtSetContextThread` → ETW-TI `SetThreadContext` event. `NtQueueApcThread` → ETW-TI `QueueApc` event.
- **Bypass options**: thread-context hijack via `NtSetContextThread` bypasses `PsSetCreateThreadNotifyRoutine` but emits ETW-TI `SetThreadContext`. PIC shellcode in private-commit memory bypasses `PsSetLoadImageNotifyRoutine` but `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE` emits ETW-TI `PageAlloc`/`Protect`. To bypass `ObRegisterCallbacks`, use an inherited process handle (process-hollowing children inherit a fully-privileged handle from the parent during the brief `PspSetupUserProcessStack` window before the EDR sees the child's first syscall). To bypass `CmRegisterCallbackEx`, write persistence to disk (DLL hijack via `Win32_TrayType` autostart locations, WMI event subscriptions in `OBJECTS.DATA`, scheduled tasks via `ITaskScheduler::RegisterTask` walking the COM `Schedule.Service` interface) rather than to registry keys.
- **Residual artifacts**: even with kernel-mode callback deregistration, the EDR's userland telemetry pipeline may have already captured the pre-bypass events and uploaded them to the cloud console (retention is 30+ days on most platforms). Deregistering callbacks in-kernel leaves the `Psp*NotifyRoutine` arrays with holes; EDRs with kernel components detect this by hashing the array and comparing against a baseline (similar to the PE-baseline approach applied to the kernel callback array). The `OB_CALLBACK` registration list (`OBJECT_TYPE.CallbackList` for `*PsProcessType` / `*PsThreadType`) has an entry per registration that an integrity-checking EDR can walk via its own kernel component. Hive transaction logs (`*.LOG1`, `*.LOG2`, `*.LOGSTOR`) persist every registry cell write even when the Cm callback permits the operation.

## Composition with Other Techniques

A realistic evasion-resilient kill chain that accounts for kernel callbacks:

1. **T-016** unhook `ntdll.dll` in your injector process — this defeats any userland hooks the EDR injected into your own process (zero direct impact on kernel callbacks but clears the easy telemetry layer that would have captured command-line and call-stack context).
2. **Avoid `NtCreateThreadEx` entirely** in the target — the kernel thread-notify callback will fire. Instead, enumerate threads of the target via `NtQuerySystemInformation(SystemProcessInformation, …)`, pick a dormant thread (`KTHREAD.State == Waiting` and `KTHREAD.WaitReason == UserRequest` or `LpcReceive` — typically a thread blocked in `WaitForSingleObject`/`GetMessage`), suspend via `NtSuspendThread`, capture its `CONTEXT` via `NtGetContextThread`, set `Rip` to the shellcode entry via `NtSetContextThread`, then resume. This emits `SetThreadContext` (TI catches it) but **no** `ThreadCreate` event, defeating EDRs that use thread-notify as their primary IOC.
3. **Avoid `NtAllocateVirtualMemory(hTarget, RWX)` in the target** — the `PageAlloc` + `Protect` TI events will fire. Instead, allocate a RW page in your own process via `NtAllocateVirtualMemory(hCurrent, …, PAGE_READWRITE)`, write shellcode into it, then share it into the target via `NtMapViewOfSection(hSection, hTarget, …, PAGE_READONLY, …)` using a section created with `SEC_COMMIT` (not `SEC_IMAGE`). This emits `MapViewOfSection` TI but the section's `AllocationAttributes` field does not carry `SEC_IMAGE`, so `PsSetLoadImageNotifyRoutine` does not fire. The shellcode executes from a private-commit mapping rather than an image-backed mapping — no image load event, no entry in `InLoadOrderModuleList`.
4. **For persistence, avoid the registry** — the `CmRegisterCallbackEx` filter blocks the standard persistence keys. Use a WMI event subscription (`__EventFilter` + `CommandLineEventConsumer` written into `root\subscription` namespace, persisted in `C:\Windows\System32\wbem\Repository\OBJECTS.DATA`), which is not visible to Cm callbacks. Alternatively use a COM hijack on `HKCU\Software\Classes\CLSID\{...}\InprocServer32\` (HKCU is often outside the EDR's Cm filter scope, which targets HKLM).

## Common Mistakes

1. **Treating T-016 as the whole evasion story.** Operators unhook `ntdll.dll`, declare victory, call `NtCreateThreadEx(hTarget, shellcode)` and wonder why Defender quarantined the payload within 50 ms. The userland stub was clean; the kernel thread-notify callback fired the moment `PspCreateThread` walked `PspCreateThreadNotifyRoutine`, and the EDR's cloud-side detonation sandbox saw the `ThreadCreate(ParentPID, StartAddress=foreign VA)` event. The userland hook on `NtCreateThreadEx` was redundant telemetry — the kernel callback was always the primary detection.
2. **Calling `NtSetContextThread` directly after T-016 and assuming silence.** The unhook covers the userland stub but `SetContextThread` emits an ETW-TI event in `NtSetContextThread`'s kernel body. The operator trades one detection (thread-notify) for another (TI `SetThreadContext`). To bypass both, the only userland-tolerant primitive is `NtQueueApcThread` with a special-user APC — but that emits `QueueApc`. The tradeoff is unavoidable in userland against a TI-subscribed EDR.
3. **Mapping a reflective DLL with `SEC_IMAGE`.** A reflective loader that calls `NtMapViewOfSection(hSection, hTarget, …, SEC_IMAGE = 0x01000000, …)` triggers `PsSetLoadImageNotifyRoutine`. Worse, the reflective loader's hallmark — absence from `InLoadOrderModuleList` — is itself an IOC that EDRs flag (an image-load event with no corresponding `LDR_DATA_TABLE_ENTRY` is suspicious). Use private-commit `NtAllocateVirtualMemory` + manual PE loader instead (triggers `PageAlloc` TI but no `LoadImage` callback, and the absence of `InLoadOrderModuleList` is less suspicious when no image-load event fires at all).
4. **Forgetting that EDRs register multiple callbacks per object type.** An operator's probe showing that `NtOpenProcess(PROCESS_VM_OPERATION)` succeeds against one target does not mean no `ObRegisterCallbacks` is registered; it may mean the EDR's filter only strips rights for protected-PID targets or for callers on a blocklist. Strip-tests must include the specific protected processes (browser children, LSASS, MsMpEng.exe) and a control case (calc.exe).
5. **Trying to deregister callbacks from userland.** No documented API exists. `NtSetSystemInformation` with `SystemDpcBehaviorInformation` and similar opaque classes do not touch the callback arrays. The only userland-visible side effect of callback activity is the result of the operations they veto (`STATUS_ACCESS_DENIED` from the user's perspective). Deregistration requires a kernel primitive — see the kernel-callback-deregistration card.
6. **Assuming ETW-TI is subscribable by anyone.** The provider requires PPL Anti-Malware status; an EDR that hasn't been granted PPL cannot subscribe. CrowdStrike, Defender, SentinelOne, Bitdefender all have PPL. Smaller or newer EDRs may not — but the absence of TI subscription on a host does not mean the kernel callbacks are silent (the driver-level callbacks fire regardless of TI). And on any host with Windows 11 22H2+, even mid-tier EDRs have moved toward PPL via the Microsoft Anti-Malware ELAM program.
7. **Operating on the assumption that `Process_Dup_Handle` is not stripped.** Many EDRs strip `PROCESS_DUP_HANDLE = 0x0040` from `OriginalDesiredAccess` in their `ObRegisterCallbacks` pre-op against protected PIDs. Operators who plan to use `NtDuplicateObject(hSource, hTarget, …, DUPLICATE_SAME_ACCESS)` to launder a handle into a protected process discover at runtime that the duplicated handle has the same stripped `GrantedAccess` as the source — duplication does not bypass the filter.

## Related Techniques

- **T-016 NTDLL Unhook** — the prerequisite this card critiques; T-016 defeats userland hooks but leaves every kernel callback intact. This card exists to make that ceiling explicit.
- **T-007 Process Injection** — injection technique choice determines which kernel callbacks fire; technique selection should be made with this card's callback map in mind (e.g., `NtMapViewOfSection` with `SEC_COMMIT` rather than `SEC_IMAGE` to avoid `PsSetLoadImageNotifyRoutine`).
- **T-013 Thread Hijack** — `CONTEXT`-based hijack via `NtSetContextThread` avoids `PsSetCreateThreadNotifyRoutine` but exposes `SetThreadContext` ETW-TI event; the tradeoff is documented here.