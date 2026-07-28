---
id: T-136
name: Anti-VM Detection Primitive API Catalog
category: anti-analysis
tier: A
crate: none
source_file: none
mitre: T1497.001
mitre_secondary: [T1497.003, T1082]
tags: [anti-vm, cpuid, rdtsc, registry-survey, mac-oui, process-enumeration, hypervisor-fingerprint, sandbox-evasion, no-privilege-required, user-mode]
member_notes: ['lgtm:gap-anti-vm-detection-primitives']
origin: atlas-synthesis
---

# Anti-VM Detection Primitive API Catalog — Recon API surface for virtualization-aware fingerprinting

## Summary

This card catalogs the user-mode Win32/NT API primitives that power anti-VM and anti-sandbox fingerprinting. Each primitive maps an OS data source — a registry value, a CPUID leaf, a MAC OUI byte triple, a process image name, a file path — to a single boolean question ("am I running on a hypervisor?") that an operator can compose into custom detection chains. The six families covered are: (1) CPUID leaf `0x40000000` vendor signature read via the `__cpuid` intrinsic; (2) RDTSC instruction-timing via `__rdtsc`/`__rdtscp` or `QueryPerformanceCounter`; (3) registry survey via `RegOpenKeyExW`/`RegQueryValueExW` on `HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` and driver service subkeys; (4) filesystem artifact walk via `FindFirstFileW`/`FindNextFileW` against `C:\Program Files\` and `C:\Windows\System32\drivers\`; (5) process enumeration via `WTSEnumerateProcessesExW` or `NtQuerySystemInformation(SystemProcessInformation)`; (6) network adapter MAC OUI extraction via `GetAdaptersAddresses` from `iphlpapi.dll`. No variant requires elevated privileges — all succeed as a standard user because the SYSTEM and HARDWARE hives grant `KEY_READ` to `Everyone`, and `NtQuerySystemInformation(SystemProcessInformation)` returns a full snapshot regardless of session. The technique's niche versus adjacent approaches is that it is composable: an operator can select three or four primitives and build a bespoke gate calibrated to a specific target environment, rather than running a fixed checklist. The vault's T-020 card documents 10 anti-VM checks as a fixed implementation but does not generalize the underlying API-to-check mapping; T-023 covers adjacent sandbox-evasion behavioral checks but not the recon API primitives documented here.

## Mechanism

### Variant 1: CPUID Hypervisor Vendor Signature

1. Call `__cpuid(cpuinfo, 1)` to read leaf 1. Check bit 31 of ECX: `(cpuinfo[2] & 0x80000000)`. This bit is the Intel/AMD-standardized "hypervisor present" flag — when set, a hypervisor is active and the CPUID leaves starting at `0x40000000` are valid.
2. If the hypervisor-present bit is set, call `__cpuid(cpuinfo, 0x40000000)` — the hypervisor vendor leaf. EAX returns the maximum supported hypervisor leaf. EBX, ECX, EDX return a 12-character ASCII vendor signature split across the three registers.
3. Reconstruct the signature string. The CPU stores EBX at the first 4 bytes, ECX at the next 4, EDX at the last 4:
   ```c
   char sig[13];
   memcpy(sig + 0, &cpuinfo[1], 4);  // EBX
   memcpy(sig + 4, &cpuinfo[2], 4);  // ECX
   memcpy(sig + 8, &cpuinfo[3], 4);  // EDX
   sig[12] = '\0';
   ```
4. Compare against known vendor signatures:
   - `"MicrosoftHV"` — Hyper-V / Windows VBS / WSL2 / Windows Sandbox / WDAG
   - `"KVMKVMKVM"` — KVM (QEMU-KVM)
   - `"VMwareVMware"` — VMware ESXi / Workstation / Fusion
   - `"XenVMMXenVMM"` — Xen hypervisor
   - `"TCGTCGTCGTCG"` — QEMU/TCG (software emulation, no KVM acceleration)
   - `"prl hyperv  "` — Parallels (note two trailing space characters)
   - `"VBoxVBoxVBox"` — VirtualBox (legacy; modern VirtualBox 6.1+ with Hyper-V paravirt returns `"MicrosoftHV"`)
5. For deeper probing, call `__cpuid(cpuinfo, 0x40000001)` — the hypervisor interface leaf. Hyper-V returns a specific interface signature in EAX that identifies the paravirt interface contract. Call `__cpuid(cpuinfo, 0x40000010)` on VMware to read the hypervisor version/build number.
6. The `__cpuid` intrinsic compiles to the `cpuid` instruction (opcode `0F A2`). On Intel VT-x, the VMM controls whether `CPUID` triggers a VM-exit via the "CPUID-exiting" secondary processor-based control (bit 25 of `IA32_VMX_PROCBASED_CTLS2` MSR). In most production hypervisors, `CPUID` does exit — this is what makes the timing variant (Variant 2) viable.

### Variant 2: RDTSC Timing-Based Hypervisor Detection

1. Read the timestamp counter (TSC) before and after a target instruction sequence. The classic target is `CPUID` itself, because it is a serializing instruction that forces a VM-exit under most hypervisors:
   ```c
   unsigned long long t1 = __rdtsc();
   int cpuinfo[4];
   __cpuid(cpuinfo, 0);
   unsigned long long t2 = __rdtsc();
   unsigned long long delta = t2 - t1;
   ```
2. On bare metal, `cpuid` completes in 80–300 cycles depending on CPU generation. Under a hypervisor where `CPUID` causes a VM-exit, the exit/entry round trip adds 1500–30000 cycles, pushing `delta` well above 1000.
3. For stable results, use `__rdtscp(&aux)` (opcode `0F 01 F9`) instead of `__rdtsc()` (opcode `0F 31`). `RDTSCP` is a serializing instruction — it waits for all prior instructions to retire before reading the TSC, preventing out-of-order execution from collapsing the measured delta to zero. `__rdtsc` is not serializing; on a superscalar CPU, the two `rdtsc` instructions can be reordered to execute in the same cycle, yielding `delta == 0`.
4. `RDTSCP` writes the `IA32_TSC_AUX` MSR contents to ECX. On Windows, `IA32_TSC_AUX` is populated with the logical processor number during `KiInitializeTsc` — the value corresponds to the KPRCB `CpuNumber` field.
5. If `RDTSCP` is unavailable (check `CPUID.80000001H:EDX[27]` — the `RDTSCP` feature flag), fall back to `__rdtsc()` bracketed by a `CPUID` serialization barrier: `cpuid` before the first `rdtsc` drains the pipeline.
6. For the `QueryPerformanceCounter` fallback — useful when the binary must not contain the `rdtsc` opcode `0F 31` in its instruction stream — call `QueryPerformanceCounter(&t1)`, execute the target instruction, call `QueryPerformanceCounter(&t2)`. QPC returns counts in 100-nanosecond units via `NtQueryPerformanceCounter` → `KeQueryPerformanceCounter` → `HalpQueryPerformanceCounter`, which reads either the TSC (invariant TSC systems) or the HPET/ACPI PM timer. The threshold differs from raw TSC cycles.
7. Threshold values are CPU-generation dependent. A modern Intel Alder Lake bare-metal `cpuid` takes ~100 cycles; under Hyper-V with optimized VM-exit paths the same call measures ~2000–4000 cycles. Under KVM with default CPUID-exit settings, the exit cost is 8000–15000 cycles. Calibrate per CPU family or use a relative measurement (compare the `cpuid` delta to a `nop`-slide delta on the same machine).

### Variant 3: Registry Artifact Survey

1. Open the disk enumeration key: `RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 0, KEY_READ, &hKey)`. This succeeds for any user — the SYSTEM hive grants `KEY_READ` to `Everyone`.
2. Query value `"0"` (the device instance ID of the first disk): `RegQueryValueExW(hKey, L"0", NULL, &type, buf, &bufLen)`. The returned `REG_SZ` string contains the PnP device instance path.
3. Match against known VM device identifiers in the string:
   - `PCI\VEN_80EE&DEV_BEEF` — VirtualBox (PCI vendor `80EE` assigned to InnoTek Systemberatung GmbH, device `BEEF` is the VirtualBox Guest Additions PCI device)
   - `PCI\VEN_15AD&DEV_...` — VMware (PCI vendor `15AD` = VMware, Inc.)
   - `_VMBUS` or `VMBUS` — Hyper-V virtualization bus
   - `PCI\VEN_1AF4&DEV_...` — virtio (PCI vendor `1AF4` = Red Hat, Inc.)
   - `SCSI\Disk&VBOX_HARDDISK` — VirtualBox SCSI disk
   - `PCI\VEN_1414&DEV_...` — Microsoft virtual device (PCI vendor `1414` = Microsoft Corporation)
4. Query `HKLM\HARDWARE\DESCRIPTION\System\BIOS` for `SystemManufacturer`, `SystemProductName`, `BIOSVersion`:
   - `"innotek GmbH"` — VirtualBox (original manufacturer string)
   - `"VMware, Inc."` — VMware
   - `"Microsoft Corporation"` with `SystemProductName` = `"Virtual Machine"` — Hyper-V
   - `"QEMU"` — QEMU/KVM
5. Walk the services tree: open `HKLM\SYSTEM\CurrentControlSet\Services` and enumerate subkeys with `RegEnumKeyExW`. Match against VM driver service names: `VBoxGuest`, `VBoxMouse`, `VBoxSF`, `VBoxVideo`, `vmci`, `vmhgfs`, `vmxnet3`, `vm3dmp`, `vmmouse`, `vmusbmouse`, `pvscsi`, `VMBus`, `hyperv`, `xenevtchn`, `xennet`, `xvda`.
6. Probe for installed-tool markers: `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions` (VirtualBox), `HKLM\SOFTWARE\VMware, Inc.\VMware Tools` (VMware Tools), `HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters` (Hyper-V Linux Integration Services / VM integration).
7. All calls use `KEY_READ` (`0x20019`) — no `SeDebugPrivilege` or administrator token required.

### Variant 4: Filesystem Artifact Walk

1. Walk the Program Files trees with `FindFirstFileW`/`FindNextFileW`:
   - `C:\Program Files\VMware\VMware Tools\` — VMware Tools directory
   - `C:\Program Files\Oracle\VirtualBox Guest Additions\` — VirtualBox Additions
2. Probe for guest-agent executables using `GetFileAttributesW` (lower overhead than `FindFirstFileW` for single-file existence checks):
   - `C:\Windows\System32\vmtoolsd.exe` (VMware Tools service, 64-bit)
   - `C:\Program Files\VMware\VMware Tools\vmtoolsd.exe`
   - `C:\Windows\System32\VBoxService.exe` (VirtualBox Guest Additions service)
   - `C:\Windows\System32\VBoxTray.exe` (VirtualBox Guest Additions tray)
   - `C:\Windows\System32\drivers\vmbus.sys` (Hyper-V VMBus driver)
3. Probe for VM driver files: `FindFirstFileW(L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys", &fd)`, repeat for `VBoxGuest.sys`, `VBoxSF.sys`, `VBoxVideo.sys`, `vmci.sys`, `vmhgfs.sys`, `vm3dmp.sys`, `vmmouse.sys`, `vmrawsock.sys`, `vmusbmouse.sys`, `vmnet*.sys`, `vmbus.sys`, `hyperv*.sys`, `pvscsi.sys`.
4. `FindFirstFileW` returns `INVALID_HANDLE_VALUE` (`(HANDLE)-1`) if the file does not exist. Check `GetLastError() == ERROR_FILE_NOT_FOUND (2)` or `ERROR_PATH_NOT_FOUND (3)`.
5. For directory walks, use `FindFirstFileExW` with `FindExInfoBasic` and `FIND_FIRST_EX_LARGE_FETCH` (`0x2`) — this tells NTFS to return larger directory buffers per IRP, reducing the number of `IRP_MJ_DIRECTORY_CONTROL` round trips.

### Variant 5: Process Enumeration

1. Use `WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &level, WTS_ANY_SESSION, (LPWSTR*)&pProcInfo, &count)` with `level = WTSTypeProcessInfoLevelEx` (value `1`). Returns a `WTS_PROCESS_INFO_EXW` array.
2. Walk the array, matching `pProcess->pProcessName` (a `LPWSTR` pointer into the returned buffer) against: `vmtoolsd.exe`, `VGAuthService.exe`, `VMwareTray.exe`, `VMwareUser.exe` (VMware); `VBoxService.exe`, `VBoxTray.exe` (VirtualBox); `vmcompute.exe`, `vmms.exe` (Hyper-V host-side); `qemu-ga.exe` (QEMU guest agent); `xenstored.exe`, `xenmon.exe` (Xen).
3. Free the buffer with `WTSFreeMemory(pProcInfo)`. The WTS API allocates the process array in the TermService heap via RPC marshaling — forgetting `WTSFreeMemory` leaks the buffer. On a long-running loader, the leak is detectable via `QueryWorkingSet` size growth.
4. Alternative API: `NtQuerySystemInformation(SystemProcessInformation, buf, bufLen, &returnLength)` with info class `0x05`. The returned buffer is a linked list of `SYSTEM_PROCESS_INFORMATION` structures linked by `NextEntryOffset`. Walk until `NextEntryOffset == 0`. Read `ImageName.Buffer` (a `PWSTR` pointer) for the process name and `UniqueProcessId` (a `HANDLE` cast of the PID) for identification.
5. For kernel-module enumeration, use `NtQuerySystemInformation(SystemModuleInformation, ...)` with info class `0x0B`. Returns `RTL_PROCESS_MODULES` containing an array of `RTL_PROCESS_MODULE_INFORMATION` entries. Note: `FullPathName` is a `CHAR[256]` — ANSI, not Unicode. Operators expecting `WCHAR*` will misparse the buffer.
6. `WTSEnumerateProcessesExW` requires RPC access to TermService via the `\pipe\tsrpc` named pipe. On hardened hosts this may fail with `RPC_S_ACCESS_DENIED (5)`. `NtQuerySystemInformation(SystemProcessInformation)` does not require `SeDebugPrivilege` — it returns a snapshot of all processes regardless of session, because the kernel's `PspEnumerateProcesses` path does not perform an access check against each `EPROCESS` for this info class.

### Variant 6: Network Adapter MAC OUI

1. Call `GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &bufLen)` to get the required buffer size. Then allocate and call again: `GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &bufLen)`.
2. Walk the `IP_ADAPTER_ADDRESSES_LH` linked list (`pAddresses->Next`). For each adapter, read `pAddresses->PhysicalAddress` (a `BYTE[8]` array) and `pAddresses->PhysicalAddressLength` (typically `6` for Ethernet).
3. Compare the first 3 bytes (the OUI — Organizationally Unique Identifier) against known VM vendor prefixes:
   - `00:05:69`, `00:0C:29`, `00:50:56`, `00:1C:14` — VMware (multiple OUIs allocated to VMware, Inc.)
   - `08:00:27` — VirtualBox (registered to Cadmus Computer Systems, acquired by InnoTek/Oracle)
   - `00:15:5D` — Microsoft Hyper-V
   - `52:54:00` — QEMU/KVM default (Realtek OUI repurposed by QEMU for virtual NICs)
   - `00:1C:42` — Parallels
4. Filter out loopback (`IfType == IF_TYPE_SOFTWARE_LOOPBACK` = `24`) and tunnel adapters (`IfType == IF_TYPE_TUNNEL` = `131`) — these do not carry VM MACs.
5. Use `memcmp` on the raw 3-byte OUI, not string comparison — `GetAdaptersAddresses` returns raw bytes, and string conversion introduces case ambiguity (`"00:50:56"` vs `"00:50:56"` is fine, but `memcmp` avoids the conversion entirely).

## OS Internals Context

### CPUID and the Hypervisor Interface

The `cpuid` instruction (opcode `0F A2`) is a serializing instruction on both Intel and AMD processors. When a hypervisor is active via Intel VT-x (VMX) or AMD-V (SVM), the VMM configures `CPUID` as either a VM-exit trigger or an unconditional pass-through. The VMX secondary processor-based controls MSR (`IA32_VMX_PROCBASED_CTLS2`) bit 25 ("CPUID exiting") governs this. In most production hypervisors — Hyper-V, KVM with default settings, VMware — `CPUID` does exit. Each exit transitions from the guest (ring 0 or ring 3) through the host's VM-exit handler (`vmx_handle_exit` on KVM, `vmbus` exit processing on Hyper-V), which emulates the `CPUID` response by modifying the register file and then resumes the guest via `VMRESUME` or `VMRUN`.

The CPUID.01H:ECX[31] bit was standardized by Intel and AMD as the "hypervisor present" flag. When set, the OS and user-mode code know to query the hypervisor-specific leaves starting at `0x40000000`. The leaf layout is:

- `0x40000000` — EAX = maximum hypervisor leaf supported; EBX:ECX:EDX = 12-byte vendor signature (packed as `EBX[0:3], ECX[0:3], EDX[0:3]`)
- `0x40000001` — hypervisor interface signature (identifies the paravirt ABI contract)
- `0x40000002`–`0x40000005` — hypervisor feature bits (vary by vendor)
- `0x40000010` — hypervisor timing / version info (VMware-specific)

On bare metal, leaf `0x40000000` returns zeroes in EAX/EBX/ECX/EDX — no hypervisor is present, so the "hypervisor present" bit in leaf 1 is clear and the OS never queries `0x40000000`. The critical false-positive vector: Windows 10/11 with Virtualization-Based Security (VBS), Windows Sandbox, WSL2, or Windows Defender Application Guard all run atop Hyper-V's hypervisor. On such systems, leaf 1 bit 31 is set and leaf `0x40000000` returns `"MicrosoftHV"` — even though the machine is a physical laptop. This makes CPUID alone insufficient for bare-metal detection on modern Windows.

### TSC Internals and Hypervisor Time Virtualization

The TSC is the `IA32_TIME_STAMP_COUNTER` MSR, read by the `RDTSC` instruction (opcode `0F 31`) and the serializing `RDTSCP` (opcode `0F 01 F9`). The "invariant TSC" feature (CPUID.15H:ECX[0] = 1, or CPUID.80000007H:EDX[8] = 1) guarantees the TSC ticks at a constant rate regardless of P-state frequency changes. Without invariant TSC, frequency scaling breaks absolute TSC measurements — but timing *deltas* between back-to-back reads are still valid because the scaling ratio is constant within a measurement window.

When a hypervisor is active, the TSC is virtualized in three modes:

1. **Native pass-through** — the guest reads the host TSC directly. `RDTSC` does not exit. This is the default for KVM when `kvm_clock` is active and Intel TSC offsetting is configured. The timing delta between two `RDTSC` reads bracketing a `CPUID` instruction still reflects the `CPUID` exit cost — because even though `RDTSC` itself does not exit, `CPUID` still does (unless CPUID pass-through is also configured).
2. **TSC offsetting** — the hypervisor adds a constant per-VM offset to the TSC on every read. The offset hides the absolute TSC value (preventing the guest from correlating TSC with host wall-clock time) but does not affect the delta between two reads. Timing detection still works.
3. **TSC scaling** — the hypervisor multiplies the TSC by a ratio. Same caveat: the bracketed instruction's exit cost is still measurable as a delta.

To fully defeat RDTSC timing detection, the VMM must configure `CPUID` as a non-exiting instruction — KVM does this via `KVM_SET_CPUID2` with the `KVM_CPUID_FLAG_STATEFUL_FUNC` and related flags that allow CPUID passthrough for specific leaves. When CPUID does not exit, the timing delta is indistinguishable from bare metal.

The `CR4.TSD` bit (bit 2 of `CR4`, "Time Stamp Disable") causes `RDTSC` and `RDTSCP` to generate `#GP(0)` in ring 3 when set. No production EDR sets this bit because it breaks legitimate performance counters, user-mode timing, and profiling tools. It is mentioned here because an operator encountering `STATUS_PRIVILEGED_INSTRUCTION` from `RDTSC` should suspect a hardened kernel configuration rather than a hypervisor.

### Registry Layout: Disk\Enum and the PnP Manager

The `HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` key is part of the SYSTEM hive, loaded at boot from `C:\Windows\System32\config\SYSTEM`. The hive's REGF format contains a base block at offset 0 (signature `regf` = `0x66676572`), followed by hive bins (`HCELL`) that contain key nodes, value nodes, value lists, and security descriptor cells. The `Disk\Enum` subkey's value `"0"` is a `REG_SZ` populated by the PnP manager during device enumeration — the PnP manager calls `IoOpenDeviceRegistryKey` to get a handle to the device's hardware key, then `ZwSetValueKey` to write the device instance ID string.

`CurrentControlSet` is itself a registry symbolic link — not a real key node. At boot, `NtInitializeRegistry` resolves `HKLM\SYSTEM\Select\Current` (a `DWORD` value, typically `1` for `ControlSet001`) and creates `CurrentControlSet` as a `REG_LINK` cell pointing to `ControlSet001`. The Configuration Manager (`CM`) resolves registry links during path parsing in `CmpParseName` — this works at the `NtOpenKey`/`NtQueryValueKey` level, not just through the Win32 `Reg*` wrapper. An operator using direct syscalls (`NtOpenKey` + `OBJECT_ATTRIBUTES` with `OBJ_CASE_INSENSITIVE`) will resolve the link correctly.

The `Disk\Enum` value `"0"` string follows the device instance ID format: `<enumerator>\<device-id>\<instance-id>`. For PCI devices: `PCI\VEN_xxxx&DEV_yyyy&SUBSYS_zzzz_wwww&REV_rr\&hash`. The PCI SIG-assigned vendor IDs map directly to VM vendors: `80EE` = VirtualBox (InnoTek), `15AD` = VMware, `1AF4` = Red Hat (virtio), `1414` = Microsoft.

### WTSEnumerateProcessesEx RPC and Session Isolation

`WTSEnumerateProcessesExW` is implemented in `wtsapi32.dll` and sends an RPC to the TermService (Terminal Services) service via the `\pipe\tsrpc` named pipe. On the server side (in `svchost.exe` hosting the `TermService` service), the handler calls `NtQuerySystemInformation(SystemProcessInformation)` to get the full process list, then enriches each entry with session ID information from `NtQueryInformationProcess(ProcessSessionInformation)` (info class `0x0C`, which returns a `PROCESS_SESSION_INFORMATION` structure containing the `SessionId` field). The enriched data is marshaled back over RPC.

For `WTS_ANY_SESSION` (value `(DWORD)-1`), the service returns processes from all sessions. Without `SeDebugPrivilege`, the service still enumerates all processes but may set `pUserSid` to `NULL` for processes whose security descriptor does not grant the caller `PROCESS_QUERY_LIMITED_INFORMATION` — the process name and PID are still returned, only the user SID is masked.

### GetAdaptersAddresses and the NDIS Layer

`GetAdaptersAddresses` is exported by `iphlpapi.dll` and internally queries the TCP/IP stack driver (`tcpip.sys`) via `DeviceIoControl` on the IP device. The IP driver calls `NdisRequest` (specifically `NdisQueryInformation` / `NdisOidRequest` on NDIS 6.x) against each bound NDIS miniport to retrieve `OID_802_3_CURRENT_ADDRESS` — the MAC address of the Ethernet adapter. The virtual NIC drivers return their MAC from the hypervisor's configuration:

- VMware's `vmxnet3.sys` reads its MAC from the VMX BIOS NVRAM (`.nvram` file), which uses VMware's allocated OUIs (`00:50:56` for the manually-assigned range `00:50:56:00:00:00`–`00:50:56:3F:FF:FF`, `00:0C:29` and `00:05:69` for auto-assigned addresses).
- VirtualBox's `82540EM`/`82543GC` emulation (in the `VBoxNetAdp` / `VBoxNetLwf` driver) uses `08:00:27` (the Cadmus Computer Systems OUI — InnoTek, later acquired by Oracle, registered this range).
- Hyper-V's `netvsc.sys` uses `00:15:5D` (Microsoft's OUI).
- QEMU's `e1000` emulation defaults to `52:54:00` (a Realtek OUI that QEMU repurposes — `52:54:00` is technically the "Realtek Cloud" range).

The MAC can be user-spoofed in all major hypervisors: VirtualBox GUI network settings, VMware `.vmx` file line `ethernet0.address = "00:50:56:XX:YY:ZZ"`, Hyper-V `Set-VMNetworkAdapter -VMName X -StaticMacAddress "..."`. MAC OUI is therefore the weakest single signal — it must be combined with at least one other variant.

## Key Implementation Details

**Privilege requirements.** All six variants succeed as a standard user without `SeDebugPrivilege` or administrator token. `RegOpenKeyExW` on `HKLM\SYSTEM` and `HKLM\HARDWARE` requires only `KEY_READ` (`0x20019`), granted to `Everyone` by the default hive security descriptor. `NtQuerySystemInformation(SystemProcessInformation)` returns the full process list regardless of session — the kernel's `PspEnumerateProcesses` path does not perform an access check per-process for this info class. `WTSEnumerateProcessesExW` requires RPC access to TermService; on a workgroup machine any local user can call it, but on a domain-joined machine with hardened RPC it may fail with `RPC_S_ACCESS_DENIED (5)` — fall back to `NtQuerySystemInformation`.

**WOW64 boundary.** A 32-bit process running under WOW64 on a 64-bit host must use `NtWow64QuerySystemInformation64` (exported by `ntdll.dll` on 64-bit Windows) instead of `NtQuerySystemInformation` — the native syscall returns 64-bit-aligned structures (`SYSTEM_PROCESS_INFORMATION` with pointer-sized fields) that a 32-bit caller cannot parse correctly. The 32-bit `NtQuerySystemInformation` thunk returns a 32-bit-shaped `SYSTEM_PROCESS_INFORMATION` that omits the high parts of pointer and `LARGE_INTEGER` fields, causing `ImageName.Buffer` to be misread. The simplest path: compile the loader as 64-bit.

**CPUID intrinsic availability.** `__cpuid` is in `<intrin.h>` on MSVC, in `<cpuid.h>` as `__get_cpuid` on GCC/Clang. `__rdtsc` is in `<intrin.h>` on MSVC, `<x86intrin.h>` on GCC. `__rdtscp` requires the `RDTSCP` feature (CPUID.80000001H:EDX[27]). If `RDTSCP` is unavailable, fall back to `__rdtsc()` with a `CPUID` serialization barrier — the `cpuid` instruction is serializing and forces all prior instructions to retire before the TSC read executes.

**RDTSC threshold calibration.** The timing delta threshold is CPU-frequency- and generation-dependent. A bare-metal Intel Core i7-12700K runs `cpuid` in ~80 cycles; under Hyper-V (with its optimized VM-exit path through `vmbus` and `hvloader`) the same call measures ~2000–4000 cycles. Under KVM with default CPUID-exit settings, the exit cost is 8000–15000 cycles. Operators should calibrate against a known-good bare-metal baseline of the same CPU family rather than hardcoding a single threshold. A more robust approach: measure the `cpuid` delta and a `nop`-slide delta on the same machine, then compute the ratio — if the ratio exceeds ~5:1, a hypervisor is intercepting `CPUID`.

**VirtualBox CPUID ambiguity.** Modern VirtualBox (6.1+) with the Hyper-V paravirtualization interface enabled returns `"MicrosoftHV"` on CPUID leaf `0x40000000`, not `"VBoxVBoxVBox"`. This is because VirtualBox uses Hyper-V's paravirt provider as its performance backend on Windows hosts where Hyper-V is active. To detect VirtualBox in this configuration, rely on registry artifacts (`Disk\Enum` value `"0"` containing `PCI\VEN_80EE`, `Services\VBoxGuest` subkey existence) and filesystem artifacts (`VBoxService.exe`, `VBoxGuest.sys`) rather than CPUID.

## Why It Matters

Anti-VM detection is the first link in most malware staging chains. A red-team operator building a loader that should behave differently on analyst sandboxes versus production targets needs composable primitives — not a hardcoded array of `strcmp` checks against fixed strings. This card provides the API-to-check mapping that lets an operator build chains like: "if CPUID reports a hypervisor AND the MAC OUI matches VMware AND `vmtoolsd.exe` is absent, then assume a stripped forensic environment and detonate the decoy payload."

T-020 enumerates 10 fixed anti-VM checks as a point-in-time implementation. This card generalizes the underlying API surface so the operator can adapt: drop the CPUID check when targeting Hyper-V-adjacent environments (where it gives false positives due to VBS), add the `52:54:00` OUI when targeting KVM-based infrastructure, or substitute `QueryPerformanceCounter` for `__rdtsc` when the loader's code-signing chain disallows inline assembly. The vault's T-023 covers adjacent sandbox-evasion checks (sleep timing, user-interaction gates) but does not document the recon API primitives; this card is the prerequisite layer beneath both.

For detection engineers, this card enumerates the specific API call patterns that constitute "VM-aware behavior" — `RegQueryValueExW` on `Services\Disk\Enum` value `"0"`, `__cpuid` with leaf `0x40000000`, `GetAdaptersAddresses` followed by a MAC byte-comparison loop. These are the IOC signatures that EDR rules and YARA patterns should target.

## Detection Considerations

- **Telemetry sources**: `CmRegisterCallbackEx` (kernel-mode registry callback) is the primary surface for Variant 3 — an EDR kernel driver registering `RegNtPreQueryValueKey` can intercept reads of `Services\Disk\Enum` and `HARDWARE\DESCRIPTION\System\BIOS`. For Variant 1, no kernel callback exists for `CPUID` — detection requires either a hypervisor-based monitor (Hyper-V with EPT-based instruction interception) or an instruction-tracing tool (Intel PT, DTrace for Windows). For Variant 5, the `\pipe\tsrpc` named pipe RPC can be monitored via the `ObjectAccess` ETW provider or named-pipe MiniFilter callbacks. `NtQuerySystemInformation` calls are visible via the ETW Threat Intelligence provider. For Variant 6, `GetAdaptersAddresses` calls through `DeviceIoControl` to the TCP/IP stack — monitorable via ETW `Microsoft-Windows-Kernel-Network` provider. For Variant 4, `FindFirstFileW`/`GetFileAttributesW` on VM artifact paths generate `IRP_MJ_CREATE` IRPs visible to MiniFilter pre-operation callbacks.

- **Bypass options**: Replace `RegQueryValueExW` with `NtQueryValueKey` (the native API beneath the Win32 wrapper) — most EDR registry hooks intercept at the Win32 `Reg*` layer, not at the `Nt*` syscall layer. For CPUID, execute the instruction via a JIT-allocated `PAGE_EXECUTE_READWRITE` code page (avoids static opcode scanning for `0F A2`). For RDTSC, use `QueryPerformanceCounter` instead of `__rdtsc` to avoid the `0F 31` opcode appearing in the binary's instruction stream. For process enumeration, use `NtQuerySystemInformation` via direct syscall (bypassing `ntdll.dll` hooks) instead of the WTS RPC. For MAC OUI, read the registry directly from `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\<index>\NetworkAddress` instead of calling `GetAdaptersAddresses`. For filesystem checks, use `NtQueryDirectoryFile` (the native API beneath `FindFirstFileW`) or `NtQueryAttributesFile` for single-file existence probes.

- **Residual artifacts**: `RegOpenKeyExW` on `Services\Disk\Enum` creates a handle in the process's handle table, visible in Process Hacker or `NtQueryInformationProcess(ProcessHandleInformation)` handle scans. `FindFirstFileW` on a non-existent path populates the directory's `$STANDARD_INFORMATION` last-access timestamp in NTFS (though Windows has `NtfsDisableLastAccessUpdate` enabled by default since Vista, so this residual is typically absent). No event log traces are generated by any of these checks. The primary residual is the comparison strings in the binary's `.rdata` section — `"VMwareVMware"`, `"VBoxGuest"`, `"\System32\drivers\vmci.sys"`, `"00:50:56"` — detectable via YARA string rules. An operator who wants to avoid string residuals should compute these at runtime: construct the MAC OUI bytes from arithmetic, build file paths from `GetSystemDirectoryW` + concatenation, and compute CPUID vendor signatures from XOR/ADD operations on constants.

## Composition with Other Techniques

A realistic kill chain for a first-stage loader delivered via T-047 (cross-session delivery):

1. **CPUID gate (Variant 1)**: read leaf `0x40000000`. If the signature is `"MicrosoftHV"`, do not immediately fail — check whether this is a production Hyper-V server or a VBS-enabled workstation. Pass to the next gate.
2. **Registry gate (Variant 3)**: query `Services\Disk\Enum` value `"0"`. If the string contains `PCI\VEN_15AD` (VMware) AND CPUID said `"VMwareVMware"`, *fail* — this is a VMware sandbox. If the string contains `_VMBUS` AND CPUID said `"MicrosoftHV"`, *pass* — this is a production Hyper-V VM. If the string contains `PCI\VEN_80EE` (VirtualBox) AND CPUID said `"MicrosoftHV"` (VirtualBox with Hyper-V paravirt), *fail* — VirtualBox sandbox.
3. **MAC gate (Variant 6)**: read adapter OUI. If `00:50:56` (VMware) and CPUID said VMware, *fail*. If `00:15:5D` (Hyper-V) and CPUID said MicrosoftHV, *pass* (target is a Hyper-V VM — likely a production server). If `52:54:00` (QEMU/KVM), check if CPUID said `"KVMKVMKVM"` — if yes, *fail* (KVM sandbox); if CPUID said `"MicrosoftHV"` (nested Hyper-V on KVM), *pass* (interesting nested-virt production case).
4. **Process gate (Variant 5)**: enumerate via `NtQuerySystemInformation`. If `vmtoolsd.exe` is running and CPUID said VMware, *fail* (VMware sandbox with tools installed). If `vmtoolsd.exe` is absent but CPUID said VMware, *pass* (VM-aware forensic environment where tools were stripped — or a production VM that doesn't run tools).

If all gates pass, proceed to T-020's behavioral checks (user interaction, uptime, desktop icon count) for the second-stage gate. If any gate fails, detonate the decoy payload — a benign document or a honeytoken beacon.

## Variant Comparison Table

| Variant | Trigger | API | Privilege | Kernel Callback Exposure | False Positive Rate |
|---|---|---|---|---|---|
| 1. CPUID Vendor | CPUID.01H:ECX[31] set | `__cpuid` intrinsic | None | None (instruction-level) | High (VBS, WSL2, WDAG all set Hyper-V CPUID) |
| 2. RDTSC Timing | `CPUID` VM-exit cost measured as TSC delta | `__rdtsc`/`__rdtscp` or `QueryPerformanceCounter` | None | None (opcode-level) | Medium (CPU-frequency dependent; KVM with CPUID passthrough defeats it) |
| 3. Registry Survey | `Disk\Enum` value `"0"` device ID string | `RegOpenKeyExW`/`RegQueryValueExW` | `KEY_READ` (Everyone) | `CmRegisterCallbackEx` (`RegNtPreQueryValueKey`) | Low (PCI vendor IDs are deterministic) |
| 4. Filesystem Walk | VM tool/driver file existence | `FindFirstFileW`/`GetFileAttributesW` | None | MiniFilter `IRP_MJ_CREATE` pre-op | Low |
| 5. Process Enum | VM guest-agent process image name | `WTSEnumerateProcessesExW` or `NtQuerySystemInformation(0x05)` | None | WTS RPC pipe monitoring; `NtQuerySystemInformation` ETW | Low (process names are deterministic) |
| 6. MAC OUI | Virtual NIC MAC prefix (3 bytes) | `GetAdaptersAddresses` (iphlpapi) | None | `DeviceIoControl` on IP device | Medium (MACs user-spoofable in all major hypervisors) |

## Common Mistakes

1. **Trusting CPUID alone on Windows 10/11.** VBS, Windows Sandbox, WSL2, WDAG, and any Hyper-V-enlightened process sets the CPUID hypervisor-present bit and returns `"MicrosoftHV"` — even on a physical laptop. CPUID alone generates ~40% false-positive rate on modern Windows. Always pair CPUID with a registry (`Disk\Enum`) or filesystem (`vmtoolsd.exe`) check that distinguishes "Hyper-V on bare metal" from "VMware guest."
2. **Hardcoding RDTSC thresholds across CPU generations.** A threshold of 10000 cycles that works on Intel Haswell will false-positive on Alder Lake bare metal (where `cpuid` is faster) and false-negative on KVM with CPUID passthrough (where `cpuid` does not exit). Calibrate per CPU family or use a relative measurement: compare the `cpuid` delta to a `nop`-slide delta measured on the same machine.
3. **Using `WTSEnumerateProcessesExW` without `WTSFreeMemory`.** The WTS API allocates the process array in the TermService heap via RPC marshaling. Forgetting `WTSFreeMemory(pProcInfo)` leaks the buffer — on long-running loaders, the leak is detectable via working-set growth monitoring.
4. **Calling `NtQuerySystemInformation` from a 32-bit process.** The returned `SYSTEM_PROCESS_INFORMATION` structures use 64-bit field sizes on an x64 OS. A 32-bit caller parsing the buffer with 32-bit offsets will misread `ImageName.Buffer` (a pointer-sized field) and either crash or match garbage. Use `NtWow64QuerySystemInformation64` or compile as 64-bit.
5. **Forgetting that `SystemModuleInformation` returns ANSI strings.** `NtQuerySystemInformation(SystemModuleInformation)` (info class `0x0B`) returns `RTL_PROCESS_MODULE_INFORMATION` entries where `FullPathName` is `CHAR[256]` — ANSI, not Unicode. Using `wcsstr` on the `FullPathName` field will match garbage. Use `strstr` or convert via `MultiByteToWideChar(CP_ACP, ...)`.
6. **Checking only the first network adapter.** A VM may have a physical NIC passthrough (PCI passthrough on KVM, SR-IOV on Hyper-V) whose MAC is a real-vendor OUI. Walk the full `IP_ADAPTER_ADDRESSES` linked list via `pAddresses->Next`, not just the first entry.

## Related Techniques

- **T-020 Anti-VM Checks** — the concrete 10-check implementation that this card generalizes; T-020 is the "what," this card is the "which API and how."
- **T-023 Sandbox Evasion** — adjacent behavioral checks (sleep timing, user interaction, desktop entropy) that compose with this card's API primitives to form a complete environment-fingerprinting gate.
- **T-047 Cross-Session Delivery** — composes upstream: T-047 delivers the loader, this card's primitives gate detonation before the real payload stage executes.