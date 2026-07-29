---
id: T-123
name: GUI Syscall Path via win32u.dll and win32k.sys
category: syscalls
tier: A
crate: none
source_file: none
mitre: T1562.001
mitre_secondary: [T1106]
tags: [win32u-syscalls, win32k, edr-bypass, hook-evasion, gui-thread, shadow-ssdt, user32, clipboard, input-injection, thread-attribution]
member_notes: ['lgtm:win32u-gui-syscall-hook-coverage', 'lgtm:gui-vs-native-syscall-path-awareness']
origin: atlas-synthesis
---

# GUI Syscall Path via win32u.dll and win32k.sys — the half of the syscall surface that T-016 does not touch

## Summary

Windows routes its user-mode system calls through two distinct user/kernel pairs: executive syscalls (`ntdll.dll` → `ntoskrnl.exe`) and GUI/windowing syscalls (`win32u.dll` → `win32k.sys`). The split became physical in Windows 10 RS1 (build 1607), when Microsoft lifted the user-mode `NtUser*` and most `NtGdi*` syscall stubs out of `user32.dll` / `gdi32.dll` into a new module, `win32u.dll`. Functions such as `NtUserOpenClipboard`, `NtUserFindWindowEx`, `NtUserMessageCall`, `NtUserSetWindowsHookEx`, `NtUserGetMessage`, `NtUserPostMessage`, and the `NtGdi*` rendering family are dispatched through `win32u.dll` stubs, not through `ntdll.dll`. EDRs instrument both paths with inline hooks — typically a `JMP rel32` (`E9 <imm32>`, 5 bytes) or a `MOV RAX, imm64; JMP RAX` trampoline (`48 B8 <imm64> FF E0`, 12 bytes) on the first instruction of the stub — so a T-016 `ntdll.dll` unhook that restores the executive syscall surface leaves the entire GUI surface fully instrumented. Worse, `win32k.sys` enforces a thread-attribution gate: a thread whose embedded `_KTHREAD.Win32Thread` pointer is `NULL` is rejected by most `NtUser*` / `NtGdi*` handlers (returning `STATUS_INVALID_THREAD` or `STATUS_ACCESS_DENIED`), so operators issuing clipboard, window-enumeration, or input-injection syscalls directly — bypassing `user32.dll` — must first ensure the calling thread is GUI-initialized, typically by forcing a benign User32 call that triggers `user32!Win32InitializeThunk` and the kernel-side `W32THREAD` allocation. The vault's T-016 card documents `ntdll.dll` unhooking thoroughly but does not cover this GUI half; the present card fills that gap and is the GUI-side mirror of T-016.

## Mechanism

### Variant 1: Direct syscall via SSN harvested from on-disk `win32u.dll`

1. Locate the on-disk `win32u.dll` at `C:\Windows\System32\win32u.dll`. Do not use the in-memory copy already resident in the current process — that copy is the one EDR has instrumented with inline hooks.
2. Open the file with `CreateFileW(L"C:\\Windows\\System32\\win32u.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)`, then `CreateFileMappingW(handle, NULL, PAGE_READONLY, 0, 0, NULL)` and `MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0)`. The result is a pristine PE image with no EDR detours.
3. Parse `IMAGE_DOS_HEADER.e_lfanew` at offset `0x3C` to locate `IMAGE_NT_HEADERS64`; verify `Signature == 0x00004550` ("PE\0\0") and `OptionalHeader.Magic == 0x20B` (PE32+).
4. Walk `IMAGE_EXPORT_DIRECTORY` at `OptionalHeader.DataDirectory[0].VirtualAddress`. Resolve `AddressOfNames`, `AddressOfNameOrdinals`, `AddressOfFunctions` arrays. Filter for `NtUser*` and `NtGdi*` prefixes.
5. For each target export (e.g., `NtUserOpenClipboard`), read the first bytes of the function body. The canonical x64 syscall stub is:
   ```
   4C 8B D1                    mov r10, rcx
   B8 ?? ?? 00 00              mov eax, <SSN>
   0F 05                       syscall
   C3                          ret
   ```
   The SSN is the little-endian 32-bit value at offset +3 of the stub. Extract it.
6. Construct a syscall stub in executable memory (`VirtualAlloc(... PAGE_EXECUTE_READWRITE = 0x40 ...)` or `NtAllocateVirtualMemory` with `PAGE_EXECUTE_READWRITE`) that mirrors the canonical stub with the discovered SSN — or, more cleanly, build a generic dispatcher taking `(SSN, argc, argv)` marshaling the first four integer args through `RCX/RDX/R8/R9` and the rest on the user stack per x64 fastcall.
7. Before invoking the stub, ensure the calling thread is GUI-attributed (see *Common Mistakes* #1 and *Key Implementation Details* below). Otherwise the call returns `STATUS_INVALID_THREAD` (`0xC000071C`) without performing the operation.
8. Call the stub. The `syscall` instruction transitions to the kernel via `KiSystemCall64` (referenced by `IA32_LSTAR` MSR). The dispatcher consults the SSDT shadow table and lands in `win32k!NtUserOpenClipboard` (or equivalent) inside `win32k.sys`.

### Variant 2: Halo's Gate / Tartarus' Gate against in-memory `win32u.dll`

1. Walk `PEB.Ldr->InLoadOrderModuleList` from the current process PEB (reached via `gs:[0x60]` on x64). Find `win32u.dll` by hashing the base name (`LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer`, matching length-prefixed Unicode).
2. Walk `win32u.dll`'s `IMAGE_EXPORT_DIRECTORY` and resolve the target `NtUser*` stub VA.
3. Inspect the first byte at the stub address. If `0x4C` (`mov r10, rcx` prefix) — the canonical unhooked pattern — read the SSN at offset +3 and proceed.
4. If the first byte is `0xE9` (relative `JMP`, 5-byte inline hook) or `0x48` followed by `0xB8` (`MOV RAX, imm64`, 12-byte absolute-jump hook), or `0xFF` (`JMP [RAX]`), or `0xEB` (short JMP), or `0xCC` (int3 trampoline), the stub is hooked. Apply Halo's Gate: walk backwards 32 bytes at a time, checking for the `4C 8B D1 B8` pattern. Each 32-byte step typically lands on a sibling `NtUser*` stub because the export table lays stubs contiguously in the `.text` section.
5. Once a clean stub is found, compute its SSN from offset +3. Add the count of stubs walked past to recover the target's true SSN (Tartarus' Gate handles the SSN delta when EDR randomizes SSNs — most production EDRs do not, but the variant survives that case too).
6. Construct a direct-syscall stub as in Variant 1.

### Variant 3: Fresh-map `win32u.dll` and patch the in-memory hooked stubs

1. Map a pristine `C:\Windows\System32\win32u.dll` into the process using `LoadLibraryExW(L"win32u.dll", NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE)` — or, more cleanly, manually map it from `CreateFile` + `NtCreateSection` (`SEC_IMAGE = 0x01000000`) + `NtMapViewOfSection`.
2. Locate `IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory[0]` (Export Directory RVA) of both the freshly mapped image and the resident (hooked) image.
3. For each `NtUser*` / `NtGdi*` export, compute its VA inside the freshly mapped image and the corresponding VA in the resident image (using each image's own `ImageBase`).
4. `VirtualProtectEx(GetCurrentProcess(), resident_stub_va, stub_size, PAGE_READWRITE = 0x04, &old_protect)` the resident stub region.
5. `memcpy(resident_stub_va, fresh_stub_va, stub_size)` — typically 6 to 9 bytes per stub.
6. `VirtualProtectEx(GetCurrentProcess(), resident_stub_va, stub_size, PAGE_EXECUTE_READ = 0x20, &old_protect)` to restore.
7. `FlushInstructionCache(GetCurrentProcess(), resident_stub_va, stub_size)` to invalidate any stale I-cache lines.
8. The in-memory `win32u.dll` is now clean. Calling `NtUserOpenClipboard` through `GetProcAddress(GetModuleHandleW(L"win32u.dll"), "NtUserOpenClipboard")` now hits the unhooked stub.

This Variant 3 is the direct analogue of the classic T-016 ntdll unhook, applied to the GUI surface. Note that EDRs which hook `win32u.dll` aggressively may re-hook on a timer or via a background worker thread — the patch may need refreshing on a heartbeat.

### Variant 4: Shadow SSDT direct read (kernel primitive required)

1. Obtain a kernel-mode read primitive (driver load, signed-driver abuse, or a kernel exploit that exposes an `MmCopyVirtualMemory`-equivalent).
2. Locate `KeServiceDescriptorTableShadow`. The public `KeServiceDescriptorTable` is exported by `ntoskrnl.exe`; the shadow table is its paired counterpart and lives at a fixed offset (build-dependent) within the same `_KSERVICE_TABLE_DESCRIPTOR` pair. Use `MmGetSystemRoutineAddress` on `KeServiceDescriptorTable` and scan nearby non-paged pool for the second descriptor with matching `Limit` semantics.
3. The shadow table is an array of two `_KSERVICE_TABLE_DESCRIPTOR` entries: index `0` is the executive table (ntoskrnl syscalls), index `1` is the GUI table (win32k syscalls).
4. The GUI table's `Base` points to `KiServiceTable` (win32k portion); `Limit` bounds the valid SSN range. Each table entry is a 32-bit value encoding the function's offset (sign-extended shifted) in its low bits and a stack-argument count in its high bits.
5. Index the table by the SSN value with the table-selector bit masked (historically `SSN & 0xFFF` on x86 where bit 12 = `0x1000` selected the shadow; on x64 modern Windows the encoding is build-specific — verify against a known-good SSN harvested from `win32u.dll` before trusting the read).
6. Resolve the function pointer, decode it, and cross-check against the SSNs harvested in Variants 1–3. This is the authoritative kernel source of truth; it also exposes undocumented `NtUser*` syscalls not exported by `win32u.dll`.

## OS Internals Context

### The dual SSDT and `KeServiceDescriptorTableShadow`

Windows maintains two service descriptor tables. `KeServiceDescriptorTable` (exported from `ntoskrnl.exe`) contains only executive syscalls. `KeServiceDescriptorTableShadow` (unexported, found by scanning near the public table or via the `KdDebuggerDataBlock`) holds both executive and GUI entries — the latter in its index-`1` descriptor slot, populated at win32k initialization. The shadow table exists because GUI threads (those with a non-`NULL` `_KTHREAD.Win32Thread`) need to issue both executive and GUI syscalls through the same dispatcher, while non-GUI threads can be confined to the executive-only public table.

When a user-mode `syscall` instruction executes, the trap entry is `KiSystemCall64` (referenced by `IA32_LSTAR` MSR at MSR address `0xC0000082`). The dispatcher reads the SSN from `EAX`, marshals arguments from the user stack per the calling convention, and consults `KiSystemServiceRepeat`. The decision of which table to use is the kernel-side shadow-table check: historically on x86 Windows, bit `12` (`0x1000`) of the SSN determined shadow vs. plain. On x64 modern Windows the mechanism is the same in spirit — the SSN encodes its table membership — but the exact masking and encoding depend on build. From the operator's perspective, the SSN harvested from a `win32u.dll` stub already encodes the right table: that is the value you load into `EAX` and `syscall` on. There is no separate user-mode action to select the shadow; the kernel dispatcher routes based on the SSN value itself.

### The `Win32Thread` gate

Every `ETHREAD` embeds a `_KTHREAD` (its `Tcb` field at offset `0`). Inside `_KTHREAD`, the `Win32Thread` field is a `PVOID` that is `NULL` until the thread is attributed to the Win32 subsystem. When the thread calls into `user32.dll`/`gdi32.dll` for the first time, the internal `user32!Win32InitializeThunk` routine executes a syscall that triggers `win32k!InitWin32Thread` (a kernel-side routine that allocates a `W32THREAD` structure — historically called `THREADINFO` in WDK headers and leaky internal symbols — and stores its address back into `_KTHREAD.Win32Thread`).

The `W32THREAD` carries per-thread GUI state: the `pTL` thread-lock list, `pcls` window-class list, `apW32GX` GDI handle-cache slots, the `pUMPD` user-mode printer driver binding, `cEnterCount` for reentrancy tracking, and a back-pointer into the thread's `ETHREAD`. It is the structure that every `NtUser*` and most `NtGdi*` syscall handlers reach for first — `KeGetCurrentThread()->Win32Thread`, dereferenced. If that pointer is `NULL`, the handler short-circuits: most return `STATUS_INVALID_THREAD` (`0xC000071C`); some return `STATUS_ACCESS_DENIED` (`0xC0000022`) or `STATUS_THREAD_IS_TERMINATING` (`0xC000004B`) depending on context. A handful of meta-syscalls (e.g., `NtUserGetThreadState` with certain state indices, or the first-call path through `Win32InitializeThunk` itself) perform lazy initialization themselves — these are the back-door through which the first ordinary `user32.dll` call bootstraps the thread.

The kernel fires `PsSetWin32ThreadCallout` (an unexported kernel callback registration, populated by `win32k.sys` during its init) when the `W32THREAD` is created or destroyed. EDRs that register this callout receive a per-thread notification that the thread has just become GUI-attributed — useful for catching operators who attempt to lazily initialize a worker thread right before issuing clipboard or hook syscalls. The notification fires once per thread lifecycle, which is what makes the signal high-fidelity.

### `win32k.sys` as a separate kernel image

`win32k.sys` is loaded at boot by `MpInitTransition` / `Phase1InitializationDiscard` and registered with the SSDT shadow table. It is one of the largest kernel images on Windows (commonly 4+ MB), exposing on the order of 600+ GUI syscalls spanning User (windowing, messaging, input, hooks, clipboard, DWM) and GDI (rendering, DC, region, bitmap). The split between `ntoskrnl.exe` and `win32k.sys` is older than `win32u.dll`: the kernel-side split has existed since Windows NT 3.5 (when GUI was moved into kernel mode from user mode to improve performance). The user-mode split — moving stubs from `user32.dll` / `gdi32.dll` into `win32u.dll` — is the RS1 (1607) change. From the operator's perspective the change is purely a relocation of the syscall stubs: any T-016-style unhook that walks `ntdll.dll`'s `.text` section misses the GUI surface entirely because the stubs are no longer there.

### Why EDRs hook `win32u.dll`

The GUI syscall surface covers the highest-value operational primitives: clipboard access (`NtUserOpenClipboard`, `NtUserGetClipboardData`, `NtUserSetClipboardData`), window enumeration (`NtUserFindWindowEx`, `NtUserEnumWindows`, `NtUserGetForegroundWindow`), input injection (`NtUserSendMouseEvent`, `NtUserSendKeyboardInput`, `NtUserSetWindowsHookEx`), cross-process window messaging (`NtUserMessageCall`, `NtUserPostMessage`, `NtUserSendMessage`), and screen-capture-adjacent GDI calls (`NtGdiBitBlt`, `NtGdiStretchBlt`, `NtGdiAlphaBlend`). EDRs hook these aggressively because:

1. They are reachable from a low-privileged process — `NtUserOpenClipboard` requires no special token, no `SeDebugPrivilege`, no admin rights.
2. They enable credential theft (clipboard contents frequently contain passwords, MFA codes, file paths), keystroke capture (window hooks of type `WH_KEYBOARD` / `WH_KEYBOARD_LL` / `WH_JOURNALRECORD`), and lateral UI manipulation (window-message injection into `explorer.exe` or browser processes for credential dialog spoofing and Shatter-style attacks).
3. They are the standard path used by commodity info-stealers (Lumma, RedLine, Raccoon, Vidar) — detecting them produces high-fidelity alerts with very low false-positive rates.

EDRs typically hook each `NtUser*` stub in `win32u.dll` with a 5-byte relative `JMP` (`E9 <rel32>`) or, when the stub is too small to host that and remain relocatable, a 12-byte absolute trampoline (`48 B8 <imm64> FF E0`). The hook intercepts the call, evaluates the arguments (e.g., does the caller's window-station match the target, is the requesting thread the foreground input thread, is the window-class on a denylist), decides allow/deny/telemetry, and either continues the call or returns a failure `NTSTATUS`. Microsoft's own ETW Threat Intelligence provider (`Microsoft-Windows-Threat-Intelligence`, GUID `{f4e8887f-cd31-4d57-a5db-349383d7227c}`) covers the same syscalls at the kernel SSDT dispatch boundary — so even with a clean `win32u.dll` unhook, kernel-side telemetry still fires.

### The Wow64 boundary

WOW64 processes (32-bit on 64-bit Windows) do not have `win32u.dll` loaded into the 32-bit address space; the equivalent stubs live in the 64-bit `win32u.dll` reached via the WoW64 transition (`wow64win.dll` → `wow64.dll` → 64-bit `win32u.dll` on the host side). An operator building direct GUI syscalls from a WOW64 process must transition to 64-bit mode (Heaven's Gate — segment selector `0x33` far jump) or run native 64-bit. This is the same boundary T-016 already concerns itself with for `ntdll.dll`; the GUI surface makes the constraint only more acute because `wow64win.dll` adds its own hookable layer above the 64-bit `win32u.dll`.

## Key Implementation Details

### Prerequisites: thread GUI attribution

The thread calling any `NtUser*` / `NtGdi*` syscall must have a non-`NULL` `_KTHREAD.Win32Thread`. There are two reliable ways to guarantee this from user mode:

1. Call any normal `user32.dll` API before issuing your direct syscall. `GetDesktopWindow()` is the safest one-line initializer — it returns the desktop window handle and forces the `user32.dll` internal trampoline through `Win32InitializeThunk`, which triggers the kernel-side `W32THREAD` allocation. `GetMessageW` with a `NULL` hwnd is **not** safe — it blocks waiting for input. `EnumChildWindows(NULL, ...)` is acceptable. `FindWindowW(NULL, NULL)` works.
2. Call `GdiDllInitialize(hinst, reason, reserved)` directly (it is exported from `gdi32.dll` / `gdi32full.dll`). This is the path `user32!DllMain` itself takes during process init for threads it owns.

Do **not** assume the syscall handler will lazily init the thread for you — most do not, and the rejection is silent in production builds (no exception, just a non-zero `NTSTATUS`).

### Hook detection on `win32u.dll`

Before using any harvested SSN, verify the stub is intact. The first byte of every legitimate `win32u.dll` `NtUser*` stub is `0x4C` (the `mov r10, rcx` prefix). Any other first byte — `0xE9` (rel JMP), `0x48` (MOV RAX abs), `0xFF` (`JMP [RAX]`), `0x68` (push imm32, used by some products), `0xEB` (short JMP) — is a hook. Some EDRs use 1-byte `0xCC` (int3) breakpoints recovered by a vectored exception handler; check for those too.

### SSN encoding

On x64 Windows, `win32u.dll` stubs encode SSNs that are in a higher range than `ntdll.dll` stubs — the GUI range starts around `0x1000` and above. The kernel dispatcher uses this encoding to route the call into the shadow SSDT's index-`1` (GUI) descriptor. Treat the SSN as opaque: copy the bytes from the clean stub verbatim into your dispatcher's `mov eax, <SSN>` slot. Do not strip the high bit. A common operator mistake is to "normalize" the SSN by masking off the table-selector bits, which silently routes the call into the wrong kernel table and produces `STATUS_INVALID_SYSTEM_SERVICE` (`0xC000001C`).

### Module presence

`win32u.dll` is loaded into any process that has pulled in `user32.dll` — i.e., the vast majority of GUI subsystem executables. A console-subsystem process (e.g., the default Rust `std` binary, `cmd.exe` before any User32 call) may not have `win32u.dll` resident. Force-load it via `LoadLibraryW(L"win32u.dll")` or, more cleanly, `LoadLibraryW(L"user32.dll")` (which pulls `win32u.dll` as a dependency) before doing any SSN harvesting or stub construction. `GetProcAddress(GetModuleHandleW(L"win32u.dll"), "NtUserOpenClipboard")` returns `NULL` if the module is not resident, and the operator's subsequent pointer dereference will fault.

### Calling convention

x64 syscall stubs follow fastcall: integer args in `RCX` / `RDX` / `R8` / `R9`, floating-point in `XMM0..3`, additional args on the user stack right-to-left with the return-address slot and 32 bytes of shadow space reserved. The `syscall` instruction clobbers `RAX` (return value), `RCX` (return RIP saved by kernel), and `R11` (RFLAGS saved by kernel). All `NtUser*` syscalls use the same calling convention as `Nt*` executive syscalls; a generic direct-syscall dispatcher built for `ntdll.dll` works verbatim against `win32u.dll` SSNs — no convention adjustment is required.

## Why It Matters

Any post-exploitation capability that touches the GUI surface — clipboard monitoring, window enumeration for finding browser windows or IM clients, input injection for keystroke simulation, `WH_CBT` or `WH_GETMESSAGE` hooks for in-process or cross-process instrumentation, `BitBlt`-based screen capture, `SendMessageW` to `DefDlgProc` for Shatter-style privilege escalation — is, by default, fully visible to the EDR. Most operators treat T-016 (`ntdll.dll` unhook) as the syscall-evasion baseline and assume the kernel boundary is now clean. It is not: half the syscall surface lives in a different module (`win32u.dll`), routing through a different kernel image (`win32k.sys`), and T-016 does not touch it.

This card is the GUI-side mirror of T-016. Apply T-016 for the executive surface (file, registry, process, token, memory, thread) and apply this card for the GUI surface (window, input, clipboard, hooks, GDI). The two compose trivially: build a single direct-syscall dispatcher that handles both ntdll-harvested and win32u-harvested SSNs, apply a fresh-map unhook to both modules in the same pass, and treat the dual unhook as the new baseline. Many commodity red-team tools do not yet do this and leak `win32u.dll`-side telemetry on every clipboard read — including, in particular, `NtUserOpenClipboard` invocations, which ETW-TI emits as Threat-Intelligence events tagged with the caller's `PROCESS` object pointer and target window-station identity.

The card also matters for thread-attribution awareness: even if every hook is bypassed, the kernel still gates GUI syscalls on `_KTHREAD.Win32Thread` and still fires `PsSetWin32ThreadCallout` when the operator initializes a worker thread right before issuing a clipboard syscall. The combination of (unhooked `win32u.dll`, GUI-attributed worker thread that just became active) is a known EDR signal and must be paced — initialize the thread at process start alongside benign User32 setup, not microseconds before the first malicious `NtUser*` call.

## Detection Considerations

- **Telemetry sources**: Microsoft-Windows-Threat-Intelligence ETW provider (`{f4e8887f-cd31-4d57-a5db-349383d7227c}`, admin-only, requires `EVENT_SYSTEM_TRACE_SID` privilege) emits kernel-level events for `NtUserOpenClipboard`, `NtUserSetWindowsHookEx`, `NtUserFindWindowEx`, `NtUserMessageCall`, `NtUserGetClipboardData`, and a dozen other GUI syscalls. These fire inside the kernel at SSDT dispatch — after the user-mode stub has been traversed — so direct-syscall bypasses still trip them. Microsoft-Windows-Win32k provider covers higher-volume GUI operational telemetry. Microsoft-Windows-Kernel-Process (`{22fb2cd6-0e7b-422b-a0da-4be426f104d1}`) covers thread create/exit, useful for correlating a worker thread's lifecycle against GUI syscall activity. EDR inline hooks on `win32u.dll` add user-mode telemetry for every hooked stub — the first-stage detection before kernel TI is consulted. The `PsSetWin32ThreadCallout` kernel callback notifies registered drivers when a thread becomes GUI-attributed — the moment an operator calls `GetDesktopWindow()` from a worker thread that never had `user32.dll` loaded, this fires.
- **Bypass options**: Fresh-map `win32u.dll` (Variant 3) defeats inline-hook telemetry. Direct syscalls (Variant 1) defeat inline-hook telemetry and the residual artifacts of Variant 3's `VirtualProtect` churn. Direct syscalls do **not** defeat ETW-TI, which lives at the kernel SSDT boundary — bypassing ETW-TI requires tampering with the provider registration (clearing `ETW_REG_ENTRY`'s `EnableMask` bits in the kernel's `EtwGuidEntry` table, or removing the EDR's kernel-mode ETW consumer thread), both of which require kernel privileges. To reduce the `PsSetWin32ThreadCallout` signal, initialize the calling thread as GUI-attributed **before** the red-team payload begins issuing flagged syscalls — ideally at process start time, ideally alongside other benign User32 initialization so the callout does not stand alone in time as an isolated event.
- **Residual artifacts**: A freshly mapped `win32u.dll` (Variant 3) leaves a second `win32u.dll` mapped view visible in the process's VAD tree (`EPROCESS.VadRoot`), with a section object whose `_CONTROL_AREA.FilePointer` points to `\Device\HarddiskVolume...\Windows\System32\win32u.dll`. The `VirtualProtect` flip to `PAGE_READWRITE` and back to `PAGE_EXECUTE_READ` on `win32u.dll`'s `.text` section leaves a working-set-trimming side-effect and, on systems with Kernel CFG (KCFG) or Hypervisor-Protected Code Integrity (HVCI) active, may be blocked outright by the Code Integrity policy — the kernel refuses to mark a section that is `IMAGE_SCN_MEM_EXECUTE` writable if the CI policy for that image disallows it. Direct syscalls (Variant 1) leave a small executable allocation visible via `VirtualQueryEx` walks; hide it by placing the stub inside a legitimate-looking existing allocation (e.g., the `.text` of a module the process already loaded — though this requires write access to that section). The thread-attribution transition is the most persistent residual: once a worker thread is GUI-attributed, the `W32THREAD` allocation persists until thread exit, and any subsequent `NtUser*` calls from that thread correlate cleanly in EDR telemetry.

## Variant Comparison Table

| Variant | Surface | Privilege | Bypasses UM Hooks | Bypasses ETW-TI | Bypasses `PsSetWin32ThreadCallout` | Operational Cost |
|---------|---------|-----------|-------------------|-----------------|------------------------------------|------------------|
| 1: Direct syscall (SSN from on-disk `win32u.dll`) | `syscall` instruction in operator-allocated executable memory | None (standard user) | Yes | No | No | Low — fresh copy of `win32u.dll` on disk |
| 2: Halo's / Tartarus' Gate (in-memory `win32u.dll`) | Same as Variant 1 | None | Yes | No | No | Lowest — no file touch; relies on EDR not randomizing SSNs |
| 3: Fresh-map + patch in-memory `win32u.dll` | `NtUser*` called normally through `GetProcAddress(win32u, "NtUser*")` | None; blocked by HVCI on some builds | Yes | No | No | Medium — leaves VAD/section artifacts; EDR re-hook possible |
| 4: Shadow SSDT direct read | Requires kernel read primitive | Kernel (driver load or exploit) | Yes | No (does not affect kernel-side telemetry) | No | High — requires separate kernel foothold |

## Common Mistakes

1. **Forgetting to initialize the calling thread as GUI-attributed.** Operators who `VirtualAlloc` a stub, fire `NtUserOpenClipboard` from a worker thread that has never touched `user32.dll`, and stare at `STATUS_INVALID_THREAD` (`0xC000071C`) for an hour. Fix: `LoadLibraryW(L"user32.dll"); GetDesktopWindow();` once on the calling thread before any `NtUser*` direct syscall.
2. **Masking the table-selector bits off the SSN.** Code that "normalizes" SSNs to "discover the executive equivalent" silently strips the high range and routes the call into `ntoskrnl.exe`'s SSDT, where the SSN is out of range and `KiSystemServiceRepeat` returns `STATUS_INVALID_SYSTEM_SERVICE` (`0xC000001C`). The SSN from a `win32u.dll` stub is opaque — use it verbatim.
3. **Assuming `win32u.dll` is loaded.** A console-subsystem process (default Rust `std` binary, `cmd.exe` before any User32 call) often does not have `win32u.dll` in its module list. `GetProcAddress(GetModuleHandleW(L"win32u.dll"), ...)` returns `NULL`, the operator's subsequent pointer dereference faults. Force-load `user32.dll` first.
4. **Trusting in-memory `win32u.dll` SSNs when running Halo's Gate.** Production EDRs occasionally hook sibling stubs too, or randomize SSNs (rare but documented in some products). Always cross-check at least one SSN against the on-disk `win32u.dll`.
5. **Using a 5-byte inline-hook pattern as the SSN signature.** The SSN at offset +3 of the canonical stub is only valid when the first three bytes are `4C 8B D1`. Operators that read offset +3 of a hooked stub (`E9 ?? ?? ?? ??`) read a 4-byte `rel32` instead of an SSN and produce garbage syscall numbers that fault inside the dispatcher.
6. **Skipping `FlushInstructionCache` after Variant 3 patch.** On Windows with strong I-cache coherency guarantees this is rare to matter, but on systems with HVCI and certain ARM64 emulation layers, stale I-cache contents can route the patched stub through the old (hooked) code path for a few hundred microseconds after `memcpy`. Always `FlushInstructionCache(GetCurrentProcess(), addr, size)`.
7. **Issuing `NtUser*` syscalls from a Wow64 32-bit process.** The 32-bit `SysWOW64` layer routes GUI syscalls through `wow64win.dll` → 64-bit `win32u.dll` via the WoW64 transition. Direct syscalls from the 32-bit stub land in the wrong SSDT. Stay native 64-bit for any direct GUI syscall work, or transition to long mode via Heaven's Gate (`JMP FAR 0x33:`) before issuing the syscall.
8. **Pacing the `PsSetWin32ThreadCallout` badly.** Operators that initialize a worker thread GUI-attributed 50 ms before issuing `NtUserOpenClipboard` produce a clean two-event sequence that any EDR correlation rule catches. Initialize the thread at process start, not on demand, or initialize alongside benign GUI activity (e.g., enumerating the desktop window list) to dilute the signal.

## Composition with Other Techniques

A realistic end-to-end kill chain that uses this card:

1. **Initial access / payload staging**. The operator has a Rust implant running as standard user in a GUI-subsystem executable (e.g., a wrapper around a benign-looking signed binary that has `user32.dll` in its import table).
2. **T-016 (ntdll unhook)**. The implant unhooks `ntdll.dll` to restore the executive syscall surface. File, registry, token, and process syscalls are now clean.
3. **This card (win32u unhook + direct syscalls)**. The implant unhooks `win32u.dll` using Variant 3, then harvests SSNs for `NtUserOpenClipboard`, `NtUserGetClipboardData`, `NtUserFindWindowEx`, `NtUserSetWindowsHookEx` from the freshly mapped pristine copy using Variant 1. Constructs a direct-syscall dispatcher.
4. **Thread attribution**. The implant spins a dedicated worker thread for GUI operations. At thread start, it calls `LoadLibraryW(L"user32.dll"); GetDesktopWindow();` to set `_KTHREAD.Win32Thread`, accepting the one-time `PsSetWin32ThreadCallout` signal as unavoidable, and paces subsequent GUI syscalls against benign-looking Explorer clipboard polling intervals (every ~5 seconds is typical for many Explorer add-ins).
5. **Capability execution**. The worker thread issues `NtUserOpenClipboard(NULL)` → `NtUserGetClipboardData(CF_UNICODETEXT = 13)` → `NtUserCloseClipboard()` on a 5-second polling loop to scrape clipboard contents (credentials, file paths, MTP-attached device metadata). Separately, `NtUserFindWindowEx(NULL, NULL, L"Chrome_WidgetWin_1", NULL)` enumerates browser windows; `NtUserMessageCall` posts benign window messages to identify foreground tab titles. The user-mode EDR sees nothing because the hooks are gone. The kernel-side ETW-TI still sees the syscalls — that is unavoidable without kernel tampering — but the volume is low and blends with normal Explorer / Office clipboard polling traffic.
6. **Cleanup**. On shutdown, the worker thread exits; the `W32THREAD` is freed via a second `PsSetWin32ThreadCallout`. The fresh-mapped `win32u.dll` view is `UnmapViewOfFile`'d. The executable allocation containing the direct-syscall stub is `VirtualFree`'d with `MEM_RELEASE = 0x8000`. The only durable artifact is the one-time `PsSetWin32ThreadCallout` event, which on most EDRs is consumed as informational rather than alert.

## Related Techniques

- **T-016 NTDLL Unhook** — the executive-surface sibling. Apply it first, then apply this card; together they constitute a complete user-mode hook bypass across both SSDT halves.
- **T-001 (syscalls, SSN harvest)** — the SSN-harvesting primitive (Hell's Gate, Halo's Gate, Tartarus' Gate) that Variants 1 and 2 of this card extend from `ntdll.dll` to `win32u.dll`.
- **T-002 (direct syscall stub construction)** — the dispatcher pattern (generic `syscall` trampoline taking `(SSN, argc, argv)`); same pattern works for `win32u.dll` SSNs as-is, no convention adjustment needed.
- **T-023** — composes for hiding the worker thread that performs GUI operations once attribution is established (thread-context spoofing, stack spoofing against ETW-TI correlation).