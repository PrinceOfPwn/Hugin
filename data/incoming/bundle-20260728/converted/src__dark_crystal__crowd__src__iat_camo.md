# crowd — iat_camo.rs  (IAT Camouflage — benign import injection for ML evasion)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/iat_camo.rs` |
| **Lines** | 233 |
| **Cards** | T013-anti-analysis |
| **Role** | IAT camouflage (3 profiles) |
| **Unsafe blocks** | 3 |

## Purpose

# crowd — iat_camo.rs  (IAT Camouflage — benign import injection for ML evasion)

## Purpose

Inject fake/benign API imports into the binary's Import Address Table to mislead
ML-based static analysis classifiers. By calling real Windows APIs from legitimate
subsystems (GDI, multimedia, internet, crypto, COM, shell), the binary's IAT
signature resembles a normal desktop application rather than a security tool.

## Profiles

Each profile is cumulative — higher levels include all lower levels.

| Level | Name     | DLLs added                              |
|-------|----------|-----------------------------------------|
| 3     | Basic    | gdi32, winmm                            |
| 4     | Network  | + wininet, crypt32                      |
| 5     | Full     | + ole32, shell32                        |

## Usage

```ignore
iat_camo::apply_camouflage(4); // Network profile (default)
```

The bitmask ensures each profile's APIs are called exactly once, even if
`apply_camouflage` is invoked multiple times with the same or overlapping levels.

## Constants

- `PROFILE_3_BIT`: `u8` = `1 << 0`
- `PROFILE_4_BIT`: `u8` = `1 << 1`
- `PROFILE_5_BIT`: `u8` = `1 << 2`

## Public API

### `apply` (line 49)
```rust
pub fn apply()
```
Call benign GDI + multimedia APIs.
- `GetDeviceCaps(NULL, 0)` queries the screen's driver version (harmless no-op).
- `timeGetTime()` returns system uptime in milliseconds.

### `apply` (line 89)
```rust
pub fn apply()
```
Call benign internet + certificate store APIs.
- `InternetOpenA("Mozilla/5.0", ...)` initializes WinINet with a standard UA string.
The handle is immediately closed — no network traffic is generated.
- `CertOpenStore("System", ...)` opens the system certificate store in read-only mode
(CERT_STORE_READONLY_FLAG = 0x8000), then closes it.

### `apply` (line 147)
```rust
pub fn apply()
```
Call benign COM + shell APIs.
- `CoInitializeEx(NULL, COINIT_MULTITHREADED)` initializes the COM library.
We track the HRESULT to avoid calling `CoUninitialize` if init failed.
- `SHGetFolderPathW(NULL, CSIDL_DESKTOP, ...)` queries the Desktop folder path.
CSIDL_DESKTOP = 0x0000.

### `apply_camouflage` (line 206)
```rust
pub fn apply_camouflage(profile: usize)
```
Apply IAT camouflage at the specified profile level (3, 4, or 5).

Each level includes all lower levels:
- **3** (Basic): GDI + multimedia — `gdi32.dll`, `winmm.dll`
- **4** (Network): Basic + internet + crypto — `wininet.dll`, `crypt32.dll`
- **5** (Full): Network + COM + shell — `ole32.dll`, `shell32.dll`

Unrecognized profile values default to level 4 (Network).

Uses an internal bitmask (`APPLIED_MASK`) to ensure each tier's APIs are
invoked exactly once, even across multiple calls. This prevents double
initialization of COM or duplicate WinINet sessions.

# Example

```ignore
// Apply full camouflage once at startup
iat_camo::apply_camouflage(5);

// Subsequent calls are no-ops for already-applied tiers
iat_camo::apply_camouflage(5); // nothing happens
```

## Internal Functions

- `GetDeviceCaps` (line 38)
- `timeGetTime` (line 43)
- `InternetOpenA` (line 62)
- `InternetCloseHandle` (line 69)
- `CertOpenStore` (line 74)
- `CertCloseStore` (line 81)
- `CoInitializeEx` (line 127)
- `CoUninitialize` (line 128)
- `SHGetFolderPathW` (line 133)

## Full Source

```rust
//! # crowd — iat_camo.rs  (IAT Camouflage — benign import injection for ML evasion)
//!
//! ## Purpose
//!
//! Inject fake/benign API imports into the binary's Import Address Table to mislead
//! ML-based static analysis classifiers. By calling real Windows APIs from legitimate
//! subsystems (GDI, multimedia, internet, crypto, COM, shell), the binary's IAT
//! signature resembles a normal desktop application rather than a security tool.
//!
//! ## Profiles
//!
//! Each profile is cumulative — higher levels include all lower levels.
//!
//! | Level | Name     | DLLs added                              |
//! |-------|----------|-----------------------------------------|
//! | 3     | Basic    | gdi32, winmm                            |
//! | 4     | Network  | + wininet, crypt32                      |
//! | 5     | Full     | + ole32, shell32                        |
//!
//! ## Usage
//!
//! ```ignore
//! iat_camo::apply_camouflage(4); // Network profile (default)
//! ```
//!
//! The bitmask ensures each profile's APIs are called exactly once, even if
//! `apply_camouflage` is invoked multiple times with the same or overlapping levels.

#![allow(dead_code)]

use std::sync::Mutex;

// ── Profile 3: Basic — GDI + Multimedia ─────────────────────────────────────

mod profile_3 {
    #[link(name = "gdi32")]
    extern "system" {
        fn GetDeviceCaps(hdc: *mut core::ffi::c_void, index: i32) -> i32;
    }

    #[link(name = "winmm")]
    extern "system" {
        fn timeGetTime() -> u32;
    }

    /// Call benign GDI + multimedia APIs.
    /// - `GetDeviceCaps(NULL, 0)` queries the screen's driver version (harmless no-op).
    /// - `timeGetTime()` returns system uptime in milliseconds.
    pub fn apply() {
        unsafe {
            let _ = GetDeviceCaps(core::ptr::null_mut(), 0);
            let _ = timeGetTime();
        }
    }
}

// ── Profile 4: Network — Internet + Crypto ──────────────────────────────────

mod profile_4 {
    #[link(name = "wininet")]
    extern "system" {
        fn InternetOpenA(
            lpszAgent: *const i8,
            dwAccessType: u32,
            lpszProxy: *const i8,
            lpszProxyBypass: *const i8,
            dwFlags: u32,
        ) -> *mut core::ffi::c_void;
        fn InternetCloseHandle(hInternet: *mut core::ffi::c_void) -> i32;
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CertOpenStore(
            lpszStoreProvider: *const i8,
            dwEncodingType: u32,
            hCryptProv: usize,
            dwFlags: u32,
            pvPara: *const core::ffi::c_void,
        ) -> *mut core::ffi::c_void;
        fn CertCloseStore(hCertStore: *mut core::ffi::c_void, dwFlags: u32) -> i32;
    }

    /// Call benign internet + certificate store APIs.
    /// - `InternetOpenA("Mozilla/5.0", ...)` initializes WinINet with a standard UA string.
    ///   The handle is immediately closed — no network traffic is generated.
    /// - `CertOpenStore("System", ...)` opens the system certificate store in read-only mode
    ///   (CERT_STORE_READONLY_FLAG = 0x8000), then closes it.
    pub fn apply() {
        unsafe {
            // WinINet: open session with a common browser user-agent, then close immediately.
            // dwAccessType = INTERNET_OPEN_TYPE_PRECONFIG (0)
            let h = InternetOpenA(
                b"Mozilla/5.0\0".as_ptr() as *const i8,
                0,
                core::ptr::null(),
                core::ptr::null(),
                0,
            );
            if !h.is_null() {
                InternetCloseHandle(h);
            }

            // Crypt32: open the system certificate store read-only, then close.
            // CERT_STORE_PROV_SYSTEM_A = ((LPCSTR) 9), but we pass the store name "System"
            // as pvPara. dwFlags = CERT_STORE_READONLY_FLAG (0x8000) |
            // CERT_SYSTEM_STORE_CURRENT_USER (0x1 << 16 = 0x10000).
            let store = CertOpenStore(
                9 as *const i8,
                0,
                0,
                0x0001_8000,
                b"My\0".as_ptr() as *const core::ffi::c_void,
            );
            if !store.is_null() {
                CertCloseStore(store, 0);
            }
        }
    }
}

// ── Profile 5: Full — COM + Shell ───────────────────────────────────────────

mod profile_5 {
    #[link(name = "ole32")]
    extern "system" {
        fn CoInitializeEx(pvReserved: *mut core::ffi::c_void, dwCoInit: u32) -> i32;
        fn CoUninitialize();
    }

    #[link(name = "shell32")]
    extern "system" {
        fn SHGetFolderPathW(
            hwnd: *mut core::ffi::c_void,
            csidl: i32,
            hToken: *mut core::ffi::c_void,
            dwFlags: u32,
            pszPath: *mut u16,
        ) -> i32;
    }

    /// Call benign COM + shell APIs.
    /// - `CoInitializeEx(NULL, COINIT_MULTITHREADED)` initializes the COM library.
    ///   We track the HRESULT to avoid calling `CoUninitialize` if init failed.
    /// - `SHGetFolderPathW(NULL, CSIDL_DESKTOP, ...)` queries the Desktop folder path.
    ///   CSIDL_DESKTOP = 0x0000.
    pub fn apply() {
        unsafe {
            // COM: initialize multi-threaded apartment, then uninitialize.
            // COINIT_MULTITHREADED = 0x0
            let hr = CoInitializeEx(core::ptr::null_mut(), 0);
            // S_OK (0) or S_FALSE (1) both indicate success; negative = failure.
            let should_uninitialize = hr >= 0;

            // Shell: query Desktop path into a stack buffer (MAX_PATH = 260 wide chars).
            let mut path = [0u16; 260];
            let _ = SHGetFolderPathW(
                core::ptr::null_mut(),
                0, // CSIDL_DESKTOP
                core::ptr::null_mut(),
                0,
                path.as_mut_ptr(),
            );

            if should_uninitialize {
                CoUninitialize();
            }
        }
    }
}

// ── Bitmask tracking ────────────────────────────────────────────────────────

const PROFILE_3_BIT: u8 = 1 << 0;
const PROFILE_4_BIT: u8 = 1 << 1;
const PROFILE_5_BIT: u8 = 1 << 2;

/// Tracks which profile tiers have already been applied.
/// Bit 0 = profile 3, bit 1 = profile 4, bit 2 = profile 5.
static APPLIED_MASK: Mutex<u8> = Mutex::new(0);

// ── Public API ──────────────────────────────────────────────────────────────

/// Apply IAT camouflage at the specified profile level (3, 4, or 5).
///
/// Each level includes all lower levels:
///   - **3** (Basic): GDI + multimedia — `gdi32.dll`, `winmm.dll`
///   - **4** (Network): Basic + internet + crypto — `wininet.dll`, `crypt32.dll`
///   - **5** (Full): Network + COM + shell — `ole32.dll`, `shell32.dll`
///
/// Unrecognized profile values default to level 4 (Network).
///
/// Uses an internal bitmask (`APPLIED_MASK`) to ensure each tier's APIs are
/// invoked exactly once, even across multiple calls. This prevents double
/// initialization of COM or duplicate WinINet sessions.
///
/// # Example
///
/// ```ignore
/// // Apply full camouflage once at startup
/// iat_camo::apply_camouflage(5);
///
/// // Subsequent calls are no-ops for already-applied tiers
/// iat_camo::apply_camouflage(5); // nothing happens
/// ```
pub fn apply_camouflage(profile: usize) {
    let requested = match profile {
        3 => PROFILE_3_BIT,
        4 => PROFILE_3_BIT | PROFILE_4_BIT,
        5 => PROFILE_3_BIT | PROFILE_4_BIT | PROFILE_5_BIT,
        _ => PROFILE_3_BIT | PROFILE_4_BIT, // default = level 4
    };

    let mut applied = match APPLIED_MASK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    if requested & PROFILE_3_BIT != 0 && *applied & PROFILE_3_BIT == 0 {
        profile_3::apply();
        *applied |= PROFILE_3_BIT;
    }

    if requested & PROFILE_4_BIT != 0 && *applied & PROFILE_4_BIT == 0 {
        profile_4::apply();
        *applied |= PROFILE_4_BIT;
    }

    if requested & PROFILE_5_BIT != 0 && *applied & PROFILE_5_BIT == 0 {
        profile_5::apply();
        *applied |= PROFILE_5_BIT;
    }
}

```