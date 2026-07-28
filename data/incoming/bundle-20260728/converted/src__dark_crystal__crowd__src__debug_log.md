# crowd — debug_log.rs  (✅ C TIER — debug logging utility)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/debug_log.rs` |
| **Lines** | 260 |
| **Tier** | D |
| **Cards** | T022-architecture |
| **Role** | Debug logging |
| **Unsafe blocks** | 1 |
| **Feature gates** | megadebug |

## Purpose

# crowd — debug_log.rs  (✅ C TIER — debug logging utility)

## Mega-Debug Logger — gated behind `--features megadebug`

En builds de producción **cero código se emite** — todas las macros son no-ops.

### Uso
```
// En cualquier .rs del crate:
mega_dbg!("valor = {}", x);                             // FILE:LINE log
phase_log!("AntiVM", result, elapsed_ms, "detalle");    // línea de fase FSM
```

## Public API

### `init` (line 86)
```rust
pub fn init()
```
Inicializa la consola de debug + file logger.
Idempotente — seguro llamar varias veces.

### `dump_config` (line 182)
```rust
pub fn dump_config(cfg: &crate::chain::ChainConfig)
```
Dump full ChainConfig to log file at FSM init.

### `log_raw` (line 219)
```rust
pub fn log_raw(file: &str, line: u32, msg: &str)
```
Llamado por la macro `mega_dbg!`.

### `phase_result` (line 226)
```rust
pub fn phase_result(state: &str, success: bool, elapsed: u128, detail: &str)
```
Llamado por la macro `phase_log!`.

### `init` (line 251)
```rust
pub fn init() {}
```

### `log_raw` (line 254)
```rust
pub fn log_raw(_: &str, _: u32, _: &str) {}
```

### `phase_result` (line 257)
```rust
pub fn phase_result(_: &str, _: bool, _: u128, _: &str) {}
```

### `dump_config` (line 260)
```rust
pub fn dump_config(_: &crate::chain::ChainConfig) {}
```

## Internal Functions

- `elapsed_ms` (line 70)
- `write_to_file` — Write a line to the log file (no ANSI codes). No-op if file not opened. (line 75)

## Macros

- `mega_dbg!` (macro_rules, line 20)
- `mega_dbg!` (macro_rules, line 28)
- `phase_log!` (macro_rules, line 36)
- `phase_log!` (macro_rules, line 47)

## Key Dependencies

- `use winapi::um::consoleapi::AllocConsole;`
- `use winapi::um::wincon::{GetConsoleWindow, SetConsoleTitleW};`
- `use winapi::um::winuser::ShowWindow;`

## Full Source

```rust
//! # crowd — debug_log.rs  (✅ C TIER — debug logging utility)
//!
//! ## Mega-Debug Logger — gated behind `--features megadebug`
//!
//! En builds de producción **cero código se emite** — todas las macros son no-ops.
//!
//! ### Uso
//! ```
//! // En cualquier .rs del crate:
//! mega_dbg!("valor = {}", x);                             // FILE:LINE log
//! phase_log!("AntiVM", result, elapsed_ms, "detalle");    // línea de fase FSM
//! ```

// ── API pública (siempre disponible, no-op en producción) ────────────────────

/// Log de bajo nivel con FILE:LINE automático.
/// No-op sin `--features megadebug`.
#[cfg(feature = "megadebug")]
#[macro_export]
macro_rules! mega_dbg {
    ($fmt:literal $(, $arg:expr)*) => {
        $crate::debug_log::log_raw(file!(), line!(), &format!($fmt $(, $arg)*))
    };
}

#[cfg(not(feature = "megadebug"))]
#[macro_export]
macro_rules! mega_dbg {
    ($($x:tt)*) => {};
}

/// Log estructurado de una fase FSM con timing en ms.
/// No-op sin `--features megadebug`.
#[cfg(feature = "megadebug")]
#[macro_export]
macro_rules! phase_log {
    ($state:expr, $ok:expr, $ms:expr, $detail:expr) => {
        $crate::debug_log::phase_result($state, $ok, $ms, $detail)
    };
    ($state:expr, $ok:expr, $ms:expr) => {
        $crate::debug_log::phase_result($state, $ok, $ms, "")
    };
}

#[cfg(not(feature = "megadebug"))]
#[macro_export]
macro_rules! phase_log {
    ($($x:tt)*) => {};
}

// ── Implementación real (solo con feature megadebug) ─────────────────────────

#[cfg(feature = "megadebug")]
pub use megadebug_impl::*;

#[cfg(feature = "megadebug")]
mod megadebug_impl {
    use std::fs::{File, OpenOptions};
    use std::io::{BufWriter, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use winapi::um::consoleapi::AllocConsole;
    use winapi::um::wincon::{GetConsoleWindow, SetConsoleTitleW};
    use winapi::um::winuser::ShowWindow;

    static INIT_DONE: AtomicBool = AtomicBool::new(false);
    static T0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    static LOG_FILE: std::sync::OnceLock<Mutex<BufWriter<File>>> = std::sync::OnceLock::new();

    fn elapsed_ms() -> u128 {
        T0.get().map(|t| t.elapsed().as_millis()).unwrap_or(0)
    }

    /// Write a line to the log file (no ANSI codes). No-op if file not opened.
    fn write_to_file(msg: &str) {
        if let Some(writer) = LOG_FILE.get() {
            if let Ok(mut w) = writer.lock() {
                let _ = writeln!(w, "{}", msg);
                let _ = w.flush();
            }
        }
    }

    /// Inicializa la consola de debug + file logger.
    /// Idempotente — seguro llamar varias veces.
    pub fn init() {
        if INIT_DONE.swap(true, Ordering::SeqCst) {
            return;
        }
        T0.get_or_init(std::time::Instant::now);

        // ── Console ──────────────────────────────────────────────────────
        unsafe {
            AllocConsole();

            let title: Vec<u16> = "[ CrystalClear — MEGA-DEBUG ]\0"
                .encode_utf16()
                .collect();
            SetConsoleTitleW(title.as_ptr());

            let hwnd = GetConsoleWindow();
            if !hwnd.is_null() {
                ShowWindow(hwnd, winapi::um::winuser::SW_SHOW);
            }
        }

        // ── File logger ──────────────────────────────────────────────────
        let log_path = {
            let cfg_path = crate::payload_cfg::MEGADEBUG_LOG_PATH;
            if cfg_path.is_empty() {
                let temp = std::env::var("TEMP")
                    .or_else(|_| std::env::var("TMP"))
                    .unwrap_or_else(|_| r"C:\Temp".to_string());
                format!(r"{}\crowd_megadebug.log", temp)
            } else {
                cfg_path.to_string()
            }
        };

        match OpenOptions::new().create(true).append(true).open(&log_path) {
            Ok(file) => {
                let _ = LOG_FILE.set(Mutex::new(BufWriter::new(file)));
                println!("  LOG FILE : {}", log_path);
            }
            Err(e) => {
                eprintln!("[warn] Cannot open megadebug log file {:?}: {}", log_path, e);
            }
        }

        // Panic hook: muestra backtrace en consola antes de morir
        std::panic::set_hook(Box::new(|info| {
            let loc = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_else(|| "<unknown>".into());
            let msg = info
                .payload()
                .downcast_ref::<&str>()
                .copied()
                .unwrap_or("<non-string panic>");
            let panic_msg = format!("[PANIC] {} @ {}", msg, loc);
            eprintln!("\n\x1b[31m{}\x1b[0m", panic_msg);
            write_to_file(&panic_msg);
        }));

        let banner_lines = [
            "",
            "======================================================",
            "    CrystalClear · killaofking · MEGA-DEBUG MODE",
            "======================================================",
            &format!("  PID : {}", std::process::id()),
            &format!("  EXE : {}", std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<?>".into())),
            &format!("  LOG : {}", log_path),
            "======================================================",
            "",
        ];

        // Print banner to console (with box-drawing chars)
        println!("\n╔══════════════════════════════════════════════════════════╗");
        println!("║    CrystalClear · killaofking · MEGA-DEBUG MODE          ║");
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║  PID : {}", std::process::id());
        println!("║  EXE : {}", std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<?>".into()));
        println!("║  LOG : {}", log_path);
        println!("╚══════════════════════════════════════════════════════════╝\n");
        println!("  {:>10}  {:^16}  {:>8}  {}", "T+ms", "PHASE", "elapsed", "DETAIL");
        println!("  {:─<10}  {:─<16}  {:─>8}  {}", "", "", "", "─────────────────────────────");

        // Write banner to file (plain text)
        for line in &banner_lines {
            write_to_file(line);
        }
        write_to_file(&format!("{:>10}  {:^16}  {:>8}  {}", "T+ms", "PHASE", "elapsed", "DETAIL"));
        write_to_file(&format!("{:->10}  {:->16}  {:->8}  {:->30}", "", "", "", ""));
    }

    /// Dump full ChainConfig to log file at FSM init.
    pub fn dump_config(cfg: &crate::chain::ChainConfig) {
        let header = "=== CHAIN CONFIG DUMP ===";
        println!("{}", header);
        write_to_file(header);

        let lines = [
            format!("  injection        = {:?}", cfg.injection_type),
            format!("  anti_vm          = {}", cfg.anti_vm),
            format!("  hammer           = {} (seed=0x{:x} iters={} min_secs={})",
                cfg.hammer, cfg.hammer_seed, cfg.hammer_iters, cfg.hammer_min_secs),
            format!("  patch_amsi       = {}", cfg.patch_amsi),
            format!("  patch_etw        = {}", cfg.patch_etw),
            format!("  block_dll        = {}", cfg.block_dll),
            format!("  ppid_auto        = {:?}", cfg.ppid_parent),
            format!("  sleep_ms         = {}", cfg.sleep_ms),
            format!("  stomp_header     = {}", cfg.stomp_header),
            format!("  self_delete      = {}", cfg.self_delete),
            format!("  peb_unlink       = {}", cfg.peb_unlink),
            format!("  block_handle     = {}", cfg.block_handle),
            format!("  use_threadless   = {}", cfg.use_threadless),
            format!("  persist          = {}", cfg.persist),
            format!("  payload_path     = {:?}", cfg.payload_path),
            format!("  c2_host          = {:?}", cfg.c2_host),
            format!("  aes_key_set      = {}", cfg.aes_key.iter().any(|&b| b != 0)),
        ];

        for line in &lines {
            println!("{}", line);
            write_to_file(line);
        }

        let footer = "=== END CONFIG DUMP ===";
        println!("{}", footer);
        write_to_file(footer);
    }

    /// Llamado por la macro `mega_dbg!`.
    pub fn log_raw(file: &str, line: u32, msg: &str) {
        let out = format!("[{:>8}ms] {}:{} > {}", elapsed_ms(), file, line, msg);
        println!("{}", out);
        write_to_file(&out);
    }

    /// Llamado por la macro `phase_log!`.
    pub fn phase_result(state: &str, success: bool, elapsed: u128, detail: &str) {
        let (icon, color) = if success {
            ("✓", "\x1b[32m") // verde
        } else {
            ("✗", "\x1b[31m") // rojo
        };
        let reset = "\x1b[0m";
        // Console: colored output
        println!(
            "  {:>10}  {}{} {:<14}{}  {:>6}ms  {}",
            elapsed_ms(), color, icon, state, reset, elapsed, detail
        );
        // File: plain text (no ANSI)
        let status = if success { "OK" } else { "FAIL" };
        let file_line = format!(
            "  {:>10}  {} {:<14}  {:>6}ms  {}",
            elapsed_ms(), status, state, elapsed, detail
        );
        write_to_file(&file_line);
    }
}

// ── Stubs para producción (cero código emitido) ───────────────────────────────

#[cfg(not(feature = "megadebug"))]
pub fn init() {}

#[cfg(not(feature = "megadebug"))]
pub fn log_raw(_: &str, _: u32, _: &str) {}

#[cfg(not(feature = "megadebug"))]
pub fn phase_result(_: &str, _: bool, _: u128, _: &str) {}

#[cfg(not(feature = "megadebug"))]
pub fn dump_config(_: &crate::chain::ChainConfig) {}

```