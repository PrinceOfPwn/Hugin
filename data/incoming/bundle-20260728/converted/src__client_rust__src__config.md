# config

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/config.rs` |
| **Lines** | 128 |
| **Cards** | T021-patterns |
| **Role** | Runtime config, build-time embedding |

## Types

### struct `FileConfig` (line 11)

## Public API

### `load` (line 23)
```rust
pub fn load(path: &Path) -> FileConfig
```
Load config from `raven_config.toml`. Returns defaults on any error.

### `save_current` (line 42)
```rust
pub fn save_current(
```
Persist runtime-changeable fields to `raven_config.toml`.
Call after SET_TARGET_FPS / SET_JPEG_QUALITY / SET_ENCODING commands.

## Internal Functions

- `tmp_with` — Helper: write content to a temp file and return it (file lives as long as the variable). (line 73)
- `default_config_has_all_none_fields` (line 80)
- `missing_file_returns_defaults` (line 93)
- `toml_parsing_sets_correct_fields` (line 101)
- `save_and_reload_roundtrip` (line 119)

## Key Dependencies

- `use serde::{Deserialize, Serialize};`
- `use super::*;`
- `use tempfile::NamedTempFile;`

## Full Source

```rust
// Persistent config file: raven_config.toml
// Priority: env vars / .env > this file > compiled-in defaults.
//
// Written automatically when the server changes target_fps, jpeg_quality,
// or encoding at runtime, so the setting survives a client restart.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct FileConfig {
    pub server_address: Option<String>,
    pub target_fps: Option<u32>,
    pub jpeg_quality: Option<u32>,
    pub encoding: Option<String>,
    pub transport: Option<String>,
    pub tcp_port: Option<u16>,
    pub log_to_file: Option<bool>,
    pub log_file_path: Option<String>,
}

/// Load config from `raven_config.toml`. Returns defaults on any error.
pub fn load(path: &Path) -> FileConfig {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return FileConfig::default(),
    };
    match toml::from_str::<FileConfig>(&text) {
        Ok(cfg) => {
            tracing::debug!("Loaded config from {}", path.display());
            cfg
        }
        Err(e) => {
            tracing::warn!("Config parse error ({}): {} — using defaults", path.display(), e);
            FileConfig::default()
        }
    }
}

/// Persist runtime-changeable fields to `raven_config.toml`.
/// Call after SET_TARGET_FPS / SET_JPEG_QUALITY / SET_ENCODING commands.
pub fn save_current(
    path: &Path,
    target_fps: u32,
    jpeg_quality: u32,
    encoding: &str,
) {
    // Re-load to preserve any fields we don't manage (e.g. server_address)
    let mut cfg = load(path);
    cfg.target_fps = Some(target_fps);
    cfg.jpeg_quality = Some(jpeg_quality);
    cfg.encoding = Some(encoding.to_string());

    match toml::to_string_pretty(&cfg) {
        Ok(text) => {
            if let Err(e) = std::fs::write(path, &text) {
                tracing::warn!("Config save failed ({}): {}", path.display(), e);
            } else {
                tracing::debug!("Config saved to {}", path.display());
            }
        }
        Err(e) => tracing::warn!("Config serialize failed: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Helper: write content to a temp file and return it (file lives as long as the variable).
    fn tmp_with(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    #[test]
    fn default_config_has_all_none_fields() {
        let cfg = FileConfig::default();
        assert!(cfg.server_address.is_none());
        assert!(cfg.target_fps.is_none());
        assert!(cfg.jpeg_quality.is_none());
        assert!(cfg.encoding.is_none());
        assert!(cfg.transport.is_none());
        assert!(cfg.tcp_port.is_none());
        assert!(cfg.log_to_file.is_none());
        assert!(cfg.log_file_path.is_none());
    }

    #[test]
    fn missing_file_returns_defaults() {
        let path = std::path::Path::new("/tmp/nonexistent_raven_config_xyz.toml");
        let cfg = load(path);
        assert!(cfg.target_fps.is_none());
        assert!(cfg.encoding.is_none());
    }

    #[test]
    fn toml_parsing_sets_correct_fields() {
        let toml = r#"
            target_fps = 30
            jpeg_quality = 75
            encoding = "h264"
            transport = "websocket"
            log_to_file = true
        "#;
        let f = tmp_with(toml);
        let cfg = load(f.path());
        assert_eq!(cfg.target_fps, Some(30));
        assert_eq!(cfg.jpeg_quality, Some(75));
        assert_eq!(cfg.encoding.as_deref(), Some("h264"));
        assert_eq!(cfg.transport.as_deref(), Some("websocket"));
        assert_eq!(cfg.log_to_file, Some(true));
    }

    #[test]
    fn save_and_reload_roundtrip() {
        let f = NamedTempFile::new().expect("tempfile");
        save_current(f.path(), 24, 85, "jpeg");

        let cfg = load(f.path());
        assert_eq!(cfg.target_fps, Some(24));
        assert_eq!(cfg.jpeg_quality, Some(85));
        assert_eq!(cfg.encoding.as_deref(), Some("jpeg"));
    }
}

```