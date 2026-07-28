# config

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/tools/xptool/src/config.rs` |
| **Lines** | 139 |
| **Cards** | T021-patterns |
| **Role** | Runtime config, build-time embedding |

## Types

### struct `CliArgs` (line 8)

### enum `InputFormat` (line 91)

### enum `ExecMethod` (line 99)

### struct `EvasionProfile` (line 126)

## Public API

### `evasion_profile` (line 108)
```rust
pub fn evasion_profile(&self) -> EvasionProfile
```

## Key Dependencies

- `use clap::{Parser, ValueEnum};`

## Full Source

```rust
use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "xptool",
    about = "Shellcode execution framework with evasion techniques"
)]
pub struct CliArgs {
    #[arg(short, long, help = "Shellcode input: hex, base64, raw, or file path")]
    pub input: Option<String>,

    #[arg(short, long, default_value = "hex", help = "Input format")]
    pub format: InputFormat,

    #[arg(short, long, default_value = "fiber", help = "Execution method")]
    pub method: ExecMethod,

    #[arg(long, help = "AES key (32 bytes hex)")]
    pub aes_key: Option<String>,

    #[arg(long, help = "AES IV (16 bytes hex)")]
    pub aes_iv: Option<String>,

    #[arg(long, default_value = "false", help = "Enable AMSI HBP bypass")]
    pub amsi_hbp: bool,

    #[arg(long, default_value = "false", help = "Enable anti-VM checks")]
    pub anti_vm: bool,

    #[arg(long, default_value = "false", help = "Enable API hammering")]
    pub hammering: bool,

    #[arg(long, default_value = "false", help = "Enable IAT camouflage")]
    pub iat_camou: bool,

    #[arg(long, default_value = "false", help = "Enable Ekko sleep obfuscation")]
    pub ekko: bool,

    #[arg(long, default_value = "false", help = "Enable threadless injection")]
    pub threadless: bool,

    #[arg(long, default_value = "false", help = "Enable process reflection")]
    pub process_reflection: bool,

    #[arg(
        long,
        default_value = "false",
        help = "Enable module overloading (PE payloads)"
    )]
    pub module_overload: bool,

    #[arg(
        long,
        default_value = "false",
        help = "Enable self-deletion after execution"
    )]
    pub self_delete: bool,

    #[arg(long, default_value = "false", help = "Enable VEH syscalls")]
    pub veh_syscalls: bool,

    #[arg(long, default_value = "false", help = "Enable stack spoofing")]
    pub stack_spoof: bool,

    #[arg(long, default_value = "false", help = "Enable all evasion techniques")]
    pub all_evasion: bool,

    #[arg(long, help = "Target DLL for module overloading")]
    pub overload_dll: Option<String>,

    #[arg(long, help = "Target export for threadless injection")]
    pub threadless_export: Option<String>,

    #[arg(long, default_value = "false", help = "Enable debug verbose output")]
    pub debug: bool,

    #[arg(
        long,
        help = "PE payload mode (expects PE file instead of raw shellcode)"
    )]
    pub pe_payload: bool,

    #[arg(long, help = "Export function name for PE payloads")]
    pub export: Option<String>,

    #[arg(long, help = "Command line arguments for PE payloads")]
    pub args: Option<String>,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum InputFormat {
    Hex,
    Base64,
    Raw,
    File,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ExecMethod {
    Fiber,
    Threadless,
    ProcessReflection,
    ModuleOverload,
    Direct,
}

impl CliArgs {
    pub fn evasion_profile(&self) -> EvasionProfile {
        EvasionProfile {
            amsi_hbp: self.all_evasion || self.amsi_hbp,
            anti_vm: self.all_evasion || self.anti_vm,
            hammering: self.all_evasion || self.hammering,
            iat_camou: self.all_evasion || self.iat_camou,
            ekko: self.all_evasion || self.ekko,
            threadless: self.all_evasion || self.threadless,
            process_reflection: self.all_evasion || self.process_reflection,
            module_overload: self.all_evasion || self.module_overload,
            self_delete: self.all_evasion || self.self_delete,
            veh_syscalls: self.all_evasion || self.veh_syscalls,
            stack_spoof: self.all_evasion || self.stack_spoof,
            debug: self.debug,
        }
    }
}

pub struct EvasionProfile {
    pub amsi_hbp: bool,
    pub anti_vm: bool,
    pub hammering: bool,
    pub iat_camou: bool,
    pub ekko: bool,
    pub threadless: bool,
    pub process_reflection: bool,
    pub module_overload: bool,
    pub self_delete: bool,
    pub veh_syscalls: bool,
    pub stack_spoof: bool,
    pub debug: bool,
}

```