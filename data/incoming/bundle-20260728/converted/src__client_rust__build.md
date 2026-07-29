# build

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/build.rs` |
| **Lines** | 32 |
| **Cards** | T020-crypto |
| **Role** | Build-time .env embedding |

## Internal Functions

- `main` (line 12)

## Full Source

```rust
// build.rs — Embed .env configuration at compile time
//
// When a .env file exists beside Cargo.toml (placed there by the builder),
// each KEY=VALUE pair is exposed as EMBEDDED_KEY via cargo:rustc-env.
// The client's Config::load() checks these compile-time values first,
// enabling single-file deployment without a separate .env file.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let env_path = Path::new(&manifest_dir).join(".env");

    if env_path.exists() {
        let content = fs::read_to_string(&env_path).unwrap();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                println!("cargo:rustc-env=EMBEDDED_{}={}", key, value);
            }
        }
    }

    println!("cargo:rerun-if-changed=.env");
}

```