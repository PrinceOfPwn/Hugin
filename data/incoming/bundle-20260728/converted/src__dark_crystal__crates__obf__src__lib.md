# lib

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/obf/src/lib.rs` |
| **Lines** | 39 |
| **Cards** | T023-client-capabilities |
| **Role** | Module declarations |

## Public API

### `obf` (line 6)
```rust
pub fn obf(input: TokenStream) -> TokenStream
```

## Internal Functions

- `simple_encrypt` (line 23)
- `deterministic_key` (line 27)

## Macros

- `obf!` (proc_macro, line 6)

## Key Dependencies

- `use proc_macro::TokenStream;`
- `use quote::quote;`
- `use syn::{parse_macro_input, LitStr};`

## Full Source

```rust
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};

#[proc_macro]
pub fn obf(input: TokenStream) -> TokenStream {
    let input_str = parse_macro_input!(input as LitStr);
    let value = input_str.value();
    let key = deterministic_key(&value);
    let encrypted_bytes = simple_encrypt(&value, key);

    let gen = quote! {
        {
            let encrypted: &[u8] = &[#(#encrypted_bytes),*];
            let decrypted: Vec<u8> = encrypted.iter().map(|byte| byte ^ #key).collect();
            String::from_utf8(decrypted).expect("obf!: decrypted bytes must be valid UTF-8")
        }
    };

    gen.into()
}

fn simple_encrypt(input: &str, key: u8) -> Vec<u8> {
    input.as_bytes().iter().map(|byte| byte ^ key).collect()
}

fn deterministic_key(input: &str) -> u8 {
    let mut hash: u32 = 0x811c9dc5;
    for byte in input.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    let key = (hash & 0xFF) as u8;
    if key == 0 {
        0xA5
    } else {
        key
    }
}

```