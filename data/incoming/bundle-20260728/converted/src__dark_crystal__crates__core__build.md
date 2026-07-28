# build

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/build.rs` |
| **Lines** | 5 |
| **Cards** | T020-crypto |
| **Role** | Build-time .env embedding |
| **Inline ASM** | Yes |

## Internal Functions

- `main` (line 1)

## Full Source

```rust
fn main() {
    // Los stubs de gateway.asm fueron migrados a global_asm! en advanced_stack.rs.
    // No se requiere compilar ningun archivo .asm externo via cc/MASM.
    println!("cargo:rerun-if-changed=build.rs");
}

```