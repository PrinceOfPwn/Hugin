# lib

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/framework/runtime/src/lib.rs` |
| **Lines** | 8 |
| **Cards** | T023-client-capabilities |
| **Role** | Module declarations |

## Public API

### `framework_version` (line 6)
```rust
pub fn framework_version() -> &'static str
```

## Full Source

```rust
pub mod contract;
pub mod materializer;
pub mod planner;
pub mod selector;

pub fn framework_version() -> &'static str {
    "0.1.0-bootstrap"
}

```