# pool_party_injection

| Field | Value |
|-------|-------|
| **Source** | `source-extracts/pool_party_injection.rs` |
| **Lines** | 15 |

## Full Source

```rust
// Source: dark_crystal/crowd/src/pool_party.rs
// Technique: T007-pool-party (Pool Party Injection — TpWorkerFactory)
// Tier: S (GOD TIER)
//
// Manipulates TpWorkerFactory.StartRoutine to execute shellcode in a pre-existing
// thread pool worker thread. Zero new threads, zero APC, zero SetThreadContext.
//
// Variant #4: Worker Factory Start Routine manipulation.
// The factory thread calls shellcode when it starts a new worker.
//
// NT structures used:
// - NtQueryInformationProcess (ProcessHandleInformation) → enumerate handles
// - NtDuplicateObject → obtain handle to target's TpWorkerFactory
// - NtQueryObject → verify type "TpWorkerFactory"
// - NtSetInformationWorkerFactory → inject the StartRoutine

```