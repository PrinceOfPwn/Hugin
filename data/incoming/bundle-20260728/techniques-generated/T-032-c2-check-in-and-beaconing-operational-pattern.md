---
id: T-032
name: C2 Check-in and Beaconing Operational Pattern
category: networking
tier: B
crate: none
source_file: none
mitre: T1071.001
tags: [c2, beaconing, check-in, jitter, task-queue, uuid-correlation, http-post, operational-pattern, listening-post, result-staging]
origin: atlas-synthesis
member_notes: ['lgtm:c2-beaconing-operational-pattern']
---

# C2 Check-in and Beaconing Operational Pattern — Implant-Side Command-Response Lifecycle

## Summary

The C2 check-in and beaconing operational pattern is the implant-side lifecycle that structures all command-and-control interaction: an initial call-home establishing presence, periodic status check-ins at jittered intervals during which the listening post issues tasks, and a result-reporting path that stages task output and returns it via HTTP POST. SEC670 presents this as the operational skeleton every implant implements regardless of transport — custom sockets, web requests, or third-party protocols are interchangeable channels beneath the same loop. Each task received from the C2 listening post (LP) is assigned a unique ID generated with the Win32 `UuidCreateSequential` API so results can be correlated to tasking, and results are serialized (JSON), encrypted, and encoded before transmission, either on the next check-in or out-of-band from a dedicated thread or thread pool. Missed-check-in tracking functions as an operator tripwire: silence at expected intervals indicates compromise or failure to execute instructions and can drive self-uninstall logic. The primary detection surface is network-interval analysis, which the jittered cadence is specifically designed to degrade.

## Mechanism

1. **Initial call-home.** One of the first actions an implant carries out after gaining execution is an outbound connection to its configured C2 LP announcing it is alive and well, typically carrying basic system information. SEC670 frames this as existential for the implant: you are lost and forgotten about until you call home.
2. **Channel selection.** The call-home can ride custom sockets, web requests, or other services and protocols; the material leaves the choice to mission objectives. It warns against pulling in large libraries — Boost is named — because of the binary size cost.
3. **Outbound-only connectivity.** All connections originate from the implant. Reverse connections are preferred over bind-style listeners because outbound traffic pokes through perimeter firewalls that block inbound sessions (the material's phrasing: "Don't call me, I'll call you").
4. **Cadence declaration.** After the initial call-home, the implant tells the LP it is going back to sleep for some random time before checking in again. The operational example given later in the material is a 30-second base interval with jitter.
5. **Main loop.** The implant enters its lifetime loop, which the material reduces to `while (alive) { check-in for tasking; sleep; }` — check in, receive tasking if any exists, sleep, repeat.
6. **Jittered sleep.** Each sleep duration is randomized around the base interval so consecutive connections do not occur at fixed offsets. Strict periodicity is the property defensive tooling measures; the random delta is what prevents it.
7. **Check-in.** At each interval the implant contacts the LP and reports its status. The check-in response is the LP's opportunity to issue commands, if any are queued.
8. **Response parsing.** The implant parses the LP response into a structured object — the material's pseudo-code "JSONify the response" — and tests whether a task was given (`CheckTasks(response)` → `taskFound`).
9. **Task ID assignment.** Each task receives a unique ID. The material names `UuidCreateSequential` — an RPC runtime API returning a time-based UUID — as the mechanism, so every task and its eventual results can be correlated by GUID.
10. **Task execution.** `RunTask()` executes the tasked capability and yields `taskResults`.
11. **Result staging.** Results are stored before transmission: held in memory, or written to an encrypted file on disk. The material presents both as valid options without stating a preference.
12. **Result preparation.** Results are serialized (JSON is the example), encrypted, and encoded prior to transmission.
13. **Result transmission.** Results return to the LP via HTTP POST. They can ride the next scheduled check-in, but do not have to wait for it — the material describes dedicated threads and thread pools as alternative architectures that report results as soon as they are ready while the main loop holds its cadence.
14. **Missed-check-in handling.** Both sides track the expected check-in schedule. An implant that misses expected times indicates compromise or failure to execute further instructions; the material lists tracking missed check-ins and potential self-deletion logic among the requirements of the beaconing subsystem.

## OS Internals Context

`UuidCreateSequential` is exported by `rpcrt4.dll` and produces a version-1 (time-based) UUID per RFC 4122: a 60-bit timestamp counting 100-nanosecond intervals since 15 October 1582, a 14-bit clock sequence, and a 48-bit node field carrying the machine's IEEE 802 MAC address. The sequential variant reorders the high time fields so that successively generated UUIDs compare monotonically — a property intended for database indexing, which is what makes it attractive for task/result correlation on the LP side. Two consequences follow. First, every task ID minted on a host embeds that host's MAC address and the generation timestamp, so captured LP-side task records are host-identifying forensic artifacts. Second, Microsoft modified `UuidCreate` to stop using the machine's IEEE address for privacy reasons, while `UuidCreateSequential` retains the node field for ordering — the operator is explicitly trading host privacy for sortability.

The sleep half of the loop is ordinary user-mode timing: `Sleep`/`SleepEx` (or `NtDelayExecution` underneath) with a per-iteration randomized duration computed in user mode. The kernel sees nothing beyond a timer object and periodic outbound TCP/TLS sessions; the distinguishing signal of this pattern is temporal, not structural. No kernel data structures are manipulated — PEB, VAD, and callback lists are untouched — which means host-based visibility comes from API telemetry and the process's socket activity, while the canonical detection is network-side interval distribution analysis.

The HTTP stack choice carries artifact implications documented elsewhere in the vault: WinHTTP leaves no IE cache or cookie artifacts, whereas WinINet does (T-019 applies this). SEC670's warning about heavyweight socket libraries is a footprint consideration — import table noise and binary size — rather than a capability one.

For the asynchronous result path, the material's "dedicated threads or thread pools" maps concretely to `CreateThread` or the Windows thread pool API (`CreateThreadpoolWork`/`SubmitThreadpoolWork`), with a shared result queue guarded by a critical section. The worker performs the blocking HTTP POST while the main thread continues the jittered sleep/check-in cycle, decoupling result latency from cadence.

Memory staging versus file staging is a persistence-versus-artifact tradeoff: memory-resident results die with the process, while encrypted on-disk staging survives reboot at the cost of a recoverable file.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C++ (SEC670 course pseudo-code).

Verification of the provided sources: `client_rust/src/amaterasu.rs` implements u32 `job_id` task dispatch and chunked result upload (`MSG_AMATERASU_CHUNK`/`HARVEST`/`LS`/`ERROR`) — the result-staging half of the pattern — but contains no jittered check-in loop, no missed-check-in tracking, and no `UuidCreateSequential` usage. `browser_hook.rs` contains only a fixed 5-second WebSocket reconnect in the sideloaded extension. `eth_rpc.rs` implements RPC endpoint fallback. None of these implements the primary mechanism.

An implementation would center on a context structure holding the LP endpoint, base interval, jitter range, an `alive` flag, and a missed-check-in counter; a task record keyed by a `UuidCreateSequential`-minted UUID carrying opcode, arguments, state, and staged results; and a main loop that sleeps `base ± random_delta`, POSTs a check-in, parses the JSON response for tasks, mints IDs, dispatches execution, and hands results to a sender thread that POSTs them immediately. Failed check-ins increment the missed counter; a threshold triggers the self-deletion path.

## Why It Matters

T-019 documents autonomous dead-drop channels and T-022 documents concrete transports (malleable C2 transforms, HTTP long-poll), but neither documents the lifecycle that runs over those channels: when to speak, at what cadence, how jitter is applied, how tasking correlates to results, and what silence means. This pattern is the state machine every C2 implant implements regardless of transport, and SEC670 treats its requirements — missed-check-in tracking, self-deletion, UUID task correlation — as first-class design decisions rather than afterthoughts. Because periodicity-based beacon detection is the standard NSM technique against implants, the jittered cadence documented here is the primary countermeasure and earns the pattern its own card.

## Detection Considerations

- **Telemetry sources**: The material names no ETW providers, Sysmon event IDs, or GUIDs for this pattern; host-based telemetry specifics are not documented. The detection model SEC670 presents is network-interval analysis — consistent check-in times identify a beacon — mirrored operator-side by missed-check-in monitoring, where absence at expected times indicates compromise or failure.
- **Bypass options**: Jitter is the bypass the material teaches: randomizing each sleep interval removes the fixed period that interval analysis keys on. Channel choice is the second lever — web requests blend with ordinary user traffic better than raw custom-socket protocols.
- **Residual artifacts**: encrypted result files if file staging is chosen; LP-side connection and task logs; task IDs minted by `UuidCreateSequential` embed the host MAC address and generation timestamp, so seized server-side records identify the originating host.

## Related Techniques

- **T-019 Edo Dead Drop (Autonomous C2 Channels)** — supplies the channels (Google Translate/rentry proxy, blockchain contract, LSB steganography) over which a check-in loop can run when no live LP exists; T-032 defines the cadence, task correlation, and result lifecycle those channels carry.
- **T-022 Network and Protocol Suite** — provides the concrete transports (Henge malleable C2 transforms, HTTP long-poll with session ID) that a beaconing implementation uses for check-ins and result POSTs; the jitter, UUID tasking, and missed-check-in logic documented here sit one layer above those transports.

## References

- Atlas material: atlas-post-exploit-part8.md (units 25–34: Calling Home, Checking In, Implementation, Sending Results)
- MITRE ATT&CK: T1071.001 — Web Protocols (https://attack.mitre.org/techniques/T1071/001/)
- LGTM notes: lgtm:c2-beaconing-operational-pattern
- Public references: SANS SEC670, *Red Teaming Tools: Developing Custom Tools for Windows* (Jonathan Reiter, © 2024) — source of the Calling Home / Checking In / Sending Results material; Microsoft RPC runtime documentation for `UuidCreateSequential`

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. The nearest adjacent code is `client_rust/src/amaterasu.rs` (u32 job-ID task dispatch and chunked result upload), which implements result staging but not the beaconing lifecycle; per T-022, `client_rust/src/http_poll_transport.rs` carries session traffic (POST /api/c2/up, GET /api/c2/down) but does not itself define the check-in state machine.