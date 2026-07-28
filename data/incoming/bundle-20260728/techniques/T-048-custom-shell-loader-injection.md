---
id: T-048
name: Custom Shell Loader as Distinct from Generic Injection
category: process-injection
tier: B
crate: client_rust
source_file: client_rust/src/commands.rs
mitre: T1059
tags: [custom-shell, loader, command-dispatch, implant-scaffolding, session-management, stdio-relay, error-handling, sec670]
origin: atlas-synthesis
member_notes: ['lgtm:customshell-shellcode-loader-card']
---

# Custom Shell Loader — Shell Scaffolding as a Capability Separate from Injection

## Summary

Custom shell construction is the design and implementation of an implant's command-execution scaffolding — session management, I/O handling, command dispatch, and error checking — treated as a capability in its own right, independent of the technique used to achieve code execution. SANS SEC670 sequences this as a dedicated lab track: Lab 4.7 (CustomShell), Lab 5.1 (The Loader, executing shellcode locally and across process boundaries), and Lab 5.5 (ShadowCraft, building a basic shell with thorough error checking). An operator builds a custom shell rather than relying on a stock reverse shell in order to control child-process lineage, define the command-channel protocol, dictate the exact command lines of spawned shells, and degrade gracefully when a session dies. The primary detection surface is process-creation telemetry on the child shell processes the scaffolding spawns and the command-line parameters those children carry.

## Mechanism

1. An execution primitive places the implant code in a running context — locally in the implant's own process or across a process boundary, per Lab 5.1's framing. This step is out of scope for this card; the T-007 family catalogs the injection primitives.
2. The implant initializes shell scaffolding state: a session table keyed by operator-assigned session IDs, a handle to the C2 transport, and a dispatch table mapping command identifiers to handler routines.
3. The transport layer delivers a command frame. The dispatcher parses the command identifier and payload and routes execution to the matching handler. Transport framing is abstracted — the shell layer consumes bytes without regard to how they arrived.
4. On a session-start command, the scaffolding spawns a child shell process (cmd.exe or powershell.exe) via CreateProcess with stdin, stdout, and stderr redirected to anonymous pipes created with CreatePipe and owned by the implant.
5. On an execute command, the scaffolding writes the operator's command line to the child's stdin, appending an echo of a sentinel token that marks end-of-output for that command.
6. A reader consumes child stdout via ReadFile until the sentinel appears or a timeout expires, accumulating the intervening bytes into a result record containing the request ID, exit code, stdout, and stderr.
7. The result record returns to the operator over the transport.
8. Error checking wraps every state transition — ShadowCraft's explicit grading requirement: spawn failure, unknown session ID, dead child process, closed pipe, and read timeout each produce a structured error result rather than a crash or a permanently hung session.
9. On a session-stop command or implant shutdown, the scaffolding calls TerminateProcess on the child, waits for process exit, and removes the session entry from the table.

## OS Internals Context

Anonymous pipes and standard-handle inheritance. CreateProcess redirects a child's standard handles through the hStdInput, hStdOutput, and hStdError fields of STARTUPINFO, with bInheritHandles set to TRUE and the pipe ends created with SECURITY_ATTRIBUTES.bInheritHandle set to TRUE. Handle inheritance on Windows is coarse: when bInheritHandles is TRUE, the child receives every handle in the parent marked inheritable, not only the three stdio handles. An implant executing inside a compromised host process must therefore treat its inheritable-handle set as part of the shell's attack surface, because any handle marked inheritable at spawn time leaks into the shell child.

Console attachment. A console application spawned from a parent without a console either allocates one visibly or runs headless under the CREATE_NO_WINDOW or CREATE_NEW_CONSOLE creation flags. A shellcode-based implant injected into a GUI process owns no console; a child cmd.exe spawned without CREATE_NO_WINDOW produces a visible console window on the victim's session. The creation flags are a component of the shell's operational posture rather than an implementation detail.

Byte-stream framing. Anonymous pipes are unframed byte streams: ReadFile blocks until bytes arrive or the last write handle closes. An interactive shell holds its stdout open across many commands, so the scaffolding cannot use end-of-file as a per-command delimiter. It requires an application-level marker — the sentinel-echo pattern — or asynchronous reads combined with PeekNamedPipe polling to implement per-command timeouts without destroying the session. This framing problem is the most common failure point in custom shell implementations and the reason ShadowCraft grades error handling as a first-class requirement.

Position independence. When the shell is delivered as shellcode across a process boundary, the scaffolding cannot link against import thunks or call a C runtime: every API it needs — CreateProcess, CreatePipe, ReadFile, WriteFile, TerminateProcess — must be resolved at runtime by walking the PEB's loaded-module list, and all strings and structures must be position-independent. This constraint set is the loader dimension of the technique; the session and I/O logic itself is identical between a shellcode build and a hosted build.

Command-line exposure. The child shell's full command line is stored in its RTL_USER_PROCESS_PARAMETERS block and is retrievable through process-creation telemetry and by any process able to read the child's PEB. The flags chosen at spawn — profile suppression, execution-policy relaxation, non-interactive mode — are therefore externally visible properties of every session the scaffolding creates.

## Key Implementation Details

`client_rust/src/commands.rs` implements the hosted form of this scaffolding. `ClientState` holds `shell_sessions: HashMap<String, std::process::Child>`, and `handle_command` is the dispatcher — a match over roughly sixty command strings covering control, capture, overlay, shell, and gate-management commands.

The `SHELL_START` handler parses a `session_id|shell_type` payload and spawns either `cmd /Q` or `powershell -NoProfile -NonInteractive -NoLogo -ExecutionPolicy Bypass` with `Stdio::piped()` on all three standard streams, inserting the resulting `Child` into the session table. `SHELL_POWERSHELL` is a fixed-type alias of the same path. `SHELL_EXEC` deserializes `{sessionId, command, requestId, timeout}` (30-second default), writes the command followed by `echo ___SHELL_SENTINEL_7f3a2b___` to the child's stdin, then spawns a blocking thread that reads stdout line-by-line with `BufReader::read_line` until the sentinel line or the timeout. Output is truncated at 4000 bytes and framed as JSON `{requestId, exitCode, stdout, stderr}` inside a `MSG_CMD_OUTPUT` protocol message. The reader thread returns the stdout handle so it can be reattached to the `Child` — a borrow-checker workaround, since `Child::stdout` was taken by value. `SHELL_STOP` removes the session, then kills and waits on the child. `CMD_EXEC` provides the one-shot path through `cmd /C` with `.output()` and no session state. `ClientState::cleanup` drains the session table and kills every child; it runs on implant shutdown and inside the Night Guy terminal sequence.

Deviations from the SEC670 framing: this is a hosted Tokio process with a full runtime, not position-independent shellcode, so the loader constraint — runtime API resolution, no CRT — does not apply. The sentinel framing is line-oriented, meaning commands whose output lacks a trailing newline before the sentinel can desynchronize the reader. No shellcode-based custom shell exists anywhere in the source tree; the loader form documented above comes from the atlas material alone.

## Why It Matters

The T-007 family documents how payload code comes to execute; nothing else in the vault documents what that payload does once running — the session, dispatch, and I/O layer that converts an execution primitive into an operable implant. SEC670's curriculum structure, with CustomShell as a Book 4 bootcamp and The Loader and ShadowCraft in Book 5, grades shell construction as a separable skill with its own failure modes — pipe framing, child lifecycle, error paths — none of which vary with the injection method selected. Treating the layer as its own card lets the vault reason about composition: any injection primitive can deliver the same scaffolding, and the same scaffolding can ride any T-022 transport. The layer also owns most of the implant's observable footprint — child processes, their command lines, inherited pipe handles — so decisions made here move detection risk independently of how execution was achieved.

## Detection Considerations

Training material does not discuss detection for this technique.

Observable artifacts follow from the mechanism itself and from the verified implementation rather than from the material. Every interactive session is a child process of the implant host, and Windows process creation exposes parent-child lineage and the full command line to any consumer of process-creation events; the implementation's powershell.exe children carry `-NoProfile -NonInteractive -NoLogo -ExecutionPolicy Bypass` and its cmd.exe children carry `/Q`, both recorded in each child's process parameters. Residual artifacts include inherited pipe handles in the child's handle table pointing back at the host process, session processes that persist until `SHELL_STOP` or implant exit, and the sentinel token `___SHELL_SENTINEL_7f3a2b___` present in the host's memory and in transit whenever sessions are active. No ETW provider GUIDs or Sysmon event IDs are documented in the material for this layer.

## Related Techniques

- **T-007 Pool Party Injection** — the T-007 process-injection family supplies the execution primitives that deliver a payload; the custom shell is what the payload implements once running. The two layers are independently selectable.
- **T-022 Network and Protocol Suite** — the shell's command channel is transport-agnostic; in client_rust, `handle_command` consumes frames delivered by the T-022 transports (WebSocket, HTTP long-poll, malleable C2), and results return over the same path.

## References

- Atlas material: atlas-labs-part2.md (units 4, 5, 7, 8)
- MITRE ATT&CK: T1059 — Command and Scripting Interpreter (https://attack.mitre.org/techniques/T1059/)
- LGTM notes: lgtm:customshell-shellcode-loader-card
- Public references: SANS SEC670 Lab 4.7 (CustomShell), Lab 5.1 (The Loader), Lab 5.5 (ShadowCraft) — lab titles as named in atlas-labs-part2.md

## Source Reference

`client_rust/src/commands.rs` — `handle_command` dispatcher; `SHELL_START`, `SHELL_POWERSHELL`, `SHELL_EXEC`, and `SHELL_STOP` session handlers; `run_command_sync` one-shot path; `ClientState::cleanup` teardown. No shellcode-based custom shell exists in the source tree; the loader form is documented from the atlas material for reference.