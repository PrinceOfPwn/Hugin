Let me analyze this task. I need to produce a technique card for T-048: "Custom Shell Loader as Distinct from Generic Injection."

The material is thin — the atlas units only reference lab titles (Lab 4.7 CustomShell, Lab 5.1 The Loader, Lab 5.5 ShadowCraft) with very brief descriptions:
- Unit 4: Bootcamp challenges listing CustomShell
- Unit 5: Table of contents with Lab 4.7: CustomShell
- Unit 7: Lab 5.5 ShadowCraft — "Create a basic shell, Implement features covered in this section, Implement thorough error checking"
- Unit 8: Lab 5.1 The Loader — "Explore executing shellcode locally and over process boundaries"

So the card documents the shell/implant scaffolding layer (command dispatch, error handling, transport abstraction, interactive session management, I/O handling) as a distinct capability from injection methods.

For source verification: the included Rust files are:
1. `src/client_rust/src/commands.rs` — this is a command dispatch layer with ClientState, handle_command, shell session management (SHELL_START, SHELL_EXEC, SHELL_STOP, SHELL_POWERSHELL, CMD_EXEC). Does this implement "custom shell loader"? The technique is about shell/implant scaffolding: command dispatch, error handling, transport abstraction, session management. The commands.rs file does implement shell session management (persistent shell sessions via std::process with piped stdin/stdout/stderr, sentinel-based output reading, command dispatch via a match statement). This is the shell scaffolding layer of the client_rust implant — it's the command dispatch and I/O handling layer. However, the cluster spec's technique is about "custom shellcode-based shell infrastructure" — developing a standalone shellcode-based shell. commands.rs is not shellcode-based; it's a full Rust binary's command dispatcher. But it IS the implant scaffolding layer (command dispatch, error handling, shell session management). The LGTM note says: "The vault's T-007 card enumerates 14 injection methods but does not document the shell/implant scaffolding layer (command dispatch, error handling, transport abstraction) as a separate concern."

The note's description says "Involves developing standalone shellcode-based shell infrastructure (interactive session management, I/O handling, command execution)."

Hmm. The test in rule 8: "for the file to count as an implementation of this technique, at least ONE function in it must implement the primary mechanism the card describes."

The primary mechanism the card describes: the shell/implant scaffolding layer — command dispatch loop, session management, I/O relay between C2 and spawned shell processes, error handling. commands.rs implements `handle_command` which is a command dispatch function, and SHELL_START/SHELL_EXEC/SHELL_STOP handlers that implement interactive shell session management with piped I/O and sentinel-based output framing. That is a legitimate implementation of the shell scaffolding layer — but not "shellcode-based." The consolidated description mentions "standalone shellcode-based shell infrastructure" but the core distinct concern per the note is the scaffolding layer.

I should be careful. The safest and most honest approach: acknowledge commands.rs implements a shell-session management and command-dispatch layer (SHELL_START/SHELL_EXEC/SHELL_STOP) which is the implant-side realization of the scaffolding concern, but note it's a full-process RAT rather than a shellcode-based custom shell, and it doesn't satisfy the SEC670 lab's "shellcode over process boundaries" framing. Actually — false attribution is worse. Let me think about whether commands.rs truly implements "the primary mechanism the card describes."

The card describes: custom shell construction — the implant scaffolding layer (command dispatch, I/O handling, session management, transport abstraction) as distinct from injection. commands.rs:
- `handle_command` — command dispatch (40+ commands matched on string names)
- SHELL_START/SHELL_POWERSHELL — spawns persistent shell processes with piped stdio
- SHELL_EXEC — writes command + sentinel to stdin, reads stdout until sentinel, returns framed output with timeout and error handling
- SHELL_STOP — kills session
- run_command_sync — one-shot exec
- Error handling throughout (exitCode, stdout/stderr framing)

That IS the shell scaffolding layer. It's not shellcode-based, but the card's canonical concern (per the LGTM note) is the scaffolding layer, not strictly shellcode. I can reference commands.rs with the deviation noted: it's a hosted Rust process, not position-independent shellcode; the SEC670 CustomShell lab is about shellcode-based shells. This satisfies the verification test (at least one function implements the primary mechanism — handle_command and the SHELL_* handlers implement command dispatch and shell session management).

overlay.rs — hit keyword grep (shell? loader?) but implements Win32 overlay windows. Does NOT implement this technique. Ignore it.

process_ghosting.rs — implements process ghosting (T-009), not this technique. Ignore it.

So source_file: `src/client_rust/src/commands.rs` — wait, the path format. Looking at the manifest: "client_rust/src/commands.rs". The input file path is "src/client_rust/src/commands.rs". Hmm, the manifest says `client_rust/src/commands.rs`. The file provided is `src/client_rust/src/commands.rs`. I'll use `client_rust/src/commands.rs` to match the manifest's repo-root-relative convention. Actually the file header says "FILE: src/client_rust/src/commands.rs". Existing cards use e.g. `client_rust/src/kamui.rs` and `dark_crystal/crowd/src/pool_party.rs`. So `client_rust/src/commands.rs` matches convention. I'll use that.

crate: client_rust.

category: process-injection (proposed). Hmm — is that right? The technique is shell/loader scaffolding. The enum: syscalls|process-injection|edr-evasion|persistence|sleep-obfuscation|anti-analysis|crypto|networking|client|privesc|exploit-primitive|discovery. The cluster spec proposes process-injection. The client_rust shell sessions are under "client" arguably. But Lab 5.1 "The Loader" (executing shellcode locally and across process boundaries) is loader/injection adjacent. The spec says proposed category process-injection and I should use it as a strong default unless atlas material clearly supports different. The material doesn't clearly contradict. Keep process-injection.

tier: B (proposed). Keep.

mitre: Best fit. The technique is about building a custom shell/implant scaffolding. Options:
- T1059 (Command and Scripting Interpreter) — execution via shell. The custom shell provides command execution.
- T1055 (Process Injection) — no, this is distinct from injection per the whole point.
- T1095 (Non-Application Layer Protocol)? No.
- T1106 (Native API)? No.

The shell infrastructure for interactive command execution maps best to T1059 (Command and Scripting Interpreter) — adversaries abuse command shells to execute commands. A custom shell is essentially a custom command interpreter. T1059 is the best single fit. Secondary could be T1059.001? No — that's PowerShell specifically; the custom shell is its own interpreter, so plain T1059. Actually maybe mitre_secondary: [T1106]? No, don't invent. I could omit secondary. Or T1071? No. Just T1059.

Hmm, but wait — would T1055 be expected since category is process-injection? The Lab 5.1 "The Loader" is about executing shellcode across process boundaries — that's injection-adjacent, but T-007 covers those methods. The card's distinct concern is the shell layer. T1059 is right.

tags: 5-10 kebab-case: [shell, loader, command-dispatch, implant-architecture, session-management, io-relay, sec670, scaffolding] — maybe [custom-shell, loader, command-dispatch, implant-scaffolding, session-management, stdio-relay, error-handling, sec670]. 5-10 entries. Good.

member_notes: ['lgtm:customshell-shellcode-loader-card']

Now the body. Minimum 800 words, target 1200-1800. Material is thin, so I need to be careful: "Material is the authority — do not fabricate." But I can contextualize against Windows internals documentation and well-established knowledge, and describe what an implementation looks like based on the verified source. I must not invent specific lab details beyond what's in the units. The units say:

- Lab 4.7 CustomShell (Book 4, "Persistence Die Another Day" — wait, Book 4 is persistence; CustomShell appears as a bootcamp challenge there)
- Lab 5.1 The Loader: "Explore executing shellcode locally and over process boundaries"
- Lab 5.5 ShadowCraft (Book 5, "Enhancing Your Implant Shellcode Evasion and C2"): "Create a basic shell, Implement features covered in this section, Implement thorough error checking"

Structure:

## Summary
3-5 sentences. The technique: construction of a custom shell as its own capability — the scaffolding layer (command dispatch, session management, I/O handling, error checking) that sits above whatever execution primitive delivered the implant. SEC670 treats this as separate from injection method selection (labs CustomShell 4.7, The Loader 5.1, ShadowCraft 5.5). Detection surface: process creation telemetry for spawned shells, child-process lineage, named pipe/stdin-stdout anomalies, command content.

## Mechanism
Numbered steps. Based on the material + the verified implementation in commands.rs:

1. Execution primitive delivers the implant code (separate concern — T-007 catalog or local execution per Lab 5.1's "locally and over process boundaries").
2. Implant initializes scaffolding state: session table, transport handle, dispatch table.
3. Receive command from C2 transport (transport abstraction — the shell doesn't care how bytes arrive).
4. Parse command identifier and payload; dispatch to handler (match/switch on opcode).
5. For interactive shell sessions: spawn cmd.exe/powershell.exe with redirected stdin/stdout/stderr (CreateProcess with STARTUPINFO hStdInput/hStdOutput pipes, or piped Stdio in Rust).
6. Write operator command to child stdin; frame output with a sentinel token; read until sentinel or timeout.
7. Return framed result (exit code, stdout, stderr) to C2.
8. Error checking at every step (ShadowCraft lab explicitly requires "thorough error checking") — handle spawn failure, broken pipes, session-not-found, timeouts.
9. Session teardown: kill child process, drain session table.

## OS Internals Context
- Anonymous pipes and console handles: CreateProcess with inherited pipe handles; the child process inherits handles marked inheritable (SECURITY_ATTRIBUTES bInheritHandle). Console applications attach to the parent's console unless CREATE_NO_WINDOW / CREATE_NEW_CONSOLE.
- Console vs. non-console: a shellcode-based implant often runs in a process without a console; spawning cmd.exe requires CREATE_NO_WINDOW or detaching to avoid a visible window.
- Handle inheritance is all-or-nothing per CreateProcess call (bInheritHandles=TRUE inherits all handles marked inheritable) — relevant because an implant inside a host process may inadvertently leak host handles to the spawned shell.
- The sentinel-framing problem: anonymous pipes are byte streams without message boundaries; ReadFile on a pipe blocks until data arrives or the write end closes. Since the shell child never closes its stdout between commands, the reader needs an application-level delimiter (sentinel) or asynchronous/overlapped reads with timeouts.
- PeekNamedPipe for non-blocking checks of pipe buffer availability.
- WOW64 / redirection considerations? Not in material — skip.
- Windows pseudo console (ConPTY) as the modern alternative for full TTY behavior — is this "well-established Windows documentation"? Yes, ConPTY is documented on MSDN. But is it appropriate? The material doesn't mention it. I can mention it briefly as the OS primitive relevant to interactive shells. Careful — keep to what's defensible: CreateProcess stdio redirection is textbook Windows Internals; ConPTY is documented. I'll mention ConPTY briefly as the OS-provided alternative, framed as internals context, not as a suggestion.

Also for shellcode-based shells (Lab 5.1 The Loader executing "shellcode locally and over process boundaries"): the shell code must be position-independent, resolve its own APIs (PEB walk / hash resolution), and cannot rely on a CRT. That contextualizes against T-001/T-002/T-004 territory but those cards cover it. The internals point: a shellcode-based shell must call CreateProcess via resolved function pointers and manage pipe handles without a runtime.

## Key Implementation Details
commands.rs verified: ClientState.shell_sessions: HashMap<String, std::process::Child>; SHELL_START handler spawns cmd /Q or powershell -NoProfile -NonInteractive -NoLogo -ExecutionPolicy Bypass with piped stdio; SHELL_EXEC writes command + `echo ___SHELL_SENTINEL_7f3a2b___`, spawns a blocking thread reading BufReader lines until sentinel or timeout (default 30s), truncates output to 4000 chars, frames JSON {requestId, exitCode, stdout, stderr}; SHELL_STOP kills child. run_command_sync one-shot via cmd /C. cleanup() kills all sessions. Deviation: this is a hosted Rust RAT process with full CRT/Tokio runtime, not position-independent shellcode; the SEC670 labs target shellcode-based shells. Also note overlay.rs and process_ghosting.rs do NOT implement this technique — I won't mention them, or rather I just won't reference them. The instruction says ignore files that don't implement. I don't need to mention them.

Wait — should I be careful about attributing commands.rs? Let me re-read the test: "at least ONE function in it must implement the primary mechanism the card describes." The card describes shell scaffolding: command dispatch, session management, I/O handling. handle_command + SHELL_* handlers implement exactly that. Yes, verified. But the "custom shell" in SEC670 is shellcode-based; the description says "developing standalone shellcode-based shell infrastructure." Hmm. "standalone shellcode-based shell infrastructure (interactive session management, I/O handling, command execution)". The parenthetical defines what the infrastructure is: session management, I/O handling, command execution. commands.rs implements session management, I/O handling, and command execution — in a hosted binary, not shellcode. I'll claim it as a partial realization: the scaffolding layer exists in client_rust; the shellcode-based form is not implemented. That's honest and precise. source_file: client_rust/src/commands.rs is defensible since the primary mechanism (shell scaffolding: dispatch + piped session I/O + error framing) is implemented there.

Actually, let me reconsider. Would "no current implementation" be safer? The rule: false attribution corrupts. Is attribution here false? The technique: custom shell loader — the scaffolding layer. commands.rs literally implements a custom command shell infrastructure within the implant: persistent shell sessions, command dispatch, output framing, error handling, teardown. That's the technique's scaffolding layer realized in a full-process implant rather than shellcode. I'll attribute with an explicit deviation note. That's the most accurate statement of reality. The card documents both the SEC670 shellcode-shell concept and the HUGIN hosted implementation.

## Why It Matters
2-4 sentences: T-007 catalogs 14 injection methods but says nothing about what runs after execution is achieved; the shell layer determines operator experience (interactivity vs. one-shot), child-process footprint, and detection surface independent of the injection method. SEC670's lab sequence (4.7 CustomShell, 5.1 The Loader, 5.5 ShadowCraft) treats shell construction as a separable, gradable capability. Documenting it separately lets the vault reason about implant architecture as a composition: execution primitive × shell scaffolding × transport.

## Detection Considerations
Material does not discuss detection explicitly. Per rule: "If the material does not cover detection for this technique, write: 'Training material does not discuss detection for this technique.' Do not invent detections." The material doesn't cover detection. I should write that line. Can I add anything else? The rule says don't invent detections. Safest: write the line, and maybe note the detection surface is inherent to spawning child shell processes — no, that's inventing. Actually the rule permits... hmm. The Summary asks for "the primary detection surface" though. There's tension: Summary template asks for detection surface, Detection section says don't invent if material doesn't cover. I can keep the Summary's detection mention minimal and generic (child process creation is observable — that's not really an invented detection technique, it's a factual OS property: CreateProcess generates process-creation events; that's well-established). Rule 4 allows "well-established Windows internals documentation." Process creation auditing/telemetry is well-established. I'll keep it conservative: in Summary mention "process-creation and child-process lineage telemetry" as the surface (this is factual: spawning cmd/powershell children is visible to process creation logging). In Detection Considerations, write the required line since material doesn't discuss detection, and perhaps add that child-process telemetry visibility follows from the OS internals described (process creation is observable via system-wide mechanisms documented in Windows Internals) — I'll keep it minimal and grounded. Actually, to be safe: write the required sentence, then a short paragraph noting the observable artifacts that follow directly from the mechanism (child processes of the implant host, inherited pipe handles visible in handle tables, powershell.exe/cmd.exe command lines containing -ExecutionPolicy Bypass flags in the HUGIN implementation) — these are facts about the implementation, not invented EDR detections. I think that's defensible: residual artifacts derive from the verified source. The powershell flags are in the source. Command-line visibility is well-established (process command lines are retrievable via NtQueryInformationProcess/Win32). I'll frame carefully: "follows from the implementation" rather than claiming training material covers it.

## Related Techniques
- T-007 (Pool Party / process-injection catalog): the execution primitives that deliver shellcode; the shell layer is downstream. The would_relate_to lists T-007. The provided T-007 card is Pool Party specifically (interesting — the manifest calls T-007 the injection catalog; the provided card is pool-party). I'll describe relationship: injection methods deliver the payload; the custom shell is what the payload implements.
- T-022 (Network and Protocol Suite): transport abstraction — the shell's command channel runs over the networking layer (HTTP poll, WebSocket, malleable C2). In client_rust, handle_command is fed by the transport layer documented in T-022.

Only these two — per restraint rule.

## References
- Atlas material: atlas-labs-part2.md
- MITRE ATT&CK: T1059 with URL https://attack.mitre.org/techniques/T1059/
- LGTM notes: lgtm:customshell-shellcode-loader-card
- Public references: SANS SEC670 labs (named in material): Lab 4.7 CustomShell, Lab 5.1 The Loader, Lab 5.5 ShadowCraft. These are named in the material so I can reference them.

## Source Reference
client_rust/src/commands.rs — handle_command, SHELL_START/SHELL_EXEC/SHELL_STOP/SHELL_POWERSHELL handlers, run_command_sync. Note no shellcode-based custom shell exists in source.

Frontmatter:
```yaml
---
id: T-048
name: Custom Shell Loader Scaffolding
category: process-injection
tier: B
crate: client_rust
source_file: client_rust/src/commands.rs
mitre: T1059
tags: [custom-shell, loader, command-dispatch, implant-scaffolding, session-management, stdio-relay, error-handling, sec670]
origin: atlas-synthesis
member_notes: ['lgtm:customshell-shellcode-loader-card']
---
```

Name: 4-8 words. "Custom Shell Loader as Distinct from Generic Injection" is the canonical name but 8 words. Hmm, name should be 4-8 words. "Custom Shell Loader as Distinct from Generic Injection" = Custom(1) Shell(2) Loader(3) as(4) Distinct(5) from(6) Generic(7) Injection(8) — exactly 8. I could keep canonical. Or shorten to "Custom Shell Loader Scaffolding" (4 words). The spec says use canonical name as strong default. I'll use the canonical name since it's exactly 8 words and is the assigned canonical name. Actually for the H1: "# <Technique Name> — <One-Line Purpose>". I can use "Custom Shell Loader" as the display name in H1 with the purpose line. For frontmatter name, canonical: "Custom Shell Loader as Distinct from Generic Injection". Hmm, that reads awkwardly as a card name. Existing cards have names like "Pool Party Injection", "Network and Protocol Suite". The canonical name is descriptive of the clustering rationale. I'll use "Custom Shell Loader" (3 words — below 4 minimum) — no. "Custom Shell Loader Scaffolding" — 4 words, captures it. But spec says canonical name as strong default, adjustable if atlas material clearly supports different choice, explain in Why It Matters. The material doesn't clearly support a different name. Keep canonical: "Custom Shell Loader as Distinct from Generic Injection". It's exactly 8 words. Fine.

H1: "# Custom Shell Loader — Implant Scaffolding as a Separate Capability from Injection"

Word count target: 1200-1800 body words. Material is thin, so I must expand via OS internals and the verified implementation without fabricating. Let me draft.

Draft:

## Summary

Custom shell construction is the design and implementation of the implant's command-execution scaffolding — session management, I/O handling, command dispatch, and error checking — treated as a capability separate from the technique used to achieve code execution. SANS SEC670 sequences this as its own lab track: Lab 4.7 (CustomShell), Lab 5.1 (The Loader, executing shellcode locally and across process boundaries), and Lab 5.5 (ShadowCraft, building a basic shell with thorough error checking). An operator uses a custom shell rather than a stock reverse shell to control process lineage, avoid known-bad command lines (e.g., powershell -enc), define the command channel protocol, and degrade gracefully when a session dies. The primary detection surface is process-creation telemetry on the child shell processes the scaffolding spawns and the command-line parameters they carry.

## Mechanism

1. An execution primitive places the implant code in a running context — local execution in the implant's own process or across a process boundary (Lab 5.1's framing). This step is deliberately out of scope; T-007 catalogs the primitives.
2. The implant initializes shell scaffolding state: a session table keyed by operator-assigned session IDs, a handle to the C2 transport, and a dispatch table mapping command opcodes to handlers.
3. The transport layer delivers a command frame; the dispatcher parses the command identifier and payload and routes to the appropriate handler. Transport framing is abstracted — the shell layer consumes bytes without regard to how they arrived.
4. On a session-start command, the scaffolding spawns a child shell process (cmd.exe or powershell.exe) with stdin, stdout, and stderr redirected to pipes it owns.
5. On an execute command, the scaffolding writes the operator's command line to the child's stdin, followed by an echo of a sentinel token that marks end-of-output for that command.
6. A reader consumes child stdout line-by-line until the sentinel appears or a timeout expires; accumulated output is framed into a result record (request ID, exit code, stdout, stderr).
7. The result record returns over the transport to the operator.
8. Error checking wraps every transition (ShadowCraft's explicit requirement): spawn failure, missing session, dead child, closed pipe, and read timeout each produce a structured error result rather than a crash or a hung session.
9. On a session-stop command or implant shutdown, the scaffolding terminates the child process, waits for it to exit, and removes the session from the table.

## OS Internals Context

Anonymous pipes and stdio inheritance. CreateProcess redirects a child's standard handles through STARTUPINFO's hStdInput/hStdOutput/hStdError fields, with bInheritHandles=TRUE and the pipe ends created via CreatePipe with SECURITY_ATTRIBUTES.bInheritHandle=TRUE. Handle inheritance on Windows is coarse: when bInheritHandles is TRUE, the child inherits every handle in the parent marked inheritable — an implant running inside a host process must audit which handles it has marked inheritable or the spawned shell leaks host handles (a well-documented operational hazard covered by Windows Internals' treatment of handle tables).

Console attachment. Console applications launched from a non-console parent either attach to the parent's console or, with CREATE_NO_WINDOW / CREATE_NEW_CONSOLE, run without a visible console window. A shellcode-based implant injected into a GUI process has no console of its own; a spawned cmd.exe without CREATE_NO_WINDOW flashes a visible window on the victim's desktop. The creation flags are therefore part of the shell's opsec posture, not an afterthought.

Byte-stream framing. Anonymous pipes are unframed byte streams: ReadFile blocks until bytes arrive or the last write handle closes. Because an interactive shell keeps its stdout open across commands, the scaffolding cannot use EOF as a per-command delimiter; it needs an application-level marker (the sentinel-echo pattern) or overlapped I/O with PeekNamedPipe polling to implement timeouts without killing the session. This is the single most common failure point in custom shell implementations and the reason ShadowCraft grades error checking.

Position independence. When the shell is delivered as shellcode across a process boundary (Lab 5.1), the scaffolding cannot link against kernel32 import thunks or use a C runtime: every API — CreateProcess, CreatePipe, ReadFile, WriteFile — must be resolved at runtime from the PEB's module list, and all strings/structures must be position-independent. The loader dimension of the technique is precisely this constraint set; the shell logic itself is identical to a hosted build.

ConPTY. Since Windows 10 1809, the OS provides a pseudo-console API (CreatePseudoConsole) that gives a child a real console with a resizeable screen buffer behind pipes — the documented alternative to raw pipe redirection for full terminal fidelity. [Should I include this? It's well-established MSDN documentation. It's internals context. But rule 3: no suggestions. Mentioning ConPTY as "the documented alternative" edges toward a suggestion. I'll mention it as context of what the OS provides, framed descriptively, since OS Internals Context invites "specific NT API contracts... undocumented behavior." ConPTY is documented. I'll keep one short paragraph, framed as the OS primitive relevant to interactive shells, not as a recommendation. Actually to be safe on rule 3 (no variant ideas), I could cut it. Hmm. The section header asks to "explain the Windows internals that make this technique work." ConPTY isn't what makes this technique work. Cut it — safer and more accurate.]

Also powershell.exe command-line flags in the implementation: -NoProfile -NonInteractive -NoLogo -ExecutionPolicy Bypass — these land in the child's command line, retrievable by any process with read access to the child's PEB/process parameters, and by process-creation telemetry. That's factual.

## Key Implementation Details

client_rust/src/commands.rs implements the hosted form of this scaffolding. ClientState holds shell_sessions: HashMap<String, std::process::Child>. handle_command is the dispatcher — a match over ~60 command strings. SHELL_START parses "session_id|shell_type" and spawns cmd /Q or powershell -NoProfile -NonInteractive -NoLogo -ExecutionPolicy Bypass with Stdio::piped() on all three standard streams; the Child is inserted into the session table. SHELL_EXEC deserializes {sessionId, command, requestId, timeout} (default 30s), writes command + newline + `echo ___SHELL_SENTINEL_7f3a2b___` to the child's stdin, then spawns a blocking thread that BufReader::read_line's stdout until the sentinel line or the timeout; output is truncated to 4000 bytes and framed as JSON {requestId, exitCode, stdout, stderr} into a MSG_CMD_OUTPUT protocol message. The thread returns the stdout handle so it can be restored to the Child (a borrow-checker workaround). SHELL_STOP removes the session, kills and waits on the child. CMD_EXEC provides the one-shot path via cmd /C with .output() (no session state). cleanup() drains the session table, killing every child — the teardown path exercised on implant shutdown and by the Night Guy terminal sequence.

Deviations from the SEC670 framing: this is a hosted Tokio process with a full runtime, not position-independent shellcode; the "loader" constraint (runtime API resolution, no CRT) does not apply. The sentinel framing is line-oriented, so binary output or commands that do not emit a trailing newline before the sentinel can desynchronize the reader. No shellcode-based custom shell exists anywhere in the source tree.

Word counts and banned words check. Banned: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable. Avoid "the key insight", "worth noting", "it is important to note", "essentially", "at its core". I used "precisely" — fine. Check "textbook" — I almost used it; avoid.

## Why It Matters

T-007 catalogs how payload code ends up executing; nothing in the vault documents what that payload does once running — the session, dispatch, and I/O layer that turns an execution primitive into an operable implant. SEC670's curriculum structure (CustomShell as a Book 4 bootcamp, The Loader and ShadowCraft in Book 5) grades shell construction as a separable skill with its own failure modes — pipe framing, child lifecycle, error paths — none of which vary with the injection method chosen. Separating the layer lets an operator compose choices independently: any T-007 primitive can deliver the same shell scaffolding, and the same scaffolding can ride any T-022 transport. The layer also owns most of the implant's observable footprint (child processes, command lines, pipe handles), so architectural decisions here move detection risk regardless of how execution was achieved.

That's 4 sentences. Good.

## Detection Considerations

Training material does not discuss detection for this technique.

Observable artifacts follow from the mechanism itself and from the verified implementation: every interactive session is a child process of the implant host (cmd.exe or powershell.exe), and Windows process creation exposes the parent-child lineage and full command line to any consumer of process-creation events; the implementation's powershell.exe command line carries -NoProfile -NonInteractive -NoLogo -ExecutionPolicy Bypass, and cmd.exe carries /Q. Residual artifacts: inherited pipe handles in the child's handle table targeting the host process, session processes that persist until SHELL_STOP or implant exit, and the 4000-byte output truncation / sentinel token (___SHELL_SENTINEL_7f3a2b___) appearing in any memory capture of the host. No ETW provider GUIDs or Sysmon IDs are documented in the material for this layer.

Is that inventing? Process creation exposing lineage and command lines is well-established (Windows Internals; also MSDN on process creation). The command lines are from verified source. The sentinel string is from verified source. I frame it as "follows from the mechanism" not "the material says." I think acceptable and useful; the rule prohibits inventing detections (like claiming specific ETW providers). I explicitly say no ETW GUIDs documented. Good.

## Related Techniques

- **T-007 Pool Party Injection** — T-007's injection catalog supplies the execution primitives that deliver a payload; the custom shell is what that payload implements once running. The two layers are independently selectable.
- **T-022 Network and Protocol Suite** — the shell's command channel is transport-agnostic; in client_rust, handle_command consumes frames delivered by the T-022 transports (WebSocket, HTTP long-poll, malleable C2), and results return through the same path.

Hmm — should I double check "T-007's injection catalog" — the provided T-007 card is Pool Party specifically, but the index says T-007 is "Pool Party — Thread pool manipulation" while the stats say "15 injection methods" and T-013 is "Remaining Methods". The cluster spec says "The vault's T-007 card enumerates 14 injection methods". The provided T-007 file is just pool party. The manifest maps many injection files to T-007. The LGTM note says T-007 enumerates 14 methods. I'll say "the T-007 process-injection family supplies..." to be safe. Relationship line: "injection methods deliver the payload; the shell scaffolding runs afterward." Fine.

## References

- Atlas material: atlas-labs-part2.md (units 4, 5, 7, 8)
- MITRE ATT&CK: T1059 — Command and Scripting Interpreter (https://attack.mitre.org/techniques/T1059/)
- LGTM notes: lgtm:customshell-shellcode-loader-card
- Public references: SANS SEC670 Lab 4.7 (CustomShell), Lab 5.1 (The Loader), Lab 5.5 (ShadowCraft) — named in atlas-labs-part2.md

## Source Reference

client_rust/src/commands.rs — handle_command dispatcher; SHELL_START, SHELL_POWERSHELL, SHELL_EXEC, SHELL_STOP session handlers; run_command_sync one-shot path; ClientState::cleanup teardown. No shellcode-based custom shell implementation exists in the source tree; the SEC670 loader form is documented here for reference only.

Now check frontmatter integrity:
- id: T-048 ✓
- category: process-injection ✓ (from enum)
- tier: B ✓
- crate: client_rust ✓
- source_file: client_rust/src/commands.rs ✓ (verified — implements the scaffolding layer)
- mitre: T1059 ✓ real
- tags: 8 kebab-case ✓
- origin: atlas-synthesis ✓
- member_notes: ['lgtm:customshell-shellcode-loader-card'] ✓

Word count check: Let me estimate. Summary ~140, Mechanism ~300, OS Internals ~380, Key Impl ~260, Why ~130, Detection ~140, Related ~80, refs/source ~80. Body sections excluding frontmatter/headers... Summary+Mechanism+Internals+Impl+Why+Detection+Related ≈ 1430. Good, within target.

Check banned words in my draft: "elegant" no; "clever" no; "textbook" no; "robust" no; "clean" no. "well-documented" — "well-crafted" is banned, "well-documented" isn't in the list. Keep. Phrases: "worth noting" no; "it is important to note" no; "essentially" no; "at its core" no. "The single most common failure point" — is that a fanboy-ish claim? It's a claim of fact; defensible but strong. It's grounded in general knowledge of pipe semantics. Keep, or soften: "the most common failure point in custom shell implementations." Fine.

"No exclamation marks" ✓. Third person ✓. No rhetorical questions ✓.

Rule 3: no suggestions/variants. My ConPTY paragraph — I decided to cut. Ensure nothing else reads as a suggestion. "an implant running inside a host process must audit which handles it has marked inheritable" — that's descriptive of the contract, not a suggestion to the reader to do something in the vault. Fine.

One more consideration on the mechanism steps — should be "concrete action or state transition... Name specific NT APIs... as they actually appear in the training material or Windows documentation." The training material is sparse (lab titles only), so the mechanism is reconstructed from the verified implementation + documented API behavior. That's the best available grounding. I'll name CreateProcess/CreatePipe/ReadFile/WriteFile which appear in Windows docs (not in the material, but rule 4 allows well-established Windows documentation).

Also note: "This step is deliberately out of scope; T-007 catalogs the primitives." The provided T-007 is Pool Party; the LGTM note says T-007 enumerates 14 injection methods. I'll phrase as "the T-007 family catalogs the injection primitives."

In Summary I wrote "an operator uses a custom shell rather than a stock reverse shell to control process lineage, avoid known-bad command lines..." — is "avoid known-bad command lines" supported? It's general operator knowledge, reasonable. "degrade gracefully when a session dies" — supported by ShadowCraft error-checking requirement. OK.

mitre_secondary — omit (only one confident ID). T1059 is solid for a command shell. 

H1: "# Custom Shell Loader — Shell Scaffolding as a Capability Separate from Injection" — good, descriptive purpose line.

Name in frontmatter: keep canonical "Custom Shell Loader as Distinct from Generic Injection" (8 words). Good.

Let me also double check tags: [custom-shell, loader, command-dispatch, implant-scaffolding, session-management, stdio-relay, error-handling, sec670] — 8 entries, kebab-case ✓. Maybe add 'pipes'? 5-10 range fine.

Final polish of Mechanism numbering and make sure each step names specifics. Write final output now. No preamble — just the markdown file.