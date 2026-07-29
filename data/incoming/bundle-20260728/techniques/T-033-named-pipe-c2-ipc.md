---
id: T-033
name: Named Pipes for C2 Communication and Implant IPC
category: networking
tier: A
crate: none
source_file: none
mitre: T1559
mitre_secondary: [T1071]
tags: [named-pipes, anonymous-pipes, ipc, c2-transport, duplex-channel, server-service, smb, stdio-redirection]
origin: atlas-synthesis
member_notes: ['lgtm:pipe-ipc-for-staged-implant-communication', 'lgtm:named-pipe-c2-transport', 'lgtm:named-pipe-ipc']
---

# Named Pipes for C2 Communication and Implant IPC — Duplex IPC and C2 Transport via the Named Pipe File System

## Summary

Windows named pipes provide a duplex, network-capable interprocess communication channel that an implant can use as a local C2 transport between an injected payload and its controlling process, or as an inter-host channel without implementing a socket listener. The SEC670 material distinguishes two pipe classes: anonymous pipes, which are local-only, one-way, restricted to related (parent/child) processes, and named pipes, which support duplex communication between unrelated processes and become remotely accessible through the Server service at `\\ComputerName\pipe\PipeName`. A pipe server creates instances with `CreateNamedPipe`, waits for clients with `ConnectNamedPipe`, and clients attach with `CreateFile` or `CallNamedPipe`. Operators use pipes because the channel is a standard Windows administrative transport, requires no WinSock/WinHTTP/WinINet stack in the implant, and delivers kernel-mode transport with implicit buffering. The primary detection surface is pipe creation and connection telemetry plus handle-table artifacts in the listening process.

## Mechanism

1. **Anonymous pipe creation.** The parent calls `BOOL CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpSecAttr, DWORD nSize)`. The function returns a read-end handle that carries only read access and a write-end handle that carries only write access. Anonymous pipes cannot perform read and write operations at the same end, are local only, and never communicate over the network.
2. **Handle sharing to the child.** Passing a `SECURITY_ATTRIBUTES` with `bInheritHandle = TRUE` lets a child process inherit one end of the pipe. Assigning the inherited handle to the child's standard input/output handles at process creation redirects child stdio over the pipe. Where inheritance is not usable, `DuplicateHandle` transfers an end into another related process.
3. **Staged parent/child handoff.** The parent writes shellcode, a second stage, or tasking to the write end; the child reads from its inherited read end via its standard input. The material notes anonymous pipes carry less overhead than named pipes, making them the lighter channel for quick IPC between a process and its child.
4. **Named pipe server creation.** The server calls `HANDLE CreateNamedPipe(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecAttr)` with `lpName` of the form `\\.\pipe\<PipeName>`. Rather than returning handles to two ends, it creates one instance of the pipe and returns a `HANDLE` to the server end; `PIPE_ACCESS_DUPLEX` in `dwOpenMode` selects a two-way pipe. The calling process is the pipe server.
5. **Connection wait.** The server calls `ConnectNamedPipe`, which blocks (or pends under overlapped I/O) until a client attaches to the instance.
6. **Client attachment.** A local client opens the pipe with `CreateFile` against `\\.\pipe\<PipeName>`; a remote client uses `\\ComputerName\pipe\PipeName`. `CallNamedPipe` combines connect, write, read, and close into a single call for one-shot message exchanges.
7. **Duplex exchange.** Both ends perform reads and writes on the same pipe instance. Per the material, communications can flow back and forth through the same pipe, which suits a pipe server communicating with multiple clients or a full request/response C2 loop.
8. **Instance reuse and concurrency.** The server disconnects a finished client and re-waits on the instance, or creates up to `nMaxInstances` additional instances of the same name to serve concurrent clients.
9. **Network reachability.** With the Server service running, all named pipes on a host become accessible to remote systems. The implant gains an inter-host channel as a property of the operating system, not of its own networking code.

## OS Internals Context

Named pipes are implemented by the Named Pipe File System driver (`npfs.sys`), which owns the device object `\Device\NamedPipe`. The Win32 path `\\.\pipe\<name>` resolves through the object manager to `\Device\NamedPipe\<name>`, so every pipe operation is file-object I/O, not socket I/O. At the NT layer, `CreateNamedPipe` corresponds to `NtCreateNamedPipeFile`, and the `ConnectNamedPipe` wait is issued as a file system control (`FSCTL_PIPE_LISTEN`) via `NtFsControlFile`. Data transfer rides the ordinary file syscall family (`NtReadFile`, `NtWriteFile`). This contrasts with the NT Sockets transport documented in T-022, which drives the Ancillary Function Driver (`\Device\Afd`) through `NtDeviceIoControlFile`; a pipe-based implant performs no AFD operations and opens no TCP/UDP endpoint.

Buffering is implicit and kernel-side. The `nOutBufferSize` and `nInBufferSize` parameters size the quotas the NPFS driver reserves per instance; data written to a pipe is buffered by the driver until the peer reads it, so writer and reader never share user-mode memory. `dwPipeMode` selects byte mode (a raw stream) or message mode (`PIPE_TYPE_MESSAGE`), in which record boundaries are preserved and transaction-style calls such as `CallNamedPipe`/`TransactNamedPipe` complete a write plus read as one operation.

Remote accessibility is a consequence of the Server service rather than the pipe API itself. A remote `CreateFile` on `\\ComputerName\pipe\<name>` is handled by the SMB redirector as a session to the target's `IPC$` share; the Server service (`lanmanserver`) exposes the local NPFS namespace over SMB. The implant therefore speaks file I/O locally and inherits network transport from the OS, which is the mechanism behind the material's statement that with the server service running, all named pipes become accessible to remote systems.

A pipe instance is a securable kernel object. The `lpSecAttr` DACL controls which principals may open the pipe, and a NULL security descriptor applies the creator token's default DACL. The server end can also call `ImpersonateNamedPipeClient` to adopt the connecting client's security context, an internals property that makes pipes a standard vehicle for privilege-context exchange between Windows components. Anonymous pipes sit behind the same machinery: `CreatePipe` is a Win32 wrapper that generates a unique pipe name and creates a one-directional instance, which is why the returned ends are access-restricted (read-only and write-only) exactly as the training material describes.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. The grep-matched file `dark_crystal/crowd/src/overload.rs` was reviewed and does not implement this technique: it implements Module Overloading (`NtCreateSection` with `SEC_IMAGE` plus `NtMapViewOfSection`) and manual-map PE loading, and contains no pipe or IPC code.

An implementation would take the form of a transport module alongside the T-022 transports (`tcp_transport.rs`, `http_poll_transport.rs`): a server path calling `CreateNamedPipeW` with `PIPE_ACCESS_DUPLEX`, `PIPE_TYPE_MESSAGE`, and an explicit security descriptor, then `ConnectNamedPipe` and a length-prefixed read/write loop over the returned handle; a client path calling `CreateFileW` on `\\.\pipe\<name>` locally or `\\<host>\pipe\<name>` for inter-host links. Async operation would use `FILE_FLAG_OVERLAPPED` or the Tokio `tokio::net::windows::named_pipe` types. An anonymous-pipe variant would call `CreatePipe` and wire the child end through `STARTUPINFO` standard handles for staged parent/child payload handoff.

## Why It Matters

T-022's networking suite covers SOCKS5, HVNC, VNC/RFB, malleable C2, peer relay, HTTP long-poll, NT sockets, and BYOVD, but no pipe transport; three independent synthesis passes (exploit-dev, post-exploit parts 5 and 10) each flagged this gap. Pipes fill two operational roles the socket-based transports do not: a local channel between an injected implant and its controlling process that adds no listening socket after a T-007 injection delivers execution, and an inter-host channel whose network reachability is supplied by the Server service rather than by implant networking code. The member notes also identify anonymous pipes as a distinct lightweight capability for parent/child shellcode handoff via stdio redirection. Per the material, named pipes offer a legitimate-looking IPC channel that blends with Windows administrative traffic and are a documented C2 transport in operational red team tradecraft.

## Detection Considerations

Training material does not discuss detection for this technique. The following telemetry is established in Microsoft documentation rather than in the atlas material:

- **Telemetry sources**: Microsoft Sysinternals Sysmon emits Event ID 17 (Pipe Created) when a named pipe is created and Event ID 18 (Pipe Connected) when a client connects, capturing the pipe name and the process image on both sides. Remote pipe access additionally produces SMB session telemetry against the `IPC$` share, including logon and network-share-access events on the target.
- **Bypass options**: the training material does not describe evasion for pipe telemetry. The material's only defensive-relevant observation is that named pipes blend with Windows administrative traffic, since the same transport backs legitimate Windows components.
- **Residual artifacts**: the named pipe object persists under `\Device\NamedPipe` and is enumerable through handle tools while the server holds it open; the server process carries the pipe instance handle in its handle table; remote use leaves SMB/Server-service session state on the target. Anonymous pipes leave only transient handle pairs between the related processes.

## Related Techniques

- **T-022 Network and Protocol Suite** — T-022 documents the implant's socket, HTTP, and proxy transports but omits pipes; T-033 is the pipe-transport complement that the member notes repeatedly recommend as an addition to that suite.
- **T-007 Pool Party Injection** — the member notes position pipes as the local C2 transport between an injected implant and its host or controlling process; T-007's injection methods deliver execution, and this technique supplies the command channel afterward.

## References

- Atlas material: atlas-exploit-dev-part9.md, atlas-post-exploit-part10.md, atlas-post-exploit-part5.md
- MITRE ATT&CK: T1559 (https://attack.mitre.org/techniques/T1559/), T1071 (https://attack.mitre.org/techniques/T1071/)
- LGTM notes: lgtm:pipe-ipc-for-staged-implant-communication, lgtm:named-pipe-c2-transport, lgtm:named-pipe-ipc
- Public references: SANS SEC670 Red Teaming Tools (pipe coverage in the course's Operational Actions book); Microsoft Learn, Named Pipes documentation (`CreateNamedPipe`, `ConnectNamedPipe`, `CallNamedPipe`); Microsoft Sysinternals Sysmon documentation (Event IDs 17 and 18)

## Source Reference

No current implementation. The grep-matched `dark_crystal/crowd/src/overload.rs` was verified and implements module overloading, not named pipes. See atlas material and MITRE reference for public tooling.