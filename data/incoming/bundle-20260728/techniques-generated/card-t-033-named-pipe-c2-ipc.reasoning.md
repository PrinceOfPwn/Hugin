Let me analyze the inputs carefully.

**Cluster spec:** T-033 — Named Pipes for C2 Communication and Implant IPC
- Category: networking
- Tier: A
- would_relate_to: T-022, T-007
- 3 member notes: lgtm:pipe-ipc-for-staged-implant-communication, lgtm:named-pipe-c2-transport, lgtm:named-pipe-ipc

**Rust source file provided:** `src/dark_crystal/crowd/src/overload.rs` — this is Module Overloading via NtCreateSection(SEC_IMAGE) + NtMapViewOfSection. This has NOTHING to do with named pipes. The grep match must have been on some keyword (maybe "pipe" appears somewhere? Let me check... I don't see "pipe" in the file. Maybe "duplex"? No. It probably matched some other keyword. Regardless, this file implements Module Overloading, not named pipes. Per Rule 8, I must NOT attribute it. State "no current implementation."

**Atlas material:**
- atlas-exploit-dev-part9.md units 36-40: Anonymous and named pipes. Unit 36: Pipes as IPC, anonymous and named, duplex. Unit 37: anonymous pipes — local only, one-way, parent/child only, less overhead, standard input/output redirection. Unit 38/39/40: CreatePipe — BOOL CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpSecAttr, DWORD nSize). Handle inheritance, DuplicateHandle.
- atlas-post-exploit-part10.md units 15-21: Unit 15: pipes intro (duplex vs one-way). Unit 16: anonymous pipes — local only, one-way, parent/child, stdio redirection. Unit 17: named pipes — over the network, duplex. Unit 18: named pipes — unrelated processes, over network, duplex, "With the server service running, all named pipes become accessible to remote systems. Communications can now flow back and forth through the same pipe." Unit 19: CreateNamedPipe signature: HANDLE CreateNamedPipe(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecAttr). "The process that calls CreateNamedPipe is the pipe server and can use the function [ConnectNamedPipe]"... clients connect using CreateFile or CallNamedPipe with \ComputerName\pipe\PipeName naming. Units 20-21: review Q: named pipe can operate over a network.
- atlas-post-exploit-part5.md units 1-6: same named pipe content — duplex, unrelated processes, server service, CreateNamedPipe, ConnectNamedPipe, CreateFile, CallNamedPipe, \\ComputerName\pipe\PipeName.

**Related cards:**
- T-007 Pool Party (brief card provided) — the actual T-007 in the vault index is "Pool Party Injection" but the broader T-007 maps to process-injection. The cluster's note says pipes relate to T-007 because pipes support communication between an injected implant and host process. I'll reference T-007 for the injection → IPC relationship (implant injected into a host process needs a channel back to the loader/parent).
- T-022 Network Suite — full card provided. Named pipes are NOT in T-022 (SOCKS5, HVNC, VNC, malleable C2, rikudo, juubi, http poll, discovery, NT sockets, BYOVD). This card fills that gap.

**MITRE mapping:** Named pipes for C2... The best-fit ATT&CK technique. Options:
- T1071 (Application Layer Protocol) — no, that's for standard app protocols.
- T1090 (Proxy) — no.
- T1095 (Non-Application Layer Protocol) — possible but not best.
- T1559 (Inter-Process Communication) — this covers IPC usage generally, including named pipes. T1559.001 is Component Object Model, T1559.002 is Dynamic Data Exchange. Named pipes per se fall under T1559 parent.
- For C2 over named pipes specifically (SMB pipes like Cobalt Strike's SMB beacon), ATT&CK references: T1071.004 (DNS)? no. Actually, Cobalt Strike SMB Beacon is often mapped to... hmm. Let me think. There's no "named pipe C2" technique per se. SMB-based C2/lateral movement: T1021.002 (SMB/Windows Admin Shares) is for lateral movement via SMB. Named pipes over the network ride over SMB (the IPC$ share, Server service, port 445). 

The cluster spec says "pick the single best-fit ATT&CK technique ID". The technique card covers both local IPC (parent/child, inter-process) and network C2 transport. 

Best fits:
- Primary: T1559 (Inter-Process Communication) — covers the IPC mechanism itself. ATT&CK T1559 description: "Adversaries may abuse inter-process communication (IPC) mechanisms... such as Component Object Model (COM), Dynamic Data Exchange (DDE), and named pipes." Yes — the ATT&CK T1559 page explicitly mentions named pipes. That's a strong fit.
- Secondary: T1071 (Application Layer Protocol) — for C2 use; though named pipes aren't an application layer protocol per ATT&CK's enumeration. Alternatively T1095 Non-Application Layer Protocol. Hmm. For SMB-named-pipe C2, MITRE maps Cobalt Strike's named-pipe SMB channel under... I've seen it mapped to T1071 in some reports and T1095 in others. Actually for SMB Beacon MITRE's own Cobalt Strike page mentions "SMB named pipes" under Command and Control. I'll use mitre: T1559 with mitre_secondary: [T1071] or [T1095]. Given network pipes traverse SMB (TCP 445) via the Server service, T1095 (Non-Application Layer Protocol) is a reasonable secondary for the C2 channel, but honestly T1071 is "Application Layer Protocol" — named pipes over SMB would be more non-application-layer? SMB is arguably an application layer protocol. Hmm.

Let me be careful. Rule 4: pick one I'm confident about. T1559 explicitly covers named pipes — I'm confident. For secondary, lateral movement via SMB admin shares T1021.002 covers remote named-pipe usage (e.g., PsExec-style service control over pipes). But the card is about C2 transport, not lateral movement. I'll list mitre_secondary: [T1095] since C2 over named pipes is non-application-layer... Actually, is named pipe an application layer protocol? ATT&CK T1071 covers "protocols like HTTP/S, DNS, FTP, SMTP". Named pipes/SMB C2 is typically cited under T1071.004? No. Hmm.

Actually, thinking more: Cobalt Strike SMB Beacon → MITRE ATT&CK software page for Cobalt Strike lists "Application Layer Protocol: Web Protocols" for HTTP, and for SMB named pipes it lists... I believe the Cobalt Strike ATT&CK entry maps SMB named pipes to T1090.001 (Internal Proxy)? No — that's for the pivoting aspect. Some sources map it to T1071. Hmm, honestly I recall that SMB named-pipe C2 is sometimes categorized under T1021.002 when used for lateral movement execution.

Safest secondary: T1071 (Application Layer Protocol) — generic C2 over a protocol. But named pipes aren't application layer... Alternatively just T1095. Let me check my confidence: T1095 "Non-Application Layer Protocol" — "Adversaries may use a non-application layer protocol for communication between host and C2 server... examples include TCP, UDP, ICMP." Named pipes over SMB isn't that either.

Honestly T1559 alone is the confident primary. For secondary, I could omit the line entirely (the template allows omitting mitre_secondary). That's the safest path per Rule 4. But the technique genuinely spans: local IPC (T1559) and remote C2 transport. For the remote C2 aspect... The named pipes are accessed over the network through the Server service which is SMB. I'll include mitre_secondary: [T1071] — hmm.

Actually wait. Let me reconsider: T1071's description: "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic." Named pipes blending with administrative traffic — the LGTM note says "Named pipes offer a legitimate-looking IPC channel that blends with Windows administrative traffic." The blending rationale matches T1071's intent. But mechanically SMB named pipes... SMB is listed under T1021.002 as a "remote service". 

I think the cleanest, most defensible: mitre: T1559, and omit secondary OR include T1071. Given Rule 4 says pick IDs I'm confident about — I'm confident T1559 covers named pipes (the ATT&CK page literally lists named pipes). For the network C2 side, I'm fairly confident many public mappings use T1071.001? No... 

Let me think about what MITRE itself does: The ATT&CK technique T1559 "Inter-Process Communication" description explicitly says: "IPC is commonly used by software... Adversaries may abuse IPC to execute arbitrary code or commands. IPC mechanisms include Component Object Model (COM), Dynamic Data Exchange (DDE), and named pipes." Yes.

For C2 channel over named pipes, I'll keep it simple and confident: primary T1559. Secondary: I'll include T1071 (Application Layer Protocol) with modest confidence... Actually no. Hmm, one more option: T1090.001 Internal Proxy — no, that's proxying.

Decision: mitre: T1559, mitre_secondary: [T1071]. Rationale to keep in mind but I won't need to write it in the card: T1559 covers the IPC primitive (named pipes are explicitly enumerated by ATT&CK under T1559), T1071 covers the C2-channel use. This is defensible. Actually — I want to double check T1071 numbering: T1071 Application Layer Protocol, sub-techniques .001 Web, .002 File Transfer, .003 Mail, .004 DNS. Named pipes/SMB don't fit any sub-technique, so parent T1071 is the right granularity. OK.

Alternatively I could argue T1021.002 SMB/Windows Admin Shares for the remote aspect. But that's Lateral Movement tactic and the card's emphasis is C2 + IPC. I'll go T1559 primary + T1071 secondary. Hmm, actually, one concern: does ATT&CK really mention named pipes in T1559? Yes — T1559's description: "Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid situations such as deadlocks... Specific implementations of IPC mechanisms abused by adversaries may include Component Object Model (COM), Dynamic Data Exchange (DDE), and named pipes." I'm quite confident named pipes are mentioned there. Good.

**Frontmatter:**
- id: T-033
- name: Named Pipes for C2 and Implant IPC (4-8 words). Canonical: "Named Pipes for C2 Communication and Implant IPC" — that's 8 words. Fine.
- category: networking
- tier: A
- crate: none (no implementation — overload.rs does NOT implement this)
- source_file: none
- mitre: T1559
- mitre_secondary: [T1071]
- tags: 5-10 kebab-case: named-pipes, ipc, c2-transport, smb, server-service, duplex, anonymous-pipes, handle-inheritance, lateral-movement maybe. Let's pick: [named-pipes, ipc, c2-transport, anonymous-pipes, duplex-channel, server-service, smb, handle-inheritance]
- origin: atlas-synthesis
- member_notes: exactly the 3 given.

**Body sections:**

Summary: 3-5 sentences. First sentence standalone: "Windows named pipes provide a duplex, network-capable IPC channel that an implant can use as a local C2 transport between processes or as an inter-host channel over SMB." Mention anonymous pipes for parent/child handoff, CreateNamedPipe/ConnectNamedPipe/CreateFile/CallNamedPipe API surface, Server service making pipes remotely accessible at \\ComputerName\pipe\PipeName, blends with admin traffic, detection surface: pipe creation events (Sysmon 17/18 — wait, rule: don't invent Sysmon IDs. Sysmon Event ID 17 (Pipe Created) and 18 (Pipe Connected) are well-established and I am confident about them — these are real Sysmon event IDs documented by Microsoft. Rule says don't fabricate Sysmon event IDs; EID 17/18 for named pipes are genuinely well-documented. I'm confident. ETW: Microsoft-Windows-Kernel-IO? There's the ETW provider for named pipes... I don't recall a canonical GUID — I'll write "GUID not documented in material" if needed. Actually, well-known: Microsoft-Windows-Kernel-File? For pipe activity, Sysmon is the standard source. Also "Object Manager" handle audits. I'll keep to Sysmon 17/18 (confident) and note the material doesn't discuss detection.

Mechanism — numbered steps. Split into server side, client side, anonymous pipe path, network path:

Server:
1. Pipe server calls CreateNamedPipe with lpName \\.\pipe\<name> (local machine), dwOpenMode (PIPE_ACCESS_DUPLEX for bidirectional), dwPipeMode (PIPE_TYPE_BYTE or PIPE_TYPE_MESSAGE, PIPE_READMODE_*, PIPE_WAIT), nMaxInstances, buffer sizes, timeout, security attributes. Returns a HANDLE to the server end of one pipe instance.
2. Server blocks in ConnectNamedPipe until a client connects (or uses overlapped I/O).
3. ReadFile/WriteFile on the handle for duplex exchange.
4. DisconnectNamedPipe + new ConnectNamedPipe to recycle the instance for the next client; additional instances via repeated CreateNamedPipe with same name.

Client:
5. Client calls CreateFile on \\.\pipe\<name> locally or \\ComputerName\pipe\PipeName remotely (material says "With the server service running, all named pipes become accessible to remote systems"), or CallNamedPipe for one-shot message write/read.
6. WaitNamedPipe if no instance available.
7. ReadFile/WriteFile duplex.

Anonymous:
8. CreatePipe returns read and write handles (one-way). 
9. Handle inheritance via SECURITY_ATTRIBUTES bInheritHandle=TRUE and STARTUPINFO std handles for parent/child stdio redirection, or DuplicateHandle for related processes.
10. Parent writes shellcode/commands, child reads — staged payload handoff without named-pipe overhead.

The material explicitly covers: CreatePipe signature, inheritance/DuplicateHandle, CreateNamedPipe signature, ConnectNamedPipe, CreateFile, CallNamedPipe, \\ComputerName\pipe\PipeName, duplex, server service remote accessibility. I'll stick to those APIs. ReadFile/WriteFile/WaitNamedPipe/DisconnectNamedPipe are standard Windows knowledge (MSDN) — allowed under "well-established Windows internals documentation" as long as I don't fabricate specifics. I'll mention them lightly.

OS Internals Context:
- Named pipes are implemented by the Named Pipe File System (NPFS) driver (npfs.sys) — device \Device\NamedPipe. Local path \\.\pipe\X maps to \Device\NamedPipe\X. Remote access goes over SMB through the IPC$ share served by the Server service (srv.sys / lanmanserver); the redirector (mrxsmb) maps \\ComputerName\pipe\X to an SMB tree connect on IPC$ then open on the named pipe file. That's why "with the Server service running, all named pipes become accessible to remote systems."
- Kernel-side, each pipe instance is a file object; data buffered in kernel-mode buffers (the nOutBufferSize/nInBufferSize parameters set quota), giving implicit buffering — the "kernel-mode transport with implicit buffering" from the consolidated description.
- Message mode (PIPE_TYPE_MESSAGE) preserves message boundaries and gives atomic writes up to buffer size; byte mode is a stream. CallNamedPipe is a convenience combining CreateFile, WriteFile, ReadFile (transact) — actually CallNamedPipe works on message-type pipes: it connects, writes, reads, closes. TransactNamedPipe is the underlying transaction API — write+read atomic op. This is established MSDN knowledge.
- Security: pipe is a securable kernel object; lpSecAttr DACL controls which SIDs may connect; default DACL grants access per creator's token. Impersonation: pipe server can ImpersonateNamedPipeClient. Mention briefly (well-established).
- Anonymous pipes: created via CreatePipe which under the hood creates a named pipe with an auto-generated name... Actually on modern Windows, CreatePipe is implemented by kernel32 calling NtCreateNamedPipeFile with a generated name (CRTL "AnonymousPipe" style? I recall CreatePipe creates \Device\NamedPipe\Win32Pipes.<pid>.<counter> or similar). Hmm — is that well-established? Yes: CreatePipe internally creates a named pipe with a unique name like "\Device\NamedPipe\Win32Pipes.%08x.%08x". I'm fairly confident this is documented behavior (visible in Process Monitor / handle tools). I'll state it carefully: "CreatePipe is a wrapper that generates a unique pipe name and creates a one-way pipe instance; the handles returned are the read and write ends." This is documented in MSJ/Russinovich-era writing and observable via handle enumeration. Keep it modest.
- No sockets stack involvement: pure file-object I/O via NtCreateNamedPipeFile / NtFsControlFile (FSCTL_PIPE_WAIT etc.). The NT-level syscalls: NtCreateNamedPipeFile (server), client open via NtCreateFile on \??\pipe\... wait, the DOS name \\.\pipe\X resolves through the object manager to \Device\NamedPipe\X. NtCreateNamedPipeFile creates the pipe; NtFsControlFile with FSCTL_PIPE_LISTEN waits for connection (ConnectNamedPipe → FSCTL_PIPE_LISTEN). This is well-established (npfs + documented FSCTL codes in ntifs.h / Windows Driver Kit docs). I'll include at moderate depth: NtCreateNamedPipeFile, FSCTL_PIPE_LISTEN. Careful not to overclaim specifics.

Also why pipes vs sockets for implants: no listener socket (no TCP/UDP endpoint), traffic over 445 blends with admin/SMB, pipe is a kernel object visible in handle tables.

Key Implementation Details: overload.rs does NOT implement this — it's Module Overloading (SEC_IMAGE mapping). Per rule: state no current implementation, note the grep-matched file was reviewed and rejected, then describe what an implementation would look like in one paragraph (Rust: windows crate NamedPipeServer? Or CreateNamedPipeW via windows::Win32::System::Pipes; tokio::net::windows::named_pipe for async; protocol framing with length-prefixed messages; integrate with henge transforms from T-022). The rule says "briefly describe what an implementation would look like (data structures, syscalls, roughly one paragraph)."

Also mention the source-file verification explicitly: overload.rs implements module overloading (NtCreateSection SEC_IMAGE) and contains no pipe code.

Why It Matters: fills the gap T-022 leaves — T-022 covers SOCKS5, HTTP poll, NT sockets, malleable C2 etc., but no pipe transport. Distinct because: (1) local implant↔host channel post-injection (T-007 methods deliver payload into a host; pipes give the back-channel without sockets), (2) network-capable without the implant opening a socket — remote access is a property of the Server service, (3) anonymous pipes enable parent/child staged handoff with stdio redirection. Blends with Windows admin traffic per the note.

Detection Considerations: Training material does not discuss detection for this technique — that's the honest statement per rule ("If the material does not cover detection for this technique, write: `Training material does not discuss detection for this technique.`"). But I can still include established telemetry without inventing? The rule says "Do not invent detections" if material doesn't cover them. Hmm — the template says if material doesn't cover detection, write that line. But it also asks for telemetry sources "the training material describes". Strictly: the material doesn't discuss detection. Rule 4 allows well-established Windows internals documentation. Sysmon 17/18 are well-established and I'm confident. I think the safest compliant approach: state "Training material does not discuss detection for this technique." and then, grounded in established documentation rather than invented specifics, list the well-known residual artifacts (pipe handle visible in handle tables, pipe name enumerable, SMB/IPC$ connections for remote use, Sysmon 17/18). The system prompt's rule: "If the material does not cover detection for this technique, write: `Training material does not discuss detection for this technique.` Do not invent detections." I'll write that sentence, then add carefully-sourced well-established facts (Sysmon Event IDs 17 and 18 are genuinely documented by Microsoft Sysinternals — I'm confident, not fabricating). ETW GUIDs — I won't guess. This balances honesty with usefulness. I'll frame the added items as "established Windows telemetry" clearly separated from the material.

Related Techniques:
- T-022 Network and Protocol Suite — T-022 documents sockets/HTTP-based transports but omits pipes; T-033 is the pipe-transport complement to T-022's suite.
- T-007 Pool Party / process injection — injected implants need a channel back to the operator-controlled process; named/anonymous pipes supply that IPC channel after injection (the member note explicitly says "local C2 transport between an injected implant and a host process").

References:
- Atlas: atlas-exploit-dev-part9.md, atlas-post-exploit-part10.md, atlas-post-exploit-part5.md
- MITRE: T1559 URL https://attack.mitre.org/techniques/T1559/
- LGTM notes: the 3 IDs
- Public references: SEC670 material itself is the source; named pipes are MSDN-documented — I can cite Microsoft Learn "Named Pipes" doc as established doc. Keep minimal: "Microsoft Learn — Named Pipes (CreateNamedPipe, ConnectNamedPipe, CallNamedPipe)" — that's a real doc set. And Sysmon doc? I mention in detection; can cite Microsoft Sysinternals Sysmon. These are not invented.

Source Reference: "No current implementation. See atlas material and MITRE reference for public tooling." — per template. Note overload.rs reviewed, does not implement.

Length: target 1200-1800 words body. Let me draft.

Tier A per spec. Category networking. Crate: none.

Now careful about banned words: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable; phrases "but wait", "interestingly", "worth noting", "the key insight", "it is important to note", "as you can see", "essentially", "at its core". Avoid "Key Implementation Details" header is mandated (contains "Key" but it's the required section name — fine).

Also no "Key Innovation" sections etc. Stick to exact headers.

Let me draft the card.

Frontmatter name: "Named Pipes for C2 Communication and Implant IPC" (8 words: Named(1) Pipes(2) for(3) C2(4) Communication(5) and(6) Implant(7) IPC(8)). OK.

H1: `# Named Pipes for C2 Communication and Implant IPC — Duplex IPC and C2 Transport via NPFS`

Summary draft:
"Windows named pipes give an implant a duplex, network-capable interprocess communication channel that can serve as a local C2 transport between an injected payload and its controlling process or as an inter-host channel without a socket-based listener. The SEC670 material covers two pipe classes: anonymous pipes (local-only, one-way, parent/child, created with CreatePipe) and named pipes (duplex, usable between unrelated processes, remotely accessible through the Server service at \\ComputerName\pipe\PipeName). A pipe server creates instances with CreateNamedPipe, waits for clients with ConnectNamedPipe, and clients attach with CreateFile or CallNamedPipe. Operators use pipes because the channel is a standard Windows administrative transport, requires no WinSock/WinHTTP stack, and provides kernel-buffered I/O. The primary detection surface is pipe creation/connection telemetry and handle-table artifacts."

That's 5 sentences. Good.

Mechanism — organize as numbered steps covering both classes:

1. Anonymous pipe creation: CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpSecAttr, DWORD nSize) returns read-only and write-only handles. nSize is a buffer-size hint; zero uses default.
2. Handle sharing: SECURITY_ATTRIBUTES with bInheritHandle=TRUE lets a child inherit one end; STARTUPINFO hStdInput/hStdOutput/hStdError assignment redirects child stdio over the pipe. DuplicateHandle transfers an end to another related process when inheritance is not usable.
3. Parent-side staged handoff: parent writes shellcode/stage or commands to the write end; child reads from its inherited read end (ReadFile on stdin) — one-way channel, less overhead than named pipes (material states anonymous pipes have "less overhead than named pipes").
4. Named pipe server: CreateNamedPipe(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecAttr) — lpName form \\.\pipe\<PipeName>; PIPE_ACCESS_DUPLEX in dwOpenMode for two-way; returns HANDLE to server end of one instance; caller is the pipe server.
5. Connection wait: ConnectNamedPipe blocks (or pends under overlapped I/O) until a client attaches.
6. Client attach: CreateFile on \\.\pipe\<PipeName> locally or \\ComputerName\pipe\PipeName remotely; CallNamedPipe performs connect+write+read+close in one call for message-mode pipes.
7. Duplex exchange: both ends ReadFile/WriteFile on the same instance — "communications can now flow back and forth through the same pipe" (material).
8. Instance recycling/additional clients: disconnect and re-wait, or create up to nMaxInstances instances of the same name.
9. Remote reachability: with the Server service running, all named pipes on a host are reachable from remote systems — inter-host implant links without implementing a network listener in the implant.

OS Internals Context:

- NPFS (npfs.sys), device \Device\NamedPipe; the Win32 path \\.\pipe\X resolves via object manager to \Device\NamedPipe\X. Pipe creation at NT level is NtCreateNamedPipeFile; ConnectNamedPipe waits via an FSCTL (FSCTL_PIPE_LISTEN) issued with NtFsControlFile. — I'm fairly confident FSCTL_PIPE_LISTEN is the documented wait control code. Yes, ntifs.h documents FSCTL_PIPE_LISTEN, FSCTL_PIPE_WAIT, FSCTL_PIPE_TRANSCEIVE, etc. OK.
- Kernel buffering: nInBufferSize/nOutBufferSize reserve nonpaged? Pipe buffers are allocated from paged/nonpaged pool? Pipe data buffers come from nonpaged pool historically... I believe NPFS uses nonpaged pool quota for pipe buffers, charged against pipe quota. Hmm — I recall pipe buffer memory is allocated from non-paged pool with quota charged to the creating process. Not 100% sure about quota accounting details. Safe phrasing: "data written to a pipe is buffered by the NPFS driver in kernel memory until read, so writer and reader never share user-mode memory" — that's safe and matches "kernel-mode transport with implicit buffering."
- Message vs byte mode: PIPE_TYPE_MESSAGE preserves record boundaries and supports CallNamedPipe/transaction semantics; PIPE_TYPE_BYTE is a raw stream. Established MSDN.
- Network path: remote pipe open is an SMB session to the IPC$ share; the Server service (lanmanserver) exposes NPFS over SMB, so the implant needs no socket code — the redirector and server service handle the network. This matches material's "With the server service running, all named pipes become accessible to remote systems."
- Security descriptor: lpSecAttr controls which principals can open the pipe; a default-NULL DACL... CreateNamedPipe with NULL security attributes gives default DACL from creator token. Established.
- Anonymous pipe implementation: CreatePipe is a Win32 wrapper that generates a unique name and creates a one-directional pipe instance; the returned handles carry only read or only write access, matching the material's "cannot perform read and write operations at the same end of the pipe."
- No thread/APC/context creation: pure file-object I/O, so the channel adds no new execution artifact beyond handles (tie to T-007 lightly? maybe in related).

Key Implementation Details:

State: No current implementation in HUGIN source. The grep-matched file dark_crystal/crowd/src/overload.rs was reviewed: it implements Module Overloading (NtCreateSection with SEC_IMAGE + NtMapViewOfSection) and manual-map loading; it contains no named-pipe or IPC code and is not an implementation of this technique. Then a paragraph on what an implementation would look like: a transport module beside T-022's tcp_transport.rs / http_poll_transport.rs; server side CreateNamedPipeW with PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE, framing = 4-byte LE length prefix + payload, henge transforms applied to frames; client side CreateFileW on \\.\pipe
ame or \\host\pipe
ame; tokio::net::windows::named_pipe for async or raw windows::Win32::System::Pipes bindings; anonymous-pipe variant via CreatePipe + STARTUPINFO stdio redirection for staged child processes.

Wait — rule 3 says no suggestions/variant ideas: "Do not add 'Consider also X' or 'A future improvement could Y' sections." But the Key Implementation Details template explicitly says when no source implements: "Then briefly describe what an implementation would look like (data structures, syscalls, roughly one paragraph)." So that paragraph is mandated by the template, not a rule-3 violation. Keep it descriptive of what an implementation would look like, framed as documentation, not as a suggestion for improvement.

Why It Matters:
- T-022 covers SOCKS5, HVNC, VNC/RFB, malleable C2, peer relay, HTTP poll, NT sockets, BYOVD — none provide a pipe transport; the member notes from three independent synthesis passes each flag this gap.
- Distinct operational properties: local channel post-injection (pairing with T-007 injection methods) without a listening socket; inter-host reachability provided by the Server service rather than implant networking code; anonymous pipes give staged parent/child handoff via stdio redirection.
- Blends with Windows administrative traffic (per lgtm:named-pipe-c2-transport) — SMB named pipes are the transport behind documented operational tradecraft.

Detection Considerations:
"Training material does not discuss detection for this technique." Then established telemetry (Microsoft-documented, not invented): Sysmon Event ID 17 (Pipe Created) and 18 (Pipe Connected) — these are the canonical Sysmon pipe events; Microsoft Sysinternals documentation. Residual artifacts: named pipe object visible under \Device\NamedPipe (enumerable via tools like pipelist / handle enumeration), server-side handle in the listening process's handle table, SMB sessions to IPC$ for remote pipes. Bypass options: material silent — state that. I must be careful: the instruction says if material doesn't cover detection, write that sentence and "Do not invent detections." Sysmon 17/18 are not invented — they're extremely well-established. I'll include them but clearly attributed to Microsoft Sysinternals documentation rather than the training material. I think that's within the spirit: don't fabricate. I'll keep it tight.

Related Techniques:
- T-022 Network and Protocol Suite — T-033 fills the pipe-transport gap in T-022's suite; a pipe transport would slot alongside its SOCKS5/HTTP-poll/NT-sockets channels.
- T-007 Pool Party (process injection) — the member note positions pipes as the local C2 channel between an injected implant and its host/controlling process; injection delivers execution, pipes carry the command channel.

References:
- Atlas material: atlas-exploit-dev-part9.md, atlas-post-exploit-part10.md, atlas-post-exploit-part5.md
- MITRE ATT&CK: T1559 (https://attack.mitre.org/techniques/T1559/), T1071 (https://attack.mitre.org/techniques/T1071/)
- LGTM notes: lgtm:pipe-ipc-for-staged-implant-communication, lgtm:named-pipe-c2-transport, lgtm:named-pipe-ipc
- Public references: Microsoft Learn — Named Pipes documentation (CreateNamedPipe, ConnectNamedPipe, CallNamedPipe); Microsoft Sysinternals Sysmon (pipe events). SANS SEC670 material. These are all real.

Source Reference: No current implementation. The grep-matched dark_crystal/crowd/src/overload.rs was verified and implements module overloading, not named pipes. See atlas material and MITRE reference for public tooling.

Word count target: aim ~1300-1500 body words.

Let me also double-check frontmatter enum: category "networking" ✓. tier A ✓. crate: none ✓ (enum allows none). source_file: none ✓.

Tags (5-10): named-pipes, anonymous-pipes, ipc, c2-transport, duplex-channel, server-service, smb, stdio-redirection. That's 8. Kebab-case ✓.

Now write it. Watch for banned words. Avoid "notable", "key" (except mandated header "Key Implementation Details"), avoid "It is important to note". Use third person declarative.

One more check on mechanism details from the material to name precisely:
- "BOOL CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpSecAttr, DWORD nSize); Has a Boolean return type" ✓
- "The handle for the read end of the pipe will naturally only have read access. The same thing goes for the write end of the pipe—it will only have write access." ✓
- Handle inheritance + DuplicateHandle ✓
- "HANDLE CreateNamedPipe(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecAttr); Has a HANDLE return type" ✓
- "Instead of returning handles to the ends of pipes, it will create an instance of the pipe. The process that calls CreateNamedPipe is the pipe server and can use the function [ConnectNamedPipe]" ✓
- Clients: "CreateFile or CallNamedPipe with specific naming conventions" — \ComputerName\pipe\PipeName ✓
- "Named pipes can be one directional like anonymous pipes, but they can also be duplex pipes." ✓
- "With the server service running, all named pipes become accessible to remote systems. Communications can now flow back and forth through the same pipe." ✓
- Anonymous: "Less overhead than named pipes", "Local only", "One-way", "cannot be used to communicate over the network, and they cannot be used to communicate with processes that are not related to them (parent/child)", "useful for quick IPC between a process and its child process using standard input/output redirection" ✓

Note: the material's unit 19 excerpt mentions clients use "\\ComputerName\pipe\PipeName" (LGTM note says \ComputerName\pipe\PipeName). Standard form is \\.\pipe
ame locally and \\ComputerName\pipe
ame remotely. Good.

Word on "kernel-mode transport with implicit buffering" from consolidated description — I'll use that phrasing in Summary or OS Internals.

Draft OS internals depth: NPFS, NtCreateNamedPipeFile, FSCTL_PIPE_LISTEN, message vs byte mode, IPC$/SMB redirector path, pipe as securable object, server-side impersonation capability (ImpersonateNamedPipeClient — established MSDN; mention briefly as why pipes double as privilege-context channels? Careful — don't drift into suggestion territory. It's factual internals context. Keep one sentence.)

Also mention: because pipe I/O is file-object I/O, the syscalls involved are the file family (NtCreateFile/NtReadFile/NtWriteFile/NtFsControlFile) rather than AFD/socket IOCTLs — contrast with T-022's NT Sockets which go through the AFD driver. That's a nice grounded contrast tying to T-022.

Hmm, one caution on NtCreateNamedPipeFile: it's documented in ntifs/ReactOS as the NT API behind CreateNamedPipe. Confident enough. FSCTL_PIPE_LISTEN documented in MS-FSCC? FSCTL_PIPE_LISTEN is documented (used by ConnectNamedPipe). OK.

Pipe buffer pool: I'll avoid specific pool claims; say "buffered by the kernel-mode NPFS driver until the peer reads it".

Let me now count approximate words as I write. Aim ~1400.

Write the final file now.

Also ensure member_notes exact: ['lgtm:pipe-ipc-for-staged-implant-communication', 'lgtm:named-pipe-c2-transport', 'lgtm:named-pipe-ipc'].

mitre_secondary formatting: [T1071] — or include T1021.002? I'll keep just [T1071]. Hmm, actually is T1071 right for named-pipe C2? Let me reconsider once more. ATT&CK T1071 Application Layer Protocol — "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server." Named pipes over SMB: SMB is an application-layer protocol in OSI terms, and pipe C2 blends with admin traffic — the LGTM note literally says "blends with Windows administrative traffic and is a documented C2 transport in operational red team tradecraft." T1071 parent is defensible. Confident enough. Keep.

Structure check — exact sections in order. Go.