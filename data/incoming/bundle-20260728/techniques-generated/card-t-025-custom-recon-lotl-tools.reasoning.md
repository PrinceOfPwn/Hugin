Let me analyze the inputs carefully.

The cluster spec assigns:
- T-NNN ID: T-025
- Canonical name: Custom Recon Tooling via LotL API Reimplementation
- Category: discovery
- Tier: A
- would_relate_to: T-023, T-020
- member_notes: ['lgtm:custom-recon-tooling-lotl-reimplementation']

The consolidated description mentions:
- ipconfig via GetAdaptersInfo/GetAdaptersAddresses
- arp via GetIpNetTable
- netstat via GetTcpTable/GetUdpTable
- No child processes, evading command-line monitoring
- Functional equivalence and EDR evasion

Atlas material: atlas-exploit-dev-part18.md, units 28-30:
- Unit 28: Lab 2.6 — Create your own version of ipconfig, optional arguments, colored output
- Unit 29: Lab 2.7 — Create your own version of arp, implement -a and -n arguments
- Unit 30: Lab 2.8 — Create your own version of netstat, implement -a, -n, -t arguments

The atlas material itself is sparse on the actual API details — it's lab descriptions. The consolidated description from the clustering pass names the specific APIs: GetAdaptersInfo/GetAdaptersAddresses (ipconfig), GetIpNetTable (arp), GetTcpTable/GetUdpTable (netstat). These are IP Helper API (iphlpapi.dll) functions — this is well-established Windows documentation, so I can elaborate on them per rule 4 (well-established Windows internals documentation).

No Rust source files were included in the inputs. So per the template:

"**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in <source language/tool>."

Wait — let me check. The vault context mentions `client_rust/src/byakugan.rs` — "Network recon (ARP, TCP, AD enum)". The T-023 card mentions Byakugan does ARP scan, TCP port scan. But no source files were provided in my inputs for this cluster. Rule 8 says "If a `.rs` file is in your inputs..." — no .rs files are in my inputs. The inputs are: cluster spec, T020 card, T023 card, atlas material. So I must write "no current implementation in source."

However, I should be careful: byakugan.rs does ARP scanning — but that's active network reconnaissance (sending ARP requests), not reimplementing the `arp -a` tool via GetIpNetTable (which reads the local ARP cache). These are different. And since the file isn't in my inputs, I can't verify it. So: no current implementation. I can note in Related Techniques that T-023's Byakugan covers active recon as a category but not LotL-reimplementation.

MITRE mapping: This is discovery. Best-fit ATT&CK technique:
- T1016 — System Network Configuration Discovery (ipconfig)
- T1018 — Remote System Discovery (arp -a is commonly mapped here... actually arp -a is often T1018 Remote System Discovery)
- T1049 — System Network Connections Discovery (netstat)

The technique spans three. The primary should be... the card covers ipconfig/arp/netstat reimplementation. The single best-fit — hmm. The cluster spans all three. I'll pick T1016 (System Network Configuration Discovery) as primary since ipconfig is listed first and it's the broadest "network config discovery" — actually, let me think. The technique is really about the *how* (API reimplementation) applied to three discovery utilities. MITRE doesn't have a "reimplement discovery tools via API" technique. The most fitting primary given three tools: T1016 covers ipconfig-like activity. Secondary: T1018, T1049.

Format: `mitre: T1016` and `mitre_secondary: [T1018, T1049]`.

Category: discovery — from the enum. Good.

Tier: A per spec.

Crate: none (no source). source_file: none.

Tags: 5-10 kebab-case: ['lotl-reimplementation', 'iphlpapi', 'recon', 'command-line-evasion', 'no-child-process', 'sysmon-evasion', 'discovery', 'api-equivalence', 'parent-child-correlation-evasion']. Let me pick 7-8 good ones.

Now the body. Minimum 800 words, target 1200-1800.

Let me draft each section.

# Custom Recon Tooling via LotL API Reimplementation — <one-line purpose>

Purpose: rebuilding ipconfig/arp/netstat functionality inside the implant via IP Helper API calls, eliminating child processes and command-line artifacts.

## Summary

3-5 sentences. First sentence standalone.

Something like: "Custom recon tooling via LotL API reimplementation replaces shelling out to system discovery utilities (ipconfig.exe, arp.exe, netstat.exe) with direct calls to the same Win32 APIs those utilities wrap, producing equivalent network configuration data from inside a single implant binary. The technique targets the IP Helper API (iphlpapi.dll): GetAdaptersInfo/GetAdaptersAddresses for interface configuration, GetIpNetTable for the ARP cache, and GetTcpTable/GetUdpTable for socket state. Operators use it to perform host network discovery without spawning child processes, which removes the parent-child process correlation and command-line telemetry that Sysmon Event ID 1 and EDR process-creation callbacks rely on to flag reconnaissance. The primary detection surface shifts from process telemetry to API-call behavior and ETW-based network instrumentation, which is monitored far less consistently."

## Mechanism

Numbered steps. Concrete. Let me structure around the three tools:

1. Operator tasking arrives specifying which discovery function to run (interface config, ARP cache, or connection table) — or the implant exposes subcommand-style arguments mirroring the original tool flags (-a, -n, -t per the labs).

2. ipconfig-equivalent: call GetAdaptersInfo (legacy IPv4) or GetAdaptersAddresses (IPv4+IPv6, Vista+) from iphlpapi.dll. Two-call pattern: first call with NULL buffer to get required size (ERROR_BUFFER_OVERFLOW), allocate, second call populates IP_ADAPTER_INFO / IP_ADAPTER_ADDRESSES linked list. Walk the list via Next pointers, extract adapter name, description, IPv4 address/mask (IpAddressList), gateway, DHCP, DNS (via GetAdaptersAddresses' FirstDnsServerAddress), MAC (PhysicalAddress).

3. arp-equivalent: call GetIpNetTable with the two-call sizing pattern; returns MIB_IPNETTABLE containing MIB_IPNETROW entries: dwAddr (IPv4 address), dwPhysAddr (MAC, dwPhysAddrLen up to 8 bytes), dwIndex (interface index), dwType (entry type: static/dynamic/etc. — MIB_IPNET_TYPE_DYNAMIC etc.). Map interface index to friendly name via GetIfEntry or the adapter list from step 2.

4. netstat-equivalent: call GetTcpTable (MIB_TCPTABLE / MIB_TCPROW: dwLocalAddr, dwLocalPort in network byte order, dwRemoteAddr, dwRemotePort, dwState) and GetUdpTable (MIB_UDPTABLE / MIB_UDPROW). Map dwState values (MIB_TCP_STATE_ESTABLISHED etc.) to the textual state names netstat prints. For -n (numeric), skip name resolution; without -n, resolve via getnameinfo/getaddrinfo. Extended variants GetExtendedTcpTable/GetExtendedUdpTable add owning PID (dwOwningPid), enabling netstat -o / -b equivalents, with PID→process-name resolution via Toolhelp32 or NtQuerySystemInformation.

5. Format results to match (or mirror) the original utility output, and return over the C2 channel. Arguments matching the original flags (-a, -n, -t) can be honored: -a = include listeners (netstat) / all adapters, -n = numeric only, -t = TCP only... actually per the material: Lab 2.7 arp: implement -a and -n; Lab 2.8 netstat: implement -a, -n, -t. And Lab 2.6 ipconfig: optional arguments, colored output. I should note the material describes these as lab deliverables.

6. All of this executes in-process — no CreateProcess, no cmd.exe, no conhost. Note per the material's framing: single implant binary, no child processes.

## OS Internals Context

- iphlpapi.dll is the same library the system utilities use — ipconfig.exe, arp.exe, netstat.exe are thin formatters over these APIs (netstat.exe uses iphlpapi's GetExtendedTcpTable; ipconfig uses GetAdaptersAddresses etc.). So API reimplementation is byte-for-byte equivalent in data, differing only in the calling process.
- The two-call buffer sizing contract: first call returns ERROR_BUFFER_OVERFLOW (Win32) / the needed length in the size parameter. This is the standard IP Helper pattern because table sizes are dynamic.
- Data structures: IP_ADAPTER_INFO linked list with Next pointer; IpAddressList as IP_ADDR_STRING list; IP_ADAPTER_ADDRESSES uses FirstUnicastAddress / FirstDnsServerAddress / FirstGatewayAddress pointer chains rather than embedded lists. MIB_TCPTABLE is a count-prefixed array (dwNumEntries followed by variable-length array of rows — the ANYSIZE_ARRAY pattern).
- Byte order: addresses and ports in the tables are in network byte order — ports require ntohs. This is a common implementation bug source. Established knowledge.
- Kernel/user boundary: GetTcpTable/GetUdpTable under the hood query the TCP/IP driver — on modern Windows the IP Helper APIs issue IOCTLs / use NsiEnumerateObjectsAllParameters against the Network Store Interface (nsi.dll / nsiproxy.sys). I need to be careful about how much I claim here. It is well-established that iphlpapi uses NSI (Network Store Interface) RPC to nsiproxy.sys on Vista+. I can state that at a moderate level — it's documented in reverse engineering literature and Windows Internals covers the network stack architecture (tcpip.sys, NSI). Keep it measured: the tables live in tcpip.sys state; iphlpapi retrieves them via the Network Store Interface service.
- ARP cache: the ARP table is maintained by tcpip.sys; entries have types (dynamic = learned, static = user-set). GetIpNetTable only covers IPv4; IPv6 neighbor cache requires GetIpNetTable2.
- No new kernel objects, handles, or events are created that differ from what the system tools create — the distinction is purely which process makes the call and what the process ancestry looks like.
- Relation to material: the SEC670 labs (Book 2, units 28-30) assign these as bootcamp deliverables within a "Getting to Know Your Target" module — i.e., API-driven host situational awareness is treated as core implant tradecraft.

## Key Implementation Details

No .rs files in inputs → required boilerplate + one paragraph on what an implementation would look like: windows crate / manual FFI to iphlpapi, two-call sizing, OnceLock cache optional, map dwState, byte-order conversion, feature gate. Mention that client_rust/src/byakugan.rs implements active network recon (ARP scanning over the wire) per the vault index, which is a different primitive than reading the local tables — wait, can I say that? The vault index/file manifest is in my system context and says byakugan.rs is "Network recon (ARP, TCP, AD enum)". The T-023 card (provided) says Byakugan: "ARP scan, TCP port scan (batches of 100, 2s timeout), banner grab, AD enumeration, passive discovery". That's an ARP scan — sending probes — not reading GetIpNetTable. But I must be careful not to over-claim about a file I haven't read. I can note in the Related Techniques section that T-023's Byakugan covers active scanning recon, distinct from passive local-table reads. In Key Implementation Details I should keep to the template: no current implementation, then describe what one would look like. I could note byakugan.rs exists but implements active scanning rather than table reads — the T-023 card supports that claim (it lists "ARP scan, TCP port scan... banner grab" — active). Saying "no file in the provided source implements local-table recon" is accurate given no source was provided at all. The template language: "no current implementation in source." I'll say: No current implementation in the HUGIN source. The closest existing module, client_rust/src/byakugan.rs (T-023), performs active network reconnaissance (ARP sweeps, TCP connect scans) rather than local table enumeration via IP Helper API. Then describe implementation sketch.

Hmm — rule: "If the source truly implements it, reference the file. If not, ignore the file and state 'no current implementation in source.'" byakugan wasn't included as a matching source file anyway. So I state no current implementation. Mentioning byakugan as related-but-different is justified via the T-023 card. Fine.

## Why It Matters

- T-023 documents recon capabilities as a suite but does not document the defensive-evasion dimension of reimplementing system utilities in-process. The gap this fills: command-line monitoring and parent-child correlation (Sysmon EID 1, process-creation callbacks, command-line regex detections like "arp -a", "netstat -ano", "ipconfig /all") are the single most commonly detected discovery behaviors; API reimplementation removes that telemetry class entirely while returning identical data. 2-4 sentences.

## Detection Considerations

What does the material say? The atlas material doesn't discuss detection directly; the LGTM note says: "evading parent-child process correlation and command-line logging" and tags include 'sysmon-evasion', 'no-child-process'. The consolidated description says "evading command-line monitoring."

Per rule: "Detection surface the training material describes for this technique" and "If the material does not cover detection for this technique, write: 'Training material does not discuss detection for this technique.' Do not invent detections."

The material (LGTM note) does describe detection-adjacent claims: evades parent-child correlation, command-line logging, Sysmon (tag: sysmon-evasion). So I can structure:

- Telemetry sources: The technique is defined by the telemetry it avoids — Sysmon Event ID 1 process creation (with command line), kernel process-creation callbacks feeding EDR, and PowerShell/cmd logging. The LGTM note frames sysmon-evasion and no-child-process as the operative properties. I can state that Sysmon EID 1 is the telemetry avoided — the note explicitly says "evading parent-child process correlation and command-line logging" and tags sysmon-evasion. Is Sysmon Event ID 1 an invention? The note tags say sysmon-evasion but doesn't name EID 1. Rule 4 says don't fabricate Sysmon event IDs. Hmm. Sysmon Event ID 1 = process creation is extremely well-established — arguably "well-established documentation" (Sysmon is Microsoft-documented). The rule says don't fabricate Sysmon event IDs — EID 1 being process creation is not a fabrication risk; it's definitional. I'll name it carefully: "Sysmon Event ID 1 (process creation, including command line and parent process)". That's safe — it's the documented schema. I think that's within the spirit: don't guess IDs for obscure events; EID 1 is the foundational documented event.

- Bypass options: the technique IS the bypass — in-process API calls produce no process-creation events.
- Residual artifacts: none at the process-telemetry layer. What residual visibility exists: ETW providers for networking... I should be careful not to invent ETW provider GUIDs. I can say the material does not document residual artifacts beyond noting the implant process itself makes the API calls, so detection shifts to in-memory/behavioral analysis of the implant rather than child-process telemetry. Keep honest: "The material does not describe residual artifacts specific to API reimplementation."

Maybe phrase: Telemetry sources section describes what is avoided (per material); note that the material does not document which telemetry, if any, still observes the API calls themselves; residual artifacts: none documented in the material.

## Related Techniques

- T-023 Client Capabilities Suite — Byakugan covers active recon (ARP sweep, port scan, banner grab); T-025 is the complementary passive local-table enumeration; T-023's sysinfo_collect gathers adapter info for HELLO — hmm, sysinfo_collect "Gathers hostname, OS, CPU, RAM, disk, network adapters" — that may overlap ipconfig-style data. But relationship: T-023 documents recon as capability category; T-025 documents the LotL-reimplementation tradecraft as an evasion primitive. 
- T-020 Anti-Analysis Suite — relationship: Kaguya is the inverse tradecraft — it inventories LOtL binaries present on target for later abuse (T1218), whereas T-025 removes the need for those binaries by reimplementing their function via API. Both reduce dependency on suspicious child-process execution. The LGTM note lists T-020 as would_relate_to; justification likely: T-020's Kaguya (LOtL-as-code) is the sibling concept. Good.

## References

- Atlas material: atlas-exploit-dev-part18.md (units 28-30, SEC670 Book 2 labs 2.6-2.8)
- MITRE: T1016 https://attack.mitre.org/techniques/T1016/, T1018, T1049
- LGTM notes: lgtm:custom-recon-tooling-lotl-reimplementation
- Public references: IP Helper API documentation (Microsoft) — that's fine as a named public reference. The material doesn't name tool authors. I could cite Microsoft IP Helper API docs as the public reference for the API contracts. That's not inventing — it's MSDN. Keep minimal.

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.

Word count target 1200-1800 body. Let me write it out carefully.

Frontmatter:
```yaml
---
id: T-025
name: Custom Recon Tooling via LotL API Reimplementation
category: discovery
tier: A
crate: none
source_file: none
mitre: T1016
mitre_secondary: [T1018, T1049]
tags: [lotl-reimplementation, iphlpapi, network-discovery, command-line-evasion, no-child-process, sysmon-evasion, api-equivalence, host-recon]
origin: atlas-synthesis
member_notes: ['lgtm:custom-recon-tooling-lotl-reimplementation']
---
```

Name is 8 words: "Custom Recon Tooling via LotL API Reimplementation" — 8 words. OK (4-8 words).

H1: `# Custom Recon Tooling via LotL API Reimplementation — In-Process Network Discovery Without Child Processes`

Now writing full body. Let me count sections and ensure depth.

Mechanism steps — let me write them concretely:

1. Receive operator tasking selecting the discovery function. The SEC670 labs (Book 2, Labs 2.6-2.8) frame the deliverables as standalone replacements supporting the original tools' flags: ipconfig with optional arguments, arp with -a and -n, netstat with -a, -n, and -t. An implant exposes these as subcommands.

2. Interface configuration (ipconfig equivalent): resolve and call GetAdaptersAddresses (or legacy GetAdaptersInfo) from iphlpapi.dll. First call passes a null buffer; the call returns ERROR_BUFFER_OVERFLOW and writes the required size to the output length parameter. Allocate the buffer, call again to receive a linked list of IP_ADAPTER_ADDRESSES nodes. Walk the Next chain; for each node read AdapterName, Description, PhysicalAddress/PhysicalAddressLength (MAC), FirstUnicastAddress chain (per-address prefix), FirstDnsServerAddress, FirstGatewayAddress, and Flags for DHCP state. GetAdaptersInfo provides the IPv4-only subset (IP_ADAPTER_INFO with embedded IpAddressList of IP_ADDR_STRING).

3. ARP cache (arp equivalent): call GetIpNetTable with the same two-call sizing contract. The returned MIB_IPNETTABLE holds dwNumEntries and an array of MIB_IPNETROW: dwIndex (interface index), dwPhysAddr + dwPhysAddrLen (MAC), dwAddr (IPv4 address of the neighbor), dwType (entry type — dynamic vs static). Resolve dwIndex to an interface via GetIfEntry or by correlating with the adapter list from step 2. This produces the data behind arp -a without touching arp.exe. GetIpNetTable covers IPv4 only.

4. Connection table (netstat equivalent): call GetTcpTable and GetUdpTable. MIB_TCPTABLE rows (MIB_TCPROW) expose dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort; MIB_UDPTABLE rows expose local endpoint only. Ports and addresses are network byte order and must be converted before formatting. Map dwState constants to netstat's state strings (ESTABLISHED, LISTENING, TIME_WAIT, etc.). The -a flag corresponds to including LISTENING rows; -n suppresses name resolution; -t restricts output to TCP.

5. Optional owning-process attribution (netstat -o/-b equivalent): GetExtendedTcpTable/GetExtendedUdpTable with TCP_TABLE_OWNER_PID_ALL / UDP_TABLE_OWNER_PID return dwOwningPid per row; resolve PIDs to image names through the Toolhelp32 snapshot APIs or NtQuerySystemInformation(SystemProcessInformation). Requires the same or higher integrity as target processes for full visibility. Hmm — careful: is that documented? GetExtendedTcpTable with owner PID classes is well-established MSDN. Fine.

6. Format and return results over the implant's existing C2 channel. The labs permit cosmetic deviation (colored output); an implant typically returns structured data instead of mimicking console text.

All steps execute inside the implant process: no CreateProcess, no cmd.exe /c, no PowerShell, no conhost.exe allocation.

OS Internals Context:

- Same library, same data: ipconfig.exe, arp.exe, netstat.exe are console formatters over iphlpapi.dll. netstat.exe calls the GetExtendedTcpTable family; ipconfig.exe calls GetAdaptersAddresses. An implant calling the same exports receives the same rows the tools would print. The tradecraft distinction is which process image makes the call and what ancestry that process has.
- Buffer sizing contract: IP Helper enumeration APIs follow a two-call pattern because table cardinality is dynamic. First call with insufficient buffer → ERROR_BUFFER_OVERFLOW with required length written back; caller allocates and recalls. ERROR_INSUFFICIENT_BUFFER variants for some. Keep accurate: GetAdaptersAddresses returns ERROR_BUFFER_OVERFLOW. GetTcpTable returns ERROR_INSUFFICIENT_BUFFER. Both are the same pattern.
- Structures: IP_ADAPTER_ADDRESSES uses pointer-chain first-node fields (FirstUnicastAddress, FirstPrefix, FirstDnsServerAddress, FirstGatewayAddress) in contrast to the older IP_ADAPTER_INFO embedded IP_ADDR_STRING list — this is why the legacy API cannot express IPv6 or per-address prefixes. MIB_TCPTABLE is a count-prefixed variable array (dwNumEntries + table[ANYSIZE_ARRAY]) requiring the caller to index rows manually.
- Kernel side: the tables are maintained by the TCP/IP driver (tcpip.sys). On Vista and later, iphlpapi retrieval goes through the Network Store Interface (NSI — nsiproxy.sys kernel provider, nsi.dll user-mode RPC client): the API issues enumerate-parameters requests against the NSI object store rather than reading raw driver memory. Net consequence for the operator: the data is authoritative kernel state, identical to what the system tools display, and the calls themselves are the same ones made constantly by legitimate software. I'll keep this measured — this is documented in Windows Internals (network stack) and public reverse engineering of nsi. It's "well-established Windows internals documentation" — acceptable.
- Byte order: row fields are network byte order; ports need ntohs before display — a frequent defect in first-pass reimplementations but invisible in output once handled.
- ARP cache scope: GetIpNetTable enumerates the IPv4 neighbor cache only (dwType distinguishes MIB_IPNET_TYPE_DYNAMIC from MIB_IPNET_TYPE_STATIC and invalid entries); IPv6 neighbors require GetIpNetTable2 — matters on IPv6-heavy targets where arp-equivalent output would otherwise silently omit neighbors.
- Versioning: GetAdaptersAddresses exists since XP... actually GetAdaptersAddresses is XP+ (IPv6 support added Vista). GetTcpTable is legacy (Win2K-era iphlpapi). The owner-PID extended tables are XP SP2+/Vista+. Keep it general: the extended-table owner-PID classes require Windows XP SP2/Vista-era or later; all are universal on modern targets. Actually GetExtendedTcpTable is available on XP SP2+ per MSDN. Fine to state.

Key Implementation Details:

Required text + paragraph sketch + byakugan note.

"**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C/C++ (SEC670 Labs 2.6-2.8 eWorkbook deliverables)."

Then: An implementation would bind iphlpapi.dll exports via the windows crate or manual FFI (GetAdaptersAddresses, GetIpNetTable, GetExtendedTcpTable, GetExtendedUdpTable), apply the two-call sizing pattern with a heap buffer, walk the structures, convert byte order, and serialize rows into the protocol's recon message types. Optionally resolve iphlpapi exports dynamically at runtime (rather than importing them) to keep the IAT clean, consistent with the vault's IAT-camouflage concerns in T-020. The closest existing module is client_rust/src/byakugan.rs (T-023), which performs active reconnaissance — ARP sweeps and TCP connect scans — rather than passive local-table enumeration; it does not call the IP Helper table APIs.

Hmm — do I know byakugan doesn't call GetIpNetTable? I haven't read it. Safer: "which implements active reconnaissance (ARP scan, TCP port scan, banner grab per T-023) — an on-the-wire primitive distinct from reading local tables; no provided source implements the table-read approach documented here." That's honest.

Why It Matters (2-4 sentences):

Discovery via system utilities is one of the most reliably alerted behaviors in an intrusion: `ipconfig /all`, `arp -a`, and `netstat -ano` appear in standard detection content as command-line and parent-child analytics. Reimplementing them in-process removes the entire telemetry class while returning identical data, which is why SEC670 teaches the rewrites as dedicated labs. T-023 catalogs recon capabilities but documents them as features; this card captures the LotL-reimplementation tradecraft as its own defensive-evasion primitive, orthogonal to what data is collected.

Detection Considerations:

- Telemetry sources: The material frames the technique by the telemetry it avoids: process-creation events carrying command lines and parent/child relationships (Sysmon Event ID 1; EDR kernel process-notify callbacks), plus script-host logging when cmd.exe or PowerShell proxies the tools. The cluster note names parent-child correlation and command-line logging as the defeated controls and tags the technique sysmon-evasion.
- Bypass options: The reimplementation is itself the bypass — no additional reduction is described in the material. The API calls originate from the implant process, which blends with ordinary iphlpapi usage by legitimate networking software. (Careful — "blends" claim is mild and reasonable; the note says "API-based approach provides functional equivalence and EDR evasion; reduces operational footprint." OK.)
- Residual artifacts: The material does not document residual artifacts specific to this technique. In-process enumeration leaves no new files, registry keys, or child processes; the calls produce no process or command-line telemetry of their own. Do not invent more.

Related Techniques:

- T-023 Client Capabilities Suite — documents recon as an operator capability (Byakugan active scanning, sysinfo collection); T-025 is the passive, in-process complement for the specific data those system utilities expose, and the cluster note explicitly links the two. 
- T-020 Anti-Analysis Suite — Kaguya inventories LOtL binaries on target for later abuse (T1218); T-025 applies the inverse of that idea, removing the need to execute those binaries at all by calling the same underlying APIs. Both reduce dependence on suspicious child processes.

References:

- Atlas material: atlas-exploit-dev-part18.md (units 28-30 — SEC670 Book 2 "Getting to Know Your Target", Labs 2.6 Ipconfig, 2.7 Arp, 2.8 Netstat)
- MITRE ATT&CK: T1016 System Network Configuration Discovery (https://attack.mitre.org/techniques/T1016/); secondary T1018 Remote System Discovery (https://attack.mitre.org/techniques/T1018/), T1049 System Network Connections Discovery (https://attack.mitre.org/techniques/T1049/)
- LGTM notes: lgtm:custom-recon-tooling-lotl-reimplementation
- Public references: Microsoft IP Helper API documentation (iphlpapi.dll: GetAdaptersAddresses, GetIpNetTable, GetTcpTable/GetExtendedTcpTable, GetUdpTable/GetExtendedUdpTable)

Source Reference:

"No current implementation. See atlas material (SEC670 Labs 2.6-2.8) and MITRE references for public tooling; nearest adjacent module is client_rust/src/byakugan.rs (active recon, T-023), which does not implement local-table enumeration."

Hmm, the template says: `<If no source: "No current implementation. See atlas material and MITRE reference for public tooling.">` — I'll follow closely with the byakugan note appended... Actually keep it tight: follow template text, optionally one clause. I'll add the byakugan clarification since it prevents future misattribution.

Check banned words: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable. Avoid "interesting" phrasing. Avoid "essentially", "at its core", "worth noting", "the key insight". I used "keep the IAT clean" — "clean" is banned. Rephrase: "to reduce IAT signature surface" or "to keep imported symbols minimal". Avoid "notably". Fine.

Word count: aiming 1200-1600. Let me write final.

Also rule: first sentence of Summary complete and standalone. 

Also — category enum includes `discovery` — good. Tier A. Crate none. source_file: none (exactly "none").

mitre_secondary format: `[T1018, T1049]` — per template `[<additional ATT&CK IDs...>]`.

One more check on the frontmatter `name`: template says "Human Readable Name — 4-8 words". "Custom Recon Tooling via LotL API Reimplementation" = Custom(1) Recon(2) Tooling(3) via(4) LotL(5) API(6) Reimplementation(7) — 7 words. Good.

Tags 5-10: I'll use 8.

Now write the final card. Ensure no first person, no rhetorical questions, no exclamation marks. Ensure sections exactly as required and ordered. Minimum 800 words body — I'll be well above.

Mechanism step detail on flags: The labs specify: ipconfig — "can add optional arguments, can make it fancy with colored output"; arp — implement -a and -n; netstat — implement -a, -n, -t. I map: arp -a displays all entries (that IS the display flag on Windows arp; -a is display on Windows... actually on Windows `arp -a` displays current ARP entries; `-N if_addr` shows entries for an interface — the lab says "-a and -n"? Windows arp doesn't have -n... Linux arp has -n (numeric). The lab may be generic. I'll just report what the material says: "Implement arguments like -a and -n" without asserting semantics for arp -n beyond "numeric output" as commonly understood. For netstat: -a (all connections and listening ports), -n (numeric), -t? Windows netstat has no -t... hmm, Linux netstat -t = TCP. The material lists them; SEC670 likely wants TCP-filter. I'll present them as the lab's required flags and map semantics generically: -a include listeners, -n numeric, -t TCP-only — stating "as assigned in the lab" framing. To stay safe: "the lab text lists -a, -n, and -t as required arguments; -a corresponds to including listening sockets, -n to suppressing name resolution, and -t to restricting output to TCP" — this maps to the conventional meaning of those flags on Unix-style netstat and matches what a reimplementation would do. I think it's fine; these are well-established flag semantics.

For arp -a/-n: -a display all current entries (Windows arp uses -a to display; -N for interface). -n numeric (don't resolve names — though arp cache has no names; on Linux arp -n shows numeric IPs instead of hostnames). I'll keep light: "display entries (-a) and numeric output (-n)".

Now, OS Internals — NSI claims: I'll write: "On Windows Vista and later, the IP Helper table functions do not read tcpip.sys memory directly; they proxy through the Network Store Interface (NSI): user-mode nsi.dll issues RPC requests that the kernel provider nsiproxy.sys services against the network stack's object store." This is documented in public reverse-engineering and consistent with Windows Internals' description of the network stack. Keep to 1-2 sentences.

Also mention: because these APIs are called constantly by legitimate software (browsers, VPN clients, ipconfig itself, network management agents), call-volume heuristics on iphlpapi are weak signals — is that inventing detection? It's a mild general statement, arguably descriptive. I'll phrase carefully in Detection as context rather than a claimed detection gap. Actually safer to put in OS Internals as "the calls are the same ones made by legitimate network management software" — factual.

Length check — I'll draft and count roughly. Target ~1400 words body.

Draft:

Summary (~150 words), Mechanism (~500), OS Internals (~450), Key Impl (~180), Why (~110), Detection (~180), Related (~90), References/Source (~80). Total ~1740. Good.

Write it now, carefully avoiding banned terms.