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

# Custom Recon Tooling via LotL API Reimplementation — In-Process Network Discovery Without Child Processes

## Summary

Custom recon tooling via LotL API reimplementation replaces shelling out to system discovery utilities (ipconfig.exe, arp.exe, netstat.exe) with direct calls to the same Win32 APIs those utilities wrap, returning equivalent network configuration data from inside a single implant binary. The technique targets the IP Helper API in iphlpapi.dll: GetAdaptersInfo/GetAdaptersAddresses for interface configuration, GetIpNetTable for the ARP cache, and GetTcpTable/GetUdpTable for connection state. Operators use it to perform host network discovery without spawning child processes, which removes the parent-child process correlation and command-line telemetry that process-creation logging relies on to flag reconnaissance. SEC670 teaches this as dedicated lab work (Labs 2.6-2.8), treating API-equivalent rewrites of the standard utilities as core implant tradecraft. The primary detection surface shifts from process telemetry — which the technique avoids entirely — to behavioral analysis of the implant process itself.

## Mechanism

1. Receive operator tasking selecting the discovery function. The SEC670 Book 2 labs frame the deliverables as standalone replacements honoring the original tools' flags: an ipconfig replacement with optional arguments (Lab 2.6), an arp replacement implementing -a and -n (Lab 2.7), and a netstat replacement implementing -a, -n, and -t (Lab 2.8). An implant exposes these as subcommands against one binary.

2. Interface configuration (ipconfig equivalent): call GetAdaptersAddresses from iphlpapi.dll, or the legacy IPv4-only GetAdaptersInfo. These follow the two-call sizing contract: the first call passes a null or undersized buffer, fails with ERROR_BUFFER_OVERFLOW, and writes the required byte count to the length parameter; the caller allocates and calls again. The result is a linked list of IP_ADAPTER_ADDRESSES nodes walked via the Next pointer. Per node, read AdapterName, Description, PhysicalAddress with PhysicalAddressLength (MAC), and the FirstUnicastAddress, FirstDnsServerAddress, and FirstGatewayAddress pointer chains. GetAdaptersInfo instead returns IP_ADAPTER_INFO nodes with an embedded IpAddressList of IP_ADDR_STRING records covering IPv4 address, mask, and gateway.

3. ARP cache (arp equivalent): call GetIpNetTable under the same two-call pattern. The returned MIB_IPNETTABLE carries dwNumEntries and an array of MIB_IPNETROW records: dwIndex (interface index), dwPhysAddr with dwPhysAddrLen (neighbor MAC), dwAddr (neighbor IPv4 address), and dwType (entry classification — dynamic versus static). Correlate dwIndex against the adapter list from step 2 or resolve it via GetIfEntry to produce interface-attributed output matching arp -a. The -n flag corresponds to suppressing any name resolution and printing numeric addresses only.

4. Connection table (netstat equivalent): call GetTcpTable and GetUdpTable. MIB_TCPTABLE rows (MIB_TCPROW) expose dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, and dwRemotePort; MIB_UDPTABLE rows (MIB_UDPROW) expose the local endpoint only. Map dwState constants to netstat's state strings (LISTENING, ESTABLISHED, TIME_WAIT, and the rest of the TCP state machine). The lab's required flags map directly: -a includes listening sockets, -n suppresses name resolution, and -t restricts output to TCP.

5. Optional owning-process attribution (netstat -o/-b equivalent): substitute GetExtendedTcpTable and GetExtendedUdpTable with the owner-PID table classes (TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID). Each row then carries dwOwningPid; resolve PIDs to image names through a Toolhelp32 snapshot or NtQuerySystemInformation(SystemProcessInformation).

6. Format the rows and return them over the implant's existing C2 channel. The labs permit cosmetic deviation from the original tools (colored output); an implant returns structured data. Every step executes in-process: no CreateProcess, no cmd.exe intermediary, no console host allocation, and no command line exists to log.

## OS Internals Context

The system utilities are console formatters over iphlpapi.dll. netstat.exe calls the GetExtendedTcpTable family; ipconfig.exe calls GetAdaptersAddresses. An implant invoking the same exports receives the same rows the tools would print — the only difference is which process image makes the call and what ancestry that process has in the process tree. This is the property the tradecraft exploits: the data is authoritative kernel state, and the calls are identical to those made constantly by legitimate network management software.

The tables themselves are maintained by the TCP/IP driver (tcpip.sys). On Windows Vista and later, the IP Helper table functions do not read driver memory directly; they proxy through the Network Store Interface, where user-mode nsi.dll issues requests serviced by the kernel provider nsiproxy.sys against the network stack's object store. The operator consequence is that table reads are ordinary, high-frequency system activity with no privileged handle requirements for the basic variants.

Two structural details matter for a correct reimplementation. First, the buffer contract: table cardinality is dynamic, so all enumeration functions use the fail-then-size-then-fill pattern — GetAdaptersAddresses signals with ERROR_BUFFER_OVERFLOW, the table functions with ERROR_INSUFFICIENT_BUFFER, and both write the required length back through the size parameter. Second, structure layout differs between generations: IP_ADAPTER_ADDRESSES uses first-node pointer chains (FirstUnicastAddress, FirstPrefix, FirstDnsServerAddress, FirstGatewayAddress), which is why the legacy IP_ADAPTER_INFO with its embedded IP_ADDR_STRING list cannot express IPv6 or per-address prefixes. MIB_TCPTABLE is a count-prefixed variable-length array (dwNumEntries followed by rows), requiring manual row indexing.

Row fields are in network byte order; ports require conversion before formatting, and failing to do so is the most common defect in first-pass rewrites, though it is invisible once handled. Scope limits also matter: GetIpNetTable enumerates only the IPv4 neighbor cache, with dwType distinguishing dynamic entries from static ones; IPv6 neighbors require GetIpNetTable2, which matters on IPv6-heavy targets where the ARP-equivalent output would otherwise silently omit neighbors. The owner-PID extended table classes require Windows XP SP2 or later and are universal on modern targets. The technique creates no new kernel objects, no handles visible to other processes, and no events — the kernel sees ordinary enumeration traffic from an unremarkable caller.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C/C++ as the SEC670 Labs 2.6-2.8 eWorkbook deliverables.

An implementation would bind iphlpapi.dll exports (GetAdaptersAddresses, GetIpNetTable, GetExtendedTcpTable, GetExtendedUdpTable) through the windows crate or manual FFI, apply the two-call sizing pattern with a heap-allocated buffer, walk the result structures with byte-order conversion, and serialize rows into the protocol's recon message types. Resolving the exports dynamically at runtime rather than importing them keeps the implant's IAT surface minimal, consistent with the import-signature concerns documented in T-020. The nearest adjacent module is client_rust/src/byakugan.rs (T-023), which implements active reconnaissance — ARP sweeps, TCP connect scans, banner grabs — an on-the-wire primitive distinct from reading local tables; no provided source implements the table-read approach this card documents.

## Why It Matters

Discovery through system utilities is among the most reliably alerted behaviors in an intrusion: ipconfig /all, arp -a, and netstat -ano appear in standard detection content as command-line analytics and parent-child correlations. Reimplementing them in-process removes that entire telemetry class while returning identical data, which is why SEC670 assigns the rewrites as dedicated labs. T-023 catalogs reconnaissance capabilities as operator features but does not document reimplemented-LotL tooling as a defensive-evasion primitive in its own right; this card captures the tradecraft separately because the evasion property is orthogonal to what data is collected.

## Detection Considerations

- **Telemetry sources**: The material defines the technique by the telemetry it avoids — process-creation events carrying command lines and parent/child relationships (Sysmon Event ID 1; EDR kernel process-notify callbacks), plus any script-host logging when cmd.exe or PowerShell would otherwise proxy the utilities. The cluster note names parent-child correlation and command-line logging as the defeated controls and tags the technique as Sysmon evasion with no child process.
- **Bypass options**: The reimplementation is itself the bypass; the material describes no additional observability reduction. Because enumeration executes inside the implant process, no process or command-line telemetry specific to the discovery action is generated, and the API calls match those made by legitimate networking software.
- **Residual artifacts**: The material does not document residual artifacts specific to this technique. In-process enumeration creates no files, registry keys, or child processes; residual visibility is limited to whatever instrumentation already observes the implant process itself.

## Related Techniques

- **T-023 Client Capabilities Suite** — documents reconnaissance as an operator capability (Byakugan active scanning, sysinfo collection for the HELLO message); T-025 is the passive, in-process complement that produces the system utilities' data without executing them.
- **T-020 Anti-Analysis Suite** — its Kaguya module inventories LOtL binaries present on a target for later abuse; T-025 applies the inverse of that idea, removing the need to execute such binaries at all by calling the same underlying APIs directly.

## References

- Atlas material: atlas-exploit-dev-part18.md (units 28-30 — SEC670 Book 2 "Getting to Know Your Target", Labs 2.6 Ipconfig, 2.7 Arp, 2.8 Netstat)
- MITRE ATT&CK: T1016 System Network Configuration Discovery (https://attack.mitre.org/techniques/T1016/); secondary T1018 Remote System Discovery (https://attack.mitre.org/techniques/T1018/), T1049 System Network Connections Discovery (https://attack.mitre.org/techniques/T1049/)
- LGTM notes: lgtm:custom-recon-tooling-lotl-reimplementation
- Public references: Microsoft IP Helper API documentation (iphlpapi.dll: GetAdaptersAddresses, GetIpNetTable, GetTcpTable/GetExtendedTcpTable, GetUdpTable/GetExtendedUdpTable)

## Source Reference

No current implementation. See atlas material and MITRE references for public tooling. Nearest adjacent module: client_rust/src/byakugan.rs (active recon, T-023), which does not implement local-table enumeration.