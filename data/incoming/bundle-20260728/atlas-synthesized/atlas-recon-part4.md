# Atlas Material — recon (part 4)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: recon
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: PowerShell, Get-DomainPolicyData, MinimumPasswordAge, MaximumPasswordAge
Summary: The unit contains a visual caption describing a PowerShell command used to retrieve domain policy information, specifically focusing on account password age limits.
Excerpt:
Visual caption: A screenshot of a PowerShell command and its output showing domain policy information. Visible text: Get-DomainPolicyData; MinimumPasswordAge; MaximumPasswordAge Alt/source label:

=== UNIT 2 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Nmap, NSE, -sV, -sc, service versioning
Summary: The unit contains a screenshot of an Nmap scan output showing service versions and NSE script results across multiple ports. It identifies key fields such as port state, method, and script results.
Excerpt:
Visual caption: A screenshot of a terminal showing the output of Nmap's -sV and -sC scripts to identify service versions and default script results for various ports. Visible text: Nmap Script Engine (NSE); Service Version; Port; State; Method; Last Modified; Script Results Alt/source label:

=== UNIT 3 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: nmap, port discovery, service version, OS fingerprinting, -sV, -O, -sC, -A
Summary: The unit contains a tutorial on using the nmap command-line tool for network scanning and port discovery. It provides specific command examples for various scan types including service version detection, OS fingerprinting, and script execution.
Excerpt:
Visual caption: A webpage showing a tutorial on how to use the 'nmap' command-line tool for network scanning and port discovery. Visible text: nmap -sT -p1-65535,tcp,udp -Pn -oN scan.txt; nmap -sV -O -p1-65535,tcp,udp -Pn -oN scan.txt; nmap -sC -p1-65535,tcp,udp -Pn -oN -r -v; nmap -A -p1-65535,tcp,udp -Pn -oN -r -v Alt/source label:

=== UNIT 4 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Network Topology Diagram, Fire_rules, Port Scanning, IDS, Vulnerability Assessment
Summary: The unit contains a visual caption describing a technical documentation page or tutorial related to network security. It lists several key components such as firewall rules, port scanning, and IDS.
Excerpt:
Visual caption: A screenshot of a technical documentation page or tutorial, likely related to cybersecurity or network security, featuring several sections with code blocks and text descriptions. Visible text: Network Topology Diagram; Security Analysis; Firewall Rules; Port Scanning; Intrusion Detection System (IDS); Packet Capture; Vulnerability Assessment; A Network Security Tutorial; Cybersecurity Training Module; System Configuration; Monitoring Tools Alt/source label:

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Process Monitor, SEC701, Red Teaming Tools, What's the Point?
Summary: The unit describes the purpose and utility of using Process Monitor (ProcMon) for analyzing system behavior. It is part of a SANS Institute course on red teaming tools and developing Windows implants.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'What's the Point?' explaining the purpose of using Process Monitor. Visible text: What's the Point?; SEC701: Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: DLL analysis, PE file structure, Dumpbin, PE-bear, PEview, CFF Explorer, WinDbg
Summary: The text describes various tools for analyzing the internal structure of DLL and PE files, including Dumpbin, PEview, PE-bear, CFF Explorer, and WinDbg. It highlights specific features of these tools and mentions that Dumpbin and PE-bear will be used in the course.
Excerpt:
Dynamic-linked Libraries (3) There are a few tools available today that let you look at what is inside of a DLL. The tools do not just parse the structure of DLL files, but they can parse almost any type of PE file you throw at it. The dumpbin utility is a command-line tool that is typically available with a standard installation of Visual Studio. PEview is a GUI application with the bare necessities for viewing the file’s structure. The headers are easily identified allowing for simple navigation through them. PE-bear is a rich GUI application that is full of great features. You can load several PE files at the same time and manually browse the file of interest. Tabs organize the structure 

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: OS Information, Process Enumeration, CreateToolhelp, WTSEnum, FileFinder, Service Packs
Summary: The unit describes a curriculum roadmap for gathering operating system information, including service packs, hotfixes, patches, and process enumeration. It lists specific labs related to tool development for identifying installed software, directory walks, user information, and network details.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 101 In this module, we will discuss how to enumerate services and tasks during the e

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: Windows services, understanding differences between services and processes, Windows Tasks enumeration
Summary: The unit outlines the learning objectives for a module on Windows services, processes, and tasks. It specifies goals to understand these components and learn how to enumerate them.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Understand Windows services Compare services and processes Understand Windows Tasks Discuss how to enumerate services and tasks 102 Objectives The objectives for this module are to understand what a Windows service is, compare services and processes, understand what Windows Tasks are, and how to enumerate them all. 102 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: service enumeration, target purpose, vulnerability identification, AV/EDR detection
Summary: This unit discusses the importance of awareness and purpose in service enumeration during a red team operation. It explains how identifying specific services (like DHCP, DNS, FTP) can reveal a target's role and help identify potential vulnerabilities or security software like AV/EDR.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Service Enumeration Why enumerate services? Why enumerate services? Awareness Awareness Purpose Purpose The better awareness you have the more successful your operation. Detect services that could be vulnerable or ones that could belong to AV/EDR. The purpose of a target will determine how it is most likely being used. It could also indicate if the target is high visibility or low. 104 Service Enumeration We typically conduct service enumeration for similar reasons that we conduct process enumeration. Services, just like processes, can tell us what a target’s purpose is or how it is being used. Certain se

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: GetNativeSystemInfo, SYSTEM_INFO struct, WoW64, x64, wProcessorArchitecture
Summary: The unit describes the GetNativeSystemInfo API, detailing its purpose for gathering system information in WoW64 and x64 environments. It explains the function's VOID return type and the use of an out-parameter structure (SYSTEM_INFO) to receive data. The text also lists specific architecture values for the wProcessorArchitecture field.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control GetNativeSystemInfo GetNativeSystemInfo GetNativeSystemInfo Gathers current system information Gathers current system information VOID GetNativeSystemInfo( _Out_ LPSYSTEM_INFO lpSystemInfo ); typedef struct _SYSTEM_INFO { [..SNIP..] DWORD dwPageSize; LPVOID lpMinimumApplicationAddress; LPVOID lpMaximumApplicationAddress; DWORD_PTR dwActiveProcessorMask; DWORD dwNumberOfProcessors; DWORD dwProcessorType; DWORD dwAllocationGranularity; WORD wProcessorLevel; WORD wProcessorRevision; } SYSTEM_INFO, *LPSYSTEM_INFO; Has VOID return type Has VOID return type 10 GetNativeSystemInfo The GetNativeSystemInfo API can

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: GetInterfaceInfo, IPv4 enabled devices, IPHLPAPI_DLL_LINKAGE, ERROR_INSUFFICIENT_BUFFER, network adapters
Summary: The text describes the GetInterfaceInfo API function used to retrieve a list of IPv4-enabled network interfaces on a target system. It details the structure of the purpose and parameters (pIfTable, dwOutBufLen) and lists potential error codes for failed calls.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control GetInterfaceInfo API GetInterfaceInfo() GetInterfaceInfo() Gets list of IPv4 enabled devices Gets list of IPv4 enabled devices IPHLPAPI_DLL_LINKAGE DWORD GetInterfaceInfo( _Out_ PIP_INTERFACE_INFO pIfTable, _Inout_ PULONG dwOutBufLen ); typedef struct _IP_INTERFACE_INFO { LONG NumAdapters; IP_ADAPTER_INDEX_MAP Adapter[1]; } IP_INTERFACE_INFO, *PIP_INTERFACE_INFO; Has DWORD return type Has DWORD return type 119 GetInterfaceInfo API The GetInterfaceInfo function can be used to gather a list of interfaces on the target that have IPv4 enabled. As you can see by the SAL annotations, the function has two parame

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: GetAdapterAddresses, IPv4/IPv6, IPHLPAPI_DLL_LINKAGE, PIP_ADAPTER_ADDRESSES
Summary: The unit describes the GetAdapterAddresses API function for identifying IP addresses associated with network adapters. It details specific parameters such as Family, Flags, and AdapterAddresses to support both IPv4 and IPv6. The text provides technical specifications of the buffer types and return values.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control GetAdapterAddresses API GetAdapterAddresses() GetAdapterAddresses() Grabs the addresses tied to the adapters Grabs the addresses tied to the adapters IPHLPAPI_DLL_LINKAGE ULONG GetAdaptersAddresses( _In_ ULONG Family, _In_ ULONG Flags, _In_ PVOID Reserved, _Inout_ PIP_ADAPTER_ADDRESSES AdapterAddresses, _Inout_ PULONG SizePointer ); Has ULONG return type Has ULONG return type 122 GetAdapterAddresses API The GetAdapterAddresses can be used when you need to find out what adapters have what IP address. The function is great because not only can it do IPv4, but it can do IPv6 as well. GetAdapterAddresses has 

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: NIC configuration, network information gathering, tool development foundations
Summary: The unit describes the importance and methods for gathering information about a target's network interface card (NIC) configuration and general network environment. It highlights how this data serves as a foundation for developing custom tools like arp, ipconfig, and netstat.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed how to gather information about the network Discussed how to gather information about the network Discussed how to gather NIC information about the target Discussed how to gather NIC information about the target 125 Module Summary In this module, we discussed the why and how of gathering information about a target’s NIC configuration, as well as any other information we can gather about the network overall. The information presented in this module can be the foundations for creating tools like arp, ipconfig, netstat, etc. 125 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a 

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: OS Information, Process Enumeration, WTSEnum, FileFinder, Widget Tool Development
Summary: The unit describes a course roadmap for gathering operating system information, including service packs, process enumeration, installed software, and network information. It also lists the contents of the user's section on Windows tool development and getting to know your target.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 130 This module will discuss how to enumerate the Windows Registry to find critical 

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: Windows Registry, survey tool, security research, privilege levels
Summary: The text discusses the importance of the Windows Registry as a source of information for survey tools. It highlights that while some sections require administrative privileges, much useful data can still be collected by basic users.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Registry Information Troves of information Troves of information The Windows Registry contains troves of information that can arguably be deemed critical to your survey tool. The registry is so important that even the system itself relies on information found in the registry. 132 Registry Information The registry was discussed in tremendous detail during Section 1, along with the APIs needed to enumerate practically everything in it. It is being included here during this day as a brief reminder that it should not be forgotten about when conducting your survey. The registry is an excellent source for colle

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: Windows Registry, registry API family, hives, subkeys, values, registry virtualization, 32-bit/64-bit
Summary: The unit describes the Windows Registry as a primary storage location for application information and system configurations. It explains the structure of registry hives (HKEY_USERS, HKEY_LOCAL_MACHINE) and the concept of registry virtualization for 32-bit applications on 64-bit systems.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (1) The registry API family provides most functionality for registry interaction. The registry API family provides most functionality for registry interaction. It is has become the go-to location for developers for storing application information. It is has become the go-to location for developers for storing application information. The Registry is a collection of five hives where each one exposes information, some critical to the functionality of the OS. The hives have keys, which then have subkeys with values that applications or services might need to query. 133 The Registry (1) If you ar

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: Registry access timing, Boot Configuration Database (BCD), user profile settings, application startup configurations, AV product behavior
Summary: The unit describes the timing and purpose of registry access during various stages of boot, logon, and application startup. It highlights how different components like the Boot Configuration Database (BCD) and user profiles are managed via the Registry. Additionally, it mentions that some applications or security products may use the registry for configuration storage or frequent polling.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (2) The Registry holds configuration data that is read during four critical times. The Registry holds configuration data that is read during four critical times. Initial boot process Initial boot process Kernel boot process Kernel boot process Logon process Logon process Application startup Application startup These are not the only times that the registry is read. New application installations trigger registry access and some applications constantly poll the registry for changes for live updates. These are not the only times that the registry is read. New application installations trigger re

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: HKEY_USER (HKU), ProfileList, Security Identifier (SID), Winlogon process, user enumeration
Summary: The text describes the structure and contents of the HKEY_USER (HKU) registry hive, specifically focusing on user profile information. It explains how HKU contains subkeys for each local user and the system account, including a default profile used by Winlogon. It also identifies the ProfileList key as a source for enumerating user profiles via their Security Identifiers (SIDs).
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (4) Deep dive: HKEY_USER (HKU) Deep dive: HKEY_USER (HKU) ProfilesDirectory ProfilesDirectory The HKU key will hold a subkey (HKCU) for each user profile on the local system. There is also a profile for the system that has its own subkey, HKU\.Default. Winlogon uses the system profile to determine various settings like the desktop background. ProfileList ProfileList 136 The Registry (4) The HKU key holds a wealth of user information. In fact, it holds user information for every user that has logged on to the local machine, as long as the user does not have a roaming profile with Active Direct

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: HKEY_CURRENT_USER, HKCU, Ntuser.dat, user-specific configuration, subkeys: console, software, control panel
Summary: This unit provides a technical overview of the HKEY_CURRENT_USER (HKCU) registry hive, detailing its purpose for storing user-specific configurations and preferences. It describes the location of the Ntuser.dat file and lists common subkeys such as Console, Software, and Control Panel. The text also mentions that service processes running under a specific user's context will load their respective HKCU.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (5) Deep dive: HKEY_CURRENT_USER (HKCU)* Deep dive: HKEY_CURRENT_USER (HKCU)* Created for each new login Created for each new login This root key holds configuration information for the locally logged-on user regarding software configuration information and user preferences. They key points to the user profile, which is located at \Users\<username>\Ntuser.dat. Subkey under HKU Subkey under HKU Subkeys: console, software, control panel, identities, printers, keyboard layout, etc. Subkeys: console, software, control panel, identities, printers, keyboard layout, etc. 137 The Registry (5) The HKC

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: HKEY_CLASSES_ROOT, HKCR, file extension associations, COM class registrations, HKCU\SOFTWARE\Classes, HKLMSOFTWARE\Classes
Summary: The unit describes the structure and purpose of the HKEY_CLASSES_ROOT (HKCR) registry key, specifically its composition from HKCU&HKEY_LMSOFTWARE&Classes. It explains how this key is used for file extension associations and COM class registrations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (6) Deep dive: HKEY_CLASSES_ROOT (HKCR)* Deep dive: HKEY_CLASSES_ROOT (HKCR)* HKCU\SOFTWARE\Classes HKCU\SOFTWARE\Classes This root key holds three types of information: file extension associations, COM class registrations, and virtualized registry root for the UAC. Every registered file extension will have its own key that is typically the REG_SZ value type. Sometimes they simply point to another key that holds the needed information. HKLM\SOFTWARE\Classes HKLM\SOFTWARE\Classes The combination of the above Classes keys make this root key. The combination of the above Classes keys make this r

=== UNIT 21 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: HKLM root key, Boot Configuration Data (BCD), Component Based Servicing (CBS), SAM account passwords, SECURITY policy keys
Summary: This unit provides a detailed overview of the HKEY_LOCAL_MACHINE (HKLM) registry hive, specifically focusing on subkeys like BCD, COMPONENTS, HARDWARE, SAM, SECURITY, and SOFTWARE. It describes the contents and significance of each subkey, such as boot configuration data, component-based servicing information, and user passwords stored in the SAM key.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (7) Deep dive: HKEY_LOCAL_MACHINE (HKLM) Deep dive: HKEY_LOCAL_MACHINE (HKLM) BCD: boot entries BCD: boot entries This root key holds vital information for the system. Some of the critical information like how the system boots is stored here. Other information is stored here, like systemwide software configurations, installed components, user passwords, and boot entries to name a few. SAM: account passwords SAM: account passwords 139 The Registry (7) The HKLM key is the root key that holds all systemwide configuration subkeys. • BCD00000000 • COMPONENTS • HARDWARE • SAM • SECURITY • SOFTWARE 

=== UNIT 22 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: HKEY_CURRENT_CONFIG, HKCC, hardware profile, backwards compatibility
Summary: The unit describes the HKEY_CURRENT_CONFIG (HKCC) registry key, explaining its role as a link to hardware profiles. It notes that while Windows no longer supports hardware profiles, the key is maintained for backward compatibility with legacy applications.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (8) Deep dive: HKEY_CURRENT_CONFIG (HKCC)* Deep dive: HKEY_CURRENT_CONFIG (HKCC)* This root key is nothing more than a link to the hardware profile that is stored in HKLM: HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current. It's not prevalent today but Windows keeps it around in the name of backwards compatibility. 141 The Registry (8) The HKEY_CURRENT_CONFIG, or HKCC for short, root key is one of the three links to other root keys. HKCC is formally linked to the HKLM root key and since this linked key points to whatever the current hardware profile is, the root key path is: HKLM\SYSTEM\

=== UNIT 23 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: HKEY_PERFORMANCE_DATA, RegQueryValueEx, Pdh.dll, registry access methods
Summary: The unit discusses the HKEY_PERFORMANCE_DATA (HKPD) registry key, noting its inaccessibility via regedit.exe and requirement for programmatic access via Registry APIs like RegQueryValueEx. It also mentions that data is provided by external providers and suggests using Performance Data Helper API functions from Pdh.dll as a preferred method.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (9) Deep dive: HKEY_PERFORMANCE_DATA (HKPD) Deep dive: HKEY_PERFORMANCE_DATA (HKPD) RegQueryValueEx RegQueryValueEx This root key is unique because it cannot be accessed directly via the Registry Editor. It must be accessed programmatically via the Registry APIs. In it you would find performance counters either from system components or server applications. Technically not stored here Technically not stored here 142 The Registry (9) One might think that every registry key would be accessible for viewing via a tool like regedit.exe. Well, the HKEY_PERFORMANCE_DATA key is not one of those keys 

=== UNIT 24 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: Registry key values, REG_DWORD, REG_BINARY, REG_SZ, 32-bit numbers, Boolean values
Summary: This unit describes the three most common Windows Registry value types: REG_DWORD, REG_BINARY, and REG_SZ. It explains their specific uses for storing numbers, binary data, and strings respectively.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (10) Registry key values can be one of 12 types, but 3 are most common. Registry key values can be one of 12 types, but 3 are most common. REG_DWORD REG_DWORD Used for numbers or Boolean values REG_BINARY REG_BINARY REG_SZ REG_SZ Can hold >32-bit numbers or encrypted password; raw data Unicode or ANSI strings like names, files names, paths, types, etc. 143 The Registry (10) A registry key’s value can hold several different types, 12 types to be exact. Despite the number of value types, there are three that you are more likely to come across. 1. REG_DWORD 2. REG_BINARY 3. REG_SZ If you remembe

=== UNIT 25 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: course roadmap, SANS SEC670, OS info gathering, process enumeration, file search, bootcamp challenges
Summary: The text lists a course roadmap for red teaming tools, specifically focusing on gathering operating system information and various enumeration techniques. It includes specific lab exercises related to process enumeration, file searching, and user information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 157 This is your time to go back and complete previous labs or move forward and comp

=== UNIT 26 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo, KUSER_SHARED_DATA
Summary: The unit describes a bootcamp challenge focused on gathering system information from a target using specific Windows APIs like GetProductInfo, GetWindowsDirectory, GetComputerName, and GetNativeSystemInfo. It also mentions an optional advanced task involving the KUSER_SHARED_DATA structure.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control OS Info Obtain complete information about your target. Use the following APIs: GetProductInfo GetProductInfo GetWindowsDirectory GetWindowsDirectory GetComputerName GetComputerName GetNativeSystemInfo GetNativeSystemInfo BONUS: KUSER_SHARED_DATA BONUS: KUSER_SHARED_DATA 159 OS Info This bootcamp challenge is about leveraging a familiar API that you learned about earlier to gather some information about your target. The real challenge comes in with the introduction of several new APIs that can be called to help gather system information. You will have to teach yourself how to use these ones. As a bonus, if

=== UNIT 27 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: OS information retrieval, Windows implants, shellcode, command and control
Summary: The unit describes the purpose of a lab focused on retrieving information about the target's operating system. It is part of a course on developing Windows implants, shellcode, and command and control.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control What’s the Point? What’s the point? 15 What’s the Point? The point of this lab was to understand how you can retrieve various information about the OS of your target. 15 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 28 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: OS version, architecture, Windows APIs, KUSER_SHARED_D_A
Summary: The unit covers methods for obtaining system information, specifically OS version and architecture details. It discusses both documented Windows APIs and an undocumented method using KUSER_SHARED_DATA.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed how obtaining accurate system information is key Discussed how obtaining accurate system information is key Covered documented and recommended methods to obtain the information Covered documented and recommended methods to obtain the information Covered undocumented methods to obtain the information Covered undocumented methods to obtain the information 16 Module Summary In this module, we discussed why you would want to know the exact details of your target’s OS version and architecture, we also explored a few Windows APIs that enable us to do so, and finally, we took a look at a

=== UNIT 29 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: OS Information, Service Packs/Hotfixes/Patches, Process Enumeration, CreateToolhelp, WTSEnum, FileFinder
Summary: The unit outlines a curriculum for gathering operating system information, including service packs, hotfixes, and patches. It lists specific labs and tools used to enumerate processes, software, installed services, and network information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 19 In this module, we will discuss how to gather information about service packs, ho

=== UNIT 30 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: Windows Hotfixes, Quick Fix Engineering (QFE), patch status awareness, avoiding detection
Summary: The unit discusses the definition and purpose of Windows Hotfixes (also known as Quick Fix Engineering updates). It explains that hotfixes are intended to apply critical fixes to software while systems remain running, though some may still require a reboot.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Hotfixes Used to fix critical issues in software Used to fix critical issues in software Also referred to as Quick Fix Engineering (QFE) updates, hotfixes are used to apply a vital fix to software applications. Users that have Windows updates set to automatic will have hotfixes downloaded without much user intervention. The only exception would be a reboot. 21 Windows Hotfixes Windows updates bring with them any number of things, but the emphasis here would be hotfixes. The term “hot fix” traditionally would mean that a patch to a software program can be applied while the system was still running.

=== UNIT 31 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: Windows Service Packs, bundled hotfixes, exploit adjustment, Metasploit Framework, target specification
Summary: The text describes the concept of Windows Service Packs (SPs) and how they bundle hotfixes to improve update efficiency. It explains that different SP levels can affect exploit compatibility, requiring developers to consider target OS versions when designing implants or local privilege escalation techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Service Packs Bundled hotfixes Bundled hotfixes Each service pack brings with it a grouping of one or more hotfixes that will be applied to the OS. Each service pack that targets a particular OS version will have all previous hotfixes that former service packs brought with it so that a user can jump straight to the most recent service pack without installing each one sequentially. 22 Service Packs It really would not make much sense for Windows to push down hotfixes by themselves one at a time, but to rather bundle them up in what is called a service pack. Bundling the hotfixes together is pretty great be

=== UNIT 32 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: 
Summary: The unit describes various methods for querying hotfixes and service packs on a Windows system, including PowerShell's Get-HotFix cmdlet, the wmic qfe list command, and using the Windows Update Agent APIs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Querying Hotfixes and Service Packs How do you go about finding hotfixes and service packs? How do you go about finding hotfixes and service packs? Get‐HotFix Get‐HotFix PowerShell cmdlet that lists updates seen by Quick Fix Engineering class. WMIC WMIC C/C++ C/C++ WMIC command line utility offers the qfe argument. E.g., wmic qfe list. Construct our own WMI query or explore Windows Update Agent APIs. 23 Querying Hotfixes and Service Packs Windows provides users and admins with a number of options to go about querying patches, or hotfixes, which have been applied to a system. Perhaps the easiest method wou

=== UNIT 33 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: Windows Update Agent (WUA), COM interfaces, Wuapi.h, Wuguid.lib, UpdateSession, UpdateSearcher, SearchResult
Summary: The unit describes the Windows Update Agent (WUA) APIs, which are used to programmatically determine available and installed updates on a system. It details the use of COM interfaces like UpdateSession, UpdateSearcher, and SearchResult for identifying missing or applied patches.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Update Agent (WUA) APIs Introduced with Windows XP, designed for system admins and developers Introduced with Windows XP, designed for system admins and developers Windows Update Windows Update Scripts and/or programs can be developed to determine what updates are available to be installed on a system, what updates have been installed, or to remove any installed updates. Windows Server Update Services (WSUS) Windows Server Update Services (WSUS) 24 Windows Update Agent (WUA) APIs Programmatically creating a solution is often more complicated than using pre-built programs or tools like the wmic too

=== UNIT 34 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: WUA SearchResult Object, IUpdateCollection, update list iteration, get_UpdateSearcher, get_Count method
Summary: The unit describes the WUA SearchResult object in Windows Update Agent (WUA) API, specifically how to retrieve and iterate through a collection of updates matching search criteria. It details the use of get_Updates and get_Count methods to manage update lists.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control WUA SearchResult Object ISearchResult ISearchResult Used to represent search results Used to represent search results // interface collection of updates from a resulting search ISearchResult* results; IUpdateCollection* upList; LONG upSize; upSsn‐>CreateUpdateSearcher(&upSearch); upSearch‐>Search(criteria, &results); results‐>get_Updates(&upList); upList‐>get_Count(&upSize); Has methods that can query updates from a resulting search Has methods that can query updates from a resulting search 27 WUA SearchResult Object The SearchResult WUA object represents the collection of updates that matched the search 

=== UNIT 35 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: WUA APIs, hotfixes, service_packs, Windows updates
Summary: The unit describes the importance of learning how to identify and gather information about Windows updates, hotfixes, and service packs. It specifically mentions using WUA APIs to retrieve this information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed the importance of updates and patches Discussed the importance of updates and patches Learned how to obtain information about patches Learned how to obtain information about patches Used the WUA APIs Used the WUA APIs 29 Module Summary In this module, we discussed hotfixes, service packs, and how to get information about them using the WUA APIs. 29 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 36 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: PowerShell, Get-HotFix, Get-Updates, Get-ServicePack, Quick Fix Engineering
Summary: This unit contains a review section for the SEC670 course, specifically focusing on PowerShell cmdlets used to query Quick Fix Engineering (QFE) information. It lists three specific cmdlets: Get-HotFix, Get-Updates, and Get-ServicePack.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What PowerShell cmdlet queries the Quick Fix Engineering class? What PowerShell cmdlet queries the Quick Fix Engineering class? A Get-HotFix A Get-HotFix B Get-Updates B Get-Updates C Get-ServicePack C Get-ServicePack 31 Unit Review Answers Q: What PowerShell cmdlet queries the Quick Fix Engineering class? A: Get-HotFix B: Get-Updates C: Get-ServicePack 31 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 37 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: WUA object, UpdateSearcher, UpdateSession, SearchResult
Summary: The unit contains a review question regarding Windows Update Agent (WUA) objects used to identify system updates. It lists multiple choice options for SearchResult, UpdateSearcher, and UpdateSession.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What WUA object is used to find updates on a system? What WUA object is used to find updates on a system? A SearchResult A SearchResult B UpdateSearcher B UpdateSearcher C UpdateSession C UpdateSession 35 Unit Review Answers Q: What WUA object is used to find updates on a system? A: SearchResult B: UpdateSearcher C: UpdateSession 35 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 38 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: course roadmap, OS info, process enumeration, Section 2 overview
Summary: The unit lists a course roadmap for gathering operating system information, including service packs, process enumeration, and installed software. It also outlines the modules in Section 2 of the training curriculum.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 36 In this module, we will look at the how and why when it comes to process enumerat

=== UNIT 39 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: EnumProcesses, CreateToolhelp32Snapshot, WTSEnumerateProcesses, documented Windows APIs
Summary: The unit discusses three documented Windows APIs for process enumeration: EnumProcesses, CreateToolhelp32Snapshot, and WTSEnumerateProcesses. It highlights the pros and cons of each method, such as simplicity versus detail level and remote system capabilities.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Documented Methods Using documented Windows APIs is safe and reliable. Using documented Windows APIs is safe and reliable. EnumProcesses EnumProcesses Arguably the easiest API to use for enumeration. Does not return detailed process information. CreateToolhelp32Snapshot CreateToolhelp32Snapshot WTSEnumerateProcesses WTSEnumerateProcesses Perhaps one of the more common APIs used in malwarez for process enumeration. Returns more detailed process information than EnumProcesses. Can query remote systems and over multiple sessions on the local computer. Returns relevant process information. 42 Documented Metho

=== UNIT 40 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: WTSEnumerateProcessesEx, wtsapi32.h, remote process enumeration, WTS_PROCESS_INFO struct
Summary: The text describes the WTSEnumerateProcessesEx API from the wtsapi32.h header file, which is used to enumerate processes on local or remote systems. It details the parameters of the function, such as hServer, pLevel, SessionId, and ppProcInfo, along with the requirement for specific registry keys to allow remote interrogation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control WTSEnumerateProcessesEx API WTSEnumerateProcessesEx() WTSEnumerateProcessesEx() Windows Terminal Services Windows Terminal Services BOOL WTSEnumerateProcessesExA( _In_ HANDLE hServer, _Inout_ WORD *pLevel, _In_ DWORD SessionId, _Out_ LPSTR *ppProcessInfo, _Out_ DWORD *pCount ); typedef struct _WTS_PROCESS_INFO_EXA { [..SNIP..] DWORD NumberOfThreads; DWORD HandleCount; DWORD PagefileUsage; DWORD PeakPagefileUsage; DWORD WorkingSetSize; DWORD PeakWorkingSetSize; LARGE_INTEGER UserTime; LARGE_INTEGER KernelTime; Has BOOL return type Has BOOL return type 51 WTSEnumerateProcessesEx API There is an entire famil
