# Atlas Material — recon (part 1)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: recon
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Table of Contents, Gathering Operating System Information, Process Enumeration, Lab 2.1 to 2.5
Summary: This page contains a Table of Contents for the section on gathering operating system information and related tools. It lists various sub-topics including service packs, process enumeration, installed software, and user information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control P a g e Table of Contents (1) 4 Gathering Operating System Information 14 Lab 2.1: OS Info 19 Service Packs/Hotfixes/Patches 36 Process Enumeration 45 Lab 2.2: ProcEnum 49 Lab 2.3: CreateToolhelp 53 Lab 2.4: WTSEnum 65 Installed Software 73 Directory Walks 83 Lab 2.5: FileFinder 88 User Information 101 Services and Tasks 2 This page intentionally left blank. 2 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Course Roadmap, Section 2, Gathering Operating System Information, Lab 2.1-2.5
Summary: The unit contains a slide outlining the course roadmap for Section 2, focusing on gathering operating system information. It lists specific labs and topics such as process enumeration, installed software, user information, and network information.
Excerpt:
Visual caption: A slide showing the course roadmap and details for Section 2, which focuses on gathering operating system information. Visible text: Course Roadmap; Section 2; Gathering Operating System Information; Lab 2.1: OS Info; Process Enumeration; Lab 2.2: ProcEnum; Lab 2.3: CreateToolobj; Lab 2.4: WSTEnum; Installed Software; Lab 2.5: FileShare; User Information; Services and Taps; Network Information; Registry Information; Bootcamp Alt/source label:

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Windows 7 x86, Windows 10 x86_64, ntoskrnl.exe, WTS API family, process enumeration
Summary: The text discusses the importance of gathering specific OS information, such as service packs and kernel versions (ntoskrnl.exe), to ensure compatibility with payloads. It highlights potential risks like system crashes if architecture mismatches occur and mentions that certain APIs may only be available on newer Windows versions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control OS Information Windows 7 x86 or Windows 10 x86_64? Windows 7 x86 or Windows 10 x86_64? Service Pack Service Pack Kernel Version Kernel Version A collection of updates to be applied as patches for bugs or vulnerabilities. Also provide features to the OS. The ntoskrnl.exe is the kernel file itself. The file is typically located under C:\Windows\System32. 7 OS Information Perhaps one of the most important pieces of information to gather first would be the exact version of the operating system, if that is not known already. Typically, you would know at least some basic information about the target beforehand,

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Windows 7/10 x86/x64, ntoskrnl.exe, Service Pack, WTS API family, process enumeration
Summary: The text discusses the importance of gathering specific OS information, such as service packs and kernel versions (ntoskrnl.exe), to ensure compatibility with payloads. It highlights potential risks like system crashes if architecture mismatches occur and mentions that certain APIs may only be available on specific Windows versions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control OS Information Windows 7 x86 or Windows 10 x86_64? Windows 7 x86 or Windows 10 x86_64? Service Pack Service Pack Kernel Version Kernel Version A collection of updates to be applied as patches for bugs or vulnerabilities. Also provide features to the OS. The ntoskrnl.exe is the kernel file itself. The file is typically located under C:\Windows\System32. 7 OS Information Perhaps one of the most important pieces of information to gather first would be the exact version of the operating system, if that is not known already. Typically, you would know at least some basic information about the target beforehand,

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: OS version, architecture, Windows APIs, KUSER_SHARED_DATA
Summary: The unit covers methods for obtaining system information, specifically OS version and architecture details. It discusses both documented Windows APIs and an undocumented method using KUSER_SHARED_DATA.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed how obtaining accurate system information is key Discussed how obtaining accurate system information is key Covered documented and recommended methods to obtain the information Covered documented and recommended methods to obtain the information Covered undocumented methods to obtain the information Covered undocumented methods to obtain the information 16 Module Summary In this module, we discussed why you would want to know the exact details of your target’s OS version and architecture, we also explored a few Windows APIs that enable us to do so, and finally, we took a look at a

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: C:\Program Files, C:\Program Files (x86), 32-bit and 64-bit applications, installation folder locations
Summary: The unit describes standard Windows directory conventions for locating 32-bit and 64-bit applications, specifically C:\Program Files and C:\Program Files (x86). It also notes that some applications may be installed in non-standard locations like the root of the C: drive or user-specific folders. The text emphasizes that automated survey tools might miss applications outside these standard paths.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Where to Look? Where can you find 32-bit and 64-bit applications? Where can you find 32-bit and 64-bit applications? C:\Program Files C:\Program Files It should be safe to assume that entries found in this folder are 64-bit applications C:\Program Files (x86) C:\Program Files (x86) C:\ C:\ A similar assumption can be made for entries found in this location; that they will be 32-bit applications Some apps, like Python, install at the root system drive, although not very common 67 Where to Look? One of the goals of recon is to determine what applications are installed on your target. Maybe you want to see i

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Windows Registry, root keys, HKEY_USERS, HKEY_CURRENT_USER, HKEY_CLASSES_ROOT, HKEY_LOCAL_MACHINE, HKEY_CURRENT_CONFIG
Summary: The text describes the five predefined root keys of the Windows Registry (HKEY_USERS, HKEY_CURRENT_USER, *HKEY_CLASSES_ROOT*, *HKEY_CURRENT_CONFIG*). It explains that 'H' stands for handle and 'KEY' stands for key. It also provides a brief overview of what information is stored in each specific root key.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (3) There are five predefined root keys the system uses. There are five predefined root keys the system uses. HKEY_USERS HKEY_USERS HKEY_CLASSES_ROOT* HKEY_CLASSES_ROOT* HKEY_CURRENT_USER* HKEY_CURRENT_USER* HKEY_LOCAL_MACHINE HKEY_LOCAL_MACHINE HKEY_CURRENT_CONFIG* HKEY_CURRENT_CONFIG* An * denotes the key is a link or a merged view of keys. An * denotes the key is a link or a merged view of keys. 135 The Registry (3) You might have noticed that each root key starts with an H. This is because the root key names are Windows handles (H) to keys (KEY); hence the name HKEY. The key names on the 

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: HKEY_CLASSES_ROOT, HKCR, file extension associations, 138, COM class registrations, roaming profiles
Summary: The text describes the structure and purpose of the HKEY_CLASSES_ROOT (HKCR) registry key, specifically its role in storing file extension associations and COM class registrations. It explains that HKCR is a virtual root key composed of the combination of HKCU&l;SOFTWARE&l;Classes and HKLM&l;SOFTWARE&l;Classes. It also notes how roaming profiles influence this structure.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (6) Deep dive: HKEY_CLASSES_ROOT (HKCR)* Deep dive: HKEY_CLASSES_ROOT (HKCR)* HKCU\SOFTWARE\Classes HKCU\SOFTWARE\Classes This root key holds three types of information: file extension associations, COM class registrations, and virtualized registry root for the UAC. Every registered file extension will have its own key that is typically the REG_SZ value type. Sometimes they simply point to another key that holds the needed information. HKLM\SOFTWARE\Classes HKLM\SOFTWARE\Classes The combination of the above Classes keys make this root key. The combination of the above Classes keys make this r

=== UNIT 9 ===
Source: CRTO Book.pdf
Value: 0.9  Key cues: Oracle DB Query, ls -la, oracle-db-query, mysql.conf, mysql.cnf, query.sql
Summary: The unit contains a screenshot of a Linux terminal showing 'ls -la' and 'oracle-db-query' commands, followed by an explanation of how to find Oracle database information.
Excerpt:
Visual caption: A screenshot of a Linux terminal showing the output of an 'ls -la' command and a subsequent 'oracle-db-query' query, followed by a text block explaining how to find Oracle database information. Visible text: Oracle DB Query; ls -la; oracle-db-query; mysql.conf; mysql.cnf; query.sql; how to find oracle db info Alt/source label:

=== UNIT 10 ===
Source: CRTO Book.pdf
Value: 0.9  Key cues: Domain Reconnaissance, standard domain user, high integrity process
Summary: The unit describes the concept of domain reconnaissance as an information gathering phase where a standard user can enumerate data from the domain. It notes that performing these actions in high- integrity processes is not required and may be detrimental.
Excerpt:
Visual caption: A screenshot of a webpage or document titled 'Domain Reconnaissance' describing the process of enumerating information from a domain as a standard user. Visible text: Domain Reconnaissance; This section will review (at a relatively high level) some of the information you can enumerate from the current domain as a standard domain user. We'll cover m; It's worth noting that performing domain recon in a high integrity process is not required, and in some cases (token duplication) can be detrimental. Alt/source label:

=== UNIT 11 ===
Source: CRTO Book.pdf
Value: 0.9  Key cues: Wireshark, TCP Dump, pcap, Ethernet II, IP, VLAN, sTCP.org, HTTP
Summary: The unit contains a description of a packet capture analysis involving various network protocols and ports, including Wireshark, TCP Dump, and HTTP.
Excerpt:
Visual caption: A technical document or tutorial page detailing a network security analysis of a packet capture file, likely for educational purposes. Visible text: Wireshark; TCP Dump; pcap; Ethernet II; IP; VLAN; sTCP.org; HTTP; Port 1080; TCP Port 32768; tDNS.org; , Alt/source label:

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.9  Key cues: Windows services, tasks, enumeration, API usage
Summary: The unit covers the definition and purpose of Windows services and tasks, as well as the APIs used for enumerating them. It serves as a summary section for Module 108.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed what Windows services are Discussed what Windows services are Learned about services and processes Learned about services and processes Discussed what Windows Tasks are Discussed what Windows Tasks are Discussed enumerating services and tasks Discussed enumerating services and tasks 108 Module Summary In this module, we discussed very briefly what services and tasks are. We also discussed why we would want to enumerate them, and the APIs involved for enumerating services and tasks. 108 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.9  Key cues: IP Helper API, GetIpStatistics, GetAdapterAddresses, NIC configuration, PowerShell Get-NetAdapter, netstat -e
Summary: The unit discusses methods for gathering network interface card (NIC) information and configuration details from a Windows system. It highlights the use of PowerShell cmdlets, command-line utilities like netstat and ipconfig, and specific Win32 APIs within the IP Helper header file such as GetIpStatistics and GetAdapterAddresses.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control NIC Information/Configuration IP Helper header file offers many great APIs for us to use. IP Helper header file offers many great APIs for us to use. GetIpStatistics GetIpStatistics IPHLPAPI_DLL_LINKAGE ULONG GetIpStatistics( _Out_ PMIB_IPSTATS Statistics ); GetAdaptersAddresses( _In_ ULONG Family, _In_ ULONG Flags, _In_ PVOID Reserved, _Inout_ PIP_ADAPTER_ADDRESSES AdapterAddresses, _Inout_ PULONG SizePointer ); GetAdapterAddresses GetAdapterAddresses 118 NIC Information/Configuration VMs are being used more and more these days in production and if you happen to get access to a VM in production, you migh

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.9  Key cues: Program Files (x86), 32-bit applications, information gathering from directory contents
Summary: The unit describes the contents of the Program Files (x86) directory as a means of identifying 32-bit applications and potential system usage. It highlights how an operator can infer information about the system's purpose based on the user-sited software.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control C:\Program Files (x86) 70 C:\Program Files (x86) This screenshot shows the contents of the Program Files x86 directory. This directory contains 34 entries, which could indicate that there are at least 34 applications installed on this system that are 32-bit. An operator might be able to make a better educated guess as to what this system is being used for after seeing several entries for development software. 70 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateToolhelp32Snapshot, CreateToolhelp122Snapshot, PROCESS_QUERY_INFORMATION, C code snippet
Summary: The unit contains a C code snippet and associated constants used for system information gathering via the CreateToolhelp32Snapshot function. It specifically highlights functions like CreateToolhelp122Snapshot and flags such as PROCESS_QUERY_INFORMATION.
Excerpt:
Visual caption: A screenshot of a C code snippet demonstrating the use of CreateToolhelp32Snapshot function. Visible text: Example: CreateToolhelp32Snapshot; CreateToolhelp122Snapshot; PROCESS_QUERY_INFORMATION; ERROR_SUCCESS Alt/source label:

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: OS Information, Process Enumered, CreateToolhelp, WTSEnum, FileFinder, Windows Tool Development
Summary: The text outlines a curriculum for gathering operating system information, including service packs, process enumeration, installed software, and network details. It lists specific labs related to tool development for identifying OS components and directory walking.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 4 In this module, we will dive into how to gather OS specific information and why it

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: OS information gathering, public method, understanding importance, undocumented method
Summary: The unit contains a slide outlining the objectives for an OS information gathering module. It lists goals such as discussing importance, exploring public methods, and exploring undocumented methods to retrieve system information.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Objectives' outlining the goals for a module on OS information gathering. Visible text: Objectives; Our objectives for this module are:; Discuss the importance of determining OS information; Explore public method to retrieve information about the system; Explore undocumented method to retrieve information about the system; SANS SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: OS version, service pack, public methods, undocumented methods
Summary: This unit outlines the learning objectives for a module on identifying OS information and service packs using both public and undocumented methods. It emphasizes the understanding of whether certain methods are reliable or accurate.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Discuss the importance of determining OS information Explore public methods to retrieve information about the system Explore undocumented method to retrieve information about the system 5 Objectives The objectives for this module are to understand how important it is to determine what OS version your target is running and/or what service pack your target has, explore a few public methods for retrieving system information, as well as explore some undocumented methods. There are some methods that are more reliable than others, as well as some methods that might

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Survey Script, reconnaissance, system exploration, host survey tool
Summary: The unit describes a 'Survey Script' used during the reconnaissance phase of system exploration. It explains that identifying the system environment is critical for operational success and outlines how host survey tools collect information.
Excerpt:
Visual caption: A slide from a SANS course titled 'Survey Script' explaining the purpose of reconnaissance in system exploration. Visible text: Survey Script; Survey the host and determine where you are.; Knowing the system that you are on is vital to the success of your operation. A host survey tool can query several pieces of information and report back its fin; SEC601 / Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: host survey, reconnaissance, AV/EDR detection, API usage, custom tool development
Summary: The unit describes the concept and purpose of a host survey tool used in red teaming operations to gather information about the target system's environment, including installed applications like AV/EDR solutions. It emphasizes that detailed reconnaissance is necessary for informed decision work, such as identifying potential privilege escalation paths. The text introduces the development of custom recon capabilities.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Survey Script Survey the host and determine where you are. Survey the host and determine where you are. Knowing the system that you are on is vital to the success of your operation. A host survey tool can query various components and report back its findings that can then be used to determine the next action. 6 Survey Script If you are a red teamer, or a penetration tester, or have taken SEC560, then you may already know that one of the first tasks that you would typically perform is some recon. Recon is such a broad term that can encompass many things, like users, networks, shares, etc. The focus at this

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: host survey, reconnaissance, API usage, AV/EDR detection, custom tool development
Summary: The text introduces the concept of a host survey tool used to gather information about a target system's components and environment. It emphasizes that detailed reconnaissance is crucial for determining subsequent actions, such as privilege escalation. The section also highlights the development of custom recon capabilities to identify specific items like installed AV/EDR solutions or targeted files.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Survey Script Survey the host and determine where you are. Survey the host and determine where you are. Knowing the system that you are on is vital to the success of your operation. A host survey tool can query various components and report back its findings that can then be used to determine the next action. 6 Survey Script If you are a red teamer, or a penetration tester, or have taken SEC560, then you may already know that one of the first tasks that you would typically perform is some recon. Recon is such a broad term that can encompass many things, like users, networks, shares, etc. The focus at this

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetNativeSystemInfo, SYSTEM_INFO struct, wProcessorArchitecture, WoW64 applications
Summary: The text describes the GetNativeSystemInfo API and its usage for gathering system information, specifically focusing on the SYSTEM_INFO structure.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control GetNativeSystemInfo GetNativeSystemInfo GetNativeSystemInfo Gathers current system information Gathers current system information VOID GetNativeSystemInfo( _Out_ LPSYSTEM_INFO lpSystemInfo ); typedef struct _SYSTEM_INFO { [..SNIP..] DWORD dwPageSize; LPVOID lpMinimumApplicationAddress; LPVOID lpMaximumApplicationAddress; DWORD_PTR dwActiveProcessorMask; DWORD dwNumberOfProcessors; DWORD dwProcessorType; DWORD dwAllocationGranularity; WORD wProcessorLevel; WORD wProcessorRevision; } SYSTEM_INFO, *LPSYSTEM_INFO; Has VOID return type Has VOID return type 10 GetNativeSystemInfo The GetNativeSystemInfo API can

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Lab 2.1, OS Info, gathering information
Summary: The unit describes Lab 2.1, which focuses on gathering information about the operating system and target. It references an eWorkbook for specific lab details.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 2.1: OS Info Gathering information about the OS and target Gathering information about the OS and target Please refer to the eWorkbook for the details of this lab. 14 Lab 2.1: OS Info Please refer to the eWorkbook for the details of the lab. 14 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: OS version, architecture, Windows APIs, KUSER_SHARED_DATA
Summary: The unit covers methods for obtaining system information, specifically OS version and architecture details. It discusses both documented Windows APIs and an undocumented method using KUSER_SHARED_DATA.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed how obtaining accurate system information is key Discussed how obtaining accurate system information is key Covered documented and recommended methods to obtain the information Covered documented and recommended methods to obtain the information Covered undocumented methods to obtain the information Covered undocumented methods to obtain the information 16 Module Summary In this module, we discussed why you would want to know the exact details of your target’s OS version and architecture, we also explored a few Windows APIs that enable us to do so, and finally, we took a look at a

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: system information, documented methods, undocumented methods, module summary
Summary: The unit describes a summary slide for a module covering techniques for obtaining system information using both documented and undocumented methods. It highlights the importance of accurate system information gathering as a key component in red teaming.
Excerpt:
Visual caption: A summary slide for a module on obtaining system information using documented and undocumented methods. Visible text: Module Summary; Discussed how obtaining accurate system information is key; Covered documented and recommended methods to obtain the information; Covered undocumented methods to obtain the information; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: OS Information, Service Packs/Hotfixes/Patches, Process Enumer., WTSEnum, FileFinder
Summary: The unit outlines a curriculum for gathering operating system information, including service packs, hotfixes, and patches. It lists specific labs and tools used to enumerate processes, software, installed services, and network information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 19 In this module, we will discuss how to gather information about service packs, ho

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Hotfixes, Quick Fix Engineering (QFE), patch status awareness, term 'hot'
Summary: The text defines Windows Hotfixes and their role in patching software vulnerabilities. It explains the difference between hot patches (no reboot required) and updates requiring a reboot, while emphasizing the importance of awarenes of patch status to avoid detection during exploitation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Hotfixes Used to fix critical issues in software Used to fix critical issues in software Also referred to as Quick Fix Engineering (QFE) updates, hotfixes are used to apply a vital fix to software applications. Users that have Windows updates set to automatic will have hotfixes downloaded without much user intervention. The only exception would be a reboot. 21 Windows Hotfixes Windows updates bring with them any number of things, but the emphasis here would be hotfixes. The term “hot fix” traditionally would mean that a patch to a software program can be applied while the system was still running.

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Hotfixes, Quick Fix Engineering (QFE), hot patching, security patch status
Summary: The unit discusses the definition and purpose of Windows Hotfixes, specifically how they are used to address critical software issues while systems remain running. It emphasizes the importance of awareness regarding which hotfixes have been applied to a system before attempting an exploit to avoid detection.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Hotfixes Used to fix critical issues in software Used to fix critical issues in software Also referred to as Quick Fix Engineering (QFE) updates, hotfixes are used to apply a vital fix to software applications. Users that have Windows updates set to automatic will have hotfixes downloaded without much user intervention. The only exception would be a reboot. 21 Windows Hotfixes Windows updates bring with them any number of things, but the emphasis here would be hotfixes. The term “hot fix” traditionally would mean that a patch to a software program can be applied while the system was still running.

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Get-HotFix, wmic qfe list, Win32_QuickFixEngineering class, Windows Update Agent APIs
Summary: The unit describes various methods for querying hotfixes and service packs on a Windows system, including PowerShell's Get-HotFix cmdlet, the wmic qfe list command, and using the Windows Update Agent APIs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Querying Hotfixes and Service Packs How do you go about finding hotfixes and service packs? How do you go about finding hotfixes and service packs? Get‐HotFix Get‐HotFix PowerShell cmdlet that lists updates seen by Quick Fix Engineering class. WMIC WMIC C/C++ C/C++ WMIC command line utility offers the qfe argument. E.g., wmic qfe list. Construct our own WMI query or explore Windows Update Agent APIs. 23 Querying Hotfixes and Service Packs Windows provides users and admins with a number of options to go about querying patches, or hotfixes, which have been applied to a system. Perhaps the easiest method wou

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Get-HotFix, WMIC qfe, C/C++ query
Summary: The unit describes three methods for querying hotfixes and service packs on a Windows system: Get-HotFix, the WMIC command line utility with the qfe argument, and C/C++ programming to interact with the WMI or Windows Update Agent APIs.
Excerpt:
Visual caption: A presentation slide titled 'Querying Hotfixes and Service Packs' outlining three methods for identifying updates: Get-HotFix, WMIC, and C/C++. Visible text: Querying Hotfixes and Service Packs; Get-HotFix; tPowerShell cmdlet that lists updates seen by Quick Fix Engineering class.; WMIC command line utility offers the qfe argument. E.g., wmic qfe; C/C++ Construct our own WM1 query or explore Windows Update Agent APIs. Alt/source label:

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Get-HotFix cmdlet, wmic qfe list, Win32_QuickFixEngineering class, Windows Update Agent APIs
Summary: The unit describes methods for identifying installed hotfixes and service packs on a Windows system using PowerShell's Get-HotFix cmdlet, the wmic qfe list command, and Windows Update Agent APIs. It highlights that both Get-HotFix and wmic qfe list query the same WMI Win32_QuickFixEngineering class, which may not provide a full view of all updates.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Querying Hotfixes and Service Packs How do you go about finding hotfixes and service packs? How do you go about finding hotfixes and service packs? Get‐HotFix Get‐HotFix PowerShell cmdlet that lists updates seen by Quick Fix Engineering class. WMIC WMIC C/C++ C/C++ WMIC command line utility offers the qfe argument. E.g., wmic qfe list. Construct our own WMI query or explore Windows Update Agent APIs. 23 Querying Hotfixes and Service Packs Windows provides users and admins with a number of options to go about querying patches, or hotfixes, which have been applied to a system. Perhaps the easiest method wou

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Update Agent, WUA API, COM interfaces, Wuaapi.h, Wuguid.lib, UpdateSession, UpdateSearcher, SearchResult
Summary: The unit describes the Windows Update Agent (WUA) APIs, which are used to programmatically determine available and installed updates on a system. It details the use of COM interfaces like UpdateSession, UpdateSearcher, and SearchResult for identifying vulnerabilities or missing patches.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Update Agent (WUA) APIs Introduced with Windows XP, designed for system admins and developers Introduced with Windows XP, designed for system admins and developers Windows Update Windows Update Scripts and/or programs can be developed to determine what updates are available to be installed on a system, what updates have been installed, or to remove any installed updates. Windows Server Update Services (WSUS) Windows Server Update Services (WSUS) 24 Windows Update Agent (WUA) APIs Programmatically creating a solution is often more complicated than using pre-built programs or tools like the wmic too

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WUA SearchResult Object, IUpdateCollection, update list, get_UpdateSearcher, query updates
Summary: The unit describes the WUA SearchResult object in Windows Update Agent (WUA) API, specifically how to retrieve and iterate through a collection of updates matching search criteria. It details the use of get_Updates and get_Count methods to manage update lists.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control WUA SearchResult Object ISearchResult ISearchResult Used to represent search results Used to represent search results // interface collection of updates from a resulting search ISearchResult* results; IUpdateCollection* upList; LONG upSize; upSsn‐>CreateUpdateSearcher(&upSearch); upSearch‐>Search(criteria, &results); results‐>get_Updates(&upList); upList‐>get_Count(&upSize); Has methods that can query updates from a resulting search Has methods that can query updates from a resulting search 27 WUA SearchResult Object The SearchResult WUA object represents the collection of updates that matched the search 

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WUA APIs, hotfixes, service packs, patch information
Summary: The unit covers the importance of updates and patches for Windows systems, specifically focusing on how to retrieve information about them using WUA APIs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed the importance of updates and patches Discussed the importance of updates and patches Learned how to obtain information about patches Learned how to obtain information about patches Used the WUA APIs Used the WUA APIs 29 Module Summary In this module, we discussed hotfixes, service packs, and how to get information about them using the WUA APIs. 29 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WUA APIs, hotfixes, service packs, patch information
Summary: The unit covers the use of WUA APIs to identify and gather information regarding Windows updates, hotfixes, and service packs. It emphasizes the importance of understanding patch status for security analysis.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed the importance of updates and patches Discussed the importance of updates and patches Learned how to obtain information about patches Learned how to obtain information about patches Used the WUA APIs Used the WUA APIs 29 Module Summary In this module, we discussed hotfixes, service packs, and how to get information about them using the WUA APIs. 29 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WUA object, UpdateSearcher, UpdateSession, SearchResult
Summary: The unit contains a review question regarding Windows Update Agent (WUA) objects used for identifying system updates. It lists multiple choice options for SearchResult, UpdateSearcher, and UpdateSession.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What WUA object is used to find updates on a system? What WUA object is used to find updates on a system? A SearchResult A SearchResult B UpdateSearcher B UpdateSearcher C UpdateSession C UpdateSession 34 Unit Review Questions Q: What WUA object is used to find updates on a system? A: SearchResult B: UpdateSearcher C: UpdateSession 34 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: process enumeration, Service Packs/Hotfixes/Patches, CreateToolhelp, WTSEnum, FileFinder
Summary: The unit outlines a curriculum for gathering operating system information, specifically focusing on process enumeration and various methods to identify service packs, hotfixes, patches, and installed software.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 36 In this module, we will look at the how and why when it comes to process enumerat

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: process enumeration, Windows processes, process states, how processes are created
Summary: This unit outlines the learning objectives for a module on process enumeration in Windows environments. It covers the necessity of understanding processes, their creation, states, and various methods for enumerating them.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Understand the need for process enumeration Take a deeper look at processes Explore the various methods to enumerate processes 37 Objectives The objectives for this module are to understand the need for enumerating processes. Furthermore, to understand processes even more, we will look at what processes are, how they are created, different process states, and the several methods involved with enumeration. Let’s get to it. 37 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: process enumeration, red team survey, running processes
Summary: The unit describes the importance of process enumeration during red teaming engagements. It highlights that identifying running applications is a critical component of surveying the environment.
Excerpt:
Visual caption: A presentation slide explaining the importance of enumerating processes during a red teaming engagement. Visible text: Why Enumerate Processes?; Must find out what applications are running; An important part of conducting a survey is gathering a list of running processes.; SEC701 / Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EnumProcesses, CreateToolhelp32Snapshot, WTSEnumerateProcess, documented APIs, process enumeration
Summary: The unit describes three documented Windows APIs for process enumeration: EnumProcesses, CreateToolhelp32Snapshot, and WTSEnumerateProcess. It highlights the pros and cons of each method, such as simplicity versus detail level and remote system capabilities.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Documented Methods Using documented Windows APIs is safe and reliable. Using documented Windows APIs is safe and reliable. EnumProcesses EnumProcesses Arguably the easiest API to use for enumeration. Does not return detailed process information. CreateToolhelp32Snapshot CreateToolhelp32Snapshot WTSEnumerateProcesses WTSEnumerateProcesses Perhaps one of the more common APIs used in malwarez for process enumeration. Returns more detailed process information than EnumProcesses. Can query remote systems and over multiple sessions on the local computer. Returns relevant process information. 42 Documented Metho
