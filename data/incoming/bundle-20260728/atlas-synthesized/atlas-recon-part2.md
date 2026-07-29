# Atlas Material — recon (part 2)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: recon
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WTSEnumerateProcessesEx, wtsapi32.h, remote process enumeration, WTS_PROCESS_INFO_EXA struct, WTSOpenServer API, WTSEnumerateMemoryEx
Summary: The text describes the WTSEnumerateProcessesEx API from the wtsapi32.h header file, which is used to enumerate processes on local or remote systems. It details the parameters of the function, such as hServer, pLevel, SessionId, and ppProcInfo, along with the requirement for specific registry keys to allow remote queries. It also mentions the necessity of using WTSEnumerateProcessesEx to retrieve detailed process information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control WTSEnumerateProcessesEx API WTSEnumerateProcessesEx() WTSEnumerateProcessesEx() Windows Terminal Services Windows Terminal Services BOOL WTSEnumerateProcessesExA( _In_ HANDLE hServer, _Inout_ WORD *pLevel, _In_ DWORD SessionId, _Out_ LPSTR *ppProcessInfo, _Out_ DWORD *pCount ); typedef struct _WTS_PROCESS_INFO_EXA { [..SNIP..] DWORD NumberOfThreads; DWORD HandleCount; DWORD PagefileUsage; DWORD PeakPagefileUsage; DWORD WorkingSetSize; DWORD PeakWorkingSetSize; LARGE_INTEGER UserTime; LARGE_INTEGER KernelTime; Has BOOL return type Has BOOL return type 51 WTSEnumerateProcessesEx API There is an entire famil

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Terminal Services, enumerate processes, query remote targets
Summary: The text describes a lab exercise focused on enumerating processes using Windows Terminal Services. It highlights the utility of these services for querying remote targets.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control What’s the Point? What’s the point? 54 What’s the Point? The point of the lab was to explore another method to enumerate processes. Using the Windows Terminal Services is nice because you have the potential to query remote targets. 54 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: process enumeration, kernel structures, local and remote systems
Summary: The unit covers the importance of process enumeration, kernel structures for representing processes in system address space, and various methods for enumerating processes on local and remote systems.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed the reason for enumerating processes Discussed the reason for enumerating processes Explored the structures the kernel uses to represent processes Explored the structures the kernel uses to represent processes Explored various methods for process enumeration Explored various methods for process enumeration 60 Module Summary In this module, we discussed why it is important to enumerate processes on a system, the structures the kernel uses to represent processes in system address space, and several methods to enumerate processes on local and remote systems. 60 © SANS Institute 2024 

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: undocumented API, enumerate processes, EnumProcesses(), WTSEnumerateProcessEx(), NtQuerySystemInformation()
Summary: This unit contains a review section for the SEC670 course, specifically focusing on undocumented APIs used for process enumeration. It lists three specific functions: EnumProcesses(), WTSEnumerateProcessEx(), and NtQuerySystemInformation().
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What undocumented API can be used to enumerate processes? What undocumented API can be used to enumerate processes? A EnumProcesses() A EnumProcesses() B WTSEnumerateProcessesEx() B WTSEnumerateProcessesEx() C NtQuerySystemInformation() C NtQuerySystemInformation() 62 Unit Review Answers Q: What undocumented API can be used to enumerate processes? A: EnumProcesses() B: WTSEnumerateProcessEx() C: NtQuerySystemInformation() 62 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: installed software, sourcing location, listing compilation, operational decision
Summary: The unit outlines the learning objectives for a module on identifying and listing installed software on Windows systems. It specifies goals such as locating software, compiling lists of other programs, and making operational decisions based on those findings.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Look at where installed software is located Compile a listing of installed software Determine if an operation should continue 66 Objectives The objectives for this module are to know where to look for installed software, compile a listing of all installed programs, and determine if an operation should continue given the presence, or absence, of software. 66 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: installed software, listing of installed software, compile a listing, determine if an operation should continue
Summary: The unit outlines the learning objectives for a module focused on identifying and listing installed software on a Windows system. It specifies goals such as locating software, compiling lists of other programs, and making operational decisions based on those findings.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Look at where installed software is located Compile a listing of installed software Determine if an operation should continue 66 Objectives The objectives for this module are to know where to look for installed software, compile a listing of all installed programs, and determine if an operation should continue given the presence, or absence, of software. 66 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: learning objectives, installed software, listing software, SEC679
Summary: The unit describes learning objectives for identifying and listing installed software on a Windows system. It outlines goals such as locating installation paths, compiling lists of software, and determining operational feasibility.
Excerpt:
Visual caption: A slide outlining the learning objectives for a module on identifying and listing installed software. Visible text: Objectives; Our objectives for this module are:; Look where installed software is located; Compile a listing of installed software; Determine if an operation should continue; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: C:\Program Files, application inventory, system purpose inference, research VM indicators
Summary: The unit describes how analyzing the contents of the 'C:\Program Files' directory can provide information about installed applications and system purpose. It highlights that specific software like Notepad++, Process Hacker, and VMware may indicate a research environment.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control C:\Program Files 69 C:\Program Files This screenshot shows the contents of the Program Files directory. The directory contains 29 entries, which could be a possible indicator that there are at least 29 applications that have been installed on this system; at least 29 items because some folders could easily hold other programs. If your tool was collecting this information then it would allow a red team operator to get a glimpse as to what 64-bit applications are here, and based on the applications, a guess could be made as to what the system’s purpose is. Seeing applications like Notepad++, Process Hacker,

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: C:\Program Files, application inventory, system purpose identification, research VM indicators
Summary: The unit describes how analyzing the contents of the C:\Program Files directory can provide information about installed applications and system purpose. It highlights that specific software like Notepad++, Process Hacker, and VMware may indicate a research environment.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control C:\Program Files 69 C:\Program Files This screenshot shows the contents of the Program Files directory. The directory contains 29 entries, which could be a possible indicator that there are at least 29 applications that have been installed on this system; at least 29 items because some folders could easily hold other programs. If your tool was collecting this information then it would allow a red team operator to get a glimpse as to what 64-bit applications are here, and based on the applications, a guess could be made as to what the system’s purpose is. Seeing applications like Notepad++, Process Hacker,

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Program Files (x86), 32-bit applications, statement of intent/purpose
Summary: The unit describes the analysis of the Program Files (x86) directory to identify installed 32-bit applications. It notes that the presence of development software in this directory can provide insights into the system's purpose.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control C:\Program Files (x86) 70 C:\Program Files (x86) This screenshot shows the contents of the Program Files x86 directory. This directory contains 34 entries, which could indicate that there are at least 34 applications installed on this system that are 32-bit. An operator might be able to make a better educated guess as to what this system is being used for after seeing several entries for development software. 70 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Current State of the Art Tools, Profit driven, Community driven, summary, Huntress Labs, PE-sieve
Summary: The unit describes current state-of-the-art tools for security analysis, comparing profit-driven and community-driven options. It specifically mentions Huntress Labs and PE-sieve as examples of these categories.
Excerpt:
Visual caption: A slide titled 'Current State of the Art Tools' showing a comparison between profit-driven and community-driven tools, with specific examples like Huntress Labs and PE-sieve. Visible text: Current State of the Art Tools; Profit driven; Huntress Labs; Community driven; PE-sieve; SEC701 Alt/source label:

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NTFS Directory Entries, CreateDirectory
Summary: The unit describes the structure of NTFS directory entries and how they are managed via APIs like CreateDirectory, CreateDirectoryEx, and CreateDirectoryTransacted. It explains that each directory contains a table of file names and supports hard links.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control NTFS Directory Entries NTFS, the design for directories and files and the links between them NTFS, the design for directories and files and the links between them CreateDirectory CreateDirectory The NT File System keeps track of the directories and any child directories that might exist on the file system in a directory tree. Each directory has a table that is used to keep track of what is held in that directory. The table holds entries with names of files. CreateDirectoryEx CreateDirectoryEx CreateDirectoryTransacted CreateDirectoryTransacted 76 NTFS Directory Entries You might already be familiar with h

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NTFS Directory Entries, CreateDirectory, CreateDirectoryEx, CreateDirectoryTransacted
Summary: The unit describes the structure of NTFS directory entries and how the file system tracks directories and child directories. It mentions specific API calls like CreateDirectory, CreateDirectoryEx, and CreateDirectoryTransacted.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'NTFS Directory Entries' explaining the structure of directory entries in the NTFS file system. Visible text: NTFS Directory Entries; NTFS, the design for directories and files and the links between them; The NT file System keeps track of the directories and any child directories that might exist on the file system tree. Each directory has a table used to keep tr; CreateDirectory; CreateDirectoryEx; CreateDirectoryTransacted; SEC701 | Red-Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: OS Information, Process Enumered, CreateToolhelp, WTSEnum, User Information
Summary: The text lists a course roadmap for gathering operating system information, including service packs, process enumeration, and software identification. It also outlines upcoming modules in the section on Windows Tool Development, specifically focusing on user information retrieval.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 88 This module will discuss the importance and benefits of gathering information abo

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: lmaccess.h, lmuse.h, NetGroupGetUsers, NetUseEnum, NetLocalGroupGetMembers, NetUseGetInfo
Summary: The unit discusses specific Windows header files (lmaccess.h and lmuse.h) and associated APIs for querying user and group information. It highlights that these headers provide a variety of functions to gather system information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Additional Information Additional headers and APIs that could be of interest Additional headers and APIs that could be of interest lmaccess.h lmaccess.h lmuse.h lmuse.h NetGroupGetUsers NetGroupGetUsers NetUseEnum NetUseEnum NetLocalGroupGetMembers NetLocalGroupGetMembers NetUseGetInfo NetUseGetInfo 96 Additional Information The lmaccess and the lmuse header files offer additional APIs that might be of interest when querying user and user group information. The listing on the slide is not an exhaustive list but merely a small sampling of what else is out there that can be used. Depending on the informatio

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: OS Information, Process Enumered, Service Packs/Hotfixes, Lab 2.1-2.5, Tool Development
Summary: The unit outlines a curriculum for gathering operating system information, including service packs, hotfixes, patches, and process enumeration. It lists specific labs related to tool development for identifying installed software, directory walks, user information, and network details.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 101 In this module, we will discuss how to enumerate services and tasks during the e

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows services, Windows Tasks, enumerate services, compare services and processes
Summary: This unit outlines the learning objectives for a module on Windows services and tasks. It covers understanding service definitions, comparing them to processes, and methods for enumerating both.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Understand Windows services Compare services and processes Understand Windows Tasks Discuss how to enumerate services and tasks 102 Objectives The objectives for this module are to understand what a Windows service is, compare services and processes, understand what Windows Tasks are, and how to enumerate them all. 102 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows services, processes, comparison of services vs processes, Windows Tasks, sec670
Summary: This unit outlines the learning objectives for a module on Windows services, processes, and tasks. It covers understanding these components and methods for enumerating them.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Understand Windows services Compare services and processes Understand Windows Tasks Discuss how to enumerate services and tasks 102 Objectives The objectives for this module are to understand what a Windows service is, compare services and processes, understand what Windows Tasks are, and how to enumerate them all. 102 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows services, processes, Windows Tasks, enumeration
Summary: The unit describes learning objectives for a module focused on Windows services and tasks. It covers understanding the differences between services and processes, as well as enumeration techniques.
Excerpt:
Visual caption: A slide outlining the learning objectives for a module on Windows services and tasks. Visible text: Objectives; Understand Windows services; Compare services and processes; Understand Windows Tasks; Discuss how to enumerate services and tasks Alt/source label:

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: service enumeration, vulnerability identification, AV/EDR detection, privilege escalation, persistence
Summary: The text discusses the importance of service enumeration during a red teaming operation to identify target purpose, potential vulnerabilities for privilege escalation or persistence, and the presence of security software like AV/EDR.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Service Enumeration Why enumerate services? Why enumerate services? Awareness Awareness Purpose Purpose The better awareness you have the more successful your operation. Detect services that could be vulnerable or ones that could belong to AV/EDR. The purpose of a target will determine how it is most likely being used. It could also indicate if the target is high visibility or low. 104 Service Enumeration We typically conduct service enumeration for similar reasons that we conduct process enumeration. Services, just like processes, can tell us what a target’s purpose is or how it is being used. Certain se

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: service enumeration, target purpose identification, vulnerability detection, security product awareness
Summary: The unit discusses the importance of awareness regarding services on a target system to determine its purpose and identify potential vulnerabilities or security software. It highlights how specific services (like DHCP, DNS) can indicate server roles, while others might reveal the presence of aware AV/EDR products.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Service Enumeration Why enumerate services? Why enumerate services? Awareness Awareness Purpose Purpose The better awareness you have the more successful your operation. Detect services that could be vulnerable or ones that could belong to AV/EDR. The purpose of a target will determine how it is most likely being used. It could also indicate if the target is high visibility or low. 104 Service Enumeration We typically conduct service enumeration for similar reasons that we conduct process enumeration. Services, just like processes, can tell us what a target’s purpose is or how it is being used. Certain se

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows services, enumerating services, Windows Tasks, SEC679
Summary: The unit provides a summary of a module covering Windows services and tasks. It covers the definition of service types, planning for service-related activities, and techniques for enumerating both services and tasks.
Excerpt:
Visual caption: A summary slide for a module on Windows services and tasks. Visible text: Module Summary; Discussed what Windows services are; Planned about services and processes; Discussed what Windows Tasks are; Discussed enumerating services and tasks; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows services, Windows Tasks, enumerating services, API usage
Summary: The unit covers the definition and purpose of Windows services and tasks, as well as the methods for enumerating them. It mentions specific APIs used for enumeration.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed what Windows services are Discussed what Windows services are Learned about services and processes Learned about services and processes Discussed what Windows Tasks are Discussed what Windows Tasks are Discussed enumerating services and tasks Discussed enumerating services and tasks 108 Module Summary In this module, we discussed very briefly what services and tasks are. We also discussed why we would want to enumerate them, and the APIs involved for enumerating services and tasks. 108 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows services, tasks, enumeration, api usage
Summary: The unit covers the definition and purpose of enumeration of Windows services and tasks. It identifies the specific APIs used for enumerating these components.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed what Windows services are Discussed what Windows services are Learned about services and processes Learned about services and processes Discussed what Windows Tasks are Discussed what Windows Tasks are Discussed enumerating services and tasks Discussed enumerating services and tasks 108 Module Summary In this module, we discussed very briefly what services and tasks are. We also discussed why we would want to enumerate them, and the APIs involved for enumerating services and tasks. 108 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: OS Information, Process Enumeration, CreateToolhelp, WTSEnum, FileFinder, Windows Tool Development
Summary: The text outlines a curriculum for gathering operating system information, including service packs, process enumeration, installed software, and network details. It lists specific labs related to tool development for identifying these components.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 115 This module will look at how to gather information about the network and the tar

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: network information, NIC configurations, statement of objectives
Summary: The unit outlines the learning objectives for a module focused on gathering network information and NIC configurations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Gather network information Gather NIC configurations 116 Objectives The objectives for this module are to determine how to gather any network information we can, as well as the target’s NIC configurations. 116 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IP Helper API, GetIpStatistics, GetAdapterAddresses, NIC configuration, PowerShell cmdlets, netstat -e
Summary: The unit describes methods for gathering network interface card (NIC) information and configuration details from a Windows system. It highlights the use of PowerShell cmdlets, command-line utilities like netstat and ipconfig, and specifically focuses on Win32 APIs within the IP Helper header file such as GetIpStatistics and GetAdapterAddresses.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control NIC Information/Configuration IP Helper header file offers many great APIs for us to use. IP Helper header file offers many great APIs for us to use. GetIpStatistics GetIpStatistics IPHLPAPI_DLL_LINKAGE ULONG GetIpStatistics( _Out_ PMIB_IPSTATS Statistics ); GetAdaptersAddresses( _In_ ULONG Family, _In_ ULONG Flags, _In_ PVOID Reserved, _Inout_ PIP_ADAPTER_ADDRESSES AdapterAddresses, _Inout_ PULONG SizePointer ); GetAdapterAddresses GetAdapterAddresses 118 NIC Information/Configuration VMs are being used more and more these days in production and if you happen to get access to a VM in production, you migh

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IP Helper API, GetIpStatistics, GetAdapterAddresses, PowerShell Get-NetAdapter, netstat -e
Summary: The unit describes methods for gathering network interface card (NIC) information and configuration details using various tools and APIs. It highlights the use of PowerShell cmdlets, Windows command-line utilities like netstat and ipconfig, and specifically focuses on Win32 APIs within the IP Helper header file.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control NIC Information/Configuration IP Helper header file offers many great APIs for us to use. IP Helper header file offers many great APIs for us to use. GetIpStatistics GetIpStatistics IPHLPAPI_DLL_LINKAGE ULONG GetIpStatistics( _Out_ PMIB_IPSTATS Statistics ); GetAdaptersAddresses( _In_ ULONG Family, _In_ ULONG Flags, _In_ PVOID Reserved, _Inout_ PIP_ADAPTER_ADDRESSES AdapterAddresses, _Inout_ PULONG SizePointer ); GetAdapterAddresses GetAdapterAddresses 118 NIC Information/Configuration VMs are being used more and more these days in production and if you happen to get access to a VM in production, you migh

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Win32 API, IP Helper, GetIpStatistics, GetAdapterAddresses, NIC Information
Summary: The unit describes Win32 API functions within the IP Helper header file used for retrieving network interface information. It specifically mentions GetIpStatistics and GetAdapterAddresses.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'NIC Information/Configuration' showing Win32 API functions for retrieving network interface information. Visible text: NIC Information/Configuration; IP Helper header file offers many great APIs for us to use.; GetIpStatistics; GetAdapterAddresses; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetInterfaceInfo, IPv4 enabled devices, IP_INTERFACE_INFO structure, ERROR_INSUFFICIENT_BUFFER, dwOutBufLen
Summary: The text describes the GetInterfaceInfo API function used to retrieve a list of IPv4-enabled network interfaces on a target system. It details the parameter types, structure definitions (IP_INTERFACE_INFO), and specific error codes returned by the purpose of each parameter.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control GetInterfaceInfo API GetInterfaceInfo() GetInterfaceInfo() Gets list of IPv4 enabled devices Gets list of IPv4 enabled devices IPHLPAPI_DLL_LINKAGE DWORD GetInterfaceInfo( _Out_ PIP_INTERFACE_INFO pIfTable, _Inout_ PULONG dwOutBufLen ); typedef struct _IP_INTERFACE_INFO { LONG NumAdapters; IP_ADAPTER_INDEX_MAP Adapter[1]; } IP_INTERFACE_INFO, *PIP_INTERFACE_INFO; Has DWORD return type Has DWORD return type 119 GetInterfaceInfo API The GetInterfaceInfo function can be used to gather a list of interfaces on the target that have IPv4 enabled. As you can see by the SAL annotations, the function has two parame

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetInterfaceInfo, IPv4 enabled devices, IP_INTERFACE_INFO structure, buffer size handling, ERROR_INSUFFICIENT_BUFFER
Summary: The text describes the GetInterfaceInfo API function used to retrieve a list of IPv4-enabled network interfaces on a target system. It details the structure of the IP_INTERFACE_INFO struct and explains how to handle buffer sizes and potential error codes like ERROR_INSUFFICIENT_BUFFER.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control GetInterfaceInfo API GetInterfaceInfo() GetInterfaceInfo() Gets list of IPv4 enabled devices Gets list of IPv4 enabled devices IPHLPAPI_DLL_LINKAGE DWORD GetInterfaceInfo( _Out_ PIP_INTERFACE_INFO pIfTable, _Inout_ PULONG dwOutBufLen ); typedef struct _IP_INTERFACE_INFO { LONG NumAdapters; IP_ADAPTER_INDEX_MAP Adapter[1]; } IP_INTERFACE_INFO, *PIP_INTERFACE_INFO; Has DWORD return type Has DWORD return type 119 GetInterfaceInfo API The GetInterfaceInfo function can be used to gather a list of interfaces on the target that have IPv4 enabled. As you can see by the SAL annotations, the function has two parame

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: ProcMon, Sysinternals Suite, process behavior, program flaws
Summary: This unit introduces Lab 1.2, which focuses on using Process Monitor (ProcMon) from the Sysinternals Suite to observe process behavior and identify program flaws during startup or OS boot.
Excerpt:
Lab 1.2: ProcMon Process Monitor is one of the tools that comes bundled with the Systinternals Suite and is great for seeing what a process is doing when it starts up. ProcMon also has the ability to monitor what is happening when the OS starts. Please refer to the eWorkbook for the details of the lab. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 1.2: ProcMon Observe how ProcMon can be used to spot flaws with a program. Observe how ProcMon can be used to spot flaws with a program. Please refer to the eWorkbook for the details of this lab. 31 31 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetNumberOfInterfaces, IPHLPAPI_DLL_LINKAGE, PDWORD, out parameter, loopback adapter
Summary: This unit describes the GetNumberOfInterfaces API function for identifying the number of network interfaces on a Windows system. It explains the usage of an out parameter to retrieve the count and notes that it includes logical interfaces and loopback adapters.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control GetNumberOfInterfaces API GetNumberOfInterfaces GetNumberOfInterfaces Grabs the number of interfaces Grabs the number of interfaces IPHLPAPI_DLL_LINKAGE DWORD GetNumberOfInterfaces( _Out_ PDWORD pdwNumIf ); // example DWORD dwCount = 0; GetNumberOfInterfaces(&dwCount); // error check Has DWORD return type Has DWORD return type 124 GetNumberOfInterfaces API If you wanted to run something quick and easy, the GetNumberOfInterfaces function would be it. The only parameter you need to worry about is an out parameter. The function will write to it the number of interfaces that have been discovered on the local 

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetNumberOfInterfaces API, PDWORD, loopback adapter, logical interfaces
Summary: The unit describes the GetNumberOfInterfaces API function for identifying the number of network interfaces on a local machine. It details the technical specifications, including its return type (DWORD) and parameter types (PDWORD). The text also explains the differences between this function and others like GetAdaptersInfo and GetInterfaceInfo regarding loopback interface inclusion.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control GetNumberOfInterfaces API GetNumberOfInterfaces GetNumberOfInterfaces Grabs the number of interfaces Grabs the number of interfaces IPHLPAPI_DLL_LINKAGE DWORD GetNumberOfInterfaces( _Out_ PDWORD pdwNumIf ); // example DWORD dwCount = 0; GetNumberOfInterfaces(&dwCount); // error check Has DWORD return type Has DWORD return type 124 GetNumberOfInterfaces API If you wanted to run something quick and easy, the GetNumberOfInterfaces function would be it. The only parameter you need to worry about is an out parameter. The function will write to it the number of interfaces that have been discovered on the local 

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NIC configuration, network information, arp, ipconfig, netstat
Summary: The unit describes the importance and methods for gathering network information, specifically focusing on target NIC configurations. It notes that this knowledge serves as a foundation for developing custom tools like arp, ipconfig, and netstat.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed how to gather information about the network Discussed how to gather information about the network Discussed how to gather NIC information about the target Discussed how to gather NIC information about the target 125 Module Summary In this module, we discussed the why and how of gathering information about a target’s NIC configuration, as well as any other information we can gather about the network overall. The information presented in this module can be the foundations for creating tools like arp, ipconfig, netstat, etc. 125 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a 

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NIC configuration, network information, arp, ipconfig, netstat
Summary: The unit covers the methodology and technical details for gathering network information, specifically focusing on NIC configurations. It explains how this data can serve as a foundation for developing custom tools like arp, ip_config, and netstat.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed how to gather information about the network Discussed how to gather information about the network Discussed how to gather NIC information about the target Discussed how to gather NIC information about the target 125 Module Summary In this module, we discussed the why and how of gathering information about a target’s NIC configuration, as well as any other information we can gather about the network overall. The information presented in this module can be the foundations for creating tools like arp, ipconfig, netstat, etc. 125 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a 

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetAdapterAddresses(), Unit Review Answers, network adapter IP addresses
Summary: The unit contains the answers to a multiple-choice question regarding which Windows API functions are used to enumerate network adapter information, specifically identifying GetAdapterAddresses().
Excerpt:
Visual caption: A slide from a SANS Institute course showing the answer to a multiple-choice question about network adapter IP addresses. Visible text: Unit Review Answers; What API will give you an IP address for a network adapter?; GetAdapterAddresses(); GetNumberOfInterfaces(); GetIpStatistics() Alt/source label:

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetAdapterAddresses(), GetNumberOfInterfaces(), GetIpStatistics()
Summary: This unit contains a review section for the SANS SEC670 course, specifically focusing on questions regarding Windows network interface APIs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What API includes logical interfaces in its results? What API includes logical interfaces in its results? A GetAdapterAddresses() A GetAdapterAddresses() B GetNumberOfInterfaces() B GetNumberOfInterfaces() C GetIpStatistics() C GetIpStatistics() 129 Unit Review Questions Q: What API includes logical interfaces in its results? A: GetAdapterAddresses() B: GetNumberOfInterfaces() C: GetIpStatistics() 129 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: OS Information, Process Enumeration, CreateToolhelp, WTSEnum, Registry Information
Summary: The unit outlines a curriculum for gathering operating system information, including service packs, process enumeration, installed software, and network details. It lists specific labs related to tool development for identifying system components like the Windows Registry.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 130 This module will discuss how to enumerate the Windows Registry to find critical 

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Registry, survey tool, information gathering, privilege levels
Summary: The text discusses the importance of the Windows Registry as a source of information for survey tools. It highlights that while some sections require administrative privileges, much data is accessible to basic users.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Registry Information Troves of information Troves of information The Windows Registry contains troves of information that can arguably be deemed critical to your survey tool. The registry is so important that even the system itself relies on information found in the registry. 132 Registry Information The registry was discussed in tremendous detail during Section 1, along with the APIs needed to enumerate practically everything in it. It is being included here during this day as a brief reminder that it should not be forgotten about when conducting your survey. The registry is an excellent source for colle
