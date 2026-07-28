# Atlas Material — recon (part 5)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: recon
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS, SystemProcessInformation, undocumented API, process enumeration
Summary: The unit discusses the use of NtQuerySystemInformation, a native API for process enumeration, and its associated undocumented SYSTEM_INFORMATION_CLASS enum. It highlights the risks and benefits of using undocumented APIs for stealthier process enumeration in red teaming.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Undocumented Methods There are more stealthy methods to enumerate processes. There are more stealthy methods to enumerate processes. NtQuerySystemInformation NtQuerySystemInformation A native API that offers incredible detail about processes and so much more. Native APIs are risky but might be worth the risk due to what they return. SYSTEM_INFORMATION_CLASS SYSTEM_INFORMATION_CLASS The enum that determines what information the native API is going to retrieve for us. It is not officially documented, but many have researched and documented it on their own. 55 Undocumented Methods Native APIs tend to be very

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: OS Information, Process Enumeration, Service Packs/Hotfixes, Tool Development, SANS SEC670
Summary: The unit outlines a course roadmap for gathering operating system information, including service packs, process enumeration, installed software, and network details. It lists specific labs related to tool development for Windows implants and introduces the next module on getting to know your target.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 4 In this module, we will dive into how to gather OS specific information and why it

=== UNIT 3 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: process enumeration, kernel structures, local and remote systems
Summary: The unit covers the importance of process enumeration, kernel structures for representing processes in system address space, and various methods for enumerating processes on local and remote systems.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed the reason for enumerating processes Discussed the reason for enumerating processes Explored the structures the kernel uses to represent processes Explored the structures the kernel uses to represent processes Explored various methods for process enumeration Explored various methods for process enumeration 60 Module Summary In this module, we discussed why it is important to enumerate processes on a system, the structures the kernel uses to represent processes in system address space, and several methods to enumerate processes on local and remote systems. 60 © SANS Institute 2024 

=== UNIT 4 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: installed software location, listing of installed software, problem-solving logic
Summary: The unit outlines the learning objectives for a module focused on identifying and listing installed software on a Windows system. It specifies goals such as locating software, compiling lists of inventory, and making operational decisions based on software presence.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Look at where installed software is located Compile a listing of installed software Determine if an operation should continue 66 Objectives The objectives for this module are to know where to look for installed software, compile a listing of all installed programs, and determine if an operation should continue given the presence, or absence, of software. 66 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: OS information, public methods, undocumented methods, system information
Summary: The unit outlines the learning objectives for a module on identifying target system information, including OS version and service packs. It covers both public and undocumented methods for gathering this information, noting differences in report reliability.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Discuss the importance of determining OS information Explore public methods to retrieve information about the system Explore undocumented method to retrieve information about the system 5 Objectives The objectives for this module are to understand how important it is to determine what OS version your target is running and/or what service pack your target has, explore a few public methods for retrieving system information, as well as explore some undocumented methods. There are some methods that are more reliable than others, as well as some methods that might

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: C:\Program Files, application inventory, system purpose inference, research VM indicators
Summary: The unit describes how analyzing the contents of the C:\Program Files directory can provide information about installed applications and the system's purpose. It highlights that identifying specific software like Notepad++, Process Hacker, or VMware suggests a research environment.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control C:\Program Files 69 C:\Program Files This screenshot shows the contents of the Program Files directory. The directory contains 29 entries, which could be a possible indicator that there are at least 29 applications that have been installed on this system; at least 29 items because some folders could easily hold other programs. If your tool was collecting this information then it would allow a red team operator to get a glimpse as to what 64-bit applications are here, and based on the applications, a guess could be made as to what the system’s purpose is. Seeing applications like Notepad++, Process Hacker,

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: NTFS Directory Entries, CreateDirectory
Summary: The unit describes the structure of NTFS directory entries and how they are managed via specific Windows APIs (CreateDirectory, CreateDirectoryEx, and CreateDirectoryTransacted). It explains that each directory contains a table of file names and supports hard links.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control NTFS Directory Entries NTFS, the design for directories and files and the links between them NTFS, the design for directories and files and the links between them CreateDirectory CreateDirectory The NT File System keeps track of the directories and any child directories that might exist on the file system in a directory tree. Each directory has a table that is used to keep track of what is held in that directory. The table holds entries with names of files. CreateDirectoryEx CreateDirectoryEx CreateDirectoryTransacted CreateDirectoryTransacted 76 NTFS Directory Entries You might already be familiar with h

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: host survey, reconnaissance, querying APIs, AV/EDR detection, custom tool development
Summary: The unit describes the importance of reconnaissance and host surveying to inform subsequent actions like privilege escalation. It introduces the concept of creating a custom recon tool that queries system components, such as installed applications (AV/EDR) and specific files or folders.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Survey Script Survey the host and determine where you are. Survey the host and determine where you are. Knowing the system that you are on is vital to the success of your operation. A host survey tool can query various components and report back its findings that can then be used to determine the next action. 6 Survey Script If you are a red teamer, or a penetration tester, or have taken SEC560, then you may already know that one of the first tasks that you would typically perform is some recon. Recon is such a broad term that can encompass many things, like users, networks, shares, etc. The focus at this

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: programmatically enumerate, directory enumeration, subdirectories, Red Teaming Tools
Summary: The text describes a lab exercise focused on programmatically enumerating directories and subdirectories to locate specific files. It is part of a Red Teaming Tools course covering Windows implants, shellcode, and C2.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control What’s the Point? What’s the point? 84 What’s the Point? The point of this lab was the explore how you can programmatically enumerate a directory to find a file, and if you had time, enumerate any subdirectories. 84 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: directory walk, FindFirstFile, NextFile, system root, API identification
Summary: The unit describes the purpose and methodology of performing a directory walk to locate files on a Windows system. It identifies FindFirstFile and FindNextFile as the primary APIs used for this task.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed why we would perform a directory walk Discussed why we would perform a directory walk Learned how to perform a directory walk to find a file Learned how to perform a directory walk to find a file Discovered the main APIs involved Discovered the main APIs involved 85 Module Summary In this module, we discussed the how to perform a directory walk and why we would do one in the first place. A recursive walk from the system root could take a while, but at the same time it could yield some great information. There were only three APIs involved with this, but there were two that did the

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: Windows 7 x86, Windows 10 x86_64, ntoskrnl.exe, Service Pack, WTS API family
Summary: The unit discusses the importance of gathering specific OS information, such as service packs and kernel versions (ntoskrnl.exe), to ensure payload compatibility and avoid system crashes. It highlights that API availability varies across different Windows versions, noting that some APIs like WTS are used for process enumeration.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control OS Information Windows 7 x86 or Windows 10 x86_64? Windows 7 x86 or Windows 10 x86_64? Service Pack Service Pack Kernel Version Kernel Version A collection of updates to be applied as patches for bugs or vulnerabilities. Also provide features to the OS. The ntoskrnl.exe is the kernel file itself. The file is typically located under C:\Windows\System32. 7 OS Information Perhaps one of the most important pieces of information to gather first would be the exact version of the operating system, if that is not known already. Typically, you would know at least some basic information about the target beforehand,

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: OS Information, Process Enumeration, CreateToolhelp, WTSEnum, FileFinder, Windows Tool Development
Summary: The unit lists a course roadmap for gathering operating system information, including service packs, process enumeration, installed software, and user information. It also outlines the development of Windows tools for various operational actions like persistence and evasion.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 88 This module will discuss the importance and benefits of gathering information abo

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: user information, net user, net localgroup, Administrator group, member of Administrator group, Domain admin, ad_attack, privilege escalation
Summary: The unit discusses gathering user information from a Windows system, including identifying members of the Administrators group and potential Domain Admins. It covers both command-line methods using 'net' commands and programmatic approaches for reconnaissance. The text highlights how this information is used for privilege escalation or lateral movement.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control User Information Who’s who on the system Who’s who on the system It is always a good idea to see what users are on the system. Limited privileged users are one thing, but finding out if a user is part of the Administrators group is great. You might even get lucky enough to see a Domain admin logged into a system! 90 User Information Another part of conducting recon is gathering user account information. From the command line, there are some common tools that can be used to do this, like the net command line utility. The net command does more than gather user information but if you pass in the net user or 

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Unit Review Answers, types of pipe, network operation, Named pipe, Anonymous pipe
Summary: The unit contains the answers to review questions regarding networking pipes, specifically identifying which types can operate over a network. It lists various pipe types such as half-pipe, named pipe, and anonymous pipe.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the answer to a question about types of pipes in networking. Visible text: Unit Review Answers; What type of pipe can operate over a network?; Half pipe; Named pipe; Anonymous pipe; SEC670 | Red Team Tactics. Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: WMI, CIM Schema, Win32 Schema, CIM_ prefix, Win32_ prefix, custom classes
Summary: The text describes the structure of WMI and CIM schemas in Windows, specifically distinguishing between CIM_ and Win32_ prefixes. It explains that developers can create custom classes within these schemas to manage objects.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 102 WMI and CIM Schemas Classes can be grouped together into what are called schemas. Classes can be grouped together into what are called schemas. CIM Schema CIM Schema Win32 Schema Win32 Schema Classes start with CIM_ and provide the definition for the Core and Common classes. Developers can create their own as well. Classes start with Win32_ and provide the definitions for the Extended CIM class specific for the Win32 environment. Developers can create their own here as well. WMI and CIM Schemas WMI and CIM classes are often grouped together to form what are called schemas, and they are typically speci

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Win32 Provider, Win32_Account, Win32_GroupPolicyObject, Win32_OperatingSystem, Win32_Process, Win32_Registry, Win32_Service, Win32_Thread
Summary: The unit describes the Win32 Provider and its associated classes used for retrieving Windows-specific data. It lists specific classes such as Win32_Account, Win32_GroupPolicyObject, and Win32_Process.
Excerpt:
Visual caption: A slide from a cybersecurity course explaining the Win32 Provider and its associated classes for Windows-specific data. Visible text: Win32 Provider and Classes; Class Name; Description; Win32_Account; Win32_GroupPolicyObject; Win32_OperatingSystem; Win32_Process; Win32_Registry; Win32_Service; Win32_Thread; SEC701: Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Win32 Provider, Win32_Process, Win32_Registry, Win32_Service, filtering mechanisms
Summary: This unit describes the Win32 Provider and its associated classes for retrieving Windows-specific data. It lists specific classes like Win32_Account, Win32_Process, and Win32_Service to gather information about users, processes, and system services. The text also explains how filters can be used to narrow down results from these classes.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 103 Win32 Provider and Classes The provider provides all data specific to Windows. The provider provides all data specific to Windows. Description Class Name Information about user and group accounts Win32_Account Relates to session and user accounts Win32_LoggedOnUser The Windows OS installed on the system Win32_OperatingSystem A process on the system Win32_Process The system registry on the system Win32_Registry A service on the system Win32_Service An executing thread in a process Win32_Thread Win32 Provider and Classes The Win32 provider is where we can fetch any data that might relate to the Windows 

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Get-WmiObject, WMI Queries, PowerShell, root\subscription, Win32_Process, win32_ntlogevent
Summary: The unit describes how to use PowerShell's Get-WmiObject cmdlet to test and execute WMI queries for identifying system components, processes, and log events. It highlights the utility of PowerShell as a development tool for simplifying the creation of complex WMI query strings.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 106 Testing WMI Queries Get‐WmiObject __EventFilter ‐Namespace root\subscription Get‐WmiObject __EventConsumer ‐Namespace root\subscription Get‐WmiObject __FilterToConsumerBinding ‐Namespace root\subscription Get‐WmiObject ‐Query "select * from Win32_Process where name='notepad.exe'" Get‐WmiObject ‐Query "select * from win32_ntlogevent where eventcode=4625 and \ logfile='security’ and message like %alice%” Can trigger logon events using smbclient \\\\#{target}\\C$ ‐U alice badpassword Testing WMI Queries PowerShell offers developers with perhaps the easiest method for testing WMI queries, thus saving us f

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: security descriptor, command-line utility, cmd.exe, sc.exe, tasklist.exe
Summary: The unit contains a multiple-choice question regarding command-line utilities for viewing security descriptors. It specifically lists options like cmd.exe, sc.exe, and tasklist.exe.
Excerpt:
Visual caption: A slide from a cybersecurity course showing a multiple-choice question about command-line utilities for viewing security descriptors. Visible text: Unit Review Answers; What command-line utility lets you view an object's security descriptor?; cmd.exe; sc.exe; tasklist.exe; SEC601 Alt/source label:

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: strings command, binary analysis, memory2.exe, SANS SEC-701
Summary: The unit contains a screenshot of a slide from a SANS Institute course showing the strings command output for a binary file named 'memory2.exe'. The text includes headers like Address, Length, Type, and String.
Excerpt:
Visual caption: A screenshot of a slide from a SANS Institute course showing the output of a strings command on a binary file. Visible text: Viewing Strings; Address; Length; Type; String; SANS SEC-701; memory2.exe Alt/source label:

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Getting to Know Your Target, Section 2 introduction, information gathering
Summary: This section introduces the concept of getting to know a target by creating custom tools for information gathering. It serves as introductory material for Section 2 of the SEC670 course.
Excerpt:
Getting to Know Your Target © 2024 Jonathan Reiter | All Rights Reserved | Version J01_05 Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control SEC670.2 Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control: 670.2 Welcome to Section 2 of SEC670. In this section, we will be getting to know the target very well by creating various tools to obtain detailed information. 1 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: OS Information, Process Enumeration, Service Packs, Lab 2.1-2.5, Windows Tool Development
Summary: The unit outlines a curriculum for gathering operating system information, including service packs, process enumeration, installed software, and network details. It lists specific labs related to tool development for identifying OS components. The section also includes a roadmap of topics like persistence and evasion.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 4 In this module, we will dive into how to gather OS specific information and why it

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: OS version identification, service pack detection, public vs. undocumented methods
Summary: This unit outlines the learning objectives for a module on identifying OS information and service packs using both public and undocumented methods. It emphasizes the importance of reliability and accuracy in these techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Discuss the importance of determining OS information Explore public methods to retrieve information about the system Explore undocumented method to retrieve information about the system 5 Objectives The objectives for this module are to understand how important it is to determine what OS version your target is running and/or what service pack your target has, explore a few public methods for retrieving system information, as well as explore some undocumented methods. There are some methods that are more reliable than others, as well as some methods that might

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: OS Information, Service Pack, Service Pack, Kernel Version, Windows 7 x86_64!, C:\Windows\System32
Summary: The unit contains a slide describing OS information gathering techniques for Windows systems, specifically highlighting fields like Service Pack, Kernel Version, and the system architecture.
Excerpt:
Visual caption: A slide from a SANS Institute course on OS information gathering techniques for Windows systems. Visible text: OS Information; Service Pack; Service Pack; Kernel Version; Windows 7 x86_64!; C:\Windows\System32 Alt/source label:

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Windows Version Mapping, OS version numbers, reference table
Summary: The unit provides a reference table mapping Windows OS versions to their internal version numbers (e.g., 6.1 for Windows 7). It explains that these numerical values are used when querying the target system's OS information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Versions Windows releases and their respective version numbers Windows releases and their respective version numbers Windows XP Windows Server 2003 Windows Vista / Server 2008 Windows 7 / Server 2008 R2 Windows 8 / Server 2012 Windows 8.1 / Server 2012 R2 Windows 10 / Server 2016 5.1 5.2 6.0 6.1 6.2 6.3 10 8 Windows Versions When you are querying the target to determine the specific version of the OS, you will not find something that tells you that the target is a Windows Vista system. Instead, you would be given back something like 6.1 to indicate Windows 7. The table is simply here for an easy r

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Windows Version Mapping, Internal Version Numbers, OS Querying
Summary: The unit provides a reference table mapping Windows OS versions to their internal version numbers (e.g., 6.1 for Windows 7). It explains that these numbers are used when querying the target system's OS information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Versions Windows releases and their respective version numbers Windows releases and their respective version numbers Windows XP Windows Server 2003 Windows Vista / Server 2008 Windows 7 / Server 2008 R2 Windows 8 / Server 2012 Windows 8.1 / Server 2012 R2 Windows 10 / Server 2016 5.1 5.2 6.0 6.1 6.2 6.3 10 8 Windows Versions When you are querying the target to determine the specific version of the OS, you will not find something that tells you that the target is a Windows Vista system. Instead, you would be given back something like 6.1 to indicate Windows 7. The table is simply here for an easy r

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: GetNativeSystemInfo, SYSTEM_INFO struct, WoW64/x64 differences, wProcessorArchitecture
Summary: The unit describes the GetNativeSystemInfo API and its usage for gathering system information in WoW64 and x64 environments. It details the SYSTEM_INFO structure, specifically highlighting fields like wProcessorArchitecture to identify processor types.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control GetNativeSystemInfo GetNativeSystemInfo GetNativeSystemInfo Gathers current system information Gathers current system information VOID GetNativeSystemInfo( _Out_ LPSYSTEM_INFO lpSystemInfo ); typedef struct _SYSTEM_INFO { [..SNIP..] DWORD dwPageSize; LPVOID lpMinimumApplicationAddress; LPVOID lpMaximumApplicationAddress; DWORD_PTR dwActiveProcessorMask; DWORD dwNumberOfProcessors; DWORD dwProcessorType; DWORD dwAllocationGranularity; WORD wProcessorLevel; WORD wProcessorRevision; } SYSTEM_INFO, *LPSYSTEM_INFO; Has VOID return type Has VOID return type 10 GetNativeSystemInfo The GetNativeSystemInfo API can

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Lab 2.1, OS Info, gathering information, eWorkbook reference
Summary: The unit contains a lab exercise titled 'OS Info' focused on gathering information about the operating system and target. It references an external eWorkbook for specific details.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 2.1: OS Info Gathering information about the OS and target Gathering information about the OS and target Please refer to the eWorkbook for the details of this lab. 14 Lab 2.1: OS Info Please refer to the eWorkbook for the details of the lab. 14 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: OS Information, Service Packs/Hotfixes/Patches, Process Enumeration, Lab 2.1-2.5, Windows Tool Development
Summary: The unit outlines a curriculum for gathering operating system information, including service packs, hotfixes, and patches. It lists specific labs and tools used to enumerate processes, software, installed services, and network information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 19 In this module, we will discuss how to gather information about service packs, ho

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: process enumeration, snapshot-based methods, limitations of detection
Summary: The text discusses the limitations of a specific process enumeration method used in red teaming. It highlights that missing newly created processes after a snapshot is taken is a major downside.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control What’s the Point? What’s the point? 50 What’s the Point? The point of the lab was to explore one of the more popular methods of enumerating processes. The major downside to this method is you can miss newly created processes after the snapshot has been taken. 50 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: WTSEnumerateProcessesEx, wtsapi32.h, remote process enumeration, WTS_PROCESS_INFO struct
Summary: The text describes the WTSEnumerateProcessesEx API from the wtsapi32.h header file, which is used to enumerate processes on local or remote systems. It details the parameters of the function, such as hServer, pLevel, SessionId, and ppProcInfo, along with the requirement for specific registry keys to allow remote queries. It also notes that memory must be freed using WTSEnumerateProcessesEx.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control WTSEnumerateProcessesEx API WTSEnumerateProcessesEx() WTSEnumerateProcessesEx() Windows Terminal Services Windows Terminal Services BOOL WTSEnumerateProcessesExA( _In_ HANDLE hServer, _Inout_ WORD *pLevel, _In_ DWORD SessionId, _Out_ LPSTR *ppProcessInfo, _Out_ DWORD *pCount ); typedef struct _WTS_PROCESS_INFO_EXA { [..SNIP..] DWORD NumberOfThreads; DWORD HandleCount; DWORD PagefileUsage; DWORD PeakPagefileUsage; DWORD WorkingSetSize; DWORD PeakWorkingSetSize; LARGE_INTEGER UserTime; LARGE_INTEGER KernelTime; Has BOOL return type Has BOOL return type 51 WTSEnumerateProcessesEx API There is an entire famil

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Windows Terminal Services, enumerate processes, query remote targets
Summary: The unit describes a lab exercise focused on enumerating processes using Windows Terminal Services. It highlights the utility of querying remote targets through this method.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control What’s the Point? What’s the point? 54 What’s the Point? The point of the lab was to explore another method to enumerate processes. Using the Windows Terminal Services is nice because you have the potential to query remote targets. 54 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: undocumented API, enumerate processes, EnumProcesses(), WTSEnumerateProcessEx(), NtQuerySystemInformation()
Summary: The unit contains a review section for the SEC670 course, specifically focusing on undocumented APIs used for process enumeration. It lists three specific functions: EnumProcesses(), WTSEnumerateProcessEx(), and NtQuerySystemInformation().
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What undocumented API can be used to enumerate processes? What undocumented API can be used to enumerate processes? A EnumProcesses() A EnumProcesses() B WTSEnumerateProcessesEx() B WTSEnumerateProcessesEx() C NtQuerySystemInformation() C NtQuerySystemInformation() 61 Unit Review Questions Q: What undocumented API can be used to enumerate processes? A: EnumProcesses() B: WTSEnumerateProcessEx() C: NtQuerySystemInformation() 61 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: undocumented API, enumerate processes, EnumProcesses(), WTSEnumerate_ProcessEx(), NtQuerySystemInformation()
Summary: This unit contains a review section for the SEC670 course, specifically focusing on undocumented APIs for process enumeration. It lists three specific functions: EnumProcesses(), WTSEnumerateProcessEx(), and NtQuerySystemInformation().
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What undocumented API can be used to enumerate processes? What undocumented API can be used to enumerate processes? A EnumProcesses() A EnumProcesses() B WTSEnumerateProcessesEx() B WTSEnumerateProcessesEx() C NtQuerySystemInformation() C NtQuerySystemInformation() 62 Unit Review Answers Q: What undocumented API can be used to enumerate processes? A: EnumProcesses() B: WTSEnumerateProcessEx() C: NtQuerySystemInformation() 62 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: OS Information, Process Enumeration, Lab 2.1-2.5, Windows Tool Development, Persistence, Evasion
Summary: The unit lists a roadmap for gathering operating system information, including service packs, process enumeration, installed software, and network details. It also outlines the development of Windows tools for various operational actions like persistence and evasion.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 65 Finding installed software can tell you a great deal about a target. Let us dive 

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: OS Information, Process Enumered, CreateToolhelp, WTSEnum, FileFinder, Section 2 roadmap
Summary: The unit contains a course roadmap for gathering operating system information, including service packs, process enumeration, and installed software. It also lists specific labs related to tool development and the curriculum for Section 2 of the training.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 65 Finding installed software can tell you a great deal about a target. Let us dive 

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: 32-bit, 64-bit, C:\Program Files, C:\Program Files (x86)
Summary: The unit describes common file paths for locating 32-bit and 64-1t applications on Windows systems. It specifically lists Program Files, Program Files (x86), and the root directory.
Excerpt:
Visual caption: A slide titled 'Where to Look?' outlining common file paths for finding 32-bit and 64-bit applications on a Windows system. Visible text: Where to Look?; C:\Program Files; C:\Program Files (x86); C:\; 32-bit and 64-bit applications Alt/source label:

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: File Explorer, user home directory, C:\, system directories
Summary: The unit contains a visual caption describing a screenshot of a file explorer window. It highlights the importance of identifying the user's home directory within system directories.
Excerpt:
Visual caption: A screenshot of a file explorer window showing various system directories and files, with accompanying text explaining the importance of finding the user's home directory. Visible text: C:\; File Explorer; Documents; Downloads; Desktop; Program Files; Python2; SEC70 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Program Files (x86), 32-bit applications, security analysis
Summary: The unit describes the analysis of the Program Files (x86) directory to identify installed 32-bit applications. It notes that the presence of 14 entries for development software can provide clues about the system's purpose.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control C:\Program Files (x86) 70 C:\Program Files (x86) This screenshot shows the contents of the Program Files x86 directory. This directory contains 34 entries, which could indicate that there are at least 34 applications installed on this system that are 32-bit. An operator might be able to make a better educated guess as to what this system is being used for after seeing several entries for development software. 70 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: course roadmap, OS info gathering, process enumeration, directory walking, Lab 2.1-2.5
Summary: The unit contains a course roadmap for gathering operating system information and a list of specific labs related to process enumeration, directory walking, and other system components. It also introduces the module on directory listing features in implants.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 73 In this module, we will discuss a feature for enumerating directories. Many impla
