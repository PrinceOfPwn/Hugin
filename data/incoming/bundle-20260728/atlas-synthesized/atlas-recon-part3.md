# Atlas Material — recon (part 3)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: recon
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Process Monitor, SEC701, Windows Implants, shellcode, Command and Control
Summary: The unit describes a slide from a SANS Institute course explaining the purpose of Process Monitor (ProcMon) for red teaming. It mentions specific topics like developing Windows implants, shellcode, and command and control.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'What's the Point?' explaining the purpose of using Process Monitor. Visible text: What's the Point?; SEC701: Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Registry access, boot process, logon process, application startup, poll for changes
Summary: This unit describes the timing and frequency of registry access by Windows components during boot, logon, and application startup. It also notes that new installations and constant polling for updates can trigger additional registry reads.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (2) The Registry holds configuration data that is read during four critical times. The Registry holds configuration data that is read during four critical times. Initial boot process Initial boot process Kernel boot process Kernel boot process Logon process Logon process Application startup Application startup These are not the only times that the registry is read. New application installations trigger registry access and some applications constantly poll the registry for changes for live updates. These are not the only times that the registry is read. New application installations trigger re

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Registry configuration, boot process, kernel initialization, user profiles, application startup, registry polling
Summary: The text describes the role of the Windows Registry as a configuration storage for critical system processes including boot, kernel initialization, and user profile loading. It highlights how various applications access registry keys during startup or through continuous polling. The section also notes that some security products use registry obfuscation to hide internal mechanisms.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (2) The Registry holds configuration data that is read during four critical times. The Registry holds configuration data that is read during four critical times. Initial boot process Initial boot process Kernel boot process Kernel boot process Logon process Logon process Application startup Application startup These are not the only times that the registry is read. New application installations trigger registry access and some applications constantly poll the registry for changes for live updates. These are not the only times that the registry is read. New application installations trigger re

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Registry, root keys, HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER
Summary: This unit describes the Windows Registry structure, specifically identifying and explaining the five predefined root keys (HKEY_USERS, HKEY_CURRENT_USER, HKEY_CLASSES_ROOT, HKEY_LOCAL_MACHINE, and HKEY_CURRENT_CONFIG).
Excerpt:
Visual caption: A slide from a SANS course titled 'The Registry (3)' explaining the five predefined root keys in Windows. Visible text: The Registry (3); HKEY_USERS; HKEY_CURRENT_USER*; HKEY_CLASSES_ROOT*; HKEY_LOCAL_MACHINE; HKEY_CURRENT_CONFIG* Alt/source label:

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HKEY_USER, HKU, HKCU, ProfileList, Security Identifier (SID), user enumeration
Summary: The text describes the structure and contents of the user profile information stored in the HKEY_USER (HKU) registry hive. It details how HKCU subkeys exist for each local user, including a system profile at HKU\.Default, and explains that the ProfileList key contains SIDs as subkey names.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (4) Deep dive: HKEY_USER (HKU) Deep dive: HKEY_USER (HKU) ProfilesDirectory ProfilesDirectory The HKU key will hold a subkey (HKCU) for each user profile on the local system. There is also a profile for the system that has its own subkey, HKU\.Default. Winlogon uses the system profile to determine various settings like the desktop background. ProfileList ProfileList 136 The Registry (4) The HKU key holds a wealth of user information. In fact, it holds user information for every user that has logged on to the local machine, as long as the user does not have a roaming profile with Active Direct

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HKEY_USER, HKU, HKCU, ProfileList, Security Identifier (SID), user enumeration
Summary: The text describes the structure and contents of the user profile information stored within the HKEY_USER (HKU) registry hive. It explains how HKCU subkeys exist for each local user, including a system profile at HKU\.Default, and identifies the ProfileList key as a source for enumerating user SIDs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (4) Deep dive: HKEY_USER (HKU) Deep dive: HKEY_USER (HKU) ProfilesDirectory ProfilesDirectory The HKU key will hold a subkey (HKCU) for each user profile on the local system. There is also a profile for the system that has its own subkey, HKU\.Default. Winlogon uses the system profile to determine various settings like the desktop background. ProfileList ProfileList 136 The Registry (4) The HKU key holds a wealth of user information. In fact, it holds user information for every user that has logged on to the local machine, as long as the user does not have a roaming profile with Active Direct

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HKEY_USER, ProfilesDirectory, ProfileList, s607
Summary: The unit describes a slide about the Windows Registry's HKEY_USER hive, specifically focusing on user profile information such as ProfilesDirectory and ProfileList. It is part of a course on developing custom tools for Windows.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'The Registry (4)' discussing HKEY_USER keys and user profile information. Visible text: The Registry (4); Deep dive: HKEY_USER (HKU); ProfilesDirectory; ProfileList; SEC607 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HKEY_CURRENT_USER, HKCU, slide content
Summary: The unit describes the Windows Registry's HKEY_CURRENT_USER hive, noting its scope and common subkeys like console, desktop, and printer.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'The Registry (5)' describing the HKEY_CURRENT_USER hive. Visible text: The Registry (5); HKEY_CURRENT_USER (HKCU); Created for each new login; Subkeys: console, desktop, control panel, identities, printer, etc. Alt/source label:

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HKEY_CURRENT_USER, HKCU, Ntuser.dat, user-specific configuration, subkeys: console, software, control panel
Summary: This unit provides a overview of the HKEY_CURRENT_USER (HKCU) registry hive, detailing its purpose for storing user-specific configuration and preferences. It describes how HKCU is created per login and maps to the Ntuser.dat file. The text also lists common subkeys like Software, Console, and Control Panel.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (5) Deep dive: HKEY_CURRENT_USER (HKCU)* Deep dive: HKEY_CURRENT_USER (HKCU)* Created for each new login Created for each new login This root key holds configuration information for the locally logged-on user regarding software configuration information and user preferences. They key points to the user profile, which is located at \Users\<username>\Ntuser.dat. Subkey under HKU Subkey under HKU Subkeys: console, software, control panel, identities, printers, keyboard layout, etc. Subkeys: console, software, control panel, identities, printers, keyboard layout, etc. 137 The Registry (5) The HKC

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HKEY_CURRENT_USER, HKCU, Ntuser.dat, user-specific configuration, subkeys: console, software, control panel
Summary: This unit provides a technical overview of the HKEY_CURRENT_USER (HKCU) registry hive, detailing its purpose for storing user-specific configurations and preferences. It describes the system's behavior regarding HKCU creation during login and its role in hosting subkeys like Console, Software, and Control Panel. The text also mentions that enumeration tools can be used to list all available subkeys.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (5) Deep dive: HKEY_CURRENT_USER (HKCU)* Deep dive: HKEY_CURRENT_USER (HKCU)* Created for each new login Created for each new login This root key holds configuration information for the locally logged-on user regarding software configuration information and user preferences. They key points to the user profile, which is located at \Users\<username>\Ntuser.dat. Subkey under HKU Subkey under HKU Subkeys: console, software, control panel, identities, printers, keyboard layout, etc. Subkeys: console, software, control panel, identities, printers, keyboard layout, etc. 137 The Registry (5) The HKC

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HKEY_CURRENT_CONFIG, HKCC, hardware profile, backwards compatibility
Summary: The text describes the HKEY_CURRENT_CONFIG (HKCC) registry key, explaining its role as a link to hardware profiles. It notes that while Windows no not support hardware profiles anymore, the key is maintained for backward compatibility with legacy applications.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (8) Deep dive: HKEY_CURRENT_CONFIG (HKCC)* Deep dive: HKEY_CURRENT_CONFIG (HKCC)* This root key is nothing more than a link to the hardware profile that is stored in HKLM: HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current. It's not prevalent today but Windows keeps it around in the name of backwards compatibility. 141 The Registry (8) The HKEY_CURRENT_CONFIG, or HKCC for short, root key is one of the three links to other root keys. HKCC is formally linked to the HKLM root key and since this linked key points to whatever the current hardware profile is, the root key path is: HKLM\SYSTEM\

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HKEY_PERFORMANCE_DATA, HKPD, RegQueryValue_Ex, RegQueryValueEx
Summary: The unit describes the Registry key HKEY_PERFORMANCE_DATA (HKPD) and its relationship with RegQueryValueEx. It notes that certain data is technically not stored in this specific location.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'The Registry' discussing the HKEY_PERFORMANCE_DATA key. Visible text: The Registry (9); Deep dive: HKEY_PERFORMANCE_DATA (HKPD); RegQueryValueEx; Technically not stored here; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Registry, REG_DWORD, REG_BINARY, REG_SZ
Summary: The unit describes the three most common Windows Registry key value types: REG_DWORD, REG_BINARY, and REG_SZ. It is presented as a slide from a cybersecurity course.
Excerpt:
Visual caption: A slide from a cybersecurity course explaining the three most common Windows Registry key value types: REG_DWORD, REG_BINARY, and REG_REZ_SZ. Visible text: The Registry (10); REG_DWORD; REG_BINARY; REG_SZ; SECY-7 | Red Team Tools Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Registry, registry keys, information retrieval
Summary: The unit provides an overview of the Windows Registry, including its structure and the types of information contained within it. It serves as a summary for a module covering registry-related data.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed the registry and information found within it. Discussed the registry and information found within it. 156 Module Summary In this module, we discussed what the registry is, many of the keys, and some of the information that can be found within the registry. 156 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo, KUSER_SHARED_DATA
Summary: The unit describes a bootcamp challenge focused on gathering system information using specific Windows APIs like GetProductInfo, GetWindowsDirectory, GetComputerName, and GetNativeSystemInfo. It also mentions an optional advanced task involving the KUSER_SHARED_DATA structure.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control OS Info Obtain complete information about your target. Use the following APIs: GetProductInfo GetProductInfo GetWindowsDirectory GetWindowsDirectory GetComputerName GetComputerName GetNativeSystemInfo GetNativeSystemInfo BONUS: KUSER_SHARED_DATA BONUS: KUSER_SHARED_DATA 159 OS Info This bootcamp challenge is about leveraging a familiar API that you learned about earlier to gather some information about your target. The real challenge comes in with the introduction of several new APIs that can be called to help gather system information. You will have to teach yourself how to use these ones. As a bonus, if

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo, KUSER_SHARED_DATA
Summary: The unit describes a bootcamp challenge involving the use of specific Windows APIs (GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo) to gather system information. It also mentions an optional advanced task involving the KUSER_SHARED_DATA structure.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control OS Info Obtain complete information about your target. Use the following APIs: GetProductInfo GetProductInfo GetWindowsDirectory GetWindowsDirectory GetComputerName GetComputerName GetNativeSystemInfo GetNativeSystemInfo BONUS: KUSER_SHARED_DATA BONUS: KUSER_SHARED_DATA 159 OS Info This bootcamp challenge is about leveraging a familiar API that you learned about earlier to gather some information about your target. The real challenge comes in with the introduction of several new APIs that can be called to help gather system information. You will have to teach yourself how to use these ones. As a bonus, if

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Dumpbin, PE-bear, PEview, CFF Explorer, WinDbg, !dh command, DLL analysis
Summary: This unit describes various tools for analyzing the structure of Dynamic-linked Libraries (DLLs) and other Portable Executable (PE) files, including Dumpbin, PEview, PE-bear, and CFF Explorer. It also mentions WinDbg's capability to parse executable images and dump headers using the !dh command.
Excerpt:
Dynamic-linked Libraries (3) There are a few tools available today that let you look at what is inside of a DLL. The tools do not just parse the structure of DLL files, but they can parse almost any type of PE file you throw at it. The dumpbin utility is a command-line tool that is typically available with a standard installation of Visual Studio. PEview is a GUI application with the bare necessities for viewing the file’s structure. The headers are easily identified allowing for simple navigation through them. PE-bear is a rich GUI application that is full of great features. You can load several PE files at the same time and manually browse the file of interest. Tabs organize the structure 

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: security descriptor, command-line utility, cmd.exe, sc.exe, tasklist.exe
Summary: The unit contains a multiple-choice question regarding command-line utilities for viewing security descriptors. It identifies specific tools like cmd.exe, sc.exe, and tasklist.exe as options.
Excerpt:
Visual caption: A slide from a cybersecurity course showing a multiple-choice question about command-line utilities for viewing security descriptors. Visible text: Unit Review Answers; What command-line utility lets you view an object's security descriptor?; cmd.exe; sc.exe; tasklist.exe; SEC601 Alt/source label:

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Win32 Provider, Win32_Account, Win32_OperatingSystem, Win32_Process, Win32_Registry
Summary: The unit describes the Win32 Provider and its associated classes for Windows-specific data. It lists specific classes such as Win32_Account, Win32_OperatingSystem, and Win32_Process.
Excerpt:
Visual caption: A slide from a cybersecurity course explaining the Win32 Provider and its associated classes for Windows-specific data. Visible text: Win32 Provider and Classes; Class Name; Description; Win32_Account; Win32_GroupPolicyObject; Win32_OperatingSystem; Win32_Process; Win32_Registry; Win32_Service; Win32_Thread; SEC701: Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Win32 Provider, Win32_Account, Win32_LoggedOnUser, Win32_OperatingSystem, Win32_Process, Win32_Registry, Win32_Service, Win32_Thread
Summary: This unit describes the Win32 Provider and its associated classes for retrieving Windows-specific data such as user accounts, operating systems, processes, registry keys, services, and threads. It explains how these classes can be used for system reconnaissance and that filters can be applied to specific classes to reduce noise and trigger events.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 103 Win32 Provider and Classes The provider provides all data specific to Windows. The provider provides all data specific to Windows. Description Class Name Information about user and group accounts Win32_Account Relates to session and user accounts Win32_LoggedOnUser The Windows OS installed on the system Win32_OperatingSystem A process on the system Win32_Process The system registry on the system Win32_Registry A service on the system Win32_Service An executing thread in a process Win32_Thread Win32 Provider and Classes The Win32 provider is where we can fetch any data that might relate to the Windows 

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Win32 Provider, Win32_Account, Win32_LoggedOnUser, Win32_Process, Win32_Registry, Win32_Service, Win32_Thread
Summary: The unit describes the Win32 Provider and its associated classes for retrieving Windows-specific data such as user accounts, operating systems, processes, registry keys, and services. It explains that these classes can be used for system reconnaissance and that filters can be used to narrow down specific events.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 103 Win32 Provider and Classes The provider provides all data specific to Windows. The provider provides all data specific to Windows. Description Class Name Information about user and group accounts Win32_Account Relates to session and user accounts Win32_LoggedOnUser The Windows OS installed on the system Win32_OperatingSystem A process on the system Win32_Process The system registry on the system Win32_Registry A service on the system Win32_Service An executing thread in a process Win32_Thread Win32 Provider and Classes The Win32 provider is where we can fetch any data that might relate to the Windows 

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WQL, Filtering Events, Query types, Data Query, Event Query, Vulnerability Query, schema
Summary: The unit describes the syntax and types of queries for Windows Query Language (WQL) used to filter events. It covers different query categories such as data, event, vulnerability, and schema queries.
Excerpt:
Visual caption: A slide titled 'Filtering Events Using WQL' explains the syntax and types of queries for Windows Query Language. Visible text: Filtering Events Using WQL; Windows Query Language; Extrinsic events can be queried normally; Intrinsic events must be polled at some defined interval; Data Query; Event Query; Vulnerability Query; Schema Query Alt/source label:

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Get-WmiObject, WMI Queries, root\subscription, Win32_Process, win32_ntlogevent
Summary: The unit describes how to test WMI queries using the Get-WmiObject cmdlet in PowerShell. It provides specific examples of querying processes, system events, and binding objects within the root\subscription namespace.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 106 Testing WMI Queries Get‐WmiObject __EventFilter ‐Namespace root\subscription Get‐WmiObject __EventConsumer ‐Namespace root\subscription Get‐WmiObject __FilterToConsumerBinding ‐Namespace root\subscription Get‐WmiObject ‐Query "select * from Win32_Process where name='notepad.exe'" Get‐WmiObject ‐Query "select * from win32_ntlogevent where eventcode=4625 and \ logfile='security’ and message like %alice%” Can trigger logon events using smbclient \\\\#{target}\\C$ ‐U alice badpassword Testing WMI Queries PowerShell offers developers with perhaps the easiest method for testing WMI queries, thus saving us f

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Get-WmiObject, WMI Queries, root\subscription, Win32_Process, win32_ntlogevent, smbclient
Summary: The unit describes how to use PowerShell's Get-WmiObject cmdlet to test and execute WMI queries for identifying processes, system events, and bindings. It highlights the ease of use provided by PowerShell for testing complex W queries before implementation in custom tools.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 106 Testing WMI Queries Get‐WmiObject __EventFilter ‐Namespace root\subscription Get‐WmiObject __EventConsumer ‐Namespace root\subscription Get‐WmiObject __FilterToConsumerBinding ‐Namespace root\subscription Get‐WmiObject ‐Query "select * from Win32_Process where name='notepad.exe'" Get‐WmiObject ‐Query "select * from win32_ntlogevent where eventcode=4625 and \ logfile='security’ and message like %alice%” Can trigger logon events using smbclient \\\\#{target}\\C$ ‐U alice badpassword Testing WMI Queries PowerShell offers developers with perhaps the easiest method for testing WMI queries, thus saving us f

=== UNIT 25 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: nmap, network scanning, information gathering, -sV, -sC, port 80,443
Summary: The unit contains a screenshot of terminal commands for network scanning and information gathering using Nmap. It specifically lists various flags such as -sV, -sC, and port-specific scans.
Excerpt:
Visual caption: A screenshot of a terminal window showing various command-line outputs related to network scanning and information gathering. Visible text: The Prior Art; nmap -sV --script=banner; nmap -sC -p 80,443; nmap -cc1 -p 80,443; nmap -sT -p 80,443; nmap -sP -p 80,443; nmap -sV -p 80,443; nmap -sC -p 80,443 Alt/source label:

=== UNIT 26 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: nmap, port scanning, server versions, http-title, http-methods, report-robots.txt
Summary: The unit contains a screenshot of a technical tutorial page featuring Nmap commands for network scanning and information gathering. The commands include port scanning, service version detection, and specific HTTP-related scripts.
Excerpt:
Visual caption: A screenshot of a technical tutorial page showing code snippets and terminal commands for network scanning and information gathering. Visible text: nmap -sT -Pn -p80,443 --script=http-title,http-methods,http-robots.txt,http-header; nmap -sV -p1024-65535,80,443 --script=100.000.000.000/24; nmap -sT -Pn -p80,443 --script=http-title,http-methods,http-robots.nuxt.com; nmap -sV -p1024-65535,80,443 --script=100.000.000.000/24 Alt/source label:

=== UNIT 27 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Nmap Scan Results, Port Status, Nmp Script Engine (NSE), -sV, -sC, --script=vuln
Summary: The unit contains a screenshot of terminal output from an Nmap scan. It details port status, service information, and the results of running NSE scripts to identify vulnerabilities.
Excerpt:
Visual caption: A screenshot of a terminal window displaying the output of an Nmap scan and other network reconnaissance tools. Visible text: Nmap Scan Results; Host Information; Port Status; Nmap Script Engine (NSE) scripts; Network Services; Nmap -p 1-65535, -sV, -sC, --script=vuln; Nmap -p 1-65535, -sV, -sC, --script=vuln Alt/source label:

=== UNIT 28 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Nmap Scan, Banner Grabbing, Banner Grabbing, DNS Enumeration, Nmap Scripting Engine (NSE), Whois Lookup, HTTP Header header analysis, Port Scanning
Summary: The unit contains a list of information gathering and enumeration techniques including Nmap, banner grabbing, and DNS enumeration. It specifically mentions tools like Netcat and TelerK.Net.Web.Forms for service discovery.
Excerpt:
Visual caption: A screenshot of a technical documentation page detailing various methods for information gathering and enumeration in a cybersecurity context. Visible text: Browse-host-information [PDF]; Information Gathering; Nmap Scan; Banner Grabbing; Information Gathering Tools; DNS Enumeration; Nmap Scripting Engine (NSE); Whois Lookup; HTTP Header Analysis; Enumeration of Services; Netcat; Telerik.Net.Web.Forms; Port Scanning; Service Discovery; Network Mapping; View Source Code; Information Gathering Tools; Banner Grabbing; DNS Enumeration; Nmap Scripting Engine (NSE) Alt/source label:

=== UNIT 29 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: ls -la, /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers
Summary: The unit contains a tutorial page showing command-line interface outputs for Linux system files like /etc/passwd, /etc/shadow, /etc/group, and /etc/sudoers.
Excerpt:
Visual caption: A tutorial page showing a command-line interface and a terminal output for a Linux system, including an example of a directory listing. Visible text: DCeye Explorer; ls -la /etc/passwd; ls -l /etc/shadow; ls -l /etc/group; ls -l /etc/sudoers; ls -l /etc/shadow.bak Alt/source label:

=== UNIT 30 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Forest & Domain Trusts, Trusting (Resource) Domain, Certified (Account) Domain, Direction of Access, Direction of Trust, One-way trust, Two-way trust, Transitive
Summary: The unit describes a diagram illustrating the trust relationships between a Trusting (Resource) Domain and a Trusted (Account) Domain within a forest trust scenario. It details various types of trusts, including one-way, two-way, transitive, and non-transitive.
Excerpt:
Visual caption: A diagram illustrating the relationship between a Trusting (Resource) Domain and a Trusted (Account) Domain in a forest trust scenario. Visible text: Forest & Domain Trusts; Trusting (Resource) Domain; Certified (Account) Domain; Direction of Access; Direction of Trust; One-way trust; Two-way trust; Transitive; Non-transitive Alt/source label:

=== UNIT 31 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: nmap, port scanning, service discovery, reverse shell script
Summary: The unit contains a collection of command-line examples for network scanning and enumeration using Nmap. It includes specific flags like -sT, -Pn, -sV, -sC, and -sS to identify services and ports.
Excerpt:
Visual caption: A series of screenshots showing various command-line tools and code snippets for network scanning, enumeration, and exploitation techniques. Visible text: nmap -sT -Pn -p1024-65535; nmap -sV -sC -p80,443; nmap -sP -p1024-65535; nmap -sS -p1024-65535; -v 1.0.0.0; python script for a reverse shell; nmap -sV -sC -p80,443; nmap -sP -p1024-65535; nmap -sS -p1024-65535; nmap -sV -sC -p1024-6535 Alt/source label:

=== UNIT 32 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: external recon, organisational vs technical, passive vs active, proxy/VPN usage
Summary: The unit describes the two main facets of external reconnaissance: organizational and technical. It defines passive and active methods for gathering information, highlighting the risks associated with active techniques.
Excerpt:
III. External Recon: 1. External Recon: If your engagement is not being kicked off via an “assume breach” methodology and you need to gain initial entry into the target network yourselves, some external reconnaissance will be required. The reconnaissance phase is vital as it provides information that will be leveraged to exploit the target or gain access to data. There are two main facets of recon - organisational and technical. Organisational During "organisational" recon, you’re focused on collecting information about the organisation. This can include the people who work there (names, jobs and skills), the organisational structure, site locations and business relationships. Technical Duri

=== UNIT 33 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: External Recon, Organisational, Technical, Passive, Active
Summary: The unit describes various categories of external reconnaissance techniques, specifically highlighting organizational, technical, passive, and active methods.
Excerpt:
Visual caption: A page from a training manual or guide describing the different types of external reconnaissance in cybersecurity. Visible text: III. External Recon:; 1. External Recon:; Organisational; Technical; Passive; Active Alt/source label:

=== UNIT 34 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: PowerShell, Find-DomainShare, CheckShareAccess, remote domain share, ls -dc.1.cyberhotic.io
Summary: The unit contains a screenshot of terminal commands used to enumerate remote domain shares and check access permissions. It specifically shows PowerShell scripts or commands for identifying share locations and listing files on a specific server.
Excerpt:
Visual caption: A screenshot of a terminal showing the execution of PowerShell commands to find and list files on a remote domain share. Visible text: Find-DomainShare; CheckShareAccess; powershell Find-DomainShare -ComputerDomain in cyberhotic.io -CheckShareAccess; ls \dc.1.cyberhotic.io data\ Alt/source label:

=== UNIT 35 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: SPF, DMARC, DKIM, Social Media, reconnaissance
Summary: The unit describes common weaknesses in email security protocols like SPF, DMARC, and DKIM, as well as social media for information gathering. It includes an exercise to perform additional external reconnaissance.
Excerpt:
Visual caption: A screenshot of a technical training document discussing email security and social engineering techniques. Visible text: subdomains. Weak email security (SPF, DMARC and DKIM); 3. Social Media.; EXERCISE: Conduct some additional external reconnaissance Alt/source label:

=== UNIT 36 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: SPF/DMARC/DKIM, Spoofcheck tool, LinkedIn reconnaissance, pretext generation, security-driven emotions
Summary: The text discusses identifying weak email security protocols (SPF, DMARC, DKIM) using tools like Spoofcheck to facilitate spoofing. It also covers social engineering techniques, including gathering intelligence from LinkedIn for pretext creation and leveraging emotional triggers like urgency or fear.
Excerpt:
subdomains. Weak email security (SPF, DMARC and DKIM) may allow us to spoof emails to appear as though they’re coming from their own domain. Spoofcheck is a Python tool that can verify the email security of a given domain. 3. Social Media: For several years, social engineering and phishing have been the most prolific methods for gaining access to a target environment. To prepare your own campaign, sites such as Linkedln are a goldmine of information because people expose a lot of professional (and sometimes personal) information about themselves. We love to demonstrate how good we are at Task X or managing Product Y - and this information is not only useful for knowing what products are bein

=== UNIT 37 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: MailSniper, domain ownership, subdomain identification, password spraying, O1W, EWS, EAS
Summary: The unit describes a tutorial on identifying domain ownership and subdomains using MailSniper. It highlights how to identify valid accounts for password spraying against OWA, EWS, and EAS services.
Excerpt:
Visual caption: A screenshot of a technical tutorial page explaining how to identify domain ownership and subdomains using tools like MailSniper. Visible text: This output shows one valid result for CYBER\lyates.; You can run this again and target -Domain DEV, which will also find valid results for:; cybertic.io; MailSniper can spray passwords against the valid accounts; identified using, Outlook Web Access (OWA), Exchange Web Services (EWS), and Exchange ActiveSync (EAS Alt/source label:

=== UNIT 38 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Nmap scan, Port 80/443, System Information, Shell access
Summary: The unit contains a technical document page featuring code snippets, network information tables, and system analysis instructions. It includes specific details regarding ports 80 and 443, Nmap scan results, and user account information.
Excerpt:
Visual caption: A technical document or tutorial page containing multiple code snippets, tables of network information, and a series of instructions for system analysis. Visible text: 123 Pages; Table of Contents; Network Information; Port 80 (HTTP); Port 443 (HTTPS); Nmap scan results; System Information; User Account Information; Shell access; Command line interface Alt/source label:

=== UNIT 39 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Get-Domain, PowerShell, domain object, forest name, DomainControllers
Summary: The unit contains a screenshot and description of the 'Get-Domain' PowerShell command. It details how to retrieve domain information such as name, forest, and domain controllers.
Excerpt:
Visual caption: A screenshot of a documentation page for the 'Get-Domain' PowerShell command, showing its output in a terminal window. Visible text: Get Domain; Returns a domain object for the current domain or the domain specified with -Domain. Useful information includes the domain name, the forest name and the domain; powershell Get-Domain; Forest: cyberbotic.io; DomainControllers: dc.2.dev.cyberbotic.io; DomainMode: Unknown; DomainModeLevel: 2; Parent: cyberbotic.io; Name: dev.cyberbotic.io Alt/source label:

=== UNIT 40 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: PowerShell, Get-DomainController, domain controller enumeration, Windows Server 2016
Summary: The unit contains a screenshot and text describing the PowerShell command 'Get-DomainController' used to enumerate domain controller information including Forest, Name, and OSVersion.
Excerpt:
Visual caption: A screenshot of a PowerShell command and its output showing domain controller information. Visible text: Get-DomainController; Returns the domain controllers for the current or specified domain.; beacone. powershell Get-DomainController | select Forest, Name, OSVersion | fl; Forest : cyberrotic.io; Name : dc-2.dev.cyberrotic.io; OSVersion : Windows Server 2016 Datacenter Alt/source label:
