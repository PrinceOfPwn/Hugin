# Atlas Material — privesc (part 2)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: privesc
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Win32 API, SeDebugPrivilege, LookupPrivilegeValue, OpenProcessToken, AdjustTokenPrivileges
Summary: The text describes how to programmatically enable or disable privileges using the Win32 API, specifically focusing on the SeDebugPrivilege. It identifies three key APIs: LookupPrivilegeValue, OpenProcessToken, and AdjustTokenPrivileges.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 95 Privileges: Programmatically Privileges can be enabled/disabled programmatically. Privileges can be enabled/disabled programmatically. LookupPrivilegeValue LookupPrivilegeValue When you have a set of privileges that are present, but listed as disabled, you can programmatically adjust those privileges to be enabled. The opposite is also true, but why limit yourself? OpenProcessToken OpenProcessToken AdjustTokenPrivileges AdjustTokenPrivileges Privileges: Programmatically With the help of the Win32 API, we can create programs that can enable or even disable privileges that are present in our access token

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Win32 API, LookupPrivilegeValue, OpenProcessToken, AdjustTokenPrivileges, SeDebugPrivilege
Summary: The unit describes how to programmatically enable or disable privileges using the Win32 API, specifically focusing on enabling SeDebugPrivilege. It details three primary APIs involved: LookupPrivilegeValue, OpenProcessToken, and AdjustTokenPrivileges.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 95 Privileges: Programmatically Privileges can be enabled/disabled programmatically. Privileges can be enabled/disabled programmatically. LookupPrivilegeValue LookupPrivilegeValue When you have a set of privileges that are present, but listed as disabled, you can programmatically adjust those privileges to be enabled. The opposite is also true, but why limit yourself? OpenProcessToken OpenProcessToken AdjustTokenPrivileges AdjustTokenPrivileges Privileges: Programmatically With the help of the Win32 API, we can create programs that can enable or even disable privileges that are present in our access token

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: LookupPrivilegeValue, SeDebugPrivilege, LUID, Winnt.h
Summary: This unit describes the Windows API function LookupPrivilegeValue, which is used to retrieve a locally unique identifier (LUID) for privilege constants like SeDebugPrivilege. It details the parameters lpSystemName, lpName, and lpLuid, along with its Boolean return type.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 96 LookupPrivilegeValue LookupPrivilegeValue LookupPrivilegeValue Gets the current LUID Gets the current LUID BOOL LookupPrivilegeValueA( _In_opt_ LPCSTR lpSystemName, _In_ LPCSTR lpName, _Out_ PLUID lpLuid ); // EXAMPLE if ( !LookupPrivilegeValue(...) ) { // code here } Has a Boolean return type Has a Boolean return type LookupPrivilegeValue Whenever you need to retrieve the locally unique identifier for a privilege constant or privilege name like SeDebugPrivilege, this is the function to use. It has a BOOL return type, so it is simple to error check. Simply wrap the function call inside the condition of

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: LookupPrivilegeValue, SeDebugPrivilege, LUID, luid pointer
Summary: The unit describes the Windows API function LookupPrivilegeValue, which is used to retrieve a locally unique identifier (LUID) for privilege constants like SeDebugPrivilege. It details the parameters of the function, including lpSystemName, lpName, and lpLuid.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 96 LookupPrivilegeValue LookupPrivilegeValue LookupPrivilegeValue Gets the current LUID Gets the current LUID BOOL LookupPrivilegeValueA( _In_opt_ LPCSTR lpSystemName, _In_ LPCSTR lpName, _Out_ PLUID lpLuid ); // EXAMPLE if ( !LookupPrivilegeValue(...) ) { // code here } Has a Boolean return type Has a Boolean return type LookupPrivilegeValue Whenever you need to retrieve the locally unique identifier for a privilege constant or privilege name like SeDebugPrivilege, this is the function to use. It has a BOOL return type, so it is simple to error check. Simply wrap the function call inside the condition of

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: LookupPrivilegeValue, LUID, BOOL, Windows programming
Summary: The unit describes the technical definition and usage of the Windows API function LookupPrivilegeValue. It covers its return type (BOOL) and purpose in obtaining a current LUID.
Excerpt:
Visual caption: A slide from a cybersecurity course showing the definition and usage of the LookupPrivilegeValue function in Windows programming. Visible text: LookupPriv_eValue; Gets the current LUID; Has a Boolean return type; BOOL LookupPrivilegeValue(; SEC07 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: OpenProcessToken, process token handle, AdjustTokenPrivileges, Windows API
Summary: The unit describes the Windows API function OpenProcessToken, which is used to obtain a handle to a process's access token. It details the parameters (ProcessHandle, DesiredAccess, TokenHandle) and explains that this handle is necessary for subsequent calls like AdjustTokenPrivileges.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 97 OpenProcessToken OpenProcessToken OpenProcessToken Obtains a handle to a process’ access token Obtains a handle to a process’ access token BOOL OpenProcessToken( _In_ HANDLE ProcessHandle, _In_ DWORD DesiredAccess, _Out_ PHANDLE TokenHandle ); // EXAMPLE if ( !OpenProcessToken(...) ) { return FALSE; } Has a Boolean return type Has a Boolean return type OpenProcessToken You cannot change any privileges in a token without having a handle to it. The OpenProcessToken gets you that token handle, when successful, of course. As with the LookupPrivilegeValue function, it has the same BOOL return type. One exam

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AdjustTokenPrivileges, TOKEN_PRIVILEGES structure, enabling privileges, buffer length, token handle
Summary: The text describes the AdjustTokenPrivileges Windows API function used to enable or disable privileges on an access token. It details the specific parameters, such as TokenHandle and NewState, required for calling the function successfully. The content focuses on technical implementation details of privilege manipulation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 98 AdjustTokenPrivileges AdjustTokenPrivileges AdjustTokenPrivileges Enables or disables privileges Enables or disables privileges BOOL AdjustTokenPrivileges( _In_ HANDLE TokenHandle _In_ BOOL DisableAllPrivileges _In_opt_ PTOKEN_PRIVILEGES NewState _In_ DWORD BufferLength _Out_opt_ PTOKEN_PRIVILEGES PreviousState _Out_opt_ PDWORD ReturnLength ); // EXAMPLE if ( !AdjustTokenPrivileges(...) ) { return FALSE; } Has a Boolean return type Has a Boolean return type AdjustTokenPrivileges This is the function you can use to enable or disable privileges and is really the last and final step you would have to take

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: token stealing, escalate privileges, api usage
Summary: The unit describes a lab exercise focused on the exploration of token stealing techniques for privilege escalation. It mentions specific APIs involved in this process.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 101 What’s the Point? What’s the point? What’s the Point? The point of this lab was to explore the steps and APIs involved with stealing a token for escalating privileges. © 2024 Jonathan Reiter 101 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows services, privilege escalation, guppdate, sp1hpvrc, BITS, Red Teaming Tools
Summary: The unit describes the use of Windows services as a vector for privilege escalation. It specifically mentions several service names like 'guppdate' and 'sp1hpvrc' alongside others such as 'EventLog' and 'BITS'.
Excerpt:
Visual caption: A screenshot of a slide or document page about Windows services and their role in privilege escalation. Visible text: Put Our Service to the Test!; Services and what they can do for your escalation needs; schedule; EventLog; guppdate; sp1hpvrc; BITS; SECF03 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Services, Service Control Manager (SCM), HKLM\SYSTEM\CurrentControlSet\Services, RPC server, remote management
Summary: The unit describes the role of Windows Services and their interaction with the Service Control Manager (SCM). It lists specific examples like schedule, EventLog, BITS, and gupdate, while explaining how they can run without a user logged on.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 102 Put Our Service to the Test! Services and what they can do for your escalation needs Services and what they can do for your escalation needs schedule schedule Services are a special kind of process that interact with the SCM. Services do not need a user to login to start as they can be started at boot and run without any user logged on to the system. BITS BITS EventLog EventLog gupdate gupdate iphlpsvc iphlpsvc Put Our Service to the Test! There are several services that execute behind the scenes, even when there is no user logged on to the system. Services can be configured to start with the system a

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Services, Service Control Manager (SCM), HKLM\SYSTEM\CurrentControlSet\Services, RPC server, BITS, EventLog
Summary: This unit describes the role of Windows Services and their interaction with the Service Control Manager (SCM). It details how services can run without a user logged in, are managed via RPC, and lists specific examples like BITS, EventLog, and iphlpsvc.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 102 Put Our Service to the Test! Services and what they can do for your escalation needs Services and what they can do for your escalation needs schedule schedule Services are a special kind of process that interact with the SCM. Services do not need a user to login to start as they can be started at boot and run without any user logged on to the system. BITS BITS EventLog EventLog gupdate gupdate iphlpsvc iphlpsvc Put Our Service to the Test! There are several services that execute behind the scenes, even when there is no user logged on to the system. Services can be configured to start with the system a

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: OpenSCManager API, SCM database handle, service enumeration, summary of service management, unquoted path privilege escalation
Summary: The text describes the process of obtaining and using handles to interact with the Service Control Manager (SCM) via the OpenSCManager API. It explains that these handles are necessary for managing service objects, including enumerating, deleting, or installing services. The section also mentions how programmatically identifying services with unquoted paths can be a method for privilege escalation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 104 Services: Handles Interacting with the SCM requires handles Interacting with the SCM requires handles SCManager SCManager There are several handles to objects that are required to be obtained when you want to interact with, modify, delete, or create a new service. Service Service Database lock Database lock Services: Handles The SCM database can be queried, modified, etc. once you obtain a handle to it. What you really have is a handle to the SCManager object and within that container object are the service objects. To request such a handle, you must call the OpenSCManager API. With the returned handl

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: OpenSCManager API, SCM database handle, service enumeration, unquoted path, sentence structure: 'Interacting with the SCM requires handles'
Summary: The text describes the process of obtaining handles to the Service Control Manager (SCM) using the OpenSCManager API. It explains how these handles are used for managing services, such as enumerating, deleting, or installing them. The section also mentions that service enumeration is a common technique for identifying unquoted paths for privilege escalation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 104 Services: Handles Interacting with the SCM requires handles Interacting with the SCM requires handles SCManager SCManager There are several handles to objects that are required to be obtained when you want to interact with, modify, delete, or create a new service. Service Service Database lock Database lock Services: Handles The SCM database can be queried, modified, etc. once you obtain a handle to it. What you really have is a handle to the SCManager object and within that container object are the service objects. To request such a handle, you must call the OpenSCManager API. With the returned handl

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EnumServicesStatus, QueryServiceStatus, unquoted path, weak permissions, CVE-2019-1322
Summary: The unit discusses the importance of enumerating Windows services to identify potential local privilege escalation (LPE) vectors. It covers specific techniques such as identifying unquoted service paths and exploiting services with weak permissions or incorrect configurations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 105 Services: Enumeration You cannot find what you do not look for. You cannot find what you do not look for. EnumServicesStatus EnumServicesStatus Enumerating services is just another part of on target recon with hopes of finding something to exploit. Most tools that deal with Windows services enumerate and query them to show the operator some potential LPE vectors. QueryServiceStatus QueryServiceStatus Services: Enumeration LPE via services has been a great success for red teamers. Regardless of the tool you may have used in the past, it probably did some form of enumeration of services. To do this, you

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EnumServicesStatus, QueryServiceStatus, unquoted service path, weak permissions, CVE-2019-1322
Summary: The unit discusses the enumeration of Windows services to identify potential local privilege escalation (LPE) vectors. It covers techniques such as identifying unquoted service paths and exploiting services with weak permissions or incorrect configurations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 105 Services: Enumeration You cannot find what you do not look for. You cannot find what you do not look for. EnumServicesStatus EnumServicesStatus Enumerating services is just another part of on target recon with hopes of finding something to exploit. Most tools that deal with Windows services enumerate and query them to show the operator some potential LPE vectors. QueryServiceStatus QueryServiceStatus Services: Enumeration LPE via services has been a great success for red teamers. Regardless of the tool you may have used in the past, it probably did some form of enumeration of services. To do this, you

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows services, enumeration, LPE vectors, EnumerateServiceStatus, QueryServiceStatus
Summary: The unit describes a presentation slide about enumerating Windows services to identify potential local privilege escalation (LPE) vectors. It highlights the importance of searching for specific service statuses.
Excerpt:
Visual caption: A presentation slide about enumerating Windows services to find potential LPE vectors. Visible text: Services: Enumeration; You cannot find what you do not look for.; EnumerateServicesStatus; QueryServiceStatus; SEC701 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: UAC, security boundary, Low-11.0, Security implications, Lsass.exe, Winlogon.exe
Summary: The unit discusses the security implications of User Account Control (UAC) in Windows, specifically noting it is not a security boundary. It highlights processes running with Low integrity levels and those with High integrity levels like Lsass.exe.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'UAC Me, Now You Don't' discussing the security implications of User Account Control (UAC). Visible text: UAC Me, Now You Don't; UAC is not a security boundary.; Processes that could lead to a system compromise typically run with Low-11.0.; Processes that typically run with High-11.s are one that have system-wide configurations or operations like Lsass.exe and Winlogon.exe. Alt/source label:

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: UAC, security boundary, Security Boundary, High-IL, Security Level, Low-IL
Summary: The text discusses UAC (User Account Control) as a non-security boundary, explaining its role as a convenience feature rather than a robust defense. It highlights that processes with Low Integrity Levels (Low-IL) are common for untrusted content like browsers, while High-IL processes manage system-wide configurations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 124 UAC Me, Now You Don’t UAC is not a security boundary. UAC is not a security boundary. Processes that could lead to a system compromise typically will run with a Low-IL. Browsers often do this in case you browse to a malicious site. Processes that typically run with High-IL are ones that have system-wide configurations or operations like Lsass.exe and Winlogon.exe. UAC Me, Now You Don’t Many people interpret UAC as a security boundary, thinking that UAC is a mechanism that is protecting them. UAC, to me, is really just an annoying method of protecting you from yourself but definitely not a true securit

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: UAC not a security boundary, Low-IL vs High-IL, Lsass.exe, Winlogon.exe, UAC bypass projects
Summary: The text discusses UAC (User Account Control) as a non-security boundary, explaining its role as a convenience feature rather than a robust defense. It highlights that processes with Low Integrity Levels (Low-IL) are common for untrusted content like browsers, while High-IL processes manage system-wide configurations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 124 UAC Me, Now You Don’t UAC is not a security boundary. UAC is not a security boundary. Processes that could lead to a system compromise typically will run with a Low-IL. Browsers often do this in case you browse to a malicious site. Processes that typically run with High-IL are ones that have system-wide configurations or operations like Lsass.exe and Winlogon.exe. UAC Me, Now You Don’t Many people interpret UAC as a security boundary, thinking that UAC is a mechanism that is protecting them. UAC, to me, is really just an annoying method of protecting you from yourself but definitely not a true securit

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: UAC prompt, title bar color, blue/yellow/red UAC, Process Explorer, PE-bear.exe
Summary: The text describes the visual indicators of UAC (User Account Control) elevation prompts, specifically focusing on different title bar colors (blue, yellow, and red). These colors signify whether an application is trusted, unverified, or blocked by policy respectively.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 125 UAC: Elevation Prompts UAC: Elevation Prompts It was mentioned before that when you are performing operations as a standard user, you typically run with Medium-IL. When you need to elevate a process because you want it to have more privileges, then you most likely will see a UAC prompt or consent pop-up. The example on this slide is from when I right-clicked on the Process Explorer icon and selected ”Run as Administrator.” The UAC prompt with the blue title bar is an indication that the application is trusted and signed by Microsoft. The yellow UAC title bar prompt indicates that a process’ publisher 

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: UAC, Elevation Prompts, Microsoft Corporation, unknown publisher
Summary: The unit describes a visual slide comparing User Account Control (UAC) prompts for verified and unknown publishers. It highlights the differences in warning messages regarding application permissions.
Excerpt:
Visual caption: A slide titled 'UAC: Elevation Prompts' showing two side-by-side User Account Control (UAC) prompts for different publisher types. Visible text: UAC: Elevation Prompts; User Account Control; Do you want to allow this app to make changes to your device?; Promepr; Verified publisher Microsoft Corporation; Yes; No; Do you want to allow this app from an unknown publisher to make changes to your device?; File -_0.exe; Publisher: Unknown; SEC-07 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: UAC: Fusion, manifest files, supportedOS, autoElevate, SEC-701
Summary: The unit describes the role of manifest files in determining application security context within a UAC (User Account Control) framework. It specifically highlights how 'supportedOS' and 'autoElevate' settings in these manifests influence whether an application is designed to run with elevated privileges.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'UAC: Fusion' explaining the role of manifest files in determining application security context. Visible text: UAC: Fusion; Applications and their manifests; supportedOS; autoElevate; autoElevate is set to TRUE; SEC-701 | Red Team Toolkit: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: UAC: Fusion, application manifest file, autoElevate, SegmentHeap, CreateProcess API
Summary: This unit discusses the role of application manifest files in Windows, specifically focusing on how they contain security context information like heapType and supportedOS. It highlights the autoElevate element within these manifests as a potential method for bypassing UAC prompts to gain higher privileges.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 126 UAC: Fusion Applications and their manifests Applications and their manifests supportedOS supportedOS Many applications have a manifest file tied to it that is used to describe the application itself. This XML file contains detailed information about the application’s security context. There are several elements in the manifest. heapType heapType autoElevate autoElevate UAC: Fusion When a process is being created, there are several checks that the CreateProcess API performs. One of them is calling into the system’s Fusion database where information from an application’s manifest file is stored. .NET a

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: UACMe project, GitHub repository, autoElev1ate field, manifest file parsing, fusion.c, FusionScanDirectory, FusionScanFiles, FusionCheckFile
Summary: The text describes the UACMe project on GitHub, specifically focusing on its methods for identifying applications with autoElevate set to TRUE in their embedded manifests. It highlights specific source code files and functions (fusion.c, FusionScanDirectory, FusionScanFiles, FusionCheckFile) used for parsing these manifests.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 127 UACMe Project GitHub repo hosts many UAC bypass methods GitHub repo hosts many UAC bypass methods FusionScanDirectory FusionScanDirectory Inside the repo are a few files that handle parsing the manifest files, and fusion.c is one such file. The main idea is to find files that have embedded manifests to parse and checking to see what the autoElevate element value is. There are roughly three key functions. FusionCheckFile FusionCheckFile FusionScanFiles FusionScanFiles UACMe Project One part of the process of finding UAC bypasses is to search an application’s embedded manifest for the autoElevate field.

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: UACMe Project, U14C bypass methods, FusionScanDirectory, FusionScanFiles, FusionCheckFile
Summary: The unit describes the UACMe project, a collection of techniques for bypassing User Account Control (UAC) on Windows. It highlights specific tools and functions within the project like FusionScanDirectory, FusionScanFiles, and FusionCheckFile.
Excerpt:
Visual caption: A presentation slide about the UACMe project, which provides various methods for bypassing User Account Control (UAC) on Windows. Visible text: UACMe Project; GitHub repo hosts many U4C bypass methods; FusionScanDirectory; FusionScanFiles; FusionCheckFile Alt/source label:

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: UACMe project, autoElevate field, embedded manifest parsing, fusion.c, fusion.h, FusionScanDirectory, FusionScanFiles, FusionCheckFile
Summary: The text describes the UACMe project on GitHub, specifically focusing on its methods for identifying applications with autoElevate set to TRUE in their embedded manifests. It highlights specific source files (fusion.c and fusion.h) and functions (FusionScanDirectory, FusionScanFiles, and FusionCheckFile) used for parsing these manifests.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 127 UACMe Project GitHub repo hosts many UAC bypass methods GitHub repo hosts many UAC bypass methods FusionScanDirectory FusionScanDirectory Inside the repo are a few files that handle parsing the manifest files, and fusion.c is one such file. The main idea is to find files that have embedded manifests to parse and checking to see what the autoElevate element value is. There are roughly three key functions. FusionCheckFile FusionCheckFile FusionScanFiles FusionScanFiles UACMe Project One part of the process of finding UAC bypasses is to search an application’s embedded manifest for the autoElevate field.

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: privilege escalation, pipes, services, tokens, UAC bypass
Summary: The unit contains a summary slide of a module covering privilege escalation techniques on Windows systems. It specifically mentions topics such as pipes, services, tokens, and UAC bypasses.
Excerpt:
Visual caption: A slide summarizing the content of a module on privilege escalation techniques. Visible text: Module Summary; Covered many ways to escalate your privileges; Discussed pipes, services, tokens; Discussed finding bypasses for UAC; SEC507: Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SE_BACKUP_NAME, SE_RESTORE_NAME, SE_WRITE_NAME, Write access, ACL bypass
Summary: This unit contains a review question regarding Windows privileges for bypassing ACLs during file operations. It specifically asks which privilege allows complete write access regardless of the ACL.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 136 Unit Review Questions What privilege gives complete write access regardless of the ACL? What privilege gives complete write access regardless of the ACL? A SE_BACKUP_NAME A SE_BACKUP_NAME B SE_RESTORE_NAME B SE_RESTORE_NAME C SE_WRITE_NAME C SE_WRITE_NAME Unit Review Questions Q: What privilege gives complete write access regardless of the ACL? A: SE_BACKUP_NAME B: SE_RESTORE_NAME C: SE_WRITE_NAME 136 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SE_BACKUP_NAME, security privilege, write access, ACL bypass
Summary: The unit contains a review question regarding Windows privileges for write access regardless of ACLs. It lists multiple choice options for SE_BACKUP_NAME, SE_RESTORE_NAME, and SE_WRITE_NAME.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 136 Unit Review Questions What privilege gives complete write access regardless of the ACL? What privilege gives complete write access regardless of the ACL? A SE_BACKUP_NAME A SE_BACKUP_NAME B SE_RESTORE_NAME B SE_RESTORE_NAME C SE_WRITE_NAME C SE_WRITE_NAME Unit Review Questions Q: What privilege gives complete write access regardless of the ACL? A: SE_BACKUP_NAME B: SE_RESTORE_NAME C: SE_WRITE_NAME 136 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows privileges, SE_BACKUP_NAME, SE_RESTORE_NAME, SE_WRITE_NAME, Unit Review
Summary: The unit contains a multiple-choice question and its corresponding answer regarding Windows privileges. It specifically identifies which privilege allows for complete write access regardless of the10 ACLs.
Excerpt:
Visual caption: A slide from a SANS course showing the answer to a multiple-choice question about Windows privileges. Visible text: Unit Review Answers; What privilege gives complete write access regardless of the ACL?; SE_BACKUP_NAME; SE_RESTORE_NAME; SE_WRITE_NAME Alt/source label:

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: UACBypass-Research, autoElevate, Process Monitor, weaponize
Summary: The unit describes Lab 3.7, which focuses on researching and weaponizing UAC bypass techniques. It outlines tasks such as identifying binaries with autoElevate set to true and analyzing process behavior using Process Monitor.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 141 Lab 3.7: UACBypass-Research Find system binaries that have autoElevate set to true. Find system binaries that have autoElevate set to true. Explore the process behavior using Process Monitor. Explore the process behavior using Process Monitor. Find a vulnerability and weaponize it to bypass UAC. Find a vulnerability and weaponize it to bypass UAC. Lab 3.7: UACBypass-Research This challenge is not for the faint of heart. There are two paths you could take with this one: you can follow along with the lab guide that only takes you so far, or you can dive off and attempt to find a brand-new UAC bypass! If

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: UACBypass-Research, autoElevate, Process Monitor, weaponize, UACme project
Summary: The unit describes Lab 3.7, which focuses on researching and weaponizing UAC bypass techniques. It outlines specific tasks such as identifying binaries with autoElevate set to true and monitoring process behavior using Process Monitor.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 141 Lab 3.7: UACBypass-Research Find system binaries that have autoElevate set to true. Find system binaries that have autoElevate set to true. Explore the process behavior using Process Monitor. Explore the process behavior using Process Monitor. Find a vulnerability and weaponize it to bypass UAC. Find a vulnerability and weaponize it to bypass UAC. Lab 3.7: UACBypass-Research This challenge is not for the faint of heart. There are two paths you could take with this one: you can follow along with the lab guide that only takes you so far, or you can dive off and attempt to find a brand-new UAC bypass! If

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HKLM hive, registry permissions, review questions
Summary: The unit contains a multiple-choice review question regarding Windows registry permissions for modifying keys in the HKLM hive. It lists options including User, Admin, and Guest.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about Windows registry permissions. Visible text: Unit Review Questions; What permissions are needed to modify keys in the HKLM hive?; User; Admin; Guest Alt/source label:

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows registry, HKLM hive, permissions, study guide
Summary: The unit contains a study guide review question regarding Windows registry permissions for modifying keys in the HKLM hive. It includes multiple-choice options such as User, Admin, and Guest.
Excerpt:
Visual caption: A screenshot of a study guide page showing a multiple-choice question about Windows registry permissions. Visible text: Unit Review Answers; What permissions are needed to modify keys in the HKLM hive?; User; Admin; Guest; SEC601 Alt/source label:

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: ACE string layout, DACL/SACL modification, ace_type, ace_flags, SID constants
Summary: This unit describes the structure and syntax of ACE (Access Control Entry) strings used for modifying DACL or SACL on Windows objects. It details specific flags, rights types (generic, standard, directory, file, registry), and common SID constants like 'BA' for built-admin.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 51 Ace String Layout ace_type A: access allowed D: access denied OA: object allowed OD: object denied AU: audit AL: alarm ace_flags CI: container inherit OI: object inherit NP: no propagate IO: inherit only ID: inherited SA: audit success generic rights GA: generic all GR: generic read GW: generic write GX: generic execute standard rights RC: read control SD: standard delete WD: write dac WO: write owner directory rights RP: read property WP: write property CC: create child DC: delete child LC: list children SW: self write registry rights KA: all KR: read KW: write KX: execute file rights FA: all FR: read

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: ace_string layout, DACL/SACL modification, access types, security descriptors, account_sid values
Summary: The text describes the structure and syntax of ace_strings used for modifying DACL or SACL on Windows objects. It details specific access types, flags, and various categories of rights (generic, standard, right-specific).
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 51 Ace String Layout ace_type A: access allowed D: access denied OA: object allowed OD: object denied AU: audit AL: alarm ace_flags CI: container inherit OI: object inherit NP: no propagate IO: inherit only ID: inherited SA: audit success generic rights GA: generic all GR: generic read GW: generic write GX: generic execute standard rights RC: read control SD: standard delete WD: write dac WO: write owner directory rights RP: read property WP: write property CC: create child DC: delete child LC: list children SW: self write registry rights KA: all KR: read KW: write KX: execute file rights FA: all FR: read

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: sc.exe, sdshow, security descriptor, BITS service
Summary: The unit describes how to use the sc.exe command-line utility to view a service's security descriptor using the sdshow flag. It explains that these descriptors can be interpreted using SDDL and ace_strings.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 52 Viewing Security Descriptors Viewing Security Descriptors Using the sc.exe command-line utility, we can view a service’s security descriptor. Running the program with the /? argument shows the help menu. From the help menu we can see the argument sdshow and its description: Displays a service’s security descriptor. This is what we want. From here we can choose a service, like BITS, and see what its security descriptor currently is. With the information we now know about SDDL and ace_strings, we can interpret the output without too much headache. 52 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SDDL, DACL, SACL, IU, SU, BA, SY, Get-Service
Summary: The unit describes a specific Security Descriptor Definition Language (SDDL) string used to configure access controls for a service. It breaks down the DACL and SACL components, identifying permissions for interactive users, service users, built-in admins, and local system. The text also suggests testing these configurations with tools like PowerShell's Get-Service or sc.exe.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 55 Exercise: SDDL: The Solution "D: DACL (D;;DCLCWPDTSD;;;IU) interactive user, deny: delete, list, write, delete tree, standard delete (D;;DCLCWPDTSD;;;SU) service user, deny: delete, list, write, delete tree, standard delete (D;;DCLCWPDTSD;;;BA) built‐in admins, deny: delete, list, write, delete tree, standard delete (A;;CCLCSWLOCRRC;;;IU) interactive user, allow: create, list, selfwrite, list obj, control access, read control (A;;CCLCSWLOCRRC;;;SU) service user, allow: create, list, selfwrite, list obj, control access, read control (A;;CCLCSWRPWPDTLOCRRC;;;SY) local system, allow: create, list, selfwri

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SDDL, DACL, SACL, service permissions, Get-Service, sc.exe
Summary: The text describes a specific Security Descriptor Definition Language (SDDL) string used to configure access permissions for a service. It breaks down the DACL and SACL components, identifying how different user groups like interactive users, service users, and administrators are restricted or granted access.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 55 Exercise: SDDL: The Solution "D: DACL (D;;DCLCWPDTSD;;;IU) interactive user, deny: delete, list, write, delete tree, standard delete (D;;DCLCWPDTSD;;;SU) service user, deny: delete, list, write, delete tree, standard delete (D;;DCLCWPDTSD;;;BA) built‐in admins, deny: delete, list, write, delete tree, standard delete (A;;CCLCSWLOCRRC;;;IU) interactive user, allow: create, list, selfwrite, list obj, control access, read control (A;;CCLCSWLOCRRC;;;SU) service user, allow: create, list, selfwrite, list obj, control access, read control (A;;CCLCSWRPWPDTLOCRRC;;;SY) local system, allow: create, list, selfwri

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetNamedSecurityInfoA, security descriptor, DACL, SACL, Owner SID, Group SID
Summary: The text describes the GetNamedSecurityInfoA API function used to retrieve security descriptors for local and remote objects such as NTFS files, services, and registry keys. It details the specific input parameters (name, type, information requested) and optional output parameters for owner SIDs, group SIDs, DACLs, and SACLs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 59 GetNamedSecurityInfoA GetNamedSecurityInfoA GetNamedSecurityInfoA Copies the security descriptor of the specified object by name Copies the security descriptor of the specified object by name DWORD GetNamedSecurityInfoA( LPCSTR pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecInfo, PSID *ppsidOwner, PSID *ppsidGroup, PACL *ppDacl, PACL *ppSacl, PSECURITY_DESCRIPTOR *pSecDscrptr ); NTFS objects, services, keys, shares, file-mapping objects NTFS objects, services, keys, shares, file-mapping objects GetNamedSecurityInfoA The GetNamedSecurityInfoA API is used for when you would want to obtai
