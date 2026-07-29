# Atlas Material — privesc (part 3)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: privesc
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SetNamedSecurityInfoA, security descriptor, DACL, SACL, SE_OBJECT_TYPE
Summary: The text describes the SetNamedSecurityInfoA API function for modifying security descriptors of objects on local or remote systems. It details the specific parameters, such as object name, type, and various security information flags like owner, group, and DACL/SACL.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 60 SetNamedSecurityInfoA SetNamedSecurityInfoA SetNamedSecurityInfoA Applies what is in the security descriptor for a chosen object Applies what is in the security descriptor for a chosen object DWORD SetNamedSecurityInfoA( LPSTR pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecInfo, PSID psidOwner, PSID psidGroup, PACL pDacl, PACL pSacl ); Objects will be given by their name Objects will be given by their name SetNamedSecurityInfoA The SetNamedSecurityInfoA API is used for when you want to confirm or apply a change to security information in an object’s security descriptor that you previou

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EXPLICIT_ACCESS_A, grfAccessPermissions, grfAccessMode, grfInheritance, TRUSTEE_A, ACL modification
Summary: This unit describes the EXPLICIT_ACCESS_A structure and its associated members (grfAccessPermissions, grfAccessMode, grfInheritance, and Trustee) used for modifying Access Control Lists (ACLs). It also provides definitions for the ACCESS_MODE enum and the TRUSTEE_A structure. The content focuses on Windows security structures related to access control.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 61 EXPLICIT_ACCESS_A EXPLICIT_ACCESS_A EXPLICIT_ACCESS_A Defines access control information for a trustee Defines access control information for a trustee typedef struct _EXPLICIT_ACCESS_A { DWORD grfAccessPerms; ACCESS_MODE grfAccessMode; DWORD grfInheritance; TRUSTEE_A Trustee; } EXPLICIT_ACCESS_A, *PEXPLICIT_ACCESS_A, EXPLICIT_ACCESSA, *PEXPLICIT_ACCESSA; The user, group, program to apply it against The user, group, program to apply it against EXPLICIT_ACCESS_A The EXPLICIT_ACCESS_A structure is heavily used whenever modifications are being made to the ACL of an object. The structure is used to describ

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IFEO, persistence, course roadmap, memory execution, binary patching
Summary: The unit contains a course roadmap and an introductory section on using Image File Execution Options (IFEO) for persistence. It lists various techniques such as memory execution, binary patching, and WMI event subscriptions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 79 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss how to persist using Image File Execution Options (IFEO). © 2024 Jonathan Reiter 79 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://lin

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IFEO persistence, HKLM Registry keys, Admin/SYSTEM permissions, cleanup logic
Summary: The unit discusses the permission requirements for IFEO (Image File Execution Options) persistence, specifically noting that Admin or SYSTEM privileges are required to modify HKLM Registry keys. It also mentions the importance of not leaving traces and suggests building an uninstall command to revert registry modifications.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 88 Permissions Needed What permissions are needed for IFEO persistence? What permissions are needed for IFEO persistence? Admin Admin Basic users do not have permission to create/edit certain Registry keys. SYSTEM SYSTEM The SYSTEM account can do pretty much anything. Never hurts to have this access. Permissions Needed Sadly, if we only have permissions as a basic user, then we will be denied access when trying to modify the HKLM Registry keys needed for the IFEO persistence method. Since we have already discussed a few ways that we can escalate our privileges, there is no need to bring that discussion he

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: BOOL, EnableDebug, AdjustTokenPrivileges, privilege adjustment
Summary: The unit provides a C++ code example for a function named EnableDebug that checks if debug privileges are successfully granted to a process. It demonstrates how the main program logic can use boolean return values to handle success or failure cases.
Excerpt:
Example: BOOL This example here is showing how a function can be called to indicate whether debug privileges were successfully given to the process. If the function cannot adjust the privileges for the token, then it will return FALSE. When it can successfully do so, it will return TRUE, and your main program logic can check this condition and proceed on or take another action, like exiting. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: BOOL BOOL EnableDebug( HANDLE Token, LPCTSTR Privilege, BOOL EnablePrivilege ) { //adjust token privileges //attributes to //SE_PRIVILEGE_ENABLED if (!AdjustTokenPrivileges()) return FALSE; return TRUE; } BOO

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: BOOL EnableDebug, AdjustTokenPrivileges, token privileges, privilege check
Summary: The unit describes a C++ function example for checking and enabling debug privileges on a process token. It demonstrates how to use the AdjustTokenPrivileges function within a logic flow to determine if privilege escalation or adjustment is successful.
Excerpt:
Example: BOOL This example here is showing how a function can be called to indicate whether debug privileges were successfully given to the process. If the function cannot adjust the privileges for the token, then it will return FALSE. When it can successfully do so, it will return TRUE, and your main program logic can check this condition and proceed on or take another action, like exiting. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: BOOL BOOL EnableDebug( HANDLE Token, LPCTSTR Privilege, BOOL EnablePrivilege ) { //adjust token privileges //attributes to //SE_PRIVILEGE_ENABLED if (!AdjustTokenPrivileges()) return FALSE; return TRUE; } BOO

=== UNIT 7 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Sharp10-GPOabuse, Group Policy Policy, PowerShell, SYSTEM
Summary: The unit contains a visual caption describing a screenshot of an article regarding GPO manipulation and its impact on permissions. It mentions specific technical terms like Sharp10-GPOabuse, Group Policy Objects, PowerShell, and the SYSTEM account.
Excerpt:
Visual caption: A screenshot of a technical article or tutorial page about GPO (Group Policy Object) manipulation and its impact on permissions. Visible text: Sharp10-GPOabuse; Group Policy Objects; PowerShell; SYSTEM; DOMAIN-1 Alt/source label:

=== UNIT 8 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: PowerView, Modify Domain Group Membership, net group ... /add
Summary: The unit describes how to use the PowerView tool to modify domain group membership. It specifically demonstrates adding a user named 'bfarmer' to the 'Oracle Admins' group.
Excerpt:
Visual caption: A screenshot of a tutorial page showing how to add a user to a group using the PowerView tool. Visible text: Modify Domain Group Membership; If we have the ACL on a group, we can add and remove members.; powershell run net group "Oracle Admins" bfarmer /add /domain; bfarmer; Bob Farmer; Domain users; Roaming Users; Developers; Oracle Admins Alt/source label:

=== UNIT 9 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: NMAP_SCAN_RESULTS, john's Privileges, SUDO_READ_FILE, SUDO_WRITE_FILE
Summary: The unit contains a screenshot of Nmap scan results and a list of user privileges for the account 'john'. It specifically lists sudo permissions such as read, write, and execute capabilities.
Excerpt:
Visual caption: A screenshot of a terminal window showing the output of an Nmap scan and a list of privileges for a user named 'john'. Visible text: NMAP_SCAN_RESULTS; Current - john's Privileges; SUDO_READ_FILE; SUDO_READ_EXECUTE; SUDED_WRITE_FILE; SUDO_WRITE_FILE; completed submission in 00:14:35 seconds Alt/source label:

=== UNIT 10 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: AppLocker, application whitelisting, enforcement, deny rules
Summary: The unit describes the functionality of Microsoft's AppLocker policy, specifically focusing on on-off enforcement and how specific deny rules interact with overrides. It highlights the application whitelisting nature of technology.
Excerpt:
Visual caption: A screenshot of a webpage explaining the concept and functionality of Microsoft's AppLocker policy. Visible text: AppLocker; Microsoft's application whitelisting technology; If an AppLocker category is enforced, then, by default everything within that category is blocked.; Specific deny rules can be used to override allow rules Alt/source label:

=== UNIT 11 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Windows service, binary permission issue, PowerShell Get-Acl, ls -la, Modify, Synchronize
Summary: The unit describes a technical demonstration of Windows service binary permission issues leading to privilege escalation. It highlights specific commands like 'Get-Acl' and 'ls -la' used to identify permissions.
Excerpt:
Visual caption: A technical demonstration of a Windows service binary permission issue leading to potential privilege escalation. Visible text: Service Binary Permissions; powershell Get-Acl; ls -la; ls -l; Allow: Modify, Synchronize; established link to child process Alt/source label:

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: BOOL, EnableDebug, 1024, AdjustTokenPrivileges, privilege adjustment
Summary: The unit describes a C++ function named EnableDebug that takes a token, privilege name, and boolean flag to attempt to adjust process privileges. It demonstrates how to use the return value of AdjustTokenPrivileges to determine if the operation succeeded or failed.
Excerpt:
Example: BOOL This example here is showing how a function can be called to indicate whether debug privileges were successfully given to the process. If the function cannot adjust the privileges for the token, then it will return FALSE. When it can successfully do so, it will return TRUE, and your main program logic can check this condition and proceed on or take another action, like exiting. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: BOOL BOOL EnableDebug( HANDLE Token, LPCTSTR Privilege, BOOL EnablePrivilege ) { //adjust token privileges //attributes to //SE_PRIVILEGE_ENABLED if (!AdjustTokenPrivileges()) return FALSE; return TRUE; } BOO

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: AdjustTokenPrivileges, Windows API, token privileges, PTOKEN_PRIVILERES, enabling privileges
Summary: The text describes the AdjustTokenPrivileges function in Windows API, specifically for enabling or disabling privileges on an access token. It details the parameters of the function, such as TokenHandle, DisableAllPrivileges, NewState, and BufferLength.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 98 AdjustTokenPrivileges AdjustTokenPrivileges AdjustTokenPrivileges Enables or disables privileges Enables or disables privileges BOOL AdjustTokenPrivileges( _In_ HANDLE TokenHandle _In_ BOOL DisableAllPrivileges _In_opt_ PTOKEN_PRIVILEGES NewState _In_ DWORD BufferLength _Out_opt_ PTOKEN_PRIVILEGES PreviousState _Out_opt_ PDWORD ReturnLength ); // EXAMPLE if ( !AdjustTokenPrivileges(...) ) { return FALSE; } Has a Boolean return type Has a Boolean return type AdjustTokenPrivileges This is the function you can use to enable or disable privileges and is really the last and final step you would have to take

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: token stealing, escalate privileges, api exploration
Summary: The unit describes the purpose of a lab exercise focused on exploring token stealing techniques for privilege escalation. It mentions specific APIs and steps involved in this process.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 101 What’s the Point? What’s the point? What’s the Point? The point of this lab was to explore the steps and APIs involved with stealing a token for escalating privileges. © 2024 Jonathan Reiter 101 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Windows services, schedules, EventLog, guppdate, sp1hpvrc, BITS
Summary: The unit describes the role of Windows services in privilege escalation. It lists specific service names like 'guppdate' and 'sp1hpvrc' as potential targets for exploitation.
Excerpt:
Visual caption: A screenshot of a slide or document page about Windows services and their role in privilege escalation. Visible text: Put Our Service to the Test!; Services and what they can do for your escalation needs; schedule; EventLog; guppdate; sp1hpvrc; BITS; SECF03 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Windows Services, Service Control Manager (SCM), HKLM\SYSTEM\CurrentControlSet\Services, RPC server, remote management
Summary: The unit describes the role of Windows Services and their interaction with the Service Control Manager (SCM). It lists specific examples like schedule, EventLog, BITS, and gupdate, while explaining how they can run without a user logged on.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 102 Put Our Service to the Test! Services and what they can do for your escalation needs Services and what they can do for your escalation needs schedule schedule Services are a special kind of process that interact with the SCM. Services do not need a user to login to start as they can be started at boot and run without any user logged on to the system. BITS BITS EventLog EventLog gupdate gupdate iphlpsvc iphlpsvc Put Our Service to the Test! There are several services that execute behind the scenes, even when there is no user logged on to the system. Services can be configured to start with the system a

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: OpenSCManager API, SCM database handle, service enumeration, unquoted path privilege escalation
Summary: The text describes the process of obtaining handles to the Service Control Manager (SCM) using the OpenSCManager API. It explains how these handles are used to manage, modify, or delete services and mentions the use of service enumeration as a technique for privilege escalation via unquoted paths.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 104 Services: Handles Interacting with the SCM requires handles Interacting with the SCM requires handles SCManager SCManager There are several handles to objects that are required to be obtained when you want to interact with, modify, delete, or create a new service. Service Service Database lock Database lock Services: Handles The SCM database can be queried, modified, etc. once you obtain a handle to it. What you really have is a handle to the SCManager object and within that container object are the service objects. To request such a handle, you must call the OpenSCManager API. With the returned handl

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: EnumServicesStatus, QueryServiceStatus, unquoted service path, weak permissions, CVE-2019-1322
Summary: The unit discusses the importance of enumerating Windows services to identify potential local privilege escalation (LPE) vectors. It covers specific Win32 APIs like EnumServicesStatus for enumeration and highlights common vulnerabilities such as unquoted service paths and weak service permissions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 105 Services: Enumeration You cannot find what you do not look for. You cannot find what you do not look for. EnumServicesStatus EnumServicesStatus Enumerating services is just another part of on target recon with hopes of finding something to exploit. Most tools that deal with Windows services enumerate and query them to show the operator some potential LPE vectors. QueryServiceStatus QueryServiceStatus Services: Enumeration LPE via services has been a great success for red teamers. Regardless of the tool you may have used in the past, it probably did some form of enumeration of services. To do this, you

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: UAC, security boundary, Low-11.0, High-11.s, Lsass.exe, Winlogon.exe
Summary: The unit discusses the security implications of User Account Control (UAC) in Windows, specifically noting it is not a security boundary. It highlights processes running with Low integrity levels and those with High integrity levels like Lsass.exe.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'UAC Me, Now You Don't' discussing the security implications of User Account Control (UAC). Visible text: UAC Me, Now You Don't; UAC is not a security boundary.; Processes that could lead to a system compromise typically run with Low-11.0.; Processes that typically run with High-11.s are one that have system-wide configurations or operations like Lsass.exe and Winlogon.exe. Alt/source label:

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: UAC not a security boundary, Low-IL vs High-IL, convenience of running as Admin, UAC bypass projects
Summary: The text discusses UAC (User Account Control) as a non-security boundary, explaining its role as a convenience feature rather than a robust defense. It highlights that processes with Low Integrity Levels (Low-IL) are common for untrusted content like browsers, while High-IL processes manage system-wide configurations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 124 UAC Me, Now You Don’t UAC is not a security boundary. UAC is not a security boundary. Processes that could lead to a system compromise typically will run with a Low-IL. Browsers often do this in case you browse to a malicious site. Processes that typically run with High-IL are ones that have system-wide configurations or operations like Lsass.exe and Winlogon.exe. UAC Me, Now You Don’t Many people interpret UAC as a security boundary, thinking that UAC is a mechanism that is protecting them. UAC, to me, is really just an annoying method of protecting you from yourself but definitely not a true securit

=== UNIT 21 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: UAC prompt, verified publisher, unknown publisher, offense-oriented
Summary: The unit describes the visual differences between UAC prompts for verified and unknown publishers. It highlights how the user is prompted to grant permission for applications from different trust levels.
Excerpt:
Visual caption: A slide titled 'UAC: Elevation Prompts' showing two side-by-side User Account Control (UAC) prompts for different publisher types. Visible text: UAC: Elevation Prompts; User Account Control; Do you want to allow this app to make changes to your device?; Promepr; Verified publisher Microsoft Corporation; Yes; No; Do you want to allow this app from an unknown publisher to make changes to your device?; File -_0.exe; Publisher: Unknown; SEC-07 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 22 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: UAC prompt, title bar color, blue title bar, yellow title bar, red title bar, Process Explorer, PE-bear.exe
Summary: The text describes the visual indicators of UAC (User Account Control) elevation prompts, specifically focusing on different title bar colors (blue, yellow, and red). It explains what each color signifies regarding the application's trust level and signing status.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 125 UAC: Elevation Prompts UAC: Elevation Prompts It was mentioned before that when you are performing operations as a standard user, you typically run with Medium-IL. When you need to elevate a process because you want it to have more privileges, then you most likely will see a UAC prompt or consent pop-up. The example on this slide is from when I right-clicked on the Process Explorer icon and selected ”Run as Administrator.” The UAC prompt with the blue title bar is an indication that the application is trusted and signed by Microsoft. The yellow UAC title bar prompt indicates that a process’ publisher 

=== UNIT 23 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: UAC: Fusion, application manifest files, autoElevate, SegmentHeap, summary of security context
Summary: The text discusses the role of security manifests in Windows applications, specifically focusing on how they define application properties like heapType and supportedOS. It highlights the autoElevate element within these manifests as a potential method for bypassing UAC prompts to gain higher privileges.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 126 UAC: Fusion Applications and their manifests Applications and their manifests supportedOS supportedOS Many applications have a manifest file tied to it that is used to describe the application itself. This XML file contains detailed information about the application’s security context. There are several elements in the manifest. heapType heapType autoElevate autoElevate UAC: Fusion When a process is being created, there are several checks that the CreateProcess API performs. One of them is calling into the system’s Fusion database where information from an application’s manifest file is stored. .NET a

=== UNIT 24 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: UAC: Fusion, manifest files, supportedOS, autoElevate, SEC-701
Summary: The unit describes the role of manifest files in determining application security context within a UAC Fusion framework. It specifically highlights how 'supportedOS' and 'autoElevate' settings in these manifests influence whether an application is granted elevated privileges.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'UAC: Fusion' explaining the role of manifest files in determining application security context. Visible text: UAC: Fusion; Applications and their manifests; supportedOS; autoElevate; autoElevate is set to TRUE; SEC-701 | Red Team Toolkit: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 25 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: UACMe project, GitHub repository, autoElevate field, manifest parsing, fusion.c, fusion.h, FusionScanDirectory, FusionScanFiles
Summary: The unit describes the UACMe project on GitHub, specifically focusing on its implementation of manifest parsing to identify applications with autoElevate set to TRUE. It highlights specific source files (fusion.c and fusion.h) and functions (FusionScanDirectory, FusionScanFiles, and FusionCheckFile) used for this purpose.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 127 UACMe Project GitHub repo hosts many UAC bypass methods GitHub repo hosts many UAC bypass methods FusionScanDirectory FusionScanDirectory Inside the repo are a few files that handle parsing the manifest files, and fusion.c is one such file. The main idea is to find files that have embedded manifests to parse and checking to see what the autoElevate element value is. There are roughly three key functions. FusionCheckFile FusionCheckFile FusionScanFiles FusionScanFiles UACMe Project One part of the process of finding UAC bypasses is to search an application’s embedded manifest for the autoElevate field.

=== UNIT 26 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: UACMe Project, sUAC bypass methods, FusionScanDirectory, FusionScanFiles, FusionCheckFile
Summary: The unit describes the UACMe project, a collection of techniques for bypassing User Account Control (UAC) on Windows systems. It highlights specific functions like FusionScanDirectory, FusionScanFiles, and FusionCheckFile within the GitHub repository.
Excerpt:
Visual caption: A presentation slide about the UACMe project, which provides various methods for bypassing User Account Control (UAC) on Windows. Visible text: UACMe Project; GitHub repo hosts many U4C bypass methods; FusionScanDirectory; FusionScanFiles; FusionCheckFile Alt/source label:

=== UNIT 27 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: privilege escalation, pipes, services, tokens, UAC bypasses
Summary: The unit contains a summary slide of a module covering privilege escalation techniques on Windows systems. It specifically mentions topics such as pipes, services, tokens, and UAC bypasses.
Excerpt:
Visual caption: A slide summarizing the content of a module on privilege escalation techniques. Visible text: Module Summary; Covered many ways to escalate your privileges; Discussed pipes, services, tokens; Discussed finding bypasses for UAC; SEC507: Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 28 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: SE_BACKUP_NAME, Security privilege, ACL bypass
Summary: The unit contains a review question regarding Windows privileges for write access regardless of ACLs. It specifically lists options SE_BACKUP_NAME, SE_RESTORE_NAME, and SE_WRITE_NAME.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 136 Unit Review Questions What privilege gives complete write access regardless of the ACL? What privilege gives complete write access regardless of the ACL? A SE_BACKUP_NAME A SE_BACKUP_NAME B SE_RESTORE_NAME B SE_RESTORE_NAME C SE_WRITE_NAME C SE_WRITE_NAME Unit Review Questions Q: What privilege gives complete write access regardless of the ACL? A: SE_BACKUP_NAME B: SE_RESTORE_NAME C: SE_WRITE_NAME 136 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 29 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Windows privileges, SE_BACKUP_PRIVILEGE, multiple-choice question
Summary: The unit contains a multiple-choice question regarding Windows privileges, specifically identifying which privilege grants full write access despite ACL restrictions. It lists options such as SE_BACKUP_PRIVILEE, SE_RESTORE_PRIVILEGE, and SE_WRITE_NAME.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about Windows privileges. Visible text: Unit Review Questions; What privilege gives complete write access regardless of the ACL?; SE_BACKUP_PRIVILEGE; SE_RESTORE_PRIVILEGE; SE_WRITE_NAME Alt/source label:

=== UNIT 30 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: UACBypass-Research, autoElevate, Process Monitor, weaponize
Summary: The unit describes Lab 3.7, which focuses on researching and weaponizing UAC bypass techniques. It outlines the objectives of finding system binaries with autoElevate set to true and analyzing process behavior using Process Monitor.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 141 Lab 3.7: UACBypass-Research Find system binaries that have autoElevate set to true. Find system binaries that have autoElevate set to true. Explore the process behavior using Process Monitor. Explore the process behavior using Process Monitor. Find a vulnerability and weaponize it to bypass UAC. Find a vulnerability and weaponize it to bypass UAC. Lab 3.7: UACBypass-Research This challenge is not for the faint of heart. There are two paths you could take with this one: you can follow along with the lab guide that only takes you so far, or you can dive off and attempt to find a brand-new UAC bypass! If

=== UNIT 31 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Objectives, escalating privileges, implementation in code
Summary: The unit contains an objectives slide from a SANS Institute course on red teaming tools. It lists goals such as discussing privilege escalation reasoning, exploring methods, and implementing them in code.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Objectives' listing goals for the module. Visible text: Objectives; Our objectives for this module are:; Discuss the reasoning for escalating privileges; Explore several methods; Implement a few methods in code; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 32 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: privilege escalation, non-admin vs admin, SeDebugPrivilege, process handles
Summary: The text discusses the strategic considerations for privilege escalation, specifically whether it is necessary to achieve administrative status before performing certain actions. It highlights that some enumeration and survey tools can function effectively as a standard user. It also introduces the concept of specific privileges like SeDebugPrivilege for process handling.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 83 Why Escalate? Is there always a requirement to escalate privileges? Is there always a requirement to escalate privileges? non-admin non-admin Knowing what you can or cannot do with your current level of privileges is important for your tool and the operator using it. admin admin Why Escalate? There is only so much that you can do with standard user permissions and accesses. Depending on what the end goal is or what you need to accomplish on the target, you might not even need to escalate your privileges. That might contradict from what others have said and what you might know and that is fine. All I am

=== UNIT 33 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Windows Privileges, Enabled vs Disabled, Security context
Summary: The unit describes the difference between enabled and disabled Windows privileges. It references a SANS course on developing Windows implants and shellcode.
Excerpt:
Visual caption: A slide from a SANS course presentation about Windows Privileges, explaining the difference between enabled and disabled privileges. Visible text: Windows Privileges; What do privileges do for you?; Enabled; Disabled; SEC407 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 34 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Windows Privileges, SeDebugPrivilege, whoami /priv, system-related operations
Summary: The unit discusses the definition and role of privileges in Windows systems, specifically how they grant rights to perform system-related operations like shutting down the system or loading drivers. It explains that standard users typically have limited privileges, and specific privileges like SeDebugPrivilege are required for certain actions such as obtaining process handles.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 84 Windows Privileges What do privileges do for you? What do privileges do for you? Enabled Enabled Disabled Disabled Indicates a privilege is present and set, or authorized, in your token. Could be disabled. Indicates a privilege is present but not set, or authorized, in your token. Could be enabled. Windows Privileges What is a privilege and what does it do for you? According to Microsoft, “A privilege is the right of an account, such as a user or group account, to perform various system-related operations on the local computer, such as shutting down the system, loading device drivers, or changing the s

=== UNIT 35 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: SE_PRIVILEGE_*, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES, SeDebugPrivilege, SeLoadDriverPrivilege
Summary: This unit describes the Windows privilege system, specifically focusing on SE_PRIVILEGE_* values and their associated attributes. It details how privileges determine if a process can perform specific actions (like debugging or loading drivers) and explains the structure of LUID_AND_ATTRIBUTES.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 87 Privileges and Attributes SE_PRIVILEGE_* values that describe the privilege SE_PRIVILEGE_* values that describe the privilege ENABLED ENABLED ENABLED_BY_DEFAULT ENABLED_BY_DEFAULT REMOVED REMOVED USED_FOR_ACCESS USED_FOR_ACCESS Privilege is simply enabled Enabled by default For removing privileges Used to obtain access to a service or to an object Privileges and Attributes Privileges are what determine if a user, or process, is allowed to carry out an operation within the system. Privileges are not necessarily tied directly to an object, but rather are tied to what can be done. Debuggers like WinDbg Pr

=== UNIT 36 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: SE_PRIVILEGE, Privileges and Attributes, ENABLED, REMOVED
Summary: The unit describes a slide from a SANS course regarding the meaning of privileges and attributes for SE_PRIVILEGE flags. It lists specific status indicators such as ENABLED, ENABLED_BY_DEFAULT, and REMOVED.
Excerpt:
Visual caption: A slide from a SANS course titled 'Privileges and Attributes' explaining the meaning of various SE_PRIVILEGE flags. Visible text: Privileges and Attributes; SE_PRIVILEGE_* values that describe the privilege; ENABLED; ENABLED_BY_DEFAULT; REMOVED; USED_FOR_ACCESS; SEC-701 | Red Team Toolkit: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 37 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Windows integrity levels, privilege separation, GetTokenNumber, Untrusted, Low, Medium, High, System
Summary: The unit describes the Windows integrity levels used for privilege separation, listing six specific levels from Untrusted to Protected. It also mentions the GetTokenInformation function.
Excerpt:
Visual caption: A slide explaining the six integrity levels in Windows systems for privilege separation. Visible text: Integrity Levels (I); Untrusted (0); Low (1); Medium (2); High (3); System (4); Protected (5); GetTokenInformation Alt/source label:

=== UNIT 38 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: whoami /priv, privilege levels, terminals
Summary: The unit contains a screenshot and description of the 'whoami /priv' command output. It details various privilege levels such as SeChangeNotifyPrivilege and SeShutdownSystemPrivilege.
Excerpt:
Visual caption: A screenshot of a terminal window showing the output of the 'whoami /priv' command, followed by explanatory text about privilege levels. Visible text: whoami /priv: non-admin (1); Privilege Name; Description; State; SeChangeNotifyPrivilege; SeShutdownSystemPrivilege; SeCreateAnonymousPrivilege; SeRemoteThread100Privilege; SeTzeZonePrivilege Alt/source label:

=== UNIT 39 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: whoami /priv, non-admin, SeChangeNotifyPrivilege, SeIncreaseWorkingSetPrivilege
Summary: The unit contains a slide showing the output of the 'whoami /priv' command for a non-admin user. It highlights specific privileges like SeChangeNotifyPrivilege and SeIncreaseWorkingSetPrivilege.
Excerpt:
Visual caption: A slide from a cybersecurity course showing the 'whoami /priv' command output for a non-admin user, highlighting a change in privilege status. Visible text: whoami /priv: non-admin (2); SystemSettings.exe; Medium; Privilege; Flags; SeChangeNotifyPrivilege; Default Enabled; SeIncreaseWorkingSetPrivilege; Disabled; SeShutdownPrivilege; Disabled; SeTimeZonePrivilege; Enabled Alt/source label:

=== UNIT 40 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: SE_BACKUP_NAME, SE_RESTORE_NAME, bypass ACLs, Windows privileges
Summary: This unit describes how specific Windows privileges (SE_BACKUP_NAME and SE_RESTORE_NAME) can be used to bypass file system Access Control Lists (ACLs). It explains that these privileges grant read and write access respectively, regardless of the existing ACL settings.
Excerpt:
Visual caption: A slide from a cybersecurity course explaining how specific Windows privileges (SE_BACKUP_NAME and SE_RESTORE_NAME) can be used to bypass Access Control Lists (ACLs). Visible text: Privileges and ACLs?; Abuse privileges to bypass ACLs!; SE_BACKUP_NAME; Regardless of the file's ACL, granted complete read access; SE_RESTORE_NAME; Regardless of the file's ACL, granted complete write access; SEC702 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:
