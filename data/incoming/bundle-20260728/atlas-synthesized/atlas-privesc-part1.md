# Atlas Material — privesc (part 1)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: privesc
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.95  Key cues: AdjustTokenPrivileges, Windows API, token privileges, enabling privileges
Summary: The text describes the AdjustTokenPrivileges function in Windows API, specifically for enabling or disabling privileges on an access token. It details the parameters of the function, such as TokenHandle, DisableAllPrivileges, and NewState, explaining how to implement it for privilege escalation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 98 AdjustTokenPrivileges AdjustTokenPrivileges AdjustTokenPrivileges Enables or disables privileges Enables or disables privileges BOOL AdjustTokenPrivileges( _In_ HANDLE TokenHandle _In_ BOOL DisableAllPrivileges _In_opt_ PTOKEN_PRIVILEGES NewState _In_ DWORD BufferLength _Out_opt_ PTOKEN_PRIVILEGES PreviousState _Out_opt_ PDWORD ReturnLength ); // EXAMPLE if ( !AdjustTokenPrivileges(...) ) { return FALSE; } Has a Boolean return type Has a Boolean return type AdjustTokenPrivileges This is the function you can use to enable or disable privileges and is really the last and final step you would have to take

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.95  Key cues: PE Format, thread injection, sentence: 'In this module, we will discuss and implement various ways to escalate your local privileges.'
Summary: The text lists a course roadmap for red teaming tools, including topics like PE format, thread injection techniques (APC, ThreadHijacker), and privilege escalation methods.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 81 Course Roadmap PE Format Lab 3.1: GetFunctionAddress Threads Injections Lab 3.2: ClassicDLLInjection Lab 3.3: APCInjection Lab 3.4: ThreadHijacker Escalations Lab 3.5: TokenThief Bootcamp Lab 3.6: So, You Think You Can Type Lab 3.7: UACBypass-Research Lab 3.8: ShadowCraft S e c t i o n 3 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss and implement various ways to escalate your local privileges. © 2024 Jonathan Reiter 81 © SANS I

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Integrity Levels, GetTokenInformation, S-1-16-0x0, Untrusted, Low, Medium, High, System
Summary: This unit describes the six integrity levels (IL) used by Windows for privilege separation, ranging from Untrusted to System. It details specific characteristics of each level, such as their associated SIDs, typical processes that run at these levels, and how they interact with system resources like Registry Keys.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 88 Integrity Levels (1) There are six integrity levels the system uses for privilege separation. There are six integrity levels the system uses for privilege separation. Untrusted (0) Untrusted (0) Low (1) Low (1) Medium (2) Medium (2) High (3) High (3) Anonymous Group started processes AppContainer processes Typical processes when UAC is turned on UAC elevated processes System (4) System (4) Protected (5) Protected (5) System services and processes; wininit, winlogon, lsass Set via kernel-mode callers Integrity Levels (1) Tokens can have an integrity level (IL) tied to them, which can be queried using th

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Integrity Levels, GetTokenInformation, SID S-1-16-0x0, UAC elevated processes, System-IL, Protected level
Summary: The unit describes the six integrity levels (IL) used by Windows for privilege separation, ranging from Untrusted to System. It details specific characteristics of each level, such as their SID associations and which types of processes typically run at these levels.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 88 Integrity Levels (1) There are six integrity levels the system uses for privilege separation. There are six integrity levels the system uses for privilege separation. Untrusted (0) Untrusted (0) Low (1) Low (1) Medium (2) Medium (2) High (3) High (3) Anonymous Group started processes AppContainer processes Typical processes when UAC is turned on UAC elevated processes System (4) System (4) Protected (5) Protected (5) System services and processes; wininit, winlogon, lsass Set via kernel-mode callers Integrity Levels (1) Tokens can have an integrity level (IL) tied to them, which can be queried using th

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: SeBackupPrivilege, SeRestorePrivilege, ACL bypass, winnt.h
Summary: The unit discusses how SeBackupPrivilege and SeRestorePrivilege can bypass standard file system ACLs to provide read and write access, respectively. It explains that these privileges trump the ACL check during specific operations. The text also points toward the winnt.h header file for additional privilege constants.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 93 Privileges and ACLs? Abuse privileges to bypass ACLs! Abuse privileges to bypass ACLs! SE_BACKUP_NAME SE_BACKUP_NAME SE_RESTORE_NAME SE_RESTORE_NAME Regardless of the file’s ACL, granted complete read access Regardless of the file’s ACL, granted complete write access Privileges and ACLs? There is an interesting tidbit when it comes to privileges. Most privileges allow you to perform some operation, but still only after the system does a privilege check. Well, there are two privileges that bypass that check: SeBackupPrivilege and SeRestorePrivilege. MSDN describes these two privileges as ones that are u

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: LookupPrivilegeValue, OpenProcessToken, AdjustTokenPrivileges, Programmatically
Summary: The unit describes programmatic methods for adjusting user privileges using specific Windows API functions like LookupPrivilegeValue, OpenProcessToken, and AdjustTokenPrivileges. It is part of a training module on developing custom tools for Windows.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Privileges: Programmatically' discussing the programmatic adjustment of user privileges. Visible text: Privileges: Programmatically; LookupPrivilegeValue; OpenProcessToken; AdjustTokenPrivileges; SEC601 Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: token stealing, privilege escalation, SANS SEC670, Windows APIs
Summary: The unit describes the purpose of educational lab exercises focused on privilege escalation via token theft. It references specific techniques involving Windows API calls and the system's internal mechanisms.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'What's the Point?' explaining the purpose of a lab exercise. Visible text: What's the Point?; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control; The point of this lab was to explore the steps and APIs involved with stealing a token for escalating privileges. Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: UAC prompt, title bar color, blue/yellow/red titles, trusted vs. untrusted, Process Explorer
Summary: The text describes the visual indicators of UAC (User Account Control) elevation prompts, specifically focusing on different title bar colors (blue, yellow, and red). It explains what each color signifies regarding the application's trust level and signing status.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 125 UAC: Elevation Prompts UAC: Elevation Prompts It was mentioned before that when you are performing operations as a standard user, you typically run with Medium-IL. When you need to elevate a process because you want it to have more privileges, then you most likely will see a UAC prompt or consent pop-up. The example on this slide is from when I right-clicked on the Process Explorer icon and selected ”Run as Administrator.” The UAC prompt with the blue title bar is an indication that the application is trusted and signed by Microsoft. The yellow UAC title bar prompt indicates that a process’ publisher 

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: UAC: Fusion, application manifest, autoElevate, SegmentHeap, XML resource
Summary: The text describes how application manifests (XML files) contain security context information such as heapType and autoElevate settings. It specifically highlights the autoElevate element, which can indicate if an application is permitted to run with elevated privileges without a UAC prompt. This information is useful for identifying potential paths for privilege escalation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 126 UAC: Fusion Applications and their manifests Applications and their manifests supportedOS supportedOS Many applications have a manifest file tied to it that is used to describe the application itself. This XML file contains detailed information about the application’s security context. There are several elements in the manifest. heapType heapType autoElevate autoElevate UAC: Fusion When a process is being created, there are several checks that the CreateProcess API performs. One of them is calling into the system’s Fusion database where information from an application’s manifest file is stored. .NET a

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: privilege escalation, Meterpreter getsystem, pipes, services, tokens, UAC bypass
Summary: The unit summarizes the module's coverage of local privilege escalation (LPE) techniques, specifically focusing on programmatic methods and underlying mechanisms like services, tokens, and pipes. It highlights how understanding these components is useful for developing custom LPE tools.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 131 Module Summary Covered many ways to escalate your privileges Covered many ways to escalate your privileges Discussed pipes, services, tokens Discussed pipes, services, tokens Discussed finding bypasses for UAC Discussed finding bypasses for UAC Module Summary In this module, we covered several methods for how you could programmatically escalate your privileges. Learning how Meterpreter’s getsytem command works on the back end can lend a hand when creating your own version of it or making a modification to it so that it would work in your target environment. The more you understand basic services, priv

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Meterpreter's getsystem command, pipes, services, tokens, UAC bypasses, local privilege escalation
Summary: The unit provides a summary of the module covering programmatic methods for local privilege escalation (LPE). It discusses technical components like pipes, services, tokens, and UAC bypasses to aid in developing custom LPE techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 131 Module Summary Covered many ways to escalate your privileges Covered many ways to escalate your privileges Discussed pipes, services, tokens Discussed pipes, services, tokens Discussed finding bypasses for UAC Discussed finding bypasses for UAC Module Summary In this module, we covered several methods for how you could programmatically escalate your privileges. Learning how Meterpreter’s getsytem command works on the back end can lend a hand when creating your own version of it or making a modification to it so that it would work in your target environment. The more you understand basic services, priv

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Windows privileges, SE_BACKUP_PRIVILEGE, SE_RESTORE_PRIVILEGE, SE_WRITE_NAME
Summary: The unit contains a multiple-choice question regarding Windows privileges, specifically identifying which privilege grants full write access regardless of Access Control Lists (ACLs).
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about Windows privileges. Visible text: Unit Review Questions; What privilege gives complete write access regardless of the ACL?; SE_BACKUP_PRIVILEGE; SE_RESTORE_PRIVILEGE; SE_WRITE_NAME Alt/source label:

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: UACBypass-Research, autoElevate, Process Monitor, UAC bypass
Summary: The unit describes a research task focused on identifying system binaries with autoElevate set to true. It outlines steps for analyzing process behavior using Process Monitor and finding vulnerabilities to bypass UAC.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Lab 3.7: UACBypass-Research' outlining the steps for a research task. Visible text: Lab 3.7: UACBypass-Research; Find system binaries that have autoElevate set to true.; Explore the process behavior using Process Monitor.; Find a vulnerability and weaponize it to bypass UAC.; SEC601 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: EXPLICIT_ACCESS_A, grfAccessPermissions, grfAccessMode, grfInheritance, TRUSTEE_A, ACCESS_MODE
Summary: This unit describes the EXPLICIT_ACCESS structure and its associated members, such as grfAccessPermissions, grfAccessMode, grfInheritance, and Trustee. It also provides definitions for the ACCESS_MODE enum and the TRUSTEE_A structure used in Windows security configurations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 61 EXPLICIT_ACCESS_A EXPLICIT_ACCESS_A EXPLICIT_ACCESS_A Defines access control information for a trustee Defines access control information for a trustee typedef struct _EXPLICIT_ACCESS_A { DWORD grfAccessPerms; ACCESS_MODE grfAccessMode; DWORD grfInheritance; TRUSTEE_A Trustee; } EXPLICIT_ACCESS_A, *PEXPLICIT_ACCESS_A, EXPLICIT_ACCESSA, *PEXPLICIT_ACCESSA; The user, group, program to apply it against The user, group, program to apply it against EXPLICIT_ACCESS_A The EXPLICIT_ACCESS_A structure is heavily used whenever modifications are being made to the ACL of an object. The structure is used to describ

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Registry modification, HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors, DLL loading, privilege escalation, System32 folder
Summary: This unit describes a method for abusing port monitors via the Windows Registry to escalate privileges. It details how to modify the Print)Monitors hive to point to a malicious DLL in System32, which can result in SYSTEM level execution when loaded.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 70 Abusing Port Monitors: The Registry Method one: Registry Method one: Registry Key holds the port monitors in place Key holds the port monitors in place Need local admin Need local admin Abusing Port Monitors: The Registry There are two ways that we can leverage and abuse port monitors. The first method we are going to look at is using the Registry to modify the Print>Monitors hive. The full path to the key is HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors and the subkeys under it should be port monitors. We can manually view this using the regedit.exe GUI. Browsing to the key, we can select each 

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Registry modification, HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors, system privilege escalation, port monitor DLL, local admin requirement
Summary: This unit describes a method for abusing port monitors via the Windows Registry to achieve SYSTEM privileges. It details how to modify the Print)Monitors hive and requires local admin rights and a system reboot to execute.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 70 Abusing Port Monitors: The Registry Method one: Registry Method one: Registry Key holds the port monitors in place Key holds the port monitors in place Need local admin Need local admin Abusing Port Monitors: The Registry There are two ways that we can leverage and abuse port monitors. The first method we are going to look at is using the Registry to modify the Print>Monitors hive. The full path to the key is HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors and the subkeys under it should be port monitors. We can manually view this using the regedit.exe GUI. Browsing to the key, we can select each 

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.9  Key cues: SANS SEC670, token stealing, escalating privileges, lab exercise
Summary: The unit describes a slide from a SANS SEC670 course explaining the purpose of a lab exercise focused on privilege escalation via token stealing.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'What's the Point?' explaining the purpose of a lab exercise. Visible text: What's the Point?; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control; The point of this lab was to explore the steps and APIs involved with stealing a token for escalating privileges. Alt/source label:

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.9  Key cues: privilege escalation, Meterpreter getsystem, pipes, services, tokens, UAC bypass
Summary: The unit provides a summary of the module covering programmatic privilege escalation techniques, including pipes, services, tokens, and UAC bypasses. It explains how understanding these components helps in creating custom local privilege escalation (LPE) tools.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 131 Module Summary Covered many ways to escalate your privileges Covered many ways to escalate your privileges Discussed pipes, services, tokens Discussed pipes, services, tokens Discussed finding bypasses for UAC Discussed finding bypasses for UAC Module Summary In this module, we covered several methods for how you could programmatically escalate your privileges. Learning how Meterpreter’s getsytem command works on the back end can lend a hand when creating your own version of it or making a modification to it so that it would work in your target environment. The more you understand basic services, priv

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.9  Key cues: Integrity Levels, GetTokenInformation, S-1-16-0x0, Untrusted, Low, Medium, High, System
Summary: The text describes the six integrity levels (IL) used by Windows for privilege separation, ranging from Untrusted to System. It details specific characteristics of which processes typically run at each level and how these levels impact write access.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 88 Integrity Levels (1) There are six integrity levels the system uses for privilege separation. There are six integrity levels the system uses for privilege separation. Untrusted (0) Untrusted (0) Low (1) Low (1) Medium (2) Medium (2) High (3) High (3) Anonymous Group started processes AppContainer processes Typical processes when UAC is turned on UAC elevated processes System (4) System (4) Protected (5) Protected (5) System services and processes; wininit, winlogon, lsass Set via kernel-mode callers Integrity Levels (1) Tokens can have an integrity level (IL) tied to them, which can be queried using th

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.9  Key cues: SeBackupPrivilege, SeRestorePrivilege, ACL bypass, winnt.h
Summary: The unit describes how SeBackupPrivilege and SeRestorePrivilege can bypass standard file system ACLs to provide read and write access, respectively. It explains that these privileges trump the ACL check during specific operations. The text also points toward the winnt.h header file for additional privilege constants.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 93 Privileges and ACLs? Abuse privileges to bypass ACLs! Abuse privileges to bypass ACLs! SE_BACKUP_NAME SE_BACKUP_NAME SE_RESTORE_NAME SE_RESTORE_NAME Regardless of the file’s ACL, granted complete read access Regardless of the file’s ACL, granted complete write access Privileges and ACLs? There is an interesting tidbit when it comes to privileges. Most privileges allow you to perform some operation, but still only after the system does a privilege check. Well, there are two privileges that bypass that check: SeBackupPrivilege and SeRestorePrivilege. MSDN describes these two privileges as ones that are u

=== UNIT 21 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.9  Key cues: OpenProcessToken, process token handle, AdjustTokenPrivileges, PROCESS_QUERY_INFORMATION
Summary: The unit describes the OpenProcessToken function in Windows API, explaining its purpose of obtaining a handle to a process's access token. It details the requirements for ProcessHandle and DesiredAccess parameters, as well as the role of which TokenHandle is used for subsequent calls like AdjustTokenPrivileges.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 97 OpenProcessToken OpenProcessToken OpenProcessToken Obtains a handle to a process’ access token Obtains a handle to a process’ access token BOOL OpenProcessToken( _In_ HANDLE ProcessHandle, _In_ DWORD DesiredAccess, _Out_ PHANDLE TokenHandle ); // EXAMPLE if ( !OpenProcessToken(...) ) { return FALSE; } Has a Boolean return type Has a Boolean return type OpenProcessToken You cannot change any privileges in a token without having a handle to it. The OpenProcessToken gets you that token handle, when successful, of course. As with the LookupPrivilegeValue function, it has the same BOOL return type. One exam

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Objectives, escalating privileges, explore several methods, implement in code
Summary: The unit contains a slide outlining the learning objectives for a module on privilege escalation. It specifies goals to discuss reasoning, explore methods, and implement code for these techniques.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Objectives' listing goals for the module. Visible text: Objectives; Our objectives for this module are:; Discuss the reasoning for escalating privileges; Explore several methods; Implement a few methods in code; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: privilege escalation, reasoning for escalating, programmatic elevation
Summary: This unit outlines the learning objectives for a module on privilege escalation. It covers the reasoning behind escalating privileges, identifying when it is necessary, and exploring programmatic methods to achieve this.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 82 Objectives Our objectives for this module are: Discuss the reasoning for escalating privileges Explore several methods Implement a few methods in code Objectives The objectives for this module are to talk about the reasoning for escalating your privileges. There could be times when you do not have to operate with higher privileges than what you have already. We will also discuss and explore several methods to programmatically elevate your current privileges. 82 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: privilege escalation, non-admin vs admin, SeDebugPrivilege, sentence structure: 'Why Escalate?'
Summary: The text discusses the strategic considerations for privilege escalation, specifically whether it is necessary to achieve administrative status before performing certain actions. It highlights that some enumeration and survey tools can function effectively as a standard user. It also introduces the concept of specific privileges like SeDebugPrivilege for handling processes.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 83 Why Escalate? Is there always a requirement to escalate privileges? Is there always a requirement to escalate privileges? non-admin non-admin Knowing what you can or cannot do with your current level of privileges is important for your tool and the operator using it. admin admin Why Escalate? There is only so much that you can do with standard user permissions and accesses. Depending on what the end goal is or what you need to accomplish on the target, you might not even need to escalate your privileges. That might contradict from what others have said and what you might know and that is fine. All I am

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: privilege escalation, non-admin vs admin, SeDebugPrivilege, SE_DEBUG_NAME
Summary: The text discusses the strategic considerations for privilege escalation, specifically whether it is necessary to achieve administrative status or if tasks can be accomplished with standard user permissions. It highlights that some actions, like enumerating processes, might only require specific privileges such as SeDebugPrivilege.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 83 Why Escalate? Is there always a requirement to escalate privileges? Is there always a requirement to escalate privileges? non-admin non-admin Knowing what you can or cannot do with your current level of privileges is important for your tool and the operator using it. admin admin Why Escalate? There is only so much that you can do with standard user permissions and accesses. Depending on what the end goal is or what you need to accomplish on the target, you might not even need to escalate your privileges. That might contradict from what others have said and what you might know and that is fine. All I am

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Privileges, SeDebugPrivilege, whoami /priv, process handle, sytem-related operations
Summary: The unit describes the concept of security privileges in Windows, defining them as rights to perform system-related operations like shutting down the system or loading drivers. It explains that certain actions, such as obtaining process handles for specific processes, require specific privileges like SeDebugPrivilege. It also mentions that while standard user tokens typically cannot change their own privileges, kernel-level access allows for privilege modification.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 84 Windows Privileges What do privileges do for you? What do privileges do for you? Enabled Enabled Disabled Disabled Indicates a privilege is present and set, or authorized, in your token. Could be disabled. Indicates a privilege is present but not set, or authorized, in your token. Could be enabled. Windows Privileges What is a privilege and what does it do for you? According to Microsoft, “A privilege is the right of an account, such as a user or group account, to perform various system-related operations on the local computer, such as shutting down the system, loading device drivers, or changing the s

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Privileges, SeDebugPrivilege, whoami /priv, kernel-100% access
Summary: The unit describes the concept of Windows privileges, defining them as rights to perform system-related operations like shutting down the system or loading drivers. It explains that standard users typically have limited privileges and highlights SeDebugPrivilege as a requirement for obtaining process handles. The text also mentions the transition from user-mode limitations to kernel-mode capabilities.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 84 Windows Privileges What do privileges do for you? What do privileges do for you? Enabled Enabled Disabled Disabled Indicates a privilege is present and set, or authorized, in your token. Could be disabled. Indicates a privilege is present but not set, or authorized, in your token. Could be enabled. Windows Privileges What is a privilege and what does it do for you? According to Microsoft, “A privilege is the right of an account, such as a user or group account, to perform various system-related operations on the local computer, such as shutting down the system, loading device drivers, or changing the s

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: security descriptor, Create* API family, Security Attributes, Win32 API, security check
Summary: The text describes the concept of security descriptors for various Windows objects such as processes, threads, files, and registry keys. It explains how the Create* family of Win32 APIs uses SECURITY_ATTRIBUTES to define these descriptors during object creation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 85 Securable Objects Objects that have a corresponding security descriptor Objects that have a corresponding security descriptor files files Most objects are created at the request of the user: CreateProcess, CreateThread, CreateFile, etc. The functions typically accept a pointer to a SECURITY_ATTRIBUTES structure. There are several object types that can be secured. processes processes threads threads reg keys reg keys Securable Objects Remember the section where we were talking about the Create* family of Win32 APIs? It might seem like a long time ago, so here is a refresher. The Create* API family is a 

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Securable Objects, security descriptor, CreateProcess, CreateFile, SECURITY_ATTRIB
Summary: The unit describes security descriptors for various Windows objects such as files, processes, registry keys, and threads. It explains that these objects are created by users via specific system calls like CreateProcess and CreateFile.
Excerpt:
Visual caption: A presentation slide titled 'Securable Objects' explaining the concept of security descriptors for various object types like files, processes, and registry keys. Visible text: Securable Objects; Objects that have a corresponding security descriptor; Most objects are created at the request of the user: CreateProcess, CreateThread, CreateFile, etc. The creation functions specify a pointer to a SECURITY_ATTRIB; files; processes; reg keys; threads; SEC-70 | Red Team_Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SE_PRIVILEGE_*, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES, luid, bit flags
Summary: The unit describes the structure and purpose of Windows privileges (SE_PRIVILEGE_*), including their attributes stored in the TOKEN_PRIVILEGES structure. It details the LUID_AND_ATTRIBUTES struct, which contains a Luid for unique identification and bit flags for privilege attributes.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 87 Privileges and Attributes SE_PRIVILEGE_* values that describe the privilege SE_PRIVILEGE_* values that describe the privilege ENABLED ENABLED ENABLED_BY_DEFAULT ENABLED_BY_DEFAULT REMOVED REMOVED USED_FOR_ACCESS USED_FOR_ACCESS Privilege is simply enabled Enabled by default For removing privileges Used to obtain access to a service or to an object Privileges and Attributes Privileges are what determine if a user, or process, is allowed to carry out an operation within the system. Privileges are not necessarily tied directly to an object, but rather are tied to what can be done. Debuggers like WinDbg Pr

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SE_PRIVILEGE_*, Privileges and Attributes, ENABLED, ENUMERATED
Summary: The unit describes various SE_PRIVILEGE flags used in Windows systems. It specifically mentions attributes like ENABLED, ENABLED_BY_DEFAULT, and REMOVED.
Excerpt:
Visual caption: A slide from a SANS course titled 'Privileges and Attributes' explaining the meaning of various SE_PRIVILEGE flags. Visible text: Privileges and Attributes; SE_PRIVILEGE_* values that describe the privilege; ENABLED; ENABLED_BY_DEFAULT; REMOVED; USED_FOR_ACCESS; SEC-701 | Red Team Toolkit: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SE_PRIVILEGE_*, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES, SeDebugPrivilege, SeLoadDriverPrivilege
Summary: The unit describes the concept of Windows privileges and their attributes, specifically focusing on how they are stored in the TOKEN_PRIVILEGES structure as LUID_AND_ATTRIBUTES. It details the technical definition of the LUID_AND_1ATTRIBUTES struct and the LUID component's role as a unique identifier for system operations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 87 Privileges and Attributes SE_PRIVILEGE_* values that describe the privilege SE_PRIVILEGE_* values that describe the privilege ENABLED ENABLED ENABLED_BY_DEFAULT ENABLED_BY_DEFAULT REMOVED REMOVED USED_FOR_ACCESS USED_FOR_ACCESS Privilege is simply enabled Enabled by default For removing privileges Used to obtain access to a service or to an object Privileges and Attributes Privileges are what determine if a user, or process, is allowed to carry out an operation within the system. Privileges are not necessarily tied directly to an object, but rather are tied to what can be done. Debuggers like WinDbg Pr

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Integrity Levels, Windows privilege separation, GetTokenInformation
Summary: The unit describes the six integrity levels used in Windows systems for privilege separation. It lists specific levels including Untrusted, Low, Medium, High, System, and Protected.
Excerpt:
Visual caption: A slide explaining the six integrity levels in Windows systems for privilege separation. Visible text: Integrity Levels (I); Untrusted (0); Low (1); Medium (2); High (3); System (4); Protected (5); GetTokenInformation Alt/source label:

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: whoami /priv, privilege levels, terminals, non-admin
Summary: The unit contains a screenshot and description of the 'whoami /priv' command output. It details various privilege levels such as SeChangeNotifyPrivilege and SeShutdownSystemPolicy.
Excerpt:
Visual caption: A screenshot of a terminal window showing the output of the 'whoami /priv' command, followed by explanatory text about privilege levels. Visible text: whoami /priv: non-admin (1); Privilege Name; Description; State; SeChangeNotifyPrivilege; SeShutdownSystemPrivilege; SeCreateAnonymousPrivilege; SeRemoteThread100Privilege; SeTzeZonePrivilege Alt/source label:

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: whoami /priv, SeChangeNotify, user privileges, Windows Dev VM
Summary: The text describes the `whoami /priv` command and its output for a standard user account on a Windows Dev VM. It explains that only the SeChangeNotify privilege is enabled by default, while others are disabled but can be capable of being enabled during specific operations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 90 whoami /priv: non-admin (1) whoami /priv: non-admin (1) As mentioned previously, privileges are tied to your primary token. The privileges shown on the slide are from the standard user account on the Windows Dev VM. After issuing the whoami /priv command, any privileges that are marked as Enabled will be listed in the command’s output. The only privilege that is enabled at the moment is SeChangeNotify, which, as the name suggests, allows you to traverse different directories to get to files or subdirectories that you can access. The privilege does not give you the access to list contents of every direc

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: whoami /priv, High Integrity, High-IL process, privileges enabled on the fly
Summary: The text describes the difference in privileges available to a process with High Integrity Level (High-IL) compared to standard processes. It notes that while many privileges are enabled on an even as-needed basis, they are still accessible.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 92 whoami /priv: High Integrity whoami /priv: High Integrity Let us look at a process with the High-IL. As can be seen on the slide, a High-IL process, command prompt in this instance, has a large increase in the number of privileges that are present. As we have seen already, even though most of the privileges are disabled, they can be enabled on the fly on an as needed basis. 92 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SeBackupPrivilege, SeRestorePrivilege, ACL bypass, winnt.h, FILE_GENERIC_READ, FILE_GENERIC_WRITE
Summary: The text describes how SeBackupPrivilege and SeRestorePrivilege can bypass standard file system ACLs to provide read and write access, respectively. It explains that these privileges trump the standard check for FILE_GENERIC_READ and FILE_GENERIC_WRITE. The section also points toward the winnt.h header file for more privilege constants.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 93 Privileges and ACLs? Abuse privileges to bypass ACLs! Abuse privileges to bypass ACLs! SE_BACKUP_NAME SE_BACKUP_NAME SE_RESTORE_NAME SE_RESTORE_NAME Regardless of the file’s ACL, granted complete read access Regardless of the file’s ACL, granted complete write access Privileges and ACLs? There is an interesting tidbit when it comes to privileges. Most privileges allow you to perform some operation, but still only after the system does a privilege check. Well, there are two privileges that bypass that check: SeBackupPrivilege and SeRestorePrivilege. MSDN describes these two privileges as ones that are u

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows privileges, SE_BACKUP_NAME, SE_RESTORE_NAME, bypass ACLs
Summary: The unit describes how specific Windows privileges (SE_BACKUP_NAME and SE_RESTORE_NAME) can be used to bypass file system Access Control Lists (ACLs). It explains that SE_BACKUP_NAME provides read access and SE_RESTORE_NAME provides write access regardless of existing ACLs.
Excerpt:
Visual caption: A slide from a cybersecurity course explaining how specific Windows privileges (SE_BACKUP_NAME and SE_RESTORE_NAME) can be used to bypass Access Control Lists (ACLs). Visible text: Privileges and ACLs?; Abuse privileges to bypass ACLs!; SE_BACKUP_NAME; Regardless of the file's ACL, granted complete read access; SE_RESTORE_NAME; Regardless of the file's ACL, granted complete write access; SEC702 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SeTakeOwnershipPrivilege, SeTakeOwnershipPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeDebugPrivilege, escalate from Admin to SYSTEM
Summary: The text describes several high-level Windows privileges (SeTakeOwnershipPrivilege, SeTcbPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeDebugPrivilege) that can be used for privilege escalation. It explains how these specific privileges allow an attacker to move from Administrator to SYSTEM level access.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 94 More Privileges There are several Se*Privileges that could be of interest. There are several Se*Privileges that could be of interest. SeTakeOwnershipPrivilege SeTakeOwnershipPrivilege SeTcbPrivilege SeTcbPrivilege SeCreateTokenPrivilege SeCreateTokenPrivilege SeLoadDriverPrivilege SeLoadDriverPrivilege SeDebugPrivilege SeDebugPrivilege More Privileges We talked about several privileges up to this point and what they can enable you do, but there are more that would be of interest. The first thing you might be wondering is why none of the privileges noted on the slide are even present for most standard u

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SeTakeOwnershipPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeDebugPrivilege, escalate from Admin to SYSTEM
Summary: The text describes several high-level Windows privileges (SeTakeOwnershipPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, and SeDebugPrivilege) that can be abused for privilege escalation from Administrator to SYSTEM. It explains the specific capabilities of each privilege, such as taking ownership of objects, becoming part of the trusted computing base, and loading drivers.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 94 More Privileges There are several Se*Privileges that could be of interest. There are several Se*Privileges that could be of interest. SeTakeOwnershipPrivilege SeTakeOwnershipPrivilege SeTcbPrivilege SeTcbPrivilege SeCreateTokenPrivilege SeCreateTokenPrivilege SeLoadDriverPrivilege SeLoadDriverPrivilege SeDebugPrivilege SeDebugPrivilege More Privileges We talked about several privileges up to this point and what they can enable you do, but there are more that would be of interest. The first thing you might be wondering is why none of the privileges noted on the slide are even present for most standard u
