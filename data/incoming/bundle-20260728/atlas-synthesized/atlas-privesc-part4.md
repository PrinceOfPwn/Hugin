# Atlas Material — privesc (part 4)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: privesc
Units: 26

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: SeTakeOwnershipPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeDebugPrivilege, escalate from Admin to SYSTEM
Summary: The text discusses various Windows Se*Privileges, specifically SeTakeOwnershipPrivilege, SeTcbPrivilege, SeTcbPrivilege (repeated), SeCreateTokenPrivilege, SeLoadDriverPrivilege, and SeDebugPrivilege. It explains that these privileges are typically not available to standard users and can be used by an administrator to escalate to SYSTEM level.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 94 More Privileges There are several Se*Privileges that could be of interest. There are several Se*Privileges that could be of interest. SeTakeOwnershipPrivilege SeTakeOwnershipPrivilege SeTcbPrivilege SeTcbPrivilege SeCreateTokenPrivilege SeCreateTokenPrivilege SeLoadDriverPrivilege SeLoadDriverPrivilege SeDebugPrivilege SeDebugPrivilege More Privileges We talked about several privileges up to this point and what they can enable you do, but there are more that would be of interest. The first thing you might be wondering is why none of the privileges noted on the slide are even present for most standard u

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Programmatically, LookupPrivilege_Value, OpenProcessToken, AdjustTokenPrivileges
Summary: The unit describes programmatic methods for adjusting privileges within a Windows environment. It specifically mentions functions like LookupPrivilegeValue, OpenProcessToken, and AdjustTokenPrivileges.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Privileges: Programmatically' discussing the programmatic adjustment of privileges. Visible text: Privileges: Programmatically; LookupPrivilegeValue; OpenProcessToken; AdjustTokenPrivileges; SEC601 Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 3 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Win32 API, LookupPrivilegeValue, OpenProcessToken, AdjustTokenPrivileges, SeDebugPrivilege
Summary: The unit describes how to programmatically enable or disable privileges using the Win32 API, specifically focusing on the SeDebugPrivilege. It details three primary APIs involved: LookupPrivilegeValue, OpenProcessToken, and AdjustTokenPrivileges.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 95 Privileges: Programmatically Privileges can be enabled/disabled programmatically. Privileges can be enabled/disabled programmatically. LookupPrivilegeValue LookupPrivilegeValue When you have a set of privileges that are present, but listed as disabled, you can programmatically adjust those privileges to be enabled. The opposite is also true, but why limit yourself? OpenProcessToken OpenProcessToken AdjustTokenPrivileges AdjustTokenPrivileges Privileges: Programmatically With the help of the Win32 API, we can create programs that can enable or even disable privileges that are present in our access token

=== UNIT 4 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: LookupPrivilegeValue, LUID, Boolean return type, Windows programming
Summary: The unit describes the technical definition and usage of the Windows API function LookupPrivilegeValue. It covers its return type (BOOL) and its role in retrieving a current LUID.
Excerpt:
Visual caption: A slide from a cybersecurity course showing the definition and usage of the LookupPrivilegeValue function in Windows programming. Visible text: LookupPriv_eValue; Gets the current LUID; Has a Boolean return type; BOOL LookupPrivilegeValue(; SEC07 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: LookupPrivilegeValue, SeDebugPrivilege, LUID, Windows API
Summary: The unit describes the Windows API function LookupPrivilegeValue, which is used to retrieve a locally unique identifier (LUID) for privilege constants like SeDebugPrivilege. It details the function's parameters (lpSystemName, lpName, lpLuid) and provides an example of how to wrap it in a conditional check.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 96 LookupPrivilegeValue LookupPrivilegeValue LookupPrivilegeValue Gets the current LUID Gets the current LUID BOOL LookupPrivilegeValueA( _In_opt_ LPCSTR lpSystemName, _In_ LPCSTR lpName, _Out_ PLUID lpLuid ); // EXAMPLE if ( !LookupPrivilegeValue(...) ) { // code here } Has a Boolean return type Has a Boolean return type LookupPrivilegeValue Whenever you need to retrieve the locally unique identifier for a privilege constant or privilege name like SeDebugPrivilege, this is the function to use. It has a BOOL return type, so it is simple to error check. Simply wrap the function call inside the condition of

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: persistence key, MITRE ATT&CK autostart, source code review, lab
Summary: The unit outlines the learning objectives for a module on persistence techniques in Windows environments. It covers identifying common persistence keys, MITRE ATT&CK autostart locations, and practical implementation through source code review and labs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 27 Objectives Our objectives for this module are: Discuss most used persistence key MITRE ATT&CK autostart locations Implement a few techniques Objectives The objectives for this module are to discuss what the most used key was for persistence. We will also explore several possible keys that can be leveraged for autostart entries. Lastly, we will reinforce the topics with source code review and a lab. © 2024 Jonathan Reiter 27 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Ace String Layout, ace_type, registry_rights, file_system_rights
Summary: The unit describes the internal structure of an Access Control Entry (ACE) string, detailing specific attribute fields such as ace_type, ace_sflags, and various rights types. It lists technical components related to ACE formatting.
Excerpt:
Visual caption: A slide titled 'Ace String Layout' detailing the structure of an ACE string, including various attribute fields like ace_type, ace_flags, generic_rights, and registry_rights. Visible text: Ace String Layout; ace_type; ace_flags; generic_rights; registry_rights; standard_rights; label_rights; file_system_rights; ACE.cc; ACE.cd; ACE.od; ACE.ad; ACE.al; CI; CC; CD; CA; CR; CN; CL Alt/source label:

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Registry modification, HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors, DLL execution as SYSTEM, local admin required, system reboot required
Summary: This unit describes a method for abusing port monitors via the Windows Registry to achieve SYSTEM privileges. It details how to modify the Print)Monitors hive and requires local admin rights and a system reboot to execute.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 70 Abusing Port Monitors: The Registry Method one: Registry Method one: Registry Key holds the port monitors in place Key holds the port monitors in place Need local admin Need local admin Abusing Port Monitors: The Registry There are two ways that we can leverage and abuse port monitors. The first method we are going to look at is using the Registry to modify the Print>Monitors hive. The full path to the key is HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors and the subkeys under it should be port monitors. We can manually view this using the regedit.exe GUI. Browsing to the key, we can select each 

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: IFEO, Image File Execution Options, Windows Registry key, debugging, persistence
Summary: The text describes the Image File Execution Options (IFEO) Windows Registry key and its purpose for debugging or tracing processes. It explains how developers use it to launch debuggers, while malware authors utilize it as a mechanism for persistence.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 81 What Is IFEO? Image File Execution Options Image File Execution Options IFEO is a Windows Registry key that enables the debugging or tracing of a process when it is started. The IFEO key is a great for developers so their application can be debugged, but it is also great for malware authors looking to persist on the target. What Is IFEO? IFEO stands for Image File Execution Options and comes in the form of a Windows Registry key. The idea behind it is to give some more options for when a process begins execution. The options can be any number of actions, like having a debugger launch when the process d

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: privilege escalation, reasoning for escalating, programmatic elevation
Summary: The unit outlines the learning objectives for a module on privilege escalation. It covers the reasoning behind escalating privileges and explores various programmatic methods to achieve this.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 82 Objectives Our objectives for this module are: Discuss the reasoning for escalating privileges Explore several methods Implement a few methods in code Objectives The objectives for this module are to talk about the reasoning for escalating your privileges. There could be times when you do not have to operate with higher privileges than what you have already. We will also discuss and explore several methods to programmatically elevate your current privileges. 82 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Why Escalate?, non-admin, admin, SEC700
Summary: The unit contains a slide discussing the necessity of privilege escalation in a red teaming context. It highlights questions regarding whether there is always a requirement to escalate privileges for specific goals.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Why Escalate?' discussing the necessity of privilege escalation. Visible text: Why Escalate?; Is there always a requirement to escalate privileges?; non-admin; admin; SEC700 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Windows Privileges, Enabled vs Disabled, SEC407
Summary: The unit describes the concept of Windows Privileges and distinguishes between enabled and disabled privileges. It is part of a SANS course on developing custom tools for Windows.
Excerpt:
Visual caption: A slide from a SANS course presentation about Windows Privileges, explaining the difference between enabled and disabled privileges. Visible text: Windows Privileges; What do privileges do for you?; Enabled; Disabled; SEC407 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: whoami /priv, non-admin, SeChangeNotifyPrivilege, SeIncreaseWorkingSetPrivilege
Summary: The unit contains a visual caption describing the output of the 'whoami /priv' command for a non-admin user. It highlights specific privileges like SeChangeNotifyPrivilege and SeIncreaseWorkingSetPrivilege.
Excerpt:
Visual caption: A slide from a cybersecurity course showing the 'whoami /priv' command output for a non-admin user, highlighting a change in privilege status. Visible text: whoami /priv: non-admin (2); SystemSettings.exe; Medium; Privilege; Flags; SeChangeNotifyPrivilege; Default Enabled; SeIncreaseWorkingSetPrivilege; Disabled; SeShutdownPrivilege; Disabled; SeTimeZonePrivilege; Enabled Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: AdjustTokenPrivileges, Windows API, s-1-5-18, Boolean return type
Summary: The unit describes the technical details of the Windows API function AdjustTokenPrivileges, including its purpose and basic signature. It mentions related functions like LookUpPrivilegeValue and OpenProcessToken.
Excerpt:
Visual caption: A slide from a technical presentation or manual explaining the AdjustTokenPrivileges function in Windows programming. Visible text: AdjustTokenPrivileges; Enables or disables privileges; Has a Boolean return type; BOOL AdjustTokenPrivileges(; LookUpPrivilegeValue; OpenProcessToken Alt/source label:

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: token stealing, privilege escalation, APIs
Summary: The unit describes a lab exercise focused on exploring the steps and APIs required to steal a token for privilege escalation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 101 What’s the Point? What’s the point? What’s the Point? The point of this lab was to explore the steps and APIs involved with stealing a token for escalating privileges. © 2024 Jonathan Reiter 101 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: SE_BACKUP_NAME, SE_RESTORE_NAME, SE_10000_WRITE_NAME, Unit Review
Summary: The unit contains a review section with multiple-choice questions regarding Windows privileges for file access. It specifically addresses which privilege allows write access regardless of the Access Control List (ACL).
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 137 Unit Review Answers What privilege gives complete write access regardless of the ACL? What privilege gives complete write access regardless of the ACL? A SE_BACKUP_NAME A SE_BACKUP_NAME B SE_RESTORE_NAME B SE_RESTORE_NAME C SE_WRITE_NAME C SE_WRITE_NAME Unit Review Answers Q: What privilege gives complete write access regardless of the ACL? A: SE_BACKUP_NAME B: SE_RESTORE_NAME C: SE_WRITE_NAME © 2024 Jonathan Reiter 137 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: SE_BACKUP_NAME, SE_RESTORE_NAME, SE_WRITE_NAME, Unit Review Answers
Summary: This unit contains a review section with multiple-choice questions regarding Windows privileges for file access. It specifically identifies the correct privilege for bypassing ACLs to gain write access.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 137 Unit Review Answers What privilege gives complete write access regardless of the ACL? What privilege gives complete write access regardless of the ACL? A SE_BACKUP_NAME A SE_BACKUP_NAME B SE_RESTORE_NAME B SE_RESTORE_NAME C SE_WRITE_NAME C SE_WRITE_NAME Unit Review Answers Q: What privilege gives complete write access regardless of the ACL? A: SE_BACKUP_NAME B: SE_RESTORE_NAME C: SE_WRITE_NAME © 2024 Jonathan Reiter 137 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 18 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: execute, elevate, Linux-based system, linter.py
Summary: The unit contains a visual caption describing technical documentation regarding the difference between 'execute' and 'elevate' commands in Linux systems.
Excerpt:
Visual caption: A screenshot of a technical documentation page explaining the differences between 'execute' and 'elevate' commands in a Linux-based system. Visible text: Execute; Execute; Execute; Execute; linter.py; Elevate; Elevate; Elevate; Elevate Alt/source label:

=== UNIT 19 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: Host Privilege Escalation, COMPLETE & CONTINUE
Summary: The unit contains an image caption describing a section on host privilege escalation techniques.
Excerpt:
Visual caption: A screenshot of a webpage or application interface displaying information about host privilege escalation. Visible text: Host Privilege Escalation; COMPLETE & CONTINUE >> Alt/source label:

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: SE_BACKUP_NAME, security privileges, ACL bypass, Unit Review
Summary: This unit contains a review section for the SEC670 course, specifically focusing on questions regarding Windows privileges and access rights. It identifies SE_BACKUP_NAME as the privilege providing write access regardless of ACLs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 137 Unit Review Answers What privilege gives complete write access regardless of the ACL? What privilege gives complete write access regardless of the ACL? A SE_BACKUP_NAME A SE_BACKUP_NAME B SE_RESTORE_NAME B SE_RESTORE_NAME C SE_WRITE_NAME C SE_WRITE_NAME Unit Review Answers Q: What privilege gives complete write access regardless of the ACL? A: SE_BACKUP_NAME B: SE_RESTORE_NAME C: SE_WRITE_NAME © 2024 Jonathan Reiter 137 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 21 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: Windows privileges, multiple-choice question, ACLS, SE_BACKUP_NAME, SE_RESTORE_NAME, SE_WRITE_NAME
Summary: The unit contains a multiple-choice question and its corresponding answer regarding Windows privileges. It specifically identifies which privilege grants full write access regardless of Access Control Lists (ACLs).
Excerpt:
Visual caption: A slide from a SANS course showing the answer to a multiple-choice question about Windows privileges. Visible text: Unit Review Answers; What privilege gives complete write access regardless of the ACL?; SE_BACKUP_NAME; SE_RESTORE_NAME; SE_WRITE_NAME Alt/source label:

=== UNIT 22 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: privilege escalation, programmatic elevation, learning objectives
Summary: The unit outlines the learning objectives for a module on privilege escalation. It covers the reasoning behind escalating privileges and explores various methods to programmatically elevate current privileges.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 82 Objectives Our objectives for this module are: Discuss the reasoning for escalating privileges Explore several methods Implement a few methods in code Objectives The objectives for this module are to talk about the reasoning for escalating your privileges. There could be times when you do not have to operate with higher privileges than what you have already. We will also discuss and explore several methods to programmatically elevate your current privileges. 82 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 23 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: Why Escalate?, non-admin, admin, SEC700
Summary: The unit contains a slide discussing the necessity of privilege escalation in a red teaming context. It highlights questions regarding whether there is always a requirement to escalate privileges for non-admin users.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Why Escalate?' discussing the necessity of privilege escalation. Visible text: Why Escalate?; Is there always a requirement to escalate privileges?; non-admin; admin; SEC700 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 24 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: Securable Objects, security descriptor, CreateProcess, CreateFile, CreateThread, SECURITY_ATTRIB
Summary: The unit describes security descriptors for various Windows objects such as files, processes, registry keys, and threads. It explains that these objects are created by users via specific system calls like CreateProcess and CreateFile.
Excerpt:
Visual caption: A presentation slide titled 'Securable Objects' explaining the concept of security descriptors for various object types like files, processes, and registry keys. Visible text: Securable Objects; Objects that have a corresponding security descriptor; Most objects are created at the request of the user: CreateProcess, CreateThread, CreateFile, etc. The creation functions specify a pointer to a SECURITY_ATTRIB; files; processes; reg keys; threads; SEC-70 | Red Team_Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 25 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: SDDL, DACL, SACL, IU, SU, BA, SY, Get-Service
Summary: The unit describes a specific Security Descriptor Definition Language (SDDL) string used to configure access permissions for a service. It breaks down the DACL and SACL components, identifying how different user groups like interactive users, service users, and administrators are restricted or granted access. The text also suggests testing these configurations with tools like PowerShell's Get-Service.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 55 Exercise: SDDL: The Solution "D: DACL (D;;DCLCWPDTSD;;;IU) interactive user, deny: delete, list, write, delete tree, standard delete (D;;DCLCWPDTSD;;;SU) service user, deny: delete, list, write, delete tree, standard delete (D;;DCLCWPDTSD;;;BA) built‐in admins, deny: delete, list, write, delete tree, standard delete (A;;CCLCSWLOCRRC;;;IU) interactive user, allow: create, list, selfwrite, list obj, control access, read control (A;;CCLCSWLOCRRC;;;SU) service user, allow: create, list, selfwrite, list obj, control access, read control (A;;CCLCSWRPWPDTLOCRRC;;;SY) local system, allow: create, list, selfwri

=== UNIT 26 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: EXPLICIT_ACCESS_A, ACL modification, grfAccessPerms, ACCESS_MODE, TRUSTEE_A
Summary: The text describes the EXPLICIT_ACCESS_A structure and its associated members (grfAccessPerms, grfAccessMode, grfInheritance, Trustee) used for modifying Access Control Lists (ACLs). It also provides definitions for the ACCESS_MODE enum and the TRUSTEE_A structure.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 61 EXPLICIT_ACCESS_A EXPLICIT_ACCESS_A EXPLICIT_ACCESS_A Defines access control information for a trustee Defines access control information for a trustee typedef struct _EXPLICIT_ACCESS_A { DWORD grfAccessPerms; ACCESS_MODE grfAccessMode; DWORD grfInheritance; TRUSTEE_A Trustee; } EXPLICIT_ACCESS_A, *PEXPLICIT_ACCESS_A, EXPLICIT_ACCESSA, *PEXPLICIT_ACCESSA; The user, group, program to apply it against The user, group, program to apply it against EXPLICIT_ACCESS_A The EXPLICIT_ACCESS_A structure is heavily used whenever modifications are being made to the ACL of an object. The structure is used to describ
