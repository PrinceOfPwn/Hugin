# Atlas Material — misc (part 1)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: unknown
Units: 28

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.95  Key cues: Windows services, persistence, memory execution, binary patching, Lab 4.1: Persistent Service
Summary: The unit covers the use of Windows services for persistence, including both existing and newly created services. It outlines a course roadmap involving memory execution, binary patching, and various other techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 39 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss how to persist using services. This includes services that we take advantage of or services that we create ourselves. © 2024 Jonathan Reiter 39 © SANS

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.95  Key cues: IFEO, Persistence: Die Another Day, Windows Tool Development, roadmap
Summary: The unit contains a roadmap of topics related to Windows tool development and persistence techniques, specifically mentioning Image File Execution Options (IFEO). It lists various methods such as memory execution, binary patching, registry keys, and WMI event subscriptions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 79 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss how to persist using Image File Execution Options (IFEO). © 2024 Jonathan Reiter 79 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://lin

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: DLL Injection, injector.exe, notepad.exe, Obtain handle, Allocate memory, Write DLL path, Spawn remote thread
Summary: The unit describes the process of classic DLL injection, including steps like obtaining a handle, allocating memory, and spawning a remote thread. It features a flowchart illustrating these stages for an educational walk-through.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Walk-through: Classic DLL Injection' showing a flowchart of the injection process. Visible text: Walk-through: Classic DLL Injection; injector.exe; notepad.exe; Obtain handle to target; Allocate memory; Write DLL path to memory; Spawn a remote thread; SANS SECF07 Alt/source label:

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows thread processing, APC queue, query about quantum
Summary: The unit contains a multiple-choice question regarding the mechanism for processing routines in Windows threads during their quantum. Options include APC queue, Contexts, and Event objects.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about Windows thread processing. Visible text: Unit Review Questions; What mechanism allows threads to process routines when it enters its quantum?; APC queue; Contexts; Event objects Alt/source label:

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AppInit_DLLs, registry key, LoadAppInit_DLLs, REG_DWORD, REG_SE
Summary: The unit describes the AppInit_DLLs registry key used to force user processes to load specific DLLs. It covers the technical details of the instance where LoadAppInit_DLLs is set to 1.
Excerpt:
Visual caption: A presentation slide explaining the AppInit_DLLs registry key and its role in loading DLLs into processes. Visible text: AppInit_DLLs; Forcing a user process to load certain DLLs; LoadAppInit_DLLs (REG_DWORD); AppInit_DLLs (REG_SE); SEC701 / Red Team_Tools: Developing Windows_Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AppInit_DLLs, User32.dll, LoadAppInit_Dlls, HKLM registry keys, privilege escalation requirement, infinite loop prevention
Summary: This unit describes the AppInit_DLLs technique for forcing user processes to load specific DLLs. It details the registry keys involved, the requirements for process linking against User32.dll, and the necessary administrative privileges. The text also discusses how to avoid infinite loops when using this method.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 30 AppInit DLLs Forcing a user process to load certain DLLs Forcing a user process to load certain DLLs LoadAppInit_DLLs (REG_DWORD) LoadAppInit_DLLs (REG_DWORD) When enabled, each newly created user mode process that is linked against User32.dll will load the DLLs annotated a list stored in the AppInit_DLLs Registry key. The list can be comma separated should there be a need to load more than one DLL. AppInit_DLLs (REG_SZ) AppInit_DLLs (REG_SZ) AppInit DLLs Windows provides users the flexibility to allow a pre-determined list of customized DLLs to be loaded into practically each user process. The catch i

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Registry Keys, Persistence: Die Another Day, Windows Tool Development, WMI Event Subscriptions
Summary: The unit covers the use of Windows Registry keys for maintaining persistence in a red teaming context. It lists various techniques and tools related to implant development, including service creation and WMI event subscriptions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 26 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge Registry Keys In this module, we will discuss how to persist using the Windows Registry. 26 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://link

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: AppInit_DLLs, LoadAppInit_DLLs, registry key, user process, DLL loading
Summary: The unit describes the AppInit_DLLs registry key used to load DLLs into user processes. It covers the mechanism of forcing process loading and includes specific registry keys like LoadAppInit_DLLs and AppInit_DLLs.
Excerpt:
Visual caption: A presentation slide explaining the AppInit_DLLs registry key and its role in loading DLLs into processes. Visible text: AppInit_DLLs; Forcing a user process to load certain DLLs; LoadAppInit_DLLs (REG_DWORD); AppInit_DLLs (REG_SE); SEC701 / Red Team_Tools: Developing Windows_Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: AppInit_DLLs, User32.dll, LoadAppInit_Dlls, HKLM Registry key, APT39, CherryPicker, T9000
Summary: The text describes the AppInit_DLLs technique for forcing user processes to load specific DLLs, specifically those linked against User32.dll. It details the registry keys involved (HKLM) and the requirements for administrative privileges.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 30 AppInit DLLs Forcing a user process to load certain DLLs Forcing a user process to load certain DLLs LoadAppInit_DLLs (REG_DWORD) LoadAppInit_DLLs (REG_DWORD) When enabled, each newly created user mode process that is linked against User32.dll will load the DLLs annotated a list stored in the AppInit_DLLs Registry key. The list can be comma separated should there be a need to load more than one DLL. AppInit_DLLs (REG_SZ) AppInit_DLLs (REG_SZ) AppInit DLLs Windows provides users the flexibility to allow a pre-determined list of customized DLLs to be loaded into practically each user process. The catch i

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: ImagePath, binPath, FailureCommand, sc.exe, CreateService API
Summary: The unit describes how to modify existing Windows services for persistence by manipulating the ImagePath and binPath Registry keys. It also explains the utility of FailureCommand as a mechanism to execute commands if a service fails. These modifications can be used to achieve persistence or maintain access.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 42 What to Change? Existing services can be modified in several areas. Existing services can be modified in several areas. ImagePath ImagePath A Registry key that holds absolute path to the service binary on disk binPath binPath FailureCommand FailureCommand The absolute path to the service binary on disk. Typically matches ImagePath. Indicates what should happen if the service does not start or gets terminated What to Change? The ImagePath is a Registry key for the service. Most of the time, the value held is the path to the service executable on disk. The value, or arguments, in the key are passed to th

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Gflags.exe, GlobalFlag, Silent Process Exit, HKLM Registry keys
Summary: The text describes the use of Gflags.exe and the GlobalFlag registry key to enable advanced debugging features, specifically Silent Process Exit. It explains how these settings can be used to trigger actions upon a process's exit for persistence.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 82 IFEO GlobalFlag A nice addition to the traditional IFEO A nice addition to the traditional IFEO Gflags.exe Gflags.exe Silent process exit Silent process exit Bundled with the Windows SDK, enables advanced debugging of applications Monitor an exiting process Image: Process to “watch” Monitor: The “watching” process IFEO GlobalFlag To use GlobalFlags, the SDK must be installed. After installation is completed, the gflags binary should be located at: C:\Program Files (x86)\Windows Kits\10\Debuggers\x64. MSDN describes the binary as one that can enable more advanced debugging and is used to turn on other i

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: GFlagx, GUI for PowerShell tool, sient process exit, SEC-701 Red Teaming Tools
Summary: The unit contains a screenshot and description of 'GFlagx', a GUI tool designed to manage Windows process flags. It specifically highlights options like 'Silent Process Exit' for red teaming purposes.
Excerpt:
Visual caption: A screenshot of a GUI tool named 'GFlagx' showing various configuration options for Windows process flags. Visible text: Running GFlagx; GUI for PowerShell tool; GFlagx; Silent Process Exit; SEC-701 Red Teaming Tools Alt/source label:

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: WIN32_FIND_DATA, KUSER_SHARED_DATA, FILE_OBJECT
Summary: The unit contains a review question regarding the specific user-mode structure used to hold file attributes in Windows.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What user-mode structure holds the attributes of a file? What user-mode structure holds the attributes of a file? A WIN32_FIND_DATA A WIN32_FIND_DATA B KUSER_SHARED_DATA B KUSER_SHARED_DATA C FILE_OBJECT C FILE_OBJECT 86 Unit Review Questions Q: What user-mode structure holds the attributes of a file? A: WIN32_FIND_DATA B: KUSER_SHARED_DATA C: FILE_OBJECT 86 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: multiple-choice, WIN32_FIND_DATA, KUSER_SHARED_DATA, FILE_OBJECT
Summary: The unit contains a multiple-choice question regarding Windows user-mode structures specifically identifying the structure that holds file attributes.
Excerpt:
Visual caption: A screenshot of a SANS Institute training slide showing a multiple-choice question about Windows user-mode structures. Visible text: Unit Review Questions; What user-mode structure holds the attributes of a file?; WIN32_FIND_DATA; KUSER_SHARED_DATA; B. KUSER_SHARED_DATA; C. FILE_OBJECT; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: WIN32_FIND_DATA, KUSER_SHARED_DATA, FILE_OBJECT
Summary: This unit contains a review question regarding the specific user-mode structure used to hold file attributes in Windows.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What user-mode structure holds the attributes of a file? What user-mode structure holds the attributes of a file? A WIN32_FIND_DATA A WIN32_FIND_DATA B KUSER_SHARED_DATA B KUSER_SHARED_DATA C FILE_OBJECT C FILE_OBJECT 87 Unit Review Answers Q: What user-mode structure holds the attributes of a file? A: WIN32_FIND_DATA B: KUSER_SHARED_DATA C: FILE_OBJECT 87 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: WIN32_FIND_DATA, KUSER_SHARED_DATA, FILE_OBJECT
Summary: This unit contains a review question regarding the specific user-mode structure used to hold file attributes in Windows.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What user-mode structure holds the attributes of a file? What user-mode structure holds the attributes of a file? A WIN32_FIND_DATA A WIN32_FIND_DATA B KUSER_SHARED_DATA B KUSER_SHARED_DATA C FILE_OBJECT C FILE_OBJECT 87 Unit Review Answers Q: What user-mode structure holds the attributes of a file? A: WIN32_FIND_DATA B: KUSER_SHARED_DATA C: FILE_OBJECT 87 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: MS-DOS header, Unit Review Answers, 0x00, 0x90, 0x5A
Summary: The unit contains a review section for the SEC670 course, specifically focusing on questions regarding MS-DOS header bytes. It lists multiple choice options and their corresponding answers.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 30 Unit Review Answers What is typically the next byte that comes after the MS-DOS header? What is typically the next byte that comes after the MS-DOS header? A 0x00 A 0x00 B 0x90 B 0x90 C 0x5A C 0x5A Unit Review Answers Q: What is typically the next byte that comes after the MS-DOS header? A: 0x00 B: 0x90 C: 0x5A 30 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: thread definition, MSDN reference, security context
Summary: The unit defines the concept of a thread as an entity within a process that can be scheduled for execution according to MSDN. It is part of a course on red teaming tools and developing Windows implants.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'SEC607' that defines what a thread is in the context of operating systems. Visible text: Definition; What is a thread?; According to MSDN: "A thread is an entity within a process that can be scheduled for execution."; SEC607 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: thread creation, object residency, multiple-choice question
Summary: The unit contains a multiple-choice review question regarding the location of newly created threads in memory (user vs. system space).
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about thread creation and object residency. Visible text: Unit Review Questions; When a new thread is created, where does the object reside?; User space; System space; Process handle table Alt/source label:

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Unit Review Questions, security descriptor, SDDL, ACL, DACL
Summary: The unit contains a multiple-choice review question regarding the security descriptors for Windows systems. It specifically asks which language is used to define these descriptors.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about security descriptors. Visible text: Unit Review Questions; What language can be used to describe the security of a descriptor?; SDDL; ACL; DACL Alt/source label:

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: security descriptor, command-line utility, multiple-choice
Summary: The unit contains a multiple-choice question regarding command-line utilities for viewing security descriptors.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about command-line utilities for viewing security descriptors. Visible text: Unit Review Questions; What command-line utility lets you view an object's security descriptor?; cmd.exe; sc.exe; tasklist.exe; SEC601; Red Teaming Tools Alt/source label:

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: GflagsX, gflags.exe, Pavel Yosifovich, github.com/zodiacon
Summary: The unit describes GflagsX, a modern version of the gflags.exe utility created by Pavel Yosifovich. It highlights its improved features and updated GUI.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 84 GflagsX A modern take on the original gflags.exe utility A modern take on the original gflags.exe utility Pavel Yosifovich created a new version of gflags that offers a great new look to the tool. Check out his repo for this and other awesome tools: https://github.com/zodiacon. GflagsX Pavel Yosifovich has been recreating several tools with better features and a nicer looking GUI. Pavel has been posting them publicly on his repo https://github.com/zodiacon. If you get a chance, check them out for yourself. 84 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.e

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: GflagsX, gflags.exe, Pavel Yosifovich, github.com/zodiacon
Summary: The unit describes GflagsX, a modern version of the gflags.exe utility for Windows. It highlights that Pavel Yosifovich created it and provides links to his GitHub repository.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 84 GflagsX A modern take on the original gflags.exe utility A modern take on the original gflags.exe utility Pavel Yosifovich created a new version of gflags that offers a great new look to the tool. Check out his repo for this and other awesome tools: https://github.com/zodiacon. GflagsX Pavel Yosifovich has been recreating several tools with better features and a nicer looking GUI. Pavel has been posting them publicly on his repo https://github.com/zodiacon. If you get a chance, check them out for yourself. 84 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.e

=== UNIT 24 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: COM interface, ITaskScheduler, 114 Unit Review Questions
Summary: The unit contains a review question regarding COM interfaces for creating enumeration objects in the context of 114-page document content.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What COM interface can be called to create an enumeration object? What COM interface can be called to create an enumeration object? A ITaskScheduler A ITaskScheduler B IUnknown B IUnknown C IBelieve C IBelieve 114 Unit Review Questions Q: What COM interface can be called to create an enumeration object? A: ITaskScheduler B: IUnknown C: IBelieve 114 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 25 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: WIN32_FIND_DATA, KUSER_SHARED_DATA, FILE_OBJECT
Summary: This unit contains a review question regarding the specific user-mode structure used to hold file attributes in Windows.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What user-mode structure holds the attributes of a file? What user-mode structure holds the attributes of a file? A WIN32_FIND_DATA A WIN32_FIND_DATA B KUSER_SHARED_DATA B KUSER_SHARED_DATA C FILE_OBJECT C FILE_OBJECT 87 Unit Review Answers Q: What user-mode structure holds the attributes of a file? A: WIN32_FIND_DATA B: KUSER_SHARED_DATA C: FILE_OBJECT 87 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 26 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: course roadmap, in-memory execution, binary patching, port monitors, persistence
Summary: The unit contains a course roadmap and an introduction to the 'Persistence: Die Another Day' module focusing on port monitors.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 67 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss how to persist using port monitors. © 2024 Jonathan Reiter 67 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 27 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: GflagsX, gflags.exe, Paweł Ýosifovich, GitHub repo
Summary: The unit describes the 'GflagsX' tool, a modern version of the gflags.exe utility created by Paweł Ýosifovich. It includes a link to the creator's GitHub repository.
Excerpt:
Visual caption: A screenshot of a webpage or document page featuring the tool 'GflagsX' and its description. Visible text: GflagsX; A modern take on the original gflags.exe utility; Paweł Ýosifovich created a new version of gflags that offers a great new look to the tool.; Check out his repo for this and other awesome tools: https://github.com/zodiacon.; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control; 84 Alt/source label:

=== UNIT 28 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: SEC670, persistence method, Image File Execution Options, process start, silent.exe
Summary: The unit describes a slide from a SEC670 course explaining the purpose of a lab exercise regarding Image File Execution Options (IFEO) for persistence.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'What's the Point?' explaining the purpose of a lab exercise. Visible text: What's the Point?; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control; The point of this lab is to become familiar with the persistence method of Image File Execution Options and the two variants: process start and silent.exe Alt/source label:
