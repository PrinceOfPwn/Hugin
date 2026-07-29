# Atlas Material — methodology (part 9)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: methodology
Units: 37

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: Course Roadmap, Windows Tool1.2: ProcMon, ReflectDLL, SA1
Summary: The unit contains a slide outlining the course roadmap for SANS SEC679, detailing modules such as Windows Tool Development and various labs like PE-Sever and ReflectDLL.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlines the modules and labs for a SANS SEC679 course. Visible text: Course Roadmap; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant; Capture the Flag Challenge; Section 1; Developing Offensive Tools; Developing Defensive Tools; Lab 1.1: PE-Sever; Lab 1.2: ProcMon; Setting Up Your Development Environment; Windows DLLs; Lab 1.3: ReflectDLL; Windows Data Types; Call Me Maybe; Lab 1.4: Call Me Maybe; SA1. Annotations; Lab 1.5: Safer with SA1 Alt/source label:

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: Purpose, Defensive mindset, sEC701, Red Teaming Tools
Summary: The unit describes the purpose of red teaming tools and the role of defensive security. It highlights the cat-and-mouse game between offensive and defensive operations.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Purpose' explaining the role of defensive tools and the cat-and-mouse game between offensive and defensive security. Visible text: Purpose; Defensive mindset; Defense: you are; SEC701 / Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 3 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: open-source, freeware, commercial, Huntress Labs, PE-sieve, Sysinternals, ProcMon, Sysmon
Summary: The unit discusses the landscape of existing tools, categorizing them into open-source, freeware, aware of commercial products like Huntress Labs and PE-sieve. It highlights specific defensive tools such as PE-sieve for detecting injected implants and Sysinternals (ProcMon, Sysmon) for monitoring system activities.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Current State of the Art Tools There are many categories of tools out there: open-source, freeware, and commercial. Profit driven Community driven Huntress Labs PE-sieve 26 Current State of the Art Tools Open-source tools are great and sites like GitHub are full of them. There is nothing wrong with closed-source, commercial tools but when you can see the code like you can on GitHub, you can fork the project and modify it to fit your needs. Granted you will need to check the license the author put on it, but often the license is not that restrictive. Freeware tools are tools that are, well, free! One possi

=== UNIT 4 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: Table of Contents, Lab 1.5-1.9, CreateFile, CreateThread, RegWriteKey, WinDigg, StudioCraft, SEC701
Summary: The unit contains a table of contents listing various labs related to Windows API functions (CreateFile, CreateThread, RegWriteKey) and tools like WinDigg and StudioCraft. It also mentions the SEC701 course title regarding red teaming tools and Windows implants.
Excerpt:
Visual caption: A table of contents page from a technical manual or course material. Visible text: Table of Contents (2); Lab 1.5: Safer with API; Lab 1.6: CreateFile; Lab 1.7: CreateThread; Lab 1.8: RegWriteKey; Lab 1.9: It's Time for WinDigg; Lab 1.10: StudioCraft; SEC701: Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: What's the Point?, SEC679, Red Teaming Tools, Development of Windows Implants, Shellcode, Command and Control
Summary: The unit contains a presentation slide titled 'What's the Point?' which lists related topics such as red teaming tools, developing Windows implants, shellcode, and command and control. It serves as introductory or transitional content for the SEC679 course.
Excerpt:
Visual caption: A presentation slide titled 'What's the Point?' with a central question box. Visible text: What's the Point?; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: WUA, LUA, FUA, Unit Review Answers
Summary: The unit contains a review section for the SEC670 course, specifically focusing on questions regarding Windows Update Agent (WUA) and other update families of APIs used to query hotfixes.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What is the update family of APIs used to query hotfixes? What is the update family of APIs used to query hotfixes? A WUA A WUA B LUA B LUA C FUA C FUA 33 Unit Review Answers Q: What is the update family of APIs used to query hotfixes? A: WUA (Windows Update Agent) B: LUA C: FUA 33 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: course roadmap, SANS SEC670, Windows Implants, Command and Control, Process Enumeration, WTSEnum, CreateToolhelp
Summary: The text lists a course roadmap for red teaming tools, specifically focusing on developing Windows implants and command and control. It outlines modules covering OS information gathering, process enumeration, installed software identification, and other system components.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 65 Finding installed software can tell you a great deal about a target. Let us dive 

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: SEC670, application installation locations, goal-oriented decision making, GO/NO-GO
Summary: The unit describes a module summary for the SEC670 course, focusing on topics related to identifying application installation locations and making go/no-go decisions based on gathered information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Explored where applications can be installed Explored where applications can be installed Learned to make a decision to continue or abort based on the listing of software Learned to make a decision to continue or abort based on the listing of software 72 Module Summary In this module, we explored where some applications might be installed, and we also discussed how GO/NO- GO decisions can be made based on gathered information. 72 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: SANS SEC670, RED TEAMING TOOLS, S122E7BB7A, offsecexam
Summary: The text is a title page or introductory section for the SANS SEC670 course on Red Teaming Tools, specifically focusing on Windows implants, shellcode, and command and control. It includes institutional branding and contact information.
Excerpt:
THE MOST TRUSTED SOURCE FOR INFORMATION SECURITY TRAINING, CERTIFICATION, AND RESEARCH | sans.org SEC670 I RED TEAMING TOOLS: DEVELOPING WINDOWS IMPLANTS, SHELLCODE, COMMAND AND CONTROL 670.3 Operational Actions © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a ibmconnect2024@gmail_com ohNrhAfzA3YUEB7zYQeMv7asRrrC6mmK live https://linktr.ee/offsecexam

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: service attributes, start type
Summary: The unit describes service attributes such as start type and service type within the context of a red team toolkit. It is part of a training module on developing Windows implants.
Excerpt:
Visual caption: A slide from a training course about service attributes, including start type and service type. Visible text: Services: Attributes; Start Type; Service Type; Error Level; SEC701 | Red Team Toolkit: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: thread definition, MSDN reference, security course content
Summary: The unit defines the concept of a thread as an entity within a process that can be scheduled for execution according to MSDN. It is part of a student training course on red teaming tools and developing Windows implants.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'SEC607' that defines what a thread is in the context of operating systems. Visible text: Definition; What is a thread?; According to MSDN: "A thread is an entity within a process that can be scheduled for execution."; SEC607 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: thread definition, MSDN definition, execution units, process vs thread distinction
Summary: The unit defines what a thread is in the context of Windows systems, explaining it as an entity within a process that can be scheduled for execution by the CPU. It describes threads as the smallest unit of execution tied to a process and explains how they are initiated at the entry point after memory mapping.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 35 Definition What is a thread? What is a thread? According to MSDN: “A thread is an entity within a process that can be scheduled for execution.” Definition MSDN provides us with a definition of a thread: “A thread is an entity within a process that can be scheduled for execution.” What does that really mean? Well, first things first, threads are what execute the instructions of a program and they are to be eventually executed by the CPU. Think of a thread as the smallest unit of execution that is tied to a process. Each process will have at least one thread that kicks off the image’s code at its Address

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: Windows dispatcher, preemptive scheduling, priority-based system, thread quantum
Summary: The text describes the Windows dispatcher's role in preemptive, priority-based thread scheduling. It explains how higher-priority threads can preempt lower-priority ones and defines a quantum as the allotted time for a thread to run on a CPU.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 37 Thread Scheduling The Windows dispatcher The Windows dispatcher Because Windows is a preemptive, and priority-based system, threads can be selected for execution but never execute because it gets preempted by a thread with a higher priority. Threads run for a certain number of clock cycles during their quantum. Thread Scheduling Threads can be assigned higher levels of priority that enable them to run before threads with a lower priority. When a thread with a high priority leaves its waiting state and becomes ready to run, it will preempt any other thread that is currently in its quantum if it has a lo

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: thread creation, object residency, multiple-choice question
Summary: The unit contains a multiple-choice review question regarding the location of newly created threads in memory (user vs. system space).
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about thread creation and object residency. Visible text: Unit Review Questions; When a new thread is created, where does the object reside?; User space; System space; Process handle table Alt/source label:

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: thread creation, memory location, review questions
Summary: The unit contains a review question regarding the memory location of a new thread object when it is created. It provides multiple-choice options for this specific technical detail.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 43 Unit Review Questions When a new thread is created, where does the object reside? When a new thread is created, where does the object reside? A User space A User space B System space B System space C Process handle table C Process handle table Unit Review Questions Q: When a new thread is created, where does the object reside? A: User space B: System space C: Process handle table © 2024 Jonathan Reiter 43 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: thread creation, sytem space vs user space, security training
Summary: The unit contains a review question answer regarding the location of new threads in memory. It specifically addresses whether thread objects reside in user space or system space.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the answer to a review question about thread creation and object residency. Visible text: Unit Review Answers; When a new thread is created, where does the object reside?; User space; System space; Process handle table; SEC670 | Red Team Training Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: thread states, quantum slice, running, waiting, ready
Summary: The unit contains a multiple-choice question regarding the operating system's thread states during a quantum slice. It is part of a study guide for red team training tools.
Excerpt:
Visual caption: A screenshot of a study guide page showing a multiple-choice question about thread states in operating systems. Visible text: Unit Review Answers; What state is a thread in during its quantum slice?; Running; Waiting; Ready; SEC601: Red Team Training Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: APC injection, SEC701, What's the Point?
Summary: The unit describes a presentation slide introducing the concept and purpose of a laboratory exercise involving APC injection.
Excerpt:
Visual caption: A presentation slide titled 'What's the Point?' explaining the purpose of a lab on APC injection. Visible text: What's the Point?; SEC701; APC injection method Alt/source label:

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: WMI, Windows Management Instrumentation, C++ development, PowerShell scripting, Get-WmiObject, WMI providers, WMI consumers
Summary: The text introduces the Windows Management Instrumentation (WMI) and its role in managing data and operations for both local and remote systems. It describes WMI's utility for administrators using PowerShell and developers using C++ to query, manage, and execute actions like creating processes or registry keys. The section concludes by stating that a deeper understanding of the backend of WMI is necessary before discussing events and filters.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 99 What Is WMI? The Windows Management Instrumentation (WMI) The Windows Management Instrumentation (WMI) The Windows OS must manage the data and operations not only for itself but also for remote systems. WMI is the method that instruments this management and is designed for developers and administrators to use with ease via C++ development or PowerShell scripting. What Is WMI? Windows generates an enormous amount of data and executes many operations. Because of this, it needs something to assist with the management of said data. Enter the Windows Management Instrumentation (WMI). WMI enables developers 

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: Course Roadmap, Section 4, In Memory Execution, Binary Patching, Registry Keys, Persistence Service, Sauron, IFEO
Summary: The unit contains a slide outlining the curriculum for Section 4 of a red teaming course. It lists various topics including in-memory execution, binary patching, registry keys, services, and specific lab exercises related to persistence.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' and 'Section 4' outlining the curriculum for a red teaming course. Visible text: Course Roadmap; Section section 4; In Memory Execution; Dropping to Disk; Binary Patching; Registry Keys; Services Revisited; Lab 4:1. Persistence Service; Port Monitors; Lab 4:2. Sauron; IFEO; Lab 4:3. IFEOPersist; WMH Event Subscriptions; Bootcamp; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 21 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: In Memory Execution, Dropping to Disk, Binary Patching, Registry Keys, W1M1 Event Subscriptions, WMI Event Subscriptions
Summary: The text outlines a course roadmap for red teaming tools, specifically focusing on Windows implants and command and control. It lists various techniques such as in-memory execution, binary patching, registry keys, and WMI event subscriptions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 13 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss why you would need to drop something to disk, where to drop, cleaning up, and more. © 2024 Jonathan Reiter 13 © SANS Institute 2024 f80c9b76f5e518e0ab

=== UNIT 22 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: Course Roadmap, Section 4, In Memory Execution, Binary Patching, Registry Keys, Services Revisited, Persistence Service, WMI Event Subscriptions
Summary: The unit contains a slide outlining the roadmap for Section 4 of a SANS course, listing topics such as in-memory execution, binary patching, and various persistence mechanisms.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Course Roadmap' showing the contents of Section 4. Visible text: Course Roadmap; Section 4; In Memory Execution; Dropping to Disk; Binary Patching; Registry Keys; Services Revisited; Lab 4:1. Persistence Service; Port Monitors; Port Monitors; Lab 4:2. Sauron; IFEO; Lab 4:3. IFEOPersist; WMI Event Subscriptions; Bootcamp Alt/source label:

=== UNIT 23 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: Course Roadmap, Section 4, In Memory Execution, Binary Patching, sauron, WMI Event Subscriptions
Summary: The unit contains a slide titled 'Course Roadmap' outlining the curriculum for Section 4 of a red teaming course. It lists specific topics including in-memory execution, binary patching, and various lab exercises related to persistence.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' showing the curriculum for Section 4 of a red teaming course. Visible text: Course Roadmap; Section 4; In Memory Execution; Dropping to Die; Binary Patching; Registry Keys; Services Revisited; Lab 4:1. Persistence Service; Port Monitors; IFE0; Lab 4:2. Sauron; IFEO; Lab 4:3. IFEOPersist; WMI Event Subscriptions; Bootcamp Alt/source label:

=== UNIT 24 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: binary patching, persistence, Windows Tool Development, Course Roadmap
Summary: The unit contains a course roadmap and an introductory section for module 4 on Windows tool development. It specifically introduces the topic of binary patching as a method for achieving persistence.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 20 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss what binary patching is and how we can leverage it for persistence on target. 20 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c1

=== UNIT 25 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: Table of Contents, In Memory Execution, Dropping to Disk, Registry Keys, Lab 4.1: PowerShellService, Lab 4.2: Sauron, Lab 4.3: IEC90pass
Summary: The unit contains a Table of Contents for a technical manual or course material regarding red teaming tools and Windows implants. It lists topics such as in-memory execution, dropping to disk, registry keys, and specific lab exercises.
Excerpt:
Visual caption: A screenshot of a Table of Contents page from a technical manual or course material. Visible text: Table of Contents (1); In Memory Execution; Dropping to Disk; Registry Keys; Lab 4.1: PowerShellService; Lab 4.2: Sauron; Lab 4.3: IEC90pass; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 26 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: Course Roadmap, Section 4, Windows Tool Development, Persistence: Die Another Day, Binary Patching, Lab 4-1, Lab 4-2, Lab 4-3
Summary: The unit contains a slide outlining the curriculum for Section 4 of a Windows Tool Development course. It lists topics such as persistence mechanisms, memory execution, binary patching, and various lab exercises.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Course Roadmap' showing the curriculum for Section 4. Visible text: Course Roadmap; Section 4; Windows Tool Development; Getting to Your Next Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant; Capture the Flag Challenge; In Memory Execution; Dropping to Disk; Binary Patching; Registry Keys; Services Revisited; Lab 4-1: Persistence Service; Port Monitors; I1FE0; Lab 4-2: Sauron; IFEO; Lab 4-3: IFEOPersist; WMPI Event Subscriptions Alt/source label:

=== UNIT 27 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: Table of Contents, Lab 4.3: Persistence, Lab 4.4: Recon-Aware, SEC701
Summary: The unit contains a table of contents for several labs related to persistence and reconnaissance-aware techniques in the context of Red Teaming tools. It lists specific lab titles such as Lab 4.3 through 4.7.
Excerpt:
Visual caption: A screenshot of a table of contents page from a technical manual or course material. Visible text: Table of Contents (2); Lab 4.3: Persistence; Lab 4.4: Recon-Aware; Lab 4.5: Inst-Voist; Lab 4.6: Obby-V01; Lab 4.7: CommandShell; SEC701 | Red Teaming Tools, Developing Windows Implants, Shellcodes, Command & Control Alt/source label:

=== UNIT 28 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: Course Roadmap, In Memory Execution, Binary Patching, Registry Keys, Services Revisited, Lab 4:1. Persistence Service, Lab 4:2. Sauron, Lab 4:3. IFEOPersist
Summary: The unit contains a slide outlining the course roadmap for a cybersecurity training module. It lists specific topics including in-memory execution, binary patching, and various persistence mechanisms like registry keys and services.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlining the curriculum for a cybersecurity course. Visible text: Course Roadmap; Section 4; In Memory Execution; Dropping to Disk; Binary Patching; Registry Keys; Services Revisited; Lab 4:1. Persistence Service; Port Monitors; Lab 4:2. Sauron; IFEO; Lab 4:3. IFEOPersist; WMI Event Subscriptions; Bootcamp Alt/source label:

=== UNIT 29 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: Course Roadmap, Section 4, In Memory Execution, Binary Patching, Registry_Keys, Services Revisited, WMI Event Subscriptions
Summary: The unit contains a slide outlining the curriculum for Section 4 of a cybersecurity course. It lists topics including in-memory execution, binary patching, and various persistence mechanisms like registry keys, services, and WMI event subscriptions.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Course Roadmap' showing the curriculum for Section 4. Visible text: Course Roadmap; Section 4; In Memory Execution; Dropping to Disk; Binary Patching; Registry Keys; Services Revisited; Lab 4.1: Persistence Service; Port Monitors; Lab 4.2: Sauron; IFEO; Lab 4.3: IFEOPersist; WMI Event Subscriptions; Bootcamp Alt/source label:

=== UNIT 30 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: Course Roadmap, Section 4, In Memory Execution, Dropping to Disk, Binary Patching, Registry Keys, Services Revisited, Lab 4:1. Persistence Service
Summary: The unit contains a slide titled 'Course Roadmap' outlining the modules for Section 4 of a red teaming course. It lists topics such as In Memory Execution, Dropping to Disk, and various persistence mechanisms like Registry Keys, Services, and WMPE Event Subscriptions.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlining the modules for Section 4 of a red teaming course. Visible text: Course Roadmap; Section 4; In Memory Execution; Dropping to Disk; Binary Patching; Registry Keys; Services Revisited; Lab 4:1. Persistence Service; Port Monitors; IFEO; Lab 4:2. Sauron; WMPE Event Subscriptions; Bootcamp Alt/source label:

=== UNIT 31 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: SEC670, RED TEAMING TOOLS, DEVELOPING WINDOWS IMPLANTS, SHELLCODE, Evasion, C2
Summary: The unit contains a title slide for the SANS SEC670 course on red teaming tools. It covers topics including Windows implants, shellcode development, evasion techniques, and command and control infrastructure.
Excerpt:
Visual caption: A title slide for a SANS Institute training course on red teaming tools and implant development. Visible text: SEC670; RED TEAMING TOOLS: DEVELOPING WINDOWS IMPLANTS, SHELLCODE, COMMAND AND CONTROL; Enhancing Your Implant: Shellcode, Evasion, and C2; 670.5; SANS; GIAC Alt/source label:

=== UNIT 32 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: Course Roadmap, Unhooking Hooks, Lab 5.1: The Loader, Lab 5.2: UnhookTheHook, Lab 5.3: No Caller ID, Lab 5.4: AMSI No More, Lab 5.5: ShadowCraft
Summary: The unit describes the course roadmap and specific modules related to developing Windows implants, shellcode evasion, and C2 infrastructure. It lists labs involving unhooking hooks, bypassing AV/EDR, and writing shellcode in C.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 26 Course Roadmap Custom Loaders Lab 5.1: The Loader Unhooking Hooks Lab 5.2: UnhookTheHook Bypassing AV/EDR Calling Home Lab 5.3: No Caller ID Writing Shellcode in C Bootcamp Lab 5.4: AMSI No More Lab 5.5: ShadowCraft S e c t i o n 5 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will go over hooks and how to unhook hooks to re-hook your own hooks. In other words, a lot of hooking. 26 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a http

=== UNIT 33 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: SEC607.5, Red Teaming Tools, SANS, Shellcode, Evasion, C2
Summary: The unit contains a title slide for a SANS Institute course module. It introduces the topics of enhancing implants with shellcode, evasion techniques, and C2 communication.
Excerpt:
Visual caption: A title slide for a SANS Institute course module on enhancing implants with shellcode, evasion techniques, and C2 communication. Visible text: SEC607.5; Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control; SANS; Enhancing Your Implant: Shellcode, Evasion, and C2; © 2024 Jonathan Reiner | All Rights Reserved | Version 01_05 Alt/source label:

=== UNIT 34 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: Table of Contents, Custom Loaders, Unhooking Hooks, Bypassing AV/EDR, Writing Shellcode in C
Summary: This page contains the Table of Contents for a training manual on developing Windows implants, shellcode, and C2 infrastructure. It lists chapters covering custom loaders, unhooking hooks, bypassing AV/EDR, and writing shellcode in C.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 2 P a g e Table of Contents 3 Custom Loaders 17 Lab 5.1: The Loader 26 Unhooking Hooks 55 Lab 5.2: UnhookTheHook 63 Bypassing AV/EDR 77 Calling Home 110 Lab 5.3: No Caller ID 119 Writing Shellcode in C 136 Bootcamp 138 Lab 5.4: AMSI No More 139 Lab 5.5: ShadowCraft This page intentionally left blank. 2 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 35 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: course roadmap, security tools, roadmap items: Loader, Unhooking Hooks, Bypassing AV/EDR, Section 5 overview
Summary: This unit contains a course roadmap and an overview of Section 5, which focuses on Windows tool development, including custom loaders, unhooking hooks, bypassing AV/EDR, and enhancing shellcode evasion and C2.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 3 Course Roadmap Custom Loaders Lab 5.1: The Loader Unhooking Hooks Lab 5.2: UnhookTheHook Bypassing AV/EDR Calling Home Lab 5.3: No Caller ID Writing Shellcode in C Bootcamp Lab 5.4: AMSI No More Lab 5.5: ShadowCraft S e c t i o n 5 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will cover how to create and use a custom loader as well as how to implement a loader in your custom shell you have been working on throughout the course. 3 © SANS Ins

=== UNIT 36 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: Course Roadmap, Section 5, Windows Tool Development, Shellcode, C2, Unhooking Hooks, Byp_pass_AV/EDR
Summary: The unit contains a slide outlining the roadmap for Section 5 of a red teaming training module focused on Windows tool development. It lists specific topics including shellcode evasion, C2 communication, custom loaders, unhooking hooks, and bypassing AV/EDR.
Excerpt:
Visual caption: A slide outlining the course roadmap and specific topics for Section 5 of a red teaming training module. Visible text: Course Roadmap; Section 5; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; Custom Loaders; Unhooking Hooks; Bypassing AV/EDR; Calling Home; Writing Shellcode in C; Bootcamp; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 37 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: course roadmap, Custom Loaders, Unhooking Hooks, Bypassing AV/EDR, Writing Shellcode in C
Summary: The text lists the course roadmap for a Red Teaming tools training module, including topics like custom loaders, unhooking hooks, bypassing AV/EDR, and writing shellcode in C. It also outlines specific labs related to these techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 77 Course Roadmap Custom Loaders Lab 5.1: The Loader Unhooking Hooks Lab 5.2: UnhookTheHook Bypassing AV/EDR Calling Home Lab 5.3: No Caller ID Writing Shellcode in C Bootcamp Lab 5.4: AMSI No More Lab 5.5: ShadowCraft S e c t i o n 5 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will cover how your implant could call home to your C2 framework, redirector, listening post, or similar. 77 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a ht
