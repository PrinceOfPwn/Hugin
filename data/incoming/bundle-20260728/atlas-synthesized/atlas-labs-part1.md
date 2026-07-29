# Atlas Material — labs (part 1)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: lab_solve
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.95  Key cues: Windows APIs, Not in service, challenge, AppInit_DLLs, WMI, baby implant
Summary: The text describes a series of bootcamp challenges focused on Windows API usage for red teaming tasks. It covers creating and hiding services, utilizing the AppInit_DLLs key for DLL execution, and using WMI for foothold establishment. The final challenge involves building a basic implant with features like recon, injection, and persistence.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 115 Bootcamp NotInService NotInService InitToWinit InitToWinit OhMyWMI OhMyWMI CustomShell CustomShell Bootcamp The bootcamp challenges today will really test your knowledge of Windows APIs. Services are important and as such, the first challenge is about services. The “Not in service” challenge requires you to create, install, and then hide your own service. The second challenge is about the AppInit method where you create the AppInit_DLLs key accordingly to get your DLL payload to execute without getting stuck in the infinite loop mentioned during that section. The third challenge is about using WMI to 

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: OS Info, bootcamp challenges, MSDN documentation, ipconfig, arp, netstat, CustomShell
Summary: The text describes the bootcamp challenges for a Red Teaming Tools course, specifically focusing on OS information gathering and creating custom tools. It outlines three specific tasks: implementing new APIs from MSDN documentation, recreating standard networking utilities like ipcount, arp, or netstat, and developing a comprehensive host survey tool.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Bootcamp OS Info OS Info Make your own ipconfig, arp, or netstat, and a custom shell Make your own ipconfig, arp, or netstat, and a custom shell Complete survey tool Complete survey tool 158 Bootcamp The bootcamp challenges will have varying degrees of difficulty. OS Info brings back something you already learned but also tosses in some new items to see how well you can look at MSDN documentation to learn how to implement new APIs you have not seen before. The second challenge is to recreate one of the following utilities: ipconfig, arp, or netstat. If you have time, then you can complete all three. The l

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Table of Contents, Lab 3.1-3.6, GetFunctionAddress, Call_DirectInjection, APC Injection, ThreadHijack, TokenTHeft
Summary: This unit contains a table of contents for a series of labs focused on advanced Windows injection techniques including GetFunctionAddress, Call_DirectInjection, APC Injection, ThreadHijack, and TokenTheft.
Excerpt:
Visual caption: A table of contents page from a technical manual or course material. Visible text: Table of Contents (1); Lab 3.1: GetFunctionAddress; Lab 3.2: Call_DirectInjection; Lab 3.3: APC Injection; Lab 3.4: ThreadHijack; Lab 3.5: TokenTheft; Lab 3.6: As You Think You Can Type; SEC70 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: UACBypass, ShadowCraft, Table of Contents
Summary: The page contains a table of contents for labs 3.7 and 3.8, specifically mentioning UACBypass-Research and ShadowCraft.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 3 P a g e Table of Contents (2) 141 Lab 3.7: UACBypass-Research 142 Lab 3.8: ShadowCraft This page intentionally left blank. © 2024 Jonathan Reiter 3 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: multiple-choice, default quantum, s_servers, SEC670
Summary: The unit contains a multiple-choice question regarding the default quantum for servers in a technical context. It includes options for 2, 8, and 12 clock cycles.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about the default quantum for servers. Visible text: Unit Review Questions; What is the default quantum for servers?; 2 clock cycles; 8 clock cycles; 12 clock cycles; SEC670 Alt/source label:

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Table of Contents, Lab 4.4: NotInService, Lab 4.5: InitToWinit, Lab 4.6: OhMyWMI, Lab 4.7: CustomShell
Summary: The unit contains a table of contents for labs 4.4 through 4.7, covering topics such as NotInService, InitToWinit, OhMyWMI, and CustomShell.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 3 P a g e Table of Contents (2) 116 Lab 4.4: NotInService 117 Lab 4.5: InitToWinit 118 Lab 4.6: OhMyWMI 119 Lab 4.7: CustomShell This page intentionally left blank. © 2024 Jonathan Reiter 3 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.9  Key cues: UACBypass, ShadowCraft, Table of Contents
Summary: The page contains a table of contents for Lab 3.7 and Lab 3.8, which focus on UACBypass-Research and ShadowCraft respectively.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 3 P a g e Table of Contents (2) 141 Lab 3.7: UACBypass-Research 142 Lab 3.8: ShadowCraft This page intentionally left blank. © 2024 Jonathan Reiter 3 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SAL, multiple-choice question, security curriculum
Summary: The unit contains a multiple-choice question regarding the definition of course acronyms. Specifically, it asks for the meaning of SAL in the context of the user's training.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about the meaning of the acronym SAL. Visible text: Unit Review Questions; What does SAL stand for?; Source-code annotation language; Structured annotation language; Silent analysis language; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Bootcamp, error handling function, Registry walker, Italian Debugger, Windows Shells
Summary: The unit contains a slide from a cybersecurity course listing four technical challenges for students. These include developing an error handling function, a Registry walker, 'The Italian Debugger', and Windows Shells.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Bootcamp' listing four specific technical challenges. Visible text: Bootcamp; Develop your own custom error handling function; Develop a Registry walker; The Italian Debugger; Windows Shells; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SANS SEC670, What's the Point?, retrieve various information about the OS
Summary: The unit describes a slide from a SANS SEC670 course explaining the purpose of a lab exercise focused on retrieving operating system information from a target.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'What's the Point?' explaining the purpose of a lab exercise. Visible text: What's the Point?; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control; The point of this lab was to understand how you can retrieve various information about the OS of your target. Alt/source label:

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: COM interface, enumeration object, multiple-choice question
Summary: The unit contains a multiple-choice question regarding the specific COM interface used for creating enumeration objects. It includes options such as ITaskScheduler, IUnknown, and IBelieve.
Excerpt:
Visual caption: A screenshot of a study guide page showing a multiple-choice question about COM interfaces for creating enumeration objects. Visible text: Unit Review Answers; What COM interface can be called to create an enumeration object?; ITaskScheduler; IUnknown; IBelieve; SEC601 Alt/source label:

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Table of Contents, IAC-Spygan Research, ShadowCraft, Windows Implants, Shellcodes, Command and Control
Summary: The unit contains a table of contents page listing specific labs related to research on IAC-Spygan, ShadowCraft, and the development of Windows implants, shellcodes, and command and control infrastructure.
Excerpt:
Visual caption: A screenshot of a table of contents page from a technical training manual. Visible text: Table of Contents (2); Lab 3.7: IAC-Spygan Research; Lab 3.8: ShadowCraft; SEC70 | Red Teaming Trade, Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: quiz question, default quantum, server cycles, SEC601
Summary: The unit contains a quiz question regarding the default quantum for servers in a technical training course. It includes multiple-choice options for cycle counts.
Excerpt:
Visual caption: A screenshot of a quiz question about the default quantum for servers in a technical training course. Visible text: Unit Review Answers; What is the default quantum for servers?; 2 clock cycles; 8 clock cycles; 12 clock cycles; SEC601 | Red Team Tactics: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: What's the Point?, SEC670, Red Teaming Tools, thread's context, hijacking
Summary: The unit describes the purpose of educational lab exercises focused on understanding thread context hijacking. It is part of a section regarding Red Teaming tools, specifically Windows implants and shellcode.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'What's the Point?' explaining the purpose of a lab exercise. Visible text: What's the Point?; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control; The point of this lab was to explore the process of hijacking a thread's context. Alt/source label:

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SANS Bootcamp, U.A.C. Bypass, CustomShell, SEC401
Summary: The unit contains a slide from a SANS Institute course outlining three specific challenges for students: 'So, You Think You Can Type', 'UAC Bypass-Research', and 'CustomShell'.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Bootcamp' outlining three main challenges: So, You Think You Can Type, UAC Bypass-Research, and CustomShell. Visible text: Bootcamp; So, You Think You Can Type; UAC Bypass-Research; CustomShell; SEC401 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Bootcamp, NotInService, InitToWinit, OhMyWItI, CustomShell, SEC701
Summary: The unit contains a slide from a SANS course listing four specific challenges: NotInService, InitToWinit, OhMyWItI, and CustomShell. These are part of the development of Windows implants, shellcode, and command and control.
Excerpt:
Visual caption: A slide from a SANS course titled 'Bootcamp' listing four challenges: NotInService, InitToWinit, OhMyWMI, and CustomShell. Visible text: Bootcamp; NotInService; InitToWinit; OhMyWMI; CustomShell; SEC701 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: shellcode execution, SEC701, s701, lab objectives
Summary: The unit contains a presentation slide titled 'What's the Point?' which outlines the objectives of a lab focused on shellcode execution. It is part of the SEC701 course material regarding Red Teaming Tools.
Excerpt:
Visual caption: A presentation slide titled 'What's the Point?' explaining the objectives of a lab on shellcode execution. Visible text: What's the Point?; SEC701 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AMSI No More, CustomShell, SEC701, SEC670
Summary: The unit contains a slide from a SANS Institute course outlining three specific challenges related to AMSI bypass and shellcode development. It mentions the courses SEC701 and SEC670.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Bootcamp' outlining three challenges related to AMSI bypass and shellcode development. Visible text: Bootcamp; AMSI No More; CustomShell; SEC701 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: SANS Bootcamp, UAC Bypass-Research, challenge names
Summary: The unit describes a slide from a SANS Institute course outlining three specific challenges: 'So, You Think You Can Type', 'UAC Bypass-Research', and 'CustomShell'. It is part of the module on Red Teaming Tools and Developing Windows Implants.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Bootcamp' outlining three main challenges: So, You Think You Can Type, UAC Bypass-Research, and CustomShell. Visible text: Bootcamp; So, You Think You Can Type; UAC Bypass-Research; CustomShell; SEC401 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: ClassicDLLInjection, Injecting your own DLL into a target process, security course content
Summary: The unit contains instructions for Lab 3.2 regarding ClassicDLLInjection. It specifies that students should refer to the eWorkbook for detailed lab instructions.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 3.2: ClassicDLLInjection' with instructions to refer to the eWorkbook. Visible text: Lab 3.2: ClassicDLLInjection; Injecting your own DLL into a target process; Please refer to the eWorkbook for the details of the lab.; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 21 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Exercise Complete, SEC679, Red Teaming Tools, Developing Windows Implants
Summary: The unit contains a slide indicating the completion of an exercise related to red teaming tools, specifically focusing on developing Windows implants, shellcode, and command and control.
Excerpt:
Visual caption: A slide from a training course showing an 'Exercise Complete' message. Visible text: Exercise Complete: STOP; You have successfully completed the exercise. Congratulations!; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 22 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Unit Review Questions, process creation, hook implementation
Summary: The unit contains a multiple-choice review question regarding the process creation lifecycle and hook implementation timing.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about process creation and hooks. Visible text: Unit Review Questions; At what stage of process creation will you not have any hooks implemented?; Suspended; Terminated; Running Alt/source label:

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Lab 1.4, Call Me Maybe, calling conventions, security training
Summary: The unit contains a slide from a SANS Institute course regarding Lab 1.4 'Call Me Maybe'. It instructs students to refer to the eWorkbook for details on learning various calling conventions.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 1.4: Call Me Maybe' which instructs the user to refer to an eWorkbook for details. Visible text: Lab 1.4: Call Me Maybe; Learn how to use the various calling conventions.; Please refer to the eWorkbook for the details of this lab.; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Lab 1.5, Safer with SAL, eWorkbook reference
Summary: The unit contains a slide from a SANS Institute course regarding 'Lab 1.5: Safer with SAL'. It instructs users to consult an eWorkbook for specific details about using SAL annotations for code clarity.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 1.5: Safer with SAL' showing instructions to refer to an eWorkbook for details. Visible text: Lab 1.5: Safer with SAL; Using SAL annotations makes your code more understandable.; Please refer to the eWorkbook for the details of this lab. Alt/source label:

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: SANS SEC507, CreateFile, WriteFile, What's the Point?
Summary: The unit contains a slide from a SANS SEC507 course describing the purpose of learning to use CreateFile and WriteFile functions. It serves as an introductory context for a lab exercise.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'What's the Point?' explaining the purpose of a lab exercise. Visible text: What's the Point?; SANS SEC507; CreateFile; WriteFile Alt/source label:

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Lab 2.1, OS Info, eWorkbook reference
Summary: The unit contains a slide from a cybersecurity course providing instructions for Lab 2.1 regarding OS information gathering. It directs students to the eWorkbook for specific details.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Lab 2.1: OS Info' providing instructions to refer to an eWorkbook for details. Visible text: Lab 2.1: OS Info; Gathering information about the OS and target; Please refer to the eWorkbook for the details of this lab.; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Lab 2.5, FileFinder, Enumerating directories, sentence structure
Summary: The unit contains a slide from a SANS Institute course regarding Lab 2.5: FileFinder. It highlights the importance of enumerating directories as a feature for developing tools.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 2.5: FileFinder' with instructions to refer to the eWorkbook for details. Visible text: Lab 2.5: FileFinder; Enumerating directories is an important feature to create.; Please refer to the eWorkbook for the details of the lab.; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: SANS Institute, What's the Point?, SEC673, Red Teaming Tools, Windows Implants, shellcode, Command and Control
Summary: The unit contains a slide from a SANS Institute course explaining the purpose of a specific lab exercise. It includes titles related to red teaming tools, developing Windows implants, shellcode, and command and control.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'What's the Point?' explaining the purpose of a lab exercise. Visible text: What's the Point?; SEC673 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: PE-sieve, injection methods, defense tool, eWorkbook
Summary: The unit describes Lab 1.1 involving the PE-sieve tool. It explains that the tool is used for detecting malware and identifying injection methods. A link to an eWorkbook is provided for further details.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 1.1: PE-sieve' describing the tool's purpose and providing a link to an eWorkbook. Visible text: Lab 1.1: PE-sieve; Observe how a defensive tool can catch injection methods.; Please refer to the eWorkbook for the details of this lab.; SANS SECF07; PE-sieve, according to hackerverse's GitHub repo, is a tool that helps detect malware running on the system Alt/source label:

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: MS-DOS header, Unit Review Answers, 0x00, 0x90, 0x5A
Summary: This unit contains a review section for the SEC670 course, specifically focusing on questions regarding MS-DOS header bytes. It lists multiple choice options and their corresponding answers.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 30 Unit Review Answers What is typically the next byte that comes after the MS-DOS header? What is typically the next byte that comes after the MS-DOS header? A 0x00 A 0x00 B 0x90 B 0x90 C 0x5A C 0x5A Unit Review Answers Q: What is typically the next byte that comes after the MS-DOS header? A: 0x00 B: 0x90 C: 0x5A 30 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: APCInjection, Queue an APC, target thread, eWorkbook
Summary: The unit contains instructions for Lab 3.3 regarding APC Injection. It directs users to refer to an eWorkbook for specific details.
Excerpt:
Visual caption: A slide from a training course titled 'Lab 3.3: APCInjection' showing instructions to refer to an eWorkbook for details. Visible text: Lab 3.3: APCInjection; Queue an APC to a target thread.; Please refer to the eWorkbook for the details of the lab.; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: ThreadHijacker, hijack execution, thread hijacking, sentence structure
Summary: The unit contains instructions for Lab 3.4 regarding ThreadHijacker, which involves hijacking the execution of a thread. It directs users to an external eWorkbook for further details.
Excerpt:
Visual caption: A slide from a training course titled 'Lab 3.4: ThreadHijacker' providing instructions to refer to an eWorkbook for details. Visible text: Lab 3.4: ThreadHijacker; Hijack execution of a thread; Please refer to the eWorkbook for the details of the lab.; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Table of Contents, Lab 4.4: NotInService, Lab 4.6: OhMyWMI, CustomShell
Summary: The text is a table of contents page for labs 4.4 through 4.7, listing specific tools and techniques like NotInService, InitToWinit, OhMyWMI, and CustomShell.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 3 P a g e Table of Contents (2) 116 Lab 4.4: NotInService 117 Lab 4.5: InitToWinit 118 Lab 4.6: OhMyWMI 119 Lab 4.7: CustomShell This page intentionally left blank. © 2024 Jonathan Reiter 3 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Table of Contents, Lab 4.3: Persistence, Lab 4.4: Recon-Aware, Lab 4.6: Obby-V01, SEC479 | Red Teaming Tools
Summary: The unit contains a table of contents listing several labs related to persistence and red teaming tools. It specifically mentions Lab 4.3 through Lab 4.7 covering topics like Recon-Aware and CommandShell.
Excerpt:
Visual caption: A screenshot of a table of contents page from a technical manual or course material. Visible text: Table of Contents (2); Lab 4.3: Persistence; Lab 4.4: Recon-Aware; Lab 4.5: Inst-Voist; Lab 4.6: Obby-V01; Lab 4.7: CommandShell; SEC479 | Red Teaming Tools, Developing Windows Implants, Shellcodes, Command & Control Alt/source label:

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: CreateNewMonitor, port monitor, API call
Summary: The unit contains a review question regarding the specific API used to create a new port monitor in a Windows environment. It lists multiple choice options for identifying the correct API.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 77 Unit Review Questions What API is called to create a new port monitor? What API is called to create a new port monitor? A CreateNewMonitor A CreateNewMonitor B AddMonitor B AddMonitor C AddNewMonitor C AddNewMonitor Unit Review Questions Q: What API is called to create a new port monitor? A: CreateNewMonitor B: AddMonitor C: AddNewMonitor © 2024 Jonathan Reiter 77 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Windows registry keys, process termination monitoring
Summary: The unit contains a multiple-choice question regarding the specific Windows registry keys used to monitor process termination. It lists options such as 'SilentProcessExit' and 'Debugger'.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about Windows registry keys for monitoring process termination. Visible text: Unit Review Questions; What registry key could be used to watch for process termination?; SilentProcessExit; Debugger; DebuggerProcessExit Alt/source label:

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Lab 5.1, The Loader, shellcode execution, process boundaries
Summary: The unit contains a slide from a SANS Institute course regarding 'Lab 5.1: The Loader'. It instructs users to execute shellcode locally and across process boundaries while referencing an eWorkbook for further details.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 5.1: The Loader' which instructs the user to refer to an eWorkbook for details. Visible text: Lab 5.1: The Loader; Explore executing shellcode locally and over process boundaries.; Please refer to the eWorkbook for the details of the lab. Alt/source label:

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: UnhookTheHook, Bitdefender, eWorkbook reference, SEC679
Summary: This unit contains a slide from a SANS course regarding Lab 5.2: UnhookTheHook. It instructs students to refer to the eWorkbook for specific details on testing unhooking skills against security software like Bitdefender.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 5.2: UnhookTheHook' providing instructions to refer to the eWorkbook for details. Visible text: Lab 5.2: UnhookTheHook; Test your unhooking skills against Bitdefender and others.; Please refer to the eWorkbook for the details of the lab.; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Lab 5.3: No Caller ID, HTTP libraries, eWorkbook reference
Summary: The unit contains a slide from Lab 5.3 titled 'No Caller ID' within a SANS SEC670 course. It provides instructions to use HTTP libraries for communication and directs users to the eWorkbook for further details.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 5.3: No Caller ID' providing instructions to refer to an eWorkbook for details. Visible text: Lab 5.3: No Caller ID; Use HTTP libraries to implement HTTP communications.; Please refer to the eWorkbook for the details of the lab.; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 40 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: ShadowCraft, basic shell, error checking, eWorkbook reference
Summary: The unit describes a lab exercise titled 'ShadowCraft' focused on creating a basic shell and implementing specific features with error checking. It references an eWorkbook for further details.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 1.10: ShadowCraft Create a basic shell. Implement features covered in this section. Implement thorough error checking. 202 Lab 1.10: ShadowCraft Please refer to the eWorkbook for the details of this bootcamp challenge. 202 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam
