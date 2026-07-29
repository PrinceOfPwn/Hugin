# Atlas Material — methodology (part 7)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: methodology
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Common Information Model, WMI, CIM classes, Core/Common/Extended
Summary: The text defines the Common Information Model (CIM) as an industry standard used by WMI to represent objects like systems, processes, and devices in a uniform way. It describes three levels of CIM classes: Core, Common, and Extended, explaining their differences in terms of scope and technology specificity.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 101 What Is CIM? The Common Information Model (CIM) The Common Information Model (CIM) The CIM is an industry standard that is used by WMI to represent various items, like systems, processes, devices, and more. CIM is object oriented and gives the look and feel of a C++ class. CIM gives us three levels of classes: Core, Common, and Extended. What Is CIM? Standards typically have models to go by and WMI is no exception because it follows the industry standard called the Common Information Model (CIM). The CIM is used to represent data in a uniformed way, data such as systems, processes/applications, networ

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: WQL, Win32_NTLogEvent, Win32_Process, Data query, Event query, Schema query, intrinsic vs extrinsic
Summary: This unit describes the use of Windows Query Language (WQL) to filter and query events for red teaming purposes. It covers three types of queries: Data, Event, and Schema, with specific examples provided for each. The text explains the difference between intrinsic and extrinsic events and the requirements for polling.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 105 Filtering Events Using WQL Windows Query Language Windows Query Language Extrinsic events can be queried normally Extrinsic events can be queried normally Data Query SELECT * FROM Win32_NTLogEvent WHERE logfile = ‘System’ AND EventCode = ‘4625’ Event Query SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstace ISA “Win32_Process” AND TargetInstance.Name = ‘notepad.exe’ Schema Query SELECT * FROM meta_class WHERE __this ISA “Win32_Process” Intrinsic events must be polled at some defined interval Intrinsic events must be polled at some defined interval Filtering Events Using WQL How are even

=== UNIT 3 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: WQL, Windows Query Language, Filtering Events, Data Query, Event Query, Vulnerability Query, Schema Query
Summary: The unit describes the syntax and types of queries for Windows Query Language (WQL) used to filter events. It covers different query categories such as data, event, vulnerability, and schema queries.
Excerpt:
Visual caption: A slide titled 'Filtering Events Using WQL' explains the syntax and types of queries for Windows Query Language. Visible text: Filtering Events Using WQL; Windows Query Language; Extrinsic events can be queried normally; Intrinsic events must be polled at some defined interval; Data Query; Event Query; Vulnerability Query; Schema Query Alt/source label:

=== UNIT 4 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Objectives, drop to disk, risk, protection
Summary: The unit describes the objectives for a module focused on dropping files to disk, including discussing risks and protection methods. It outlines three specific goals: understanding the need, assessing risks, and implementing protections.
Excerpt:
Visual caption: A slide titled 'Objectives' outlining the goals for a module on dropping to disk and its risks, as well as protection methods. Visible text: Objectives; Our objectives for this module are:; Discuss the need to drop to disk; Discuss the risk of being on disk; Cover how to protect yourself and your data Alt/source label:

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Course Roadmap, Section 4, Registry Keys, Persistence: Die Another Day, Lab 4.1, Lab 4.2, Lab 4.3
Summary: The unit contains a slide outlining the course roadmap for Section 4 of a Windows tool development course. It lists various topics including registry keys, services, and specific lab exercises related to persistence.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Course Roadmap' and 'Section 4', highlighting the topic of Registry Keys. Visible text: Course Roadmap; Section 4; Windows Tool Development; Getting to Know Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant; Capture the Flag Challenge; In Memory Execution; Dropping to Disk; Binary Patching; Registry Keys; Services Revisited; Lab 4.1: Persistence Service; Port Monitors; Lab 4.2: Sauron; IFEO; Lab 4.3: IFEOPersist; WMI Event Subscriptions; Bootcamp Alt/source label:

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Table of Contents, In Memory Execution, Binary Patching, Registry Keys, Summary of Persistence methods
Summary: The unit contains a Table of Contents for the 'Red Teaming Tools' course, listing topics such as in-memory execution, binary patching, and various persistence mechanisms like registry keys, services, and WMI event subscriptions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 2 P a g e Table of Contents (1) 4 In Memory Execution 13 Dropping to Disk 20 Binary Patching 26 Registry Keys 39 Services Revisited 47 Lab 4.1: PersistentService 67 Port Monitors 74 Lab 4.2: Sauron 79 IFEO 90 Lab 4.3: IFEOPersisto 97 WMI Event Subscriptions 114 Bootcamp This page intentionally left blank. 2 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: SDDL Example, MSDN documentation, ACCESS_ALLOWED_ACE_TYPE, READ_CONTROL, WRITE_DAC, GENERIC_ALL, NULL SID
Summary: The unit provides a technical breakdown of an SDDL (Security Descriptor Definition Language) string example from MSDN documentation. It explains the components of an access control entry (ACE) and maps specific abbreviations like 'RP', 'WP', 'CC', and 'GA' to their corresponding Windows security rights.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 53 SDDL Example #1 MSDN Example MSDN Example Several field types skipped Several field types skipped "O:AOG:DAD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)” Revision: 0x00000001, Control: 0x0004, SE_DACL_PRESENT Owner: (S-1-5-32-548) PrimaryGroup: (S-1-5-21-397955417-626881126- 188441444-512) DACL - Revision: 0x02, Size: 0x1c, AceCount: 0x01 Ace[00] AceType: 0x00 (ACCESS_ALLOWED_ACE_TYPE) AceSize: 0x0014 InheritFlags: 0x00 Access Mask: 0x100e003f READ_CONTROL | WRITE_DAC | WRITE_OWNER | GENERIC_ALL, Others(0x0000003f) Ace Sid : (S-1-0-0) Uses the NULL well-known SID Uses the NULL well-known SID SDDL Example #1 Th

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: In Memory Execution, Dropping to Disk, Binary Patching, Registry Keys, Services Revisited, WMI Event Subscriptions
Summary: The unit contains a course roadmap and an introduction to in-memory execution techniques for red teaming. It lists various topics including binary patching, registry keys, services, and WMI event subscriptions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 4 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In Memory Execution In this module, we will discuss what in memory execution is and how it can benefit us. We will also look at some disadvantages with only living in memory. Hint: it

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Course Roadmap, In Memory Execution, Binary Patching, Registry Keys, Services Revisited, WMI Event Subscriptions
Summary: The unit contains a slide outlining the curriculum for Section 4 of a cybersecurity course. It lists topics including in-memory execution, binary patching, and various persistence mechanisms like registry keys, services, and WMI event subscriptions.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Course Roadmap' showing the curriculum for Section 4. Visible text: Course Roadmap; Section 4; In Memory Execution; Dropping to Disk; Binary Patching; Registry Keys; Services Revisited; Lab 4:1. Persistence Service; Port Monitors; Lab 4:2. Sauron; IFEO; Lab 4:3. IFEOPersist; WMI Event Subscriptions; Bootcamp Alt/source label:

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: SEC670, Red Teaming Tools, course roadmap, persistence, In Memory Execution, Binary Patching
Summary: The text provides a course roadmap for the SEC670 module on Windows tool development, covering topics like in-memory execution, binary patching, and various persistence mechanisms.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 97 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss why you would need to drop something to disk, where to drop, cleaning up, and more. © 2024 Jonathan Reiter 97 © SANS Institute 2024 f80c9b76f5e518e0ab

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Course Roadmap, s6-windows-tool-dev, shellcode evasion, unhooking hooks, Bypass_API_Hooker/EDR
Summary: The unit contains a slide titled 'Course Roadmap' outlining the modules for Section 6 of a cybersecurity course focused on Windows tool development. It lists specific topics such as shellcode evasion, custom loaders, unhooking hooks, and various lab exercises.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlining the modules for a cybersecurity course, specifically focusing on Section 6. Visible text: Course Roadmap; Section 6; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Custom Loaders; Unhooking Hooks; Bypass_API_Hooker/EDR; Calling Home; Writing Shellcode in C; Bootcamp; Lab 5.1: The Loader; Lab 5.2: Unhooking_NetHook; Lab 5.3: No Caller ID; Lab 5.4: AMSI_No_More; Lab 5.5: ShadowCraft Alt/source label:

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Course Roadmap, Section 6, Security training curriculum
Summary: The unit contains a slide titled 'Course Roadmap' outlining the curriculum for SANS SEC-713. It lists specific topics including Windows Tool Development, shellcode evasion, custom loaders, and C2 communication.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlines the curriculum for a SANS SEC-713 course, specifically focusing on Section 6. Visible text: Course Roadmap; Section 6; Windows Tool Development; Getting in and Staying on Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Custom Loaders; Unhooking Hooks; Bypass_api_hook/EDR; Calling Home; Writing Shellcode in C; Bootcamp; SEC-713 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: SEC670, Course Roadmap, content list, Bootcamp
Summary: The text provides a course roadmap for the SEC670 Red Teaming Tools course, listing various modules including custom loaders, unhooking hooks, bypassing AV/EDR, and shellcode development.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 136 Course Roadmap Custom Loaders Lab 5.1: The Loader Unhooking Hooks Lab 5.2: UnhookTheHook Bypassing AV/EDR Calling Home Lab 5.3: No Caller ID Writing Shellcode in C Bootcamp Lab 5.4: AMSI No More Lab 5.5: ShadowCraft S e c t i o n 5 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge This bootcamp module is going to present some of the most challenging coding challenges you have faced in this course. This final bootcamp is meant to be more hands off, meaning there 

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Course Roadmap, s6, Windows Tool Development, shellcode, evasion, unhooking, EDR bypass
Summary: The unit contains a slide outlining the roadmap for Section 6 of a SANS course on red teaming tools. It lists specific topics including shellcode evasion, custom loaders, unhooking hooks, and EDR bypass techniques.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Course Roadmap' and 'Section 6', detailing various red teaming topics. Visible text: Course Roadmap; Section 6; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Custom Loaders; Unhooking Hooks; Bypass any EDR; Calling Home; Writing Shellcode in C; Bootcamp; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: loader definition, use cases, custom loader implementation
Summary: The unit outlines the learning objectives for a module on Windows implants, shellcode, and C2. It specifically focuses on defining loaders, their use cases, and the implementation of custom loaders.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 4 Objectives Our objectives for this module are: Understand what a loader is Understand its use cases Implement a custom loader Objectives The objectives for this module are to discuss at a high level what a loader is, how/when to use one, and then finally how to implement a custom loader. 4 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Course Roadmap, Windows Tool Development, Enhancing Your Implant, Shellcode, Unhooking Hooks, Bypassing AV/EDR
Summary: The text describes a course roadmap for Section 6 of a red teaming training program. It lists topics including Windows tool development, shellcode evasion, custom loaders, unhooking hooks, and bypassing AV/EDR systems.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Course Roadmap' and 'Section 6', detailing various topics related to Windows tool development and implant enhancement. Visible text: Course Roadmap; Section 6; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; Custom Loaders; Unhooking Hooks; Bypassing AV/EDR; Calling Home; Writing Shellcode in C; Bootcamp; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: SANS SEC670, Red Teaming Tools, Developing Windows Implants, page 205
Summary: The text contains metadata and branding for a SANS SEC670 course on Red Teaming tools, specifically focusing on page 205 of the material.
Excerpt:
THE MOST TRUSTED SOURCE FOR INFORMATION SECURITY TRAINING, CERTIFICATION, AND RESEARCH | sans.org SEC670 | RED TEAMING TOOLS: DEVELOPING WINDOWS IMPLANTS, SHELLCODE, COMMAND AND CONTROL 670.2 Getting to Know Your Target © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a ibmconnect2024@gmail_com ohNrhAfzA3YUEB7zYQeMv7asRrrC6mmK live https://linktr.ee/offsecexam

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Table of Contents, SEC679, Red Teaming Tools, Lab 2.1-2.5
Summary: The unit contains a table of contents for the SEC679 Red Teaming Tools module. It lists several labs related to tool development such as OS_Env, ProcDump, Create_Toolhelp, Win_Dump, and PsExecer.
Excerpt:
Visual caption: A table of contents page for a cybersecurity course module titled 'SEC679 | Red Teaming Tools'. Visible text: Table of Contents (1); Lab 2.1: OS_Env; Lab 2.2: ProcDump; Lab 2.3: Create_Toolhelp; Lab 2.4: Win_Dump; Lab 2.5: PsExecer; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Metasploit, Cobalt Strike, Empire, Mimikatz, PsExec, Eternal*, Zerologon
Summary: The unit discusses the current state of offensive security tools and frameworks, listing examples like Metasploit, Cobalt Strike, Cobalt Strike, Mimikatz, PsExec, and Eternal*. It highlights the debate over open-sourcing powerful capabilities and mentions how developers create tools to exploit vulnerabilities like Zerologon.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Current State of the Art Frameworks and Tools There are many frameworks or offensive tools available for use today: Metasploit Framework Cobalt Strike Empire Mimikatz PsExec Eternal* 20 Current State of the Art Frameworks and Tools Today, there are some amazing tools out there and many are free for anyone to grab and leverage. We see this happening very frequently and such actions have sparked intense discussions regarding open sourcing powerful tools and capabilities that nation state and non-nation-state actors can use against us. Regardless of where you stand in that debate, offensive tools will almost

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Metasploit, Cobalt Strike, Empire, Mimikatz, PsExec, Eternal*, Red Teaming Tools
Summary: The unit lists common cybersecurity frameworks and tools used in red teaming operations, including Metasploit, Cobalt Strike, Empire, Mimikatz, and PsExec. It also mentions the Eternal* exploit and references a specific course module on developing Windows implants.
Excerpt:
Visual caption: A slide titled 'Current State of the Art Frameworks and Tools' listing several cybersecurity tools like Metasploit, Cobalt Strike, Empire, Mimikatz, and PsExec. Visible text: Current State of the Art Frameworks and Tools; Metasploit Framework; Cobalt Strike; Empire; Mimikatz; PsExec; Eternal*; SEC701 / Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Windows Hotfixes, Quick Fix Engineering (QFE), critical issues, software engineering
Summary: The unit describes the concept of Windows Hotfixes, also known as Quick Fix Engineering (QFE) updates. It explains that these are used to address critical issues in software. The text is part of a training course on Red Team tactics.
Excerpt:
Visual caption: A slide from a cybersecurity training course explaining the concept of Windows Hotfixes. Visible text: Windows Hotfixes; Used to fix critical issues in software; Also referred to as Quick Fix Engineering (QFE) updates, hotfixes are used to apply a vital fix to software engineering. Users that have Windows updates set to ; SEC670 | Red Team Tactics: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: WUA, LUA, FUA, Unit Review Answers
Summary: This unit contains a review section for the SEC670 course, specifically focusing on questions regarding Windows Update Agent (WUA) APIs used to query hotfixes.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What is the update family of APIs used to query hotfixes? What is the update family of APIs used to query hotfixes? A WUA A WUA B LUA B LUA C FUA C FUA 33 Unit Review Answers Q: What is the update family of APIs used to query hotfixes? A: WUA (Windows Update Agent) B: LUA C: FUA 33 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: open-source, Metasploit, Sliver C2, intellectual property, tool development
Summary: The unit discusses the importance of open-sourcing code, contributing to existing projects like Metasploit or Sliver C2, and developing in-house tools for red teams. It also emphasizes legal considerations regarding intellectual property when publishing online and advises against knowledge compartmentalization.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control How You Can Contribute Make your work available to the public; open-source your code Contribute to an already existing open-source code project Develop tools for your red team Don’t compartmentalize your knowledge 22 How You Can Contribute Before you start publishing your offensive tools online, be sure to check with your current employer as to what their intellectual property terms are. You do not want to be in a situation where whatever you create during your own free time with your own equipment belongs to your employer. It could land you in some hot water with a legal team. If you are good to go on th

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: open-source contribution, intellectual report, tool development, knowledge sharing
Summary: The unit discusses the importance of and methods for contributing to open-source projects, developing in-house tools, and sharing knowledge within a team. It also includes a warning regarding intellectual property rights when publishing offensive tools online.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control How You Can Contribute Make your work available to the public; open-source your code Contribute to an already existing open-source code project Develop tools for your red team Don’t compartmentalize your knowledge 22 How You Can Contribute Before you start publishing your offensive tools online, be sure to check with your current employer as to what their intellectual property terms are. You do not want to be in a situation where whatever you create during your own free time with your own equipment belongs to your employer. It could land you in some hot water with a legal team. If you are good to go on th

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: course roadmap, OS info gathering, process enumeration, Lab 2.1-2.5, Windows Tool Development
Summary: The unit contains a course roadmap for gathering operating system information, including service packs, process enumeration, and installed software. It also lists specific labs related to tool development and the section outline for Windows Tool Development.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 36 In this module, we will look at the how and why when it comes to process enumerat

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Course Roadmap, Process Enumeration, Windows Tool Development, SEC473
Summary: The unit contains a visual caption describing a course roadmap and the specific topic of process enumeration within the context of Windows tool development. It references related courses like SEC473.
Excerpt:
Visual caption: A slide showing the course roadmap and a specific section on process enumeration. Visible text: Course Roadmap; Section 2; Gathering Operating System Information; Process Enumeration; Windows Tool Development; SEC473 Alt/source label:

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: offensive security tools, state of the art frameworks, knowledge sharing, mentoring
Summary: The unit provides a summary of the module's objectives, focusing on the necessity of developing custom offensive security tools and sharing knowledge within the community. It highlights current state-of-the-art frameworks and the importance of mentoring.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed the need for offensive security tools Discussed the current state of the art frameworks and offensive tools Learned to share your knowledge; be a mentor 23 Module Summary In this module, we discussed several reasons why it is necessary to develop offensive security tools. We also discussed various state of the art frameworks and offensive tools, where we can take things from here, and not hoarding the knowledge and experience you might have gained over the years. 23 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: offensive security tools, state of the art frameworks, knowledge sharing, mentoring
Summary: The unit provides a summary of the module's objectives, focusing on the importance of developing custom offensive security tools and sharing knowledge within the community. It highlights current state-of-the-art frameworks and the role of mentoring.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed the need for offensive security tools Discussed the current state of the art frameworks and offensive tools Learned to share your knowledge; be a mentor 23 Module Summary In this module, we discussed several reasons why it is necessary to develop offensive security tools. We also discussed various state of the art frameworks and offensive tools, where we can take things from here, and not hoarding the knowledge and experience you might have gained over the years. 23 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: SANS SEC701, What's the Point?, API purpose
Summary: The unit contains a slide from a SANS Institute course (SEC701) titled 'What's the Point?' which introduces the purpose of a specific API.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'What's the Point?' explaining the purpose of using a specific API. Visible text: What's the Point?; SEC701; SANS Alt/source label:

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Purpose, Defensive mindset, SEC701 Red Teaming Tools
Summary: The unit describes the purpose of red teaming tools and the role of defensive security. It highlights the cat-and-mouse game between offensive and defensive operations.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Purpose' explaining the role of defensive tools and the cat-and-mouse game between offensive and defensive security. Visible text: Purpose; Defensive mindset; Defense: you are; SEC701 / Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: OpenProcess(), WTSEnumerateProcessesEx(), NtQuerySystemInformation()
Summary: This unit contains a review section for the SEC670 course, specifically focusing on Windows process information retrieval. It lists multiple options for APIs used to identify processes by PID.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What API could be used to obtain more information about a process given only its PID? What API could be used to obtain more information about a process given only its PID? A OpenProcess() A OpenProcess() B WTSEnumerateProcessesEx() B WTSEnumerateProcessesEx() C NtQuerySystemInformation() C NtQuerySystemInformation() 64 Unit Review Questions Q: What API could be used to obtain more information about a process given only its PID? A: OpenProcess() B: WTSEnumerateProcessEx() C: NtQuerySystemInformation() 64 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Course Roadmap, Gathering Operating System Information, Windows Tool Development, Lab 2.1 to 2.5
Summary: The unit contains a slide titled 'Course Roadmap' outlining the curriculum for a cybersecurity course focused on Windows tool development.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlines the curriculum for a cybersecurity course, specifically focusing on Section 2: Gathering Operating System Information. Visible text: Course Roadmap; Section 2; Gathering Operating System Information; Windows Tool Development; Getting to Know Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; Lab 2.1: OS Info; Lab 2.2: ProcEnum; Lab 2.3: CreaTool00p; Lab 2.4: W2TEnum; Installed Software; Directory Walk; Lab 2.5: FileFinder; User Information; Services and Tasks; Network Information; Registry Information Alt/source label:

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: OS Information, Process Enumer_ation, Lab 2.1-2.5, Windows Tool Development, sequence of modules
Summary: The unit lists a course roadmap for gathering operating system information, including service packs, process enumeration, installed software, and network information. It also outlines the development of Windows tools for various red teaming tasks like persistence and evasion.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 101 In this module, we will discuss how to enumerate services and tasks during the e

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: What's the Point?, SEC679, Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control
Summary: The unit contains a presentation slide titled 'What's the Point?' which introduces the core concepts of red teaming tools, specifically focusing on development for Windows implants, shellcode, and command and control.
Excerpt:
Visual caption: A presentation slide titled 'What's the Point?' with a central question box. Visible text: What's the Point?; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Objectives, Gather network information, Gather NIC configurations
Summary: The unit contains a slide outlining the learning objectives for a module on red teaming tools. It specifically lists goals related to gathering network information and NIC configurations.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Objectives' listing goals for the module. Visible text: Objectives; Our objectives for this module are:; Gather network information; Gather NIC configurations; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: OS Information, Process Enumeration, CreateToolhelp, WTSEnum, Registry Information, Windows Tool Development
Summary: The unit lists a course roadmap for gathering operating system information, including service packs, process enumeration, and software discovery. It also outlines the development of Windows tools for various operational actions like persistence and evasion.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 130 This module will discuss how to enumerate the Windows Registry to find critical 

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Objectives, Gather registry information, SEC701, Red Teaming Tools
Summary: The unit contains a presentation slide outlining the learning objectives for a module on gathering registry information. It references the SEC701 course material regarding red teaming tools and developing Windows implants.
Excerpt:
Visual caption: A presentation slide titled 'Objectives' outlining the goal of gathering registry information. Visible text: Objectives; Our objectives for this module are:; Gather registry information; SEC701: Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: PE-sieve, defense tool development, AI/ML integration, 10.24.3.156, Rust
Summary: The unit summarizes the module's content regarding the necessity of developing defensive security tools and mentions specific technologies like PE-sieve, AI/ML integration in security tools, and the growing popularity of Rust.
Excerpt:
Module Summary In this module, we discussed several reasons why it is necessary to develop defensive security tools. We also discussed a few tools like PE-sieve, the current state of the art tools, and the future of more advanced tools with better AI/ML integration. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Learned AI/ML is getting better Learned Rust is becoming more popular Discussed how defensive tools are getting more advanced Discussed how you should contribute however you can 33 33 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: PE-sieve, AI/ML integration, 100% Rust, defensive security tools
Summary: The unit provides a summary of the module covering defensive security tools, current state-of-the-art tools like PE-sieve, and future trends including AI/ML integration. It also highlights the growing popularity of Rust for development and encourages contribution to the field.
Excerpt:
Module Summary In this module, we discussed several reasons why it is necessary to develop defensive security tools. We also discussed a few tools like PE-sieve, the current state of the art tools, and the future of more advanced tools with better AI/ML integration. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Learned AI/ML is getting better Learned Rust is becoming more popular Discussed how defensive tools are getting more advanced Discussed how you should contribute however you can 33 33 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: SEC670, Windows Tool Development, SANS Institute, Lab 2.6-2.9, ShadowCraft
Summary: The text lists a series of labs and sections within the SANS SEC670 course, specifically focusing on Windows tool development, operational actions, and implant enhancements like shellcode and evasion.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Lab 2.6: Ipconfig Lab 2.7: Arp Lab 2.8: Netstat Lab 2.9: ShadowCraft S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 160 This is your time to go back and complete previous labs or move forward and complete the bootcamp challenges. 160 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam
