# Atlas Material — methodology (part 2)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: methodology
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: requirement analysis, 32-bit/64-bit binaries, code injection, persistence, privilege escalation, HTTP C2
Summary: The unit describes a group exercise involving the analysis of requirements for a new red team capability. It lists specific technical requirements such as multi-architecture support, size constraints, and various features like code injection, persistence, and privilege escalation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Group Exercise Scenario: You have just received requirements from the Red Team lead Scenario: You have just received requirements from the Red Team lead 15 Go over the requirements Determine which ones are not technically possible Determine which ones need more of an explanation Discuss a timeline for release Group Exercise Let us pause for a moment and go over a scenario where you are the team lead for the development shop. The Red Team lead has just created a ticket that has a fairly large number of requirements in it for a new capability for an upcoming engagement they have. The Red Team will be facing

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Objects, object manager, Object header, object body, handle count, ObTypeIndexTable
Summary: The text describes the structure and management of Windows objects, specifically focusing on object headers and bodies. It explains how the Object Manager handles creation, validation, and handle management for these objects. The content covers technical details regarding handle counts, type indices in the ObTypeIndexTable, and the differences between header and body structures.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Objects (4) Every object has the same structure Every object has the same structure object header object header This means that there can be one portion of the system that manages all objects. The appropriately named object manager has the role of maintaining all objects. object body object body - type - name - directory - security descriptor - handle count and list - optional subheaders - unique to the object type 168 Windows Objects (4) The object manager can perform several tasks, such as following: - Create objects and validate that a process has the rights to use that object. - Create the obj

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Objects, object manager, CloseHandle API, process objects, file objects, different routine creation
Summary: The text describes the architecture of Windows objects and their associated services, such as CloseHandle, create, open, and query. It explains how different object types (files vs. processes) share common headers but have unique bodies and specific management routines. The content focuses on the underlying OS mechanisms for managing various system resources.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Objects (5) Objects have services that can operate on them. Objects have services that can operate on them. Close, duplicate, query/set security, wait for single object, duplicate, etc. Close, duplicate, query/set security, wait for single object, duplicate, etc. The Windows subsystems makes these services available to Windows applications. All objects, regardless of type, support several generic services. In addition, each object will have its own services like create, open, and query. 169 Windows Objects (5) With the standardization of object headers and sub headers, the object manager can provi

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Objects, subsystem services, close, duplicate, query/test security
Summary: The unit describes the core concept of Windows objects and the services provided by system subsystems to applications interacting with these objects. It lists specific common operations like closing, duplicating, and querying security on objects.
Excerpt:
Visual caption: A presentation slide titled 'Windows Objects (5)' explaining the concept of services provided by Windows subsystems to applications. Visible text: Windows Objects (5); Objects have services that can operate on them.; The Windows subsystems may offer these services available to Windows applications. All objects, regardless of their own type, support several generic services. ; Close, duplicate, query/test security, wait for single object, duplicate, etc. Alt/source label:

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Objects, access control list (ACL), security descriptors, object manager, Process Explorer
Summary: The text describes the security mechanisms of Windows objects, specifically how they are protected by access control lists (ACLs) and security descriptors. It explains that the object manager acts as a gatekeeper for user-mode exposed objects while internal kernel objects do not require similar protections. The section also mentions using Process Explorer to view and manage handles to these objects.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Objects (6) Objects can leverage the security of Windows. Objects can leverage the security of Windows. “You shall not pass!” “You shall not pass!” Objects that are exposed to user mode must be protected. Objects will have their own access control list (ACL) that dictates what actions can be performed on the object from a querying process. Securable objects have security descriptors, and the system acts as the gatekeeper to the objects. 170 Windows Objects (6) Objects must be secured or protected from malicious abuse or unauthorized access. Whenever an object is exposed directly to the user, it mu

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Objects, access control list (ACL), security descriptors, object manager, process explorer
Summary: The text describes the security mechanisms of Windows objects, explaining how they are protected via access control lists (ACLs) and security descriptors. It details the role of the object manager as a gatekeeper for user-mode exposed objects and explains how to view handles using Process Explorer.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Objects (6) Objects can leverage the security of Windows. Objects can leverage the security of Windows. “You shall not pass!” “You shall not pass!” Objects that are exposed to user mode must be protected. Objects will have their own access control list (ACL) that dictates what actions can be performed on the object from a querying process. Securable objects have security descriptors, and the system acts as the gatekeeper to the objects. 170 Windows Objects (6) Objects must be secured or protected from malicious abuse or unauthorized access. Whenever an object is exposed directly to the user, it mu

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Objects (6), user mode, security of objects, SECF07.1 Red Teaming Tools
Summary: The unit describes a slide from a cybersecurity course regarding the security of objects in user mode within a Windows environment. It highlights that objects exposed in user mode must be protected and references specific red teaming tools for developing implants, shellcode, and C2.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Windows Objects (6)' discussing the security of objects in user mode. Visible text: Windows Objects (6); Objects can leverage the security of Windows.; Objects that are exposed in user mode must be protected.; You shall not pass!; SECF07.1 Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Handles, handle table entries, purpose of handle table, access levels, Primary Principle of Least Privilege, CloseHandle API, DuplicateHandle API, GetHandleInformation API
Summary: The text describes the mechanics of Windows handles, explaining how they function as indices into handle tables and their role in protecting objects via access rights. It details specific APIs for managing handles, such as CreateProcess, CloseHandle, and DuplicateHandle, while emphasizing the principle of least privilege regarding handle access.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Handles (2) Handle tables store handle table entries. Handle tables store handle table entries. Each process will have its own handle table. Each process will have its own handle table. The handle is an index into the handle table. The handle is an index into the handle table. Various APIs require a valid object handle to manipulate it. Various APIs require a valid object handle to manipulate it. 172 Windows Handles (2) As mentioned previously, handles are the direct result of the creation of named objects. There are several APIs that can create objects and handles (they were also mentioned earlie

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Handles, handle table entries, purpose of handle table, access levels, PROCESS_ALL_ ACCESS, CloseHandle, DuplicateHandle, GetHandleInformation
Summary: This unit describes the mechanics of Windows handles, explaining how they function as indices into handle tables and their role in protecting objects via access rights. It details specific APIs for managing handles, such as CreateProcess, CloseHandle, and DuplicateHandle, while emphasizing the principle of least privilege regarding handle access.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Handles (2) Handle tables store handle table entries. Handle tables store handle table entries. Each process will have its own handle table. Each process will have its own handle table. The handle is an index into the handle table. The handle is an index into the handle table. Various APIs require a valid object handle to manipulate it. Various APIs require a valid object handle to manipulate it. 172 Windows Handles (2) As mentioned previously, handles are the direct result of the creation of named objects. There are several APIs that can create objects and handles (they were also mentioned earlie

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SANS SEC670, Course Roadmap, Developing Offensive Tools, Windows DLLs, Lab 1.3: HelloDLL, Windows API, Call Me Maybe
Summary: The text provides a course roadmap for the SANS SEC670 Red Teaming Tools course, listing various modules and labs related to Windows tool development, DLLs, and API usage. It outlines the curriculum structure including topics like shellcode, evasion, and C2.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 17 In this module, we will discuss what it means to develop offensive tools

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, Windows Tool Development, Shellcode, Evasion, C2
Summary: The unit contains a slide titled 'Course Roadmap' outlining modules for a Windows Tool Development course. It lists topics such as getting your target, operational actions, persistence, and enhancing implants with shellcode and evasion.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlining the modules for a Windows Tool Development course. Visible text: Course Roadmap; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; Section 1; Developing Offensive Tools; Setting Up Your Development Environment; Windows DLLs; Windows Data Types; Call Me Maybe; SAL Annotations; Windows API; Bootcamp Alt/source label:

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SANS SEC670, Course Roadmap, Developing Offensive Tools, Windows DLLs, SAL Annotations, Lab 1.1: PE-sieve
Summary: The text provides a course roadmap and overview for the SANS SEC670 Red Teaming Tools course. It lists specific modules including Windows DLLs, Data Types, SAL Annotations, and various labs involving PE-sieve and ProcMon.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 17 In this module, we will discuss what it means to develop offensive tools

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows API, kernel objects, error handling, SEC679
Summary: The unit contains a summary slide from a SANS course on Windows API programming. It covers the basics of Windows APIs, including their capabilities, naming conventions, and error handling.
Excerpt:
Visual caption: A summary slide from a SANS Institute course on Windows API programming. Visible text: Module Summary; Discussed how Windows APIs provide robust capability; Learned they can have lengthy but descriptive names; Learned APIs can request to create kernel objects; Learned how to handle errors; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SANS SEC679, Windows Tool Development, Operational Actions, Persistence, Windows API
Summary: The text describes a slide outlining the roadmap for SANS SEC679, focusing on topics like Windows tool development, operational actions, and persistence. It lists specific technical modules including DLLs, data types, and Windows APIs.
Excerpt:
Visual caption: A slide outlining the course roadmap and section one topics for a SANS SEC679 training course. Visible text: Course Roadmap; Windows Tool Development; Getting in, Staying on Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; Section 1; Course Overview; Developing Offensive Tools; Setting Up Your Development Environment; Windows DLLs; Windows Data Types; Call Me Maybe; SAM Annotations; Windows API; Bootcamp Alt/source label:

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: course roadmap, SANS SEC670, Windows Tool Development, Lab 1.1-1.6, Windows API
Summary: This unit contains a course roadmap and overview of the SEC670 Red Teaming Tools curriculum. It lists specific lab modules covering Windows DLLs, data types, SAL annotations, and Windows API functions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 196 The bootcamp portion of the class is really extended class hours but wi

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: course roadmap, SANS SEC670, Windows Tool Development, Development Environment, Windows API
Summary: This unit contains a course roadmap and overview of the SANS SEC670 Red Teaming Tools course. It lists various modules including Windows DLLs, Data Types, SAL Annotations, and Windows API usage for tool development.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 196 The bootcamp portion of the class is really extended class hours but wi

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SANS Institute, Offensive mindset, Developing Windows Implants, Shellcode, Command and Control
Summary: The unit contains a slide from a SANS Institute course introducing the concept of an offensive mindset. It lists core topics including red teaming tools, developing Windows implants, shellcode, and command and control.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Developing Offensive Tools' featuring an introductory text about the offensive mindset. Visible text: Developing Offensive Tools; Offensive mindset; Offensive, you are; SECF06; Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Tool Development, Shellcode, Evasion, C2, Lab 1.7 - 1.10
Summary: The text lists a series of labs and sections related to Windows tool development, including topics like shellcode, evasion, and C2 infrastructure. It also mentions a bootcamp portion of the class with lecture-free time for practice.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Lab 1.7: Can'tHandleIt Lab 1.7: Can'tHandleIt Lab 1.8: RegWalker Lab 1.9: It's Me, WinDbg Lab 1.10: ShadowCraft S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 198 The bootcamp portion of the class is really extended class hours but without the lecture. This will give you lecture-free time for you to go back and practice labs again or take on a few of the challenges listed on the next slide. 198 © SANS Institute 2024 f80c9b76f5e518e0

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SEC670.2, Red Teaming Tools, Windows Implants, Shellcode, Command and Control
Summary: The unit contains a title slide for the SEC670.2 module focusing on red teaming tools, including Windows implants, shellcode, and command and control systems.
Excerpt:
Visual caption: A title slide for a SANS Institute course module on red teaming tools and target reconnaissance. Visible text: SEC670.2; Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control; SANS Getting to Know Your Target; © 2024 Jonathan Reiser | All Rights Reserved | Version 01_05 Alt/source label:

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Table of Contents, Gathering Operating System Information, Process Enumeration, CreateToolhelp, WTSEnum, Directory Walks
Summary: This page contains a Table of Contents for the section on Gathering Operating System Information and related labs. It lists topics such as Service Packs, Process Enumer system enumeration methods like CreateToolhelp and WTSEnum, and directory walks.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control P a g e Table of Contents (1) 4 Gathering Operating System Information 14 Lab 2.1: OS Info 19 Service Packs/Hotfixes/Patches 36 Process Enumeration 45 Lab 2.2: ProcEnum 49 Lab 2.3: CreateToolhelp 53 Lab 2.4: WTSEnum 65 Installed Software 73 Directory Walks 83 Lab 2.5: FileFinder 88 User Information 101 Services and Tasks 2 This page intentionally left blank. 2 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Table of Contents, Network Information, Registry Information, Bootmgr, Nemesis, ShadowCraft, SEC701
Summary: The unit contains a table of contents page listing various technical topics including network information, registry information, and specific tools like Nemesis and ShadowCraft. It also references labs related to encoding and other red teaming tools.
Excerpt:
Visual caption: A table of contents page from a technical manual or course material. Visible text: Table of Contents (2); Network Information; Registry Information; Bootmgr; Lab 2.6: -f_enoding; Lab 2.7: Any; Lab 2.8: Nemesis; Lab 2.9: ShadowCraft; SEC701 | Red Teaming Tools, Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Table of Contents, Network Information, Registry Information, Ipconfig, Arp, Netstat, ShadowCraft
Summary: The text contains a table of contents for the Red Teaming Tools course, specifically listing sections on Network Information, Registry Information, and several labs involving tools like Ipconfig, Arp, and ShadowCraft.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control P a g e Table of Contents (2) 115 Network Information 130 Registry Information 157 Bootcamp 161 Lab 2.6: Ipconfig 162 Lab 2.7: Arp 163 Lab 2.8: Netstat 164 Lab 2.9: ShadowCraft 3 This page intentionally left blank. 3 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: offensive tooling, red team ops, sustainability of defense, audit requirements
Summary: The text discusses the necessity of offensive tools in red teaming and cybersecurity operations. It highlights reasons such as fulfilling audit requirements, national security needs, and practicing against realistic threats to improve defensive capabilities.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Purpose Do we even need to have offensive tools in our arsenal? Why can’t we just have defensive tools everywhere? Defensive tools can’t always catch everything Can always count on a nation-state to be there Allows companies to strengthen their defenses Keeps giving you a paycheck 19 Purpose Offensive tooling is necessary for several reasons, the first one is that you probably would not have a job without it. Several organizations might even require external assessments to be conducted every so often. Financial institutions have audit requirements that must take place at certain intervals, and an external

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: offensive tooling, red team ops, audit requirements, national security
Summary: The unit discusses the necessity of offensive tools in red teaming and cybersecurity operations. It highlights reasons such as fulfilling audit requirements, national security needs, and practicing against realistic threats to improve defensive capabilities.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Purpose Do we even need to have offensive tools in our arsenal? Why can’t we just have defensive tools everywhere? Defensive tools can’t always catch everything Can always count on a nation-state to be there Allows companies to strengthen their defenses Keeps giving you a paycheck 19 Purpose Offensive tooling is necessary for several reasons, the first one is that you probably would not have a job without it. Several organizations might even require external assessments to be conducted every so often. Financial institutions have audit requirements that must take place at certain intervals, and an external

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Purpose, Defensive tools can't always catch everything, strengthen their defenses, SEC679
Summary: The unit describes the purpose of offensive tooling in red teaming. It highlights how creating custom tools helps identify defensive gaps, prepare for nation-state threats, and provide career growth.
Excerpt:
Visual caption: A slide titled 'Purpose' explaining the reasons for offensive tooling, including defense strengthening and career opportunities. Visible text: Purpose; Defensive tools can't always catch everything; Can always count on a. nation-state to be there; Allows companies to strengthen their defenses; Keeps giving you a paycheck; SEC679 | Red Teaming Tools: Developing Windows, Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: course roadmap, SEC679, enum, SANS
Summary: The unit contains a slide outlining the course roadmap for Section 2 of SANS SEC679. It lists specific enumeration tasks such as gathering OS information, process enumeration, and network information.
Excerpt:
Visual caption: A slide showing the course roadmap and details for Section 2 of a SANS SEC679 training course. Visible text: Course Roadmap; Section 2; Gathering Operating System Information; Process Enumeration; Installed Software; Directory Walk; User Information; Services and Tars; Network Information; Registry Information; Bootcamp; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Objectives, patch status, SEC407, Windows Implants
Summary: The unit contains a slide outlining the learning objectives for a module on red teaming tools and developing Windows implants. It specifically mentions identifying patch status and discussing the importance of patches.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Objectives' listing goals for the module. Visible text: Objectives; Our objectives for this module are:; Determine what patches, hotfixes, etc. might be present; Discuss the importance of patches; SEC407: Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: patch analysis, hot_fix identification, module objectives
Summary: The unit outlines the learning objectives for a module on identifying and analyzing system patches and hotfixes. It emphasizes understanding how these updates impact operational security during red teaming operations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Determine what patches, hotfixes, etc. might be present Discuss the importance of patches 20 Objectives The objectives are to determine what patches or hotfixes a system might have and how they might affect an operation. 20 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: patch identification, hot1fix analysis, red team operations
Summary: The unit outlines the learning objectives for a module on identifying and analyzing system patches and hotfixes. It emphasizes understanding how these specific updates affect red team operations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Determine what patches, hotfixes, etc. might be present Discuss the importance of patches 20 Objectives The objectives are to determine what patches or hotfixes a system might have and how they might affect an operation. 20 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Service Packs, bundled hotfixes, exploit adjustment, Metasploit Framework, target specification
Summary: The text describes the concept of Windows Service Packs and how they bundle hotfixes to improve update efficiency. It explains that different service pack levels can affect exploit compatibility, requiring developers to consider target OS versions when creating implants or local privilege escalation techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Service Packs Bundled hotfixes Bundled hotfixes Each service pack brings with it a grouping of one or more hotfixes that will be applied to the OS. Each service pack that targets a particular OS version will have all previous hotfixes that former service packs brought with it so that a user can jump straight to the most recent service pack without installing each one sequentially. 22 Service Packs It really would not make much sense for Windows to push down hotfixes by themselves one at a time, but to rather bundle them up in what is called a service pack. Bundling the hotfixes together is pretty great be

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: future of tools, creative use of APIs, GitHub bans, offensive security capabilities
Summary: The text discusses the future of offensive security tool development, focusing on the role of creativity and the impact of potential restrictions on public code repositories.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Future How will time change how we develop tools? Will code repos eventually ban the storage of such tools? New tools are limited by your creative use of the APIs. 21 Future The future can be somewhat what we make it to be if you stop and think about it. If you close off all creativity, ban the posting on offensive security tools to GitHub and other similar sites then you could run the risk of not advancing by much. On the flip side, if your organization can invigorate and inspire creative thinking, then the future for developing new offensive tools and capabilities could be very bright. 21 © SANS Institu

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Future, time change, code repositories, API usage
Summary: The unit describes a presentation slide discussing future trends in tool development, specifically regarding time constraints, code repository policies, and API limitations. It highlights the importance of creative use of APIs for new tool creation.
Excerpt:
Visual caption: A presentation slide titled 'Future' discussing the implications of time, code repositories, and API usage on tool development. Visible text: Future; How will time change how we develop tools?; Will code repos eventually ban the storage of such tools?; New tools are limited by your creative use of the APIs.; SANS SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WUA APIs, updates and patches, module summary
Summary: The unit provides a summary of a module covering updates, patches, and the use of WUA APIs. It highlights learning points regarding patch information retrieval and the integration of WUA APIs in red teaming tools.
Excerpt:
Visual caption: A slide summarizing the key learning points of a module on updates, patches, and WUA APIs. Visible text: Module Summary; Discussed the importance of updates and patches; Learned how to obtain information about patches; Used the WUA APIs; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: process enumeration, Windows implants, process states, methodology
Summary: This unit outlines the learning objectives for a module on process enumeration in Windows environments. It covers the purpose of understanding processes, their creation, states, and various methods for enumerating them.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Understand the need for process enumeration Take a deeper look at processes Explore the various methods to enumerate processes 37 Objectives The objectives for this module are to understand the need for enumerating processes. Furthermore, to understand processes even more, we will look at what processes are, how they are created, different process states, and the several methods involved with enumeration. Let’s get to it. 37 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateProcess API
Summary: The unit describes the mechanism of process creation in Windows environments, specifically focusing on the CreateProcess API. It lists common example processes like Explorer.exe, Notepad.exe, and Winword.exe.
Excerpt:
Visual caption: A presentation slide explaining how processes are created in Windows, specifically highlighting the CreateProcess API. Visible text: How Are Processes Created?; The main method to create a process is an API call.; CreateProcess API; Explorer.exe; Notepad.exe; Winword.exe; SEC704 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateProcess API, kernel process management, _EPROCESS object, _KPROCESS object, process linked list
Summary: The text describes the mechanism of process creation in Windows, specifically focusing on user-mode API calls like CreateProcess and the kernel's role in managing process objects. It details the difference between _EPROCESS and _KPROCESS structures, noting that KPROCESS is embedded within EPROCESS.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control How Are Processes Created? The main method to create a process is an API call. The CreateProcess API is one of the main drivers for creating a process on a system. The API is complex, it has many arguments, and requires the kernel to kick in and make the system object in system space. The kernel tracks all processes and keeps the process objects organized in a linked list. Explorer.exe Explorer.exe Notepad.exe Notepad.exe Winword.exe Winword.exe 39 How Are Processes Created? Process creation can be kicked off by calling the CreateProcess API. User programs can easily make calls to CreateProcess, but they 

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Module Summary, SANS SEC670, learning objectives, offensive security tools
Summary: The unit contains a summary slide from a SANS Institute course (SEC670) outlining learning objectives. It covers the need for offensive security tools, current state-of-the-art frameworks, knowledge sharing, and mentoring.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Module Summary' listing key learning objectives. Visible text: Module Summary; Discussed the need for offensive security tools; Discussed the current state of the art frameworks and offensive tools; Learn to share your knowledge; be a mentor; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, Windows Tool Development, summary, ProcMon, ReflectDLL
Summary: The unit contains a slide titled 'Course Roadmap' outlining the modules and labs for SANS SEC679. It lists specific topics such as Windows Tool Development, Operational Actions, Persistence, and various lab exercises involving PE-Sever, ProcMon, and ReflectDLL.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlines the modules and labs for a SANS SEC679 course. Visible text: Course Roadmap; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant; Capture the Flag Challenge; Section 1; Developing Offensive Tools; Developing Defensive Tools; Lab 1.1: PE-Sever; Lab 1.2: ProcMon; Setting Up Your Development Environment; Windows DLLs; Lab 1.3: ReflectDLL; Windows Data Types; Call Me Maybe; Lab 1.4: Call Me Maybe; SA1. Annotations; Lab 1.5: Safer with SAL Alt/source label:

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: course roadmap, SANS SEC670, Windows Tool Development, Developing Defensive Tools
Summary: The text provides a course roadmap for the SANS SEC670 Red Teaming Tools course, listing various modules and labs related to Windows tool development, DLLs, and API usage. It also includes a section on developing defensive tools.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 24 In this module, we will discuss the development of defensive tools, thei

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NqQuerySystemInformation, NSTATUS return type, NtQuerySystem_information, SYSTEM_PROCESS_INFORMATION
Summary: The unit describes the NqQuerySystemInformation API, which is used to enumerate system information. It notes that it returns an NSTATUS type and relates it to NtQuerySystemInformation.
Excerpt:
Visual caption: A slide from a technical presentation about the NqQuerySystemInformation API. Visible text: NqQuerySystemInformation API; Grabs specific information about the system; Has NSTATUS return type; NtQuerySystemInformation; SYSTEM_PROCESS_INFORMATION Alt/source label:
