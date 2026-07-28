# Atlas Material — methodology (part 4)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: methodology
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Securable Objects, security descriptor, Create* API family, SECURITY_ATTRIBUTES structure, OpenProcess, ERROR_ACCESS_VIOLATION
Summary: The text describes the concept of Securable Objects in Windows, specifically those that have a corresponding security descriptor. It explains how the Create* family of Win32 APIs uses SECURITY_ATTRIBUTES to define these descriptors and how access is checked during operations like OpenProcess.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 85 Securable Objects Objects that have a corresponding security descriptor Objects that have a corresponding security descriptor files files Most objects are created at the request of the user: CreateProcess, CreateThread, CreateFile, etc. The functions typically accept a pointer to a SECURITY_ATTRIBUTES structure. There are several object types that can be secured. processes processes threads threads reg keys reg keys Securable Objects Remember the section where we were talking about the Create* family of Win32 APIs? It might seem like a long time ago, so here is a refresher. The Create* API family is a 

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: testing environment, sustainability, scaliness, 100+ test cases, validation
Summary: The unit describes best practices for establishing a robust testing environment for red team tools. It emphasizes the scalability of the environment, testing against multiple Windows versions, and performing extensive testing iterations to ensure reliability before deployment.
Excerpt:
Visual caption: A presentation slide titled 'Your Testing Environment' outlining best practices for testing tools in a red teaming context. Visible text: Your Testing Environment; Your testing environment is just for that, testing. It should be robust and capable of scalability to suit your needs.; It might be a good idea to test your tool with various version of Windows.; Don't perform only a single test case and assume all is well—perform hundreds.; Validate your tool before you put it live on a target. Alt/source label:

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: dedicated testing environment, development vs test VM, validation of tool functions, VM snapshotting, requirement for repeated testing
Summary: The unit describes the importance of using a dedicated testing environment separate from development environments to prevent system instability and ensure reliable tool functionality. It emphasizes the need for repeated testing and validation of specific actions (e.g., creating users, registry keys) before deployment. The text also highlights the ability to use snapshots in virtual machines to revert states after failed tests.
Excerpt:
Your Testing Environment Testing your tools on the same system you use to develop them is not a good practice. Even if you were not developing offensive tools, it would not be a wise decision. Since this is an offensive development class, we want to make sure your testing environment is dedicated and not the same as your development environment. For this very reason, you were provided two primary Windows images: a development VM and a test VM. The other images will be used later for AV evasion. With offensive tools, if you are working on a capability that modified sensitive or critical parts of the registry, then there is a chance you could place your machine in an unusable state, forcing yo

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IPC, Pipes, Anonymous pipes, Named pipes
Summary: The unit describes the concept of interprocess communication (IPC) specifically focusing on understanding pipes as a method for IPC.
Excerpt:
Visual caption: A slide from a cybersecurity course about interprocess communication (IPC) using pipes. Visible text: Pipes!; One of many method of interprocess communications (IPC); Anonymous pipes; Named pipes; SEC.670 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SANS SEC679, Diversity with your tools, sumary slide, Windows Implants, Shellcode, Command and Control
Summary: The unit contains a summary slide from a SANS Institute course regarding red teaming tools and Windows implants. It covers topics such as tool diversity, target platform identification, build creation for single targets, and IDE selection.
Excerpt:
Visual caption: A summary slide from a SANS Institute course on red teaming tools and Windows implants. Visible text: Module Summary; Diversity with your tools is vital; Discussed how to know your target platform; Learned to create a Build for a single target; Discussed choosing the IDE that best suits your needs; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: PE Format, DLL Injection, APC Injection, Thread Hijacker, TokenThief, UACBypass
Summary: The unit lists a course roadmap for red teaming tools, specifically focusing on Windows implants, shellcode, and C2. It outlines several injection techniques including DLL Injection, APC Injection, and Thread Hijacking.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 138 Course Roadmap PE Format Lab 3.1: PEParser Threads Injections Lab 3.2: ClassicDLLInjection Lab 3.3: APCInjection Lab 3.4: ThreadHijacker Escalations Lab 3.5: TokenThief Bootcamp Lab 3.6: So, You Think You Can Type Lab 3.7: UACBypass-Research Lab 3.8: ShadowCraft S e c t i o n 3 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss several techniques centered around injection. There are a large number of injection methods and as you ca

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, slide content, SEC670
Summary: The unit contains a visual caption describing a slide showing the course roadmap and specific sections of a red teaming course, including topics like PE format, threads, injections, and evasion.
Excerpt:
Visual caption: A slide showing the course roadmap and section 3 contents for a red teaming course. Visible text: Course Roadmap; Section 3; PE Format; Threads; Injections; Evasion; Bootcamp; SEC670 Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SEC670, RED TEAMING TOOLS, Windows implants, shellcode, Command and Control
Summary: The unit contains a title slide for the SANS SEC670 course focusing on red teaming tools, specifically Windows implants, shellcode, and C2 infrastructure.
Excerpt:
Visual caption: A title slide for a SANS Institute course on red teaming tools and persistence. Visible text: SEC670 | RED TEAMING TOOLS: DEVELOPING WINDOWS IMPLANTS, SHELLCODE, COMMAND AND CONTROL; https://linktr.ee/offsecexam; 670.4; Persistence: Die Another Day Alt/source label:

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Table of Contents, In Memory Execution, Binary Patching, Registry Keys, Services, WMI Event Subscriptions
Summary: This page contains a Table of Contents for the section on Red Teaming Tools, specifically focusing on topics like In Memory Execution, Dropping to Disk, Binary Patching, Registry Keys, Services, and various persistence mechanisms.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 2 P a g e Table of Contents (1) 4 In Memory Execution 13 Dropping to Disk 20 Binary Patching 26 Registry Keys 39 Services Revisited 47 Lab 4.1: PersistentService 67 Port Monitors 74 Lab 4.2: Sauron 79 IFEO 90 Lab 4.3: IFEOPersisto 97 WMI Event Subscriptions 114 Bootcamp This page intentionally left blank. 2 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: In Memory Execution, Dropping to Disk, Binary Patching, Registry Keys, Services Revisited, WMI Event Subscriptions
Summary: The unit contains a course roadmap for red teaming tools, specifically focusing on topics like in-memory execution, dropping to disk, binary patching, and various persistence mechanisms.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 4 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In Memory Execution In this module, we will discuss what in memory execution is and how it can benefit us. We will also look at some disadvantages with only living in memory. Hint: it

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: In Memory Execution, Dropping to Disk, Binary Patching, Registry Keys, Services Revisited, WMI Event Subscriptions
Summary: The text outlines a course roadmap for red teaming tools, specifically focusing on topics like in-memory execution, dropping to disk, binary patching, and various persistence mechanisms such as registry keys, services, and WMI event subscriptions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 13 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss why you would need to drop something to disk, where to drop, cleaning up, and more. © 2024 Jonathan Reiter 13 © SANS Institute 2024 f80c9b76f5e518e0ab

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SEC670, Red Teaming Tools, summary of modules, In Memory Execution, binary patching, persistence techniques
Summary: The text provides a course roadmap for the SEC670 Red Teaming Tools module, listing topics such as in-memory execution, binary patching, and various persistence techniques like registry keys and WMI event subscriptions. It also outlines specific lab exercises related to service persistence and other tools.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 13 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss why you would need to drop something to disk, where to drop, cleaning up, and more. © 2024 Jonathan Reiter 13 © SANS Institute 2024 f80c9b76f5e518e0ab

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: In Memory Execution, Binary Patching, Registry Keys, WMI Event Subscriptions, Sauron
Summary: The text outlines a course roadmap for red teaming tools, specifically focusing on Windows implants, shellcode, and C2. It lists various techniques such as in-memory execution, binary patching, and WMI event subscriptions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 20 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss what binary patching is and how we can leverage it for persistence on target. 20 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c1

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, Section 4, Widget: Registry Keys, Lab 4.1, Lab 4.2, Lab 4.3
Summary: The unit contains a slide outlining the course roadmap for Section 4 of a Windows Tool Development course. It lists various topics including Registry Keys, Persistence techniques, and several lab exercises related to security research.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Course Roadmap' and 'Section 4', highlighting the topic of Registry Keys. Visible text: Course Roadmap; Section 4; Windows Tool Development; Getting to Know Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant; Capture the Flag Challenge; In Memory Execution; Dropping to Disk; Binary Patching; Registry Keys; Services Revisited; Lab 4.1: Persistence Service; Port Monitors; Lab 4.2: Sauron; IFEO; Lab 4.3: IFEOPersist; WMI Event Subscriptions; Bootcamp Alt/source label:

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: memory execution, ceiling of service persistence, binary patching, WMI event subscriptions, Sauron, IFEO
Summary: The text outlines a course roadmap for red teaming tools, specifically focusing on memory execution, disk dropping, binary patching, and various persistence mechanisms like services and WMI event subscriptions. It introduces Section 4, which which focuses on Windows tool development and operational actions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 39 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss how to persist using services. This includes services that we take advantage of or services that we create ourselves. © 2024 Jonathan Reiter 39 © SANS

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, Section 4, Windows Tool Development, Persistence: Die Another Day, Binary Patching, Lab 4-1, Lab 4-2, Lab 4-3
Summary: The unit contains a slide outlining the curriculum for Section 4 of a Windows Tool Development course. It lists various topics including persistence mechanisms, memory execution, binary patching, and specific lab exercises.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Course Roadmap' showing the curriculum for Section 4. Visible text: Course Roadmap; Section 4; Windows Tool Development; Getting to Your Next Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant; Capture the Flag Challenge; In Memory Execution; Dropping to Disk; Binary Patching; Registry Keys; Services Revisited; Lab 4-1: Persistence Service; Port Monitors; I1FE0; Lab 4-2: Sauron; IFEO; Lab 4-3: IFEOPersist; WMPI Event Subscriptions Alt/source label:

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SDDL, Security Descriptor Definition Language, ConvertSecurityDescriptorToStringSecurityDescriptor, Owner (O:), SACL (S:), DACL (D:), Primary Group (G:), control flags
Summary: The unit describes the Security Descriptor Definition Language (SDDL) used to define security descriptors as strings for specific Windows APIs. It details the components of a security descriptor, such as Owner (O:), SACL (S:), DACL (D:), and Primary Group (G:), along with their respective control flags.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 50 SDDL Security descriptor definition language Security descriptor definition language O: Owner O: Owner O: owner_sid applies to the owner of the object G: group_sid applies to the primary group for the object D: DACL D: DACL S: SACL S: SACL G: Group G: Group D: dacl_flags S: sacl_flags applies to the object’s DACL/SACL control flags SDDL The security descriptor definition language, or SDDL, is not really a language, per se, but something that is specific to the definition of a string format for two APIs: ConvertSecurityDescriptorToStringSecurityDescriptor and ConvertStringSecurityDescriptorToSecurityDes

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SDDL, Security Descriptor Definition Language, DACL, SACL, Owner (O:), Primary Group (G:), control flags
Summary: This unit describes the Security Descriptor Definition Language (SDDL) used in Windows for defining security descriptors as strings. It details the components of a security descriptor including Owner, SACL, DACL, and Primary Group, along with specific control flags like SDDL_PROTECTED and SD1_AUTO_INHERITED.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 50 SDDL Security descriptor definition language Security descriptor definition language O: Owner O: Owner O: owner_sid applies to the owner of the object G: group_sid applies to the primary group for the object D: DACL D: DACL S: SACL S: SACL G: Group G: Group D: dacl_flags S: sacl_flags applies to the object’s DACL/SACL control flags SDDL The security descriptor definition language, or SDDL, is not really a language, per se, but something that is specific to the definition of a string format for two APIs: ConvertSecurityDescriptorToStringSecurityDescriptor and ConvertStringSecurityDescriptorToSecurityDes

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SDDL Example, ace_string breakdown, ACCESS_ALLOWED_ACE_TYPE, ADS_RIGHT_DS_READ_PROP, GENERIC_ALL
Summary: The unit provides a detailed breakdown of an SDDL (Security Descriptor Definition Language) string example from MSDN documentation. It explains the components of the ace_string, specifically focusing on rights like read property, write property, and generic all access.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 53 SDDL Example #1 MSDN Example MSDN Example Several field types skipped Several field types skipped "O:AOG:DAD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)” Revision: 0x00000001, Control: 0x0004, SE_DACL_PRESENT Owner: (S-1-5-32-548) PrimaryGroup: (S-1-5-21-397955417-626881126- 188441444-512) DACL - Revision: 0x02, Size: 0x1c, AceCount: 0x01 Ace[00] AceType: 0x00 (ACCESS_ALLOWED_ACE_TYPE) AceSize: 0x0014 InheritFlags: 0x00 Access Mask: 0x100e003f READ_CONTROL | WRITE_DAC | WRITE_OWNER | GENERIC_ALL, Others(0x0000003f) Ace Sid : (S-1-0-0) Uses the NULL well-known SID Uses the NULL well-known SID SDDL Example #1 Th

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: In Memory Execution, Dropping to Disk, Binary Patching, Registry Keys, Port Monitors, WMI Event Subscriptions
Summary: The unit describes a curriculum roadmap for red teaming tools, specifically focusing on Windows-based techniques like in-memory execution, binary patching, and persistence mechanisms.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 67 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss how to persist using port monitors. © 2024 Jonathan Reiter 67 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: In Memory Execution, Dropping to Disk, Binary Patching, Port Monitors, WMI Event Subscriptions
Summary: The text lists a course roadmap for red teaming tools, specifically focusing on topics like in-memory execution, binary patching, and various persistence mechanisms including port monitors and WMI event subscriptions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 67 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss how to persist using port monitors. © 2024 Jonathan Reiter 67 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, s4, In Memory Execution, Binary Patching, Registry Keys, WMI Event Subscriptions
Summary: The unit contains a slide outlining the curriculum for Section 4 of a cybersecurity course. It lists topics including in-memory execution, binary patching, and various persistence mechanisms like registry keys and WMI event subscriptions.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Course Roadmap' showing the curriculum for Section 4. Visible text: Course Roadmap; Section 4; In Memory Execution; Dropping to Disk; Binary Patching; Registry Keys; Services Revisited; Lab 4.1: Persistence Service; Port Monitors; Lab 4.2: Sauron; IFEO; Lab 4.3: IFEOPersist; WMI Event Subscriptions; Bootcamp Alt/source label:

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: port monitors, user-mode to kernel-mode bridge, swoolsv.exe, Win32 API AddPrinter, printer queue
Summary: The text describes the function and architecture of Windows port monitors, specifically their role as bridges between user-mode (spoolsv.exe) and kernel-mode drivers. It explains how they are used to manage printer ports and interact with the Win32 API AddPrinter.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 69 Port Monitors What are port monitors? What are port monitors? Windows has two type of print monitors: language monitor and port monitor. Port monitors do what they say by monitoring a printer port and bridging the physical connection to the printer queue, which we see as a user. Port Monitors What exactly are port monitors? According to Microsoft, a port monitor acts like a bridge of sorts from user- mode to kernel-mode. The user-mode side comes from the spoolsv.exe image and it communicates with a port driver that resides in the kernel. The spoolsv.exe is a Windows service known as the Windows Print S

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, Section 4, In Memory Execution, Binary Patching, Registry Key, Service Persistence
Summary: The unit contains a slide outlining the curriculum for Section 4 of a cybersecurity course. It lists topics including in-memory execution, binary patching, and various persistence mechanisms like registry keys and services.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Course Roadmap' showing the curriculum for Section 4. Visible text: Course Roadmap; Section 4; In Memory Execution; Dropping to Disk; Binary Patching; Registry Keys; Services Revisited; Lab 4:1. Persistence Service; Port Monitors; Lab 4:2. Sauron; IFEO; Lab 4:3. IFEOPersist; WMI Event Subscriptions; Bootcamp Alt/source label:

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SANS SEC670, Course Roadmap, curriculum overview, Windows Tool Development, Shellcode, C2
Summary: The text provides a high-level overview of the SANS SEC670 course curriculum, including topics like Windows tool development, DLLs, and API usage. It outlines specific labs and modules covering offensive and defensive tools, shellcode, and C2 infrastructure.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 4 In this module, we will discuss at a high level what the course will be c

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: In Memory Execution, Dropping to Disk, Binary Patching, Registry Keys, Services Revisited, WMI Event Subscriptions
Summary: The text outlines a course roadmap for red teaming tools, specifically focusing on topics like in-memory execution, dropping to disk, binary patching, and various persistence mechanisms such as registry keys, services, and WMI event subscriptions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 97 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss why you would need to drop something to disk, where to drop, cleaning up, and more. © 2024 Jonathan Reiter 97 © SANS Institute 2024 f80c9b76f5e518e0ab

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Common Information Model, WMI, CIM classes, Core/Common/Extended
Summary: The text defines the Common Information Model (CIM) as an industry standard used by WMI to represent objects like systems, processes, and devices in a uniform way. It describes three levels of CIM classes: Core, Common, and Extended, explaining their differences in terms of scope and technology specificity.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 101 What Is CIM? The Common Information Model (CIM) The Common Information Model (CIM) The CIM is an industry standard that is used by WMI to represent various items, like systems, processes, devices, and more. CIM is object oriented and gives the look and feel of a C++ class. CIM gives us three levels of classes: Core, Common, and Extended. What Is CIM? Standards typically have models to go by and WMI is no exception because it follows the industry standard called the Common Information Model (CIM). The CIM is used to represent data in a uniformed way, data such as systems, processes/applications, networ

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Common Information Model, CIM, Core, Common, and Extended
Summary: The unit describes the definition and structure of the Common Information Model (CIM) within a security context. It identifies three core components: Core, Common, and Extended.
Excerpt:
Visual caption: A slide from a SANS course explaining the definition and structure of the Common Information Model (CIM). Visible text: What Is CIM?; The Common Information Model (CIM); Core, Common, and Extended Alt/source label:

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Common Information Model, WMI, CIM classes, Core/Common/Extended
Summary: The text defines the Common Information Model (CIM) as an industry standard used by WMI to represent objects like systems, processes, and devices in a uniform way. It describes three levels of CIM classes: Core, Common, and Extended, explaining their differences in terms of generality and technology specificity.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 101 What Is CIM? The Common Information Model (CIM) The Common Information Model (CIM) The CIM is an industry standard that is used by WMI to represent various items, like systems, processes, devices, and more. CIM is object oriented and gives the look and feel of a C++ class. CIM gives us three levels of classes: Core, Common, and Extended. What Is CIM? Standards typically have models to go by and WMI is no exception because it follows the industry standard called the Common Information Model (CIM). The CIM is used to represent data in a uniformed way, data such as systems, processes/applications, networ

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WMI, CIM Schema, Win32 Schema, CIM_ prefix, Win32_ prefix, custom classes
Summary: The text describes the structure of WMI and CIM schemas in Windows, specifically distinguishing between CIM_ and Win32_ prefixes. It explains that developers can create custom classes within these schemas to manage objects.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 102 WMI and CIM Schemas Classes can be grouped together into what are called schemas. Classes can be grouped together into what are called schemas. CIM Schema CIM Schema Win32 Schema Win32 Schema Classes start with CIM_ and provide the definition for the Core and Common classes. Developers can create their own as well. Classes start with Win32_ and provide the definitions for the Extended CIM class specific for the Win32 environment. Developers can create their own here as well. WMI and CIM Schemas WMI and CIM classes are often grouped together to form what are called schemas, and they are typically speci

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: In Memory Execution, Binary Patching, triage of persistence methods, WMI Event Subscriptions, Lab 4.1: Persistent Service
Summary: The text provides a roadmap for Section 4 of the SEC670 course, outlining topics such as in-memory execution, binary patching, and various persistence mechanisms like registry keys and WMI event subscriptions. It also lists specific lab exercises related to creating persistent services and other evasion techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 114 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge Welcome to the bootcamp for Section 4! The challenges during the bootcamp will be very challenging but have fun with them and do not hesitate to reach out for assistance, guidance, 

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, s6, Windows Tool Development, Shellcode, Evasion, C2
Summary: The unit contains a slide outlining the roadmap for Section 6 of a SANS course on red teaming tools. It lists specific topics including tool development, operational actions, persistence, shellcode, evasion techniques, and C2 communication.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Course Roadmap' and 'Section 6', detailing various topics related to red teaming tools. Visible text: Course Roadmap; Section 6; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; Custom Loaders; Unhooking Hooks; Bypass any EDR; Calling Home; Writing Shellcode in C; Bootcamp; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NTDLL.DLL, native vs GUI, NtOpenProcess, NtUserOpenClipboard, WIN32K.SYS
Summary: The unit describes the difference between native and GUI-based system calls in Windows, specifically comparing NTDLL.DLL and WIN32.DLL functions.
Excerpt:
Visual caption: A slide from a technical presentation explaining the difference between native and GUI-based system calls in Windows, using Notepad++ as an example. Visible text: GUI or Console Thread?; Notepad++.exe; NTDLL.DLL (Native); NtOpenProcess; NtCreateProcess; WIN32.DLL (GUI); NtUserOpenClipboard; NtUserCloseClipboard; KERNEL (and EXECUTIVE); WIN32K.SYS; SEC67 / Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Wow64, 32-bit to 64-bit transition, syscalls, Heaven's Gate
Summary: The unit describes the transition between 32-bit and 64-bit code in Windows environments using Wow64. It specifically mentions how 32-bit processes on 64-bit systems handle system calls.
Excerpt:
Visual caption: A slide from a training course titled 'Heaven's Gate', explaining the transition between 32-bit and 64-bit code in Windows. Visible text: Heaven's Gate; Hooking Wow64 and the gate to 64-bit code; 32-bit processes on 64-bit systems have an interesting method when it comes to making syscalls. Thanks to Wow64, on Windows 64, this is all made possible. The t; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Objectives, tool development, surveying the land, operational actions, password/persistence methods
Summary: The unit contains a slide outlining learning objectives for a module on tool development and system operations. It lists goals such as understanding tool development, surveying the land, performing operational actions, and identifying persistence methods.
Excerpt:
Visual caption: A slide titled 'Objectives' listing the learning goals for a module on tool development and system operations. Visible text: Objectives; Our objectives for this module are:; Discuss what tool development is; Determine what surveying the land means; Figure out how to carry out operational actions; Discover various persistence methods; Enhance your implant; SANS SEC679 Alt/source label:

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SEC670, Custom Loaders, unhooking Hooks, Bypassing AV/EDR, Shellcode in C
Summary: The text lists a course roadmap for the SEC670 Red Teaming Tools course, including topics like custom loaders, unhooking hooks, bypassing AV/EDR, and writing shellcode in C. It also outlines specific labs related to these techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 63 Course Roadmap Custom Loaders Lab 5.1: The Loader Unhooking Hooks Lab 5.2: UnhookTheHook Bypassing AV/EDR Calling Home Lab 5.3: No Caller ID Writing Shellcode in C Bootcamp Lab 5.4: AMSI No More Lab 5.5: ShadowCraft S e c t i o n 5 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will cover the concepts of bypassing AV solutions and possibly EDR solutions. 63 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, Windows Tool Development, Bevariation of Shellcode, C2 Frameworks, Unhooking Hooks, Bypassing EAVEDR
Summary: The unit contains a slide outlining the curriculum for Section 6 of a red teaming course. It lists topics such as Windows tool development, shellcode, evasion techniques, and C2 frameworks.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Course Roadmap' and 'Section 6', detailing various topics related to Windows tool development, shellcode, and C2 frameworks. Visible text: Course Roadmap; Section 6; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; Custom Loaders; Unhooking Hooks; Bypassing EAVEDR; Calling Home; Writing Shellcode in C; Bootcamp; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows DLLs, Linux shared objects, dlopen, LoadLibrary, dlsym, GetProcAddress, ELF format, difference in export syntax
Summary: This unit compares Windows DLLs and Linux shared objects, highlighting their similarities in dynamic loading and symbol resolution. It notes that while both provide functionality for programs to import, they differ in export syntax requirements.
Excerpt:
Shared Objects For those who are coming over from the *Nix side of C/C++ development, Linux shared objects can be viewed the same as Windows DLLs. Both provide functionality that can be imported and utilized in your programs. Both are a form of executable, though the file format is specific to the platform: Windows PE or Linux ELF. Both provide symbols for programs to utilize and just like on Windows, they can be loaded and unloaded dynamically (explicit linking) using functions dlopen (LoadLibrary), dlclose (FreeLibrary). Resolution can be done just like Windows as well using dlsym (GetProcAddress). As mentioned previously, the resolution of a symbol’s address is required since the library 

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, Section 6, Windows Tool Development, Shellcode, Evasion, Unhooking Hooks, Bypass_API_Hooker/EDR
Summary: The unit contains a slide titled 'Course Roadmap' outlining the modules for Section 6 of a cybersecurity course focused on Windows tool development. It lists specific topics such as shellcode, evasion techniques, and various lab exercises related to loader development and EDR bypass.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlining the modules for a cybersecurity course, specifically focusing on Section 6. Visible text: Course Roadmap; Section 6; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Custom Loaders; Unhooking Hooks; Bypass_API_Hooker/EDR; Calling Home; Writing Shellcode in C; Bootcamp; Lab 5.1: The Loader; Lab 5.2: Unhooking_NetHook; Lab 5.3: No Caller ID; Lab 5.4: AMSI_No_More; Lab 5.5: ShadowCraft Alt/source label:

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, Section 6, Windows Tool Development, Shellcode, Evasion, C2
Summary: The unit contains a slide titled 'Course Roadmap' outlining the curriculum for SANS SEC-713. It lists specific topics including Windows tool development, shellcode, evasion techniques, and C2 infrastructure.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlines the curriculum for a SANS SEC-713 course, specifically focusing on Section 6. Visible text: Course Roadmap; Section 6; Windows Tool Development; Getting in and Staying on Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Custom Loaders; Unhooking Hooks; Bypass_api_hook/EDR; Calling Home; Writing Shellcode in C; Bootcamp; SEC-713 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:
