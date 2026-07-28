# Atlas Material — methodology (part 1)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: methodology
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: CRTO Book.pdf
Value: 0.95  Key cues: Rules of Engagement, deconfliction, data handling, offshore tools, legal requirements
Summary: The unit describes the operational requirements for red teaming engagements, specifically focusing on Rules of Engagement (RoE), record keeping, and data handling protocols. It outlines the necessity of signed RoE documents, the importance of even tracking activities to distinguish them from real attacks, and the requirements for legal compliance when handling sensitive information.
Excerpt:
8. ROE: The Rules of Engagement (RoE) document defines the rules and methodologies against which the engagement will be conducted; and should be agreed and signed by all parties. The RoE should: • Define the engagement objectives. • Define the target(s) of the engagement, including domains and IP ranges. • Identify any legal or regulatory requirements and/or restrictions. • Contain emergency contact lists for key persons in all parties. Any changes made to the RoE should also be agreed and signed by all relevant parties. Even though physical red teaming (physically attempting to gain entry to a premise or property) is out of scope of this course, members of those engagements should carry a s

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: FindFirstFileA, WIN32_FIND_DATA, lpFileName, search handle, INVALID_HANDLE_VALUE
Summary: The unit describes the FindFirstFileA API, which is used to initiate a directory walk by returning a search handle and populating a WIN32_FIND_DATA structure. It details the parameters lpFileName (supporting wildcards) and pFindFData, while noting that Unicode versions should be used for non-English characters.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control FindFirstFile API FindFirstFileA() FindFirstFileA() Used to obtain a search handle Used to obtain a search handle HANDLE FindFirstFileA( _In_ LPCSTR lpFileName, _In_ LPWIN32_FIND_DATAA pFindFData ); // example HANDLE hSearch = INVALID_HANDLE_VALUE; WIN32_FIND_DATA FindData; hSearch = FindFirstFileA(Dir, FindData); Has HANDLE return type Has HANDLE return type 78 FindFirstFile API The first API that we need to use to kick of the directory walk is none other than the FindFirstFile API. Like most other APIs that have string arguments, it is just a macro that is expanded to support Unicode or ANSI depending o

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Course Roadmap, Lab 3.1-3.8, PE Format, Thread Hijacking, APC Injection, UACBypass
Summary: The unit contains a course roadmap and list of labs related to Windows tool development, including topics like PE format, threads, injections (ClassicDLLInjection, APCInjection, ThreadHijacker), and privilege escalation techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 33 Course Roadmap PE Format Lab 3.1: GetFunctionAddress Threads Injections Lab 3.2: ClassicDLLInjection Lab 3.3: APCInjection Lab 3.4: ThreadHijacker Escalations Lab 3.5: TokenThief Bootcamp Lab 3.6: So, You Think You Can Type Lab 3.7: UACBypass-Research Lab 3.8: ShadowCraft S e c t i o n 3 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge Threads Before we move into injections, we need to continue learning some of the internals of the system, particularly threads. 

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: SEC670, Course Roadmap, PE Format, Threads, Injections, Lab 3.1-3.8
Summary: The text lists a course roadmap for the SEC670 Red Teaming Tools course, including topics like PE format, thread management, and various injection techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 33 Course Roadmap PE Format Lab 3.1: GetFunctionAddress Threads Injections Lab 3.2: ClassicDLLInjection Lab 3.3: APCInjection Lab 3.4: ThreadHijacker Escalations Lab 3.5: TokenThief Bootcamp Lab 3.6: So, You Think You Can Type Lab 3.7: UACBypass-Research Lab 3.8: ShadowCraft S e c t i o n 3 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge Threads Before we move into injections, we need to continue learning some of the internals of the system, particularly threads. 

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Course Roadmap, Section 3, Windows Tool Development, Shellcode, Evasion, PE Format
Summary: The unit contains a slide outlining the course roadmap for SANS SEC670. It lists topics including Windows tool development, OS fundamentals, operational actions, persistence, shellcode, evasion, and PE format.
Excerpt:
Visual caption: A slide outlining the course roadmap and section 3 topics for a SANS SEC670 training course. Visible text: Course Roadmap; Section 3; Windows Tool Development; Getting to Know the OS; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; PE Format; Threads; Injections; Evasion; Bootcamp; SEC670 | Red Team Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Course Roadmap, Section 3, Windows Tool Development, Persistence, Shellcode, Evasion, DLL Injection, APCInjection
Summary: The unit contains a slide outlining the course roadmap for Section 3 of a SANS SEC670 training course. It lists specific topics including Windows tool development, persistence techniques, shellcode, evasion, and various injection methods.
Excerpt:
Visual caption: A slide outlining the course roadmap and specific topics for Section 3 of a SANS Institute cybersecurity training course. Visible text: Course Roadmap; Section 3; Windows Tool Development; Getting to New Levels; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; PE Format; Threads; Injections; Evasion; Bootcamp; Lab 3.1: GetFunctionAddress; Lab 3.2: Classic DLL Injection; Lab 3.3: APCInjection; Lab 3.4: ThreadHijacker; Lab 3.5: TokenThief; Lab 3.6: You Think You Can Type; Lab 3.7: UAVPass-Research Alt/source label:

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: dedicated testing VM, development vs test environment, security risks of local testing, validation of tools, testing frequency
Summary: The unit describes the importance of using a dedicated testing environment separate from development environments to ensure safety and reliability. It emphasizes the need for repeated testing and validation of tool functionality before deployment in an operation.
Excerpt:
Your Testing Environment Testing your tools on the same system you use to develop them is not a good practice. Even if you were not developing offensive tools, it would not be a wise decision. Since this is an offensive development class, we want to make sure your testing environment is dedicated and not the same as your development environment. For this very reason, you were provided two primary Windows images: a development VM and a test VM. The other images will be used later for AV evasion. With offensive tools, if you are working on a capability that modified sensitive or critical parts of the registry, then there is a chance you could place your machine in an unusable state, forcing yo

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: tool diversity, implant variety, IDE selection, target platform details, build creation
Summary: The unit summarizes the key learning objectives of a module on red teaming tools, specifically focusing on tool diversity, IDE selection, and target platform identification. It emphasizes the importance of varying implants to avoid detection and the process of creating builds for specific targets.
Excerpt:
Module Summary In this module, we discussed the importance of having a diverse toolset, picking the best IDE for you, testing your tools, and knowing what kind of systems you would be targeting. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Diversity with your tools is vital and perhaps more so depending on your current work role and employer. Dropping the same implant every time only works for so long. Discussed how to know your target platform with as much detail as possible Learned to create a Build for a single target Discussed choosing the IDE that best suits your needs 49 49 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a 

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: SEC670, Red Teaming Tools, In Memory Execution, Binary Patching, Registry Keys, WMI Event Subscriptions, Lab 4.1, Lab 4.2
Summary: The text provides a course roadmap for the SEC670 Red Teaming Tools module, listing topics such as in-memory execution, binary patching, and various persistence techniques like registry keys and WMI event subscriptions. It also outlines specific lab exercises related to persistent services and other evasion techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 97 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss why you would need to drop something to disk, where to drop, cleaning up, and more. © 2024 Jonathan Reiter 97 © SANS Institute 2024 f80c9b76f5e518e0ab

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: In Memory Execution, Binary Patching, summary, Registry Keys, WMI Event Subscriptions, Lab 4.1: Persistent Service
Summary: The text provides a roadmap for Section 4 of the SEC670 course, listing topics such as in-memory execution, binary patching, and various persistence techniques like registry keys and WMI event subscriptions. It also includes specific lab exercises related to service persistence and other tools.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 114 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge Welcome to the bootcamp for Section 4! The challenges during the bootcamp will be very challenging but have fun with them and do not hesitate to reach out for assistance, guidance, 

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: tool development, surveying the land, operational actions, persistence, implant enhancement
Summary: The unit outlines the core objectives of the SEC670 course, focusing on tool development, surveying the land (recon), operational actions post-initial access, persistence methods, and implant enhancement.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Discuss what tool development is Determine what surveying the land means Figure out how to carry out operational actions Discover various persistence methods Enhance your implant 5 Objectives The objectives for this course are straightforward. Each section will be talked about at a high level and then during that section’s content, we will take a deep dive into what each one involves. We start off discussing tool development, what it is, how to do it, and different perspectives. Next, we will discuss surveying the land and how to develop custom recon tools. D

=== UNIT 12 ===
Source: CRTO Book.pdf
Value: 0.9  Key cues: methodology, scope
Summary: The unit describes the methodology, scope, and threat model for a red team engagement. It lists specific sections regarding planning and team engagement, scope, and threat modeling.
Excerpt:
Visual caption: A page of text describing the methodology and scope of a red team engagement. Visible text: 3. Planning and team engagement:; 4. Scope.; 5. Threat Model: Alt/source label:

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.9  Key cues: course roadmap, injection techniques, PE format, Lab 3.1-3.8, Windows Tool Development
Summary: The unit describes the course roadmap and curriculum for a red teaming tools development course. It lists specific labs involving injection techniques, privilege escalation, and evasion. The section on PE format details its importance for understanding file structures to facilitate injection methods.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 4 Course Roadmap PE Format Lab 3.1: GetFunctionAddress Threads Injections Lab 3.2: ClassicDLLInjection Lab 3.3: APCInjection Lab 3.4: ThreadHijacker Escalations Lab 3.5: TokenThief Bootcamp Lab 3.6: So, You Think You Can Type Lab 3.7: UACBypass-Research Lab 3.8: ShadowCraft S e c t i o n 3 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge PE Format In this module, we will discuss in detail the format of PE files. Knowing the structure of various headers is vital for

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.9  Key cues: SEC670, In Memory Execution, binary patching, persistence, WMI Event Subscriptions, Lab 4.1, Lab 4.2, Lab 4.3
Summary: The text provides a roadmap for Section 4 of the SEC670 course, listing topics such as in-memory execution, binary patching, and various persistence techniques like registry keys and WMI event subscriptions. It also lists specific lab exercises related to persistent services and other tools.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 114 Course Roadmap In Memory Execution Dropping to Disk Binary Patching Registry Keys Services Revisited Lab 4.1: Persistent Service Port Monitors Lab 4.2: Sauron IFEO Lab 4.3: IFEOPersisto WMI Event Subscriptions Bootcamp S e c t i o n 4 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge Welcome to the bootcamp for Section 4! The challenges during the bootcamp will be very challenging but have fun with them and do not hesitate to reach out for assistance, guidance, 

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.9  Key cues: course roadmap, custom loaders, unhooking hooks, bypass AV/EDR, shellcode in C
Summary: The text provides a course roadmap for the SEC670 module, listing topics such as custom loaders, unhooking hooks, bypassing AV/EDR, and writing shellcode in C. It also outlines specific lab exercises including 'UnhookTheHook', 'No Caller ID', and 'AMS No More'.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 63 Course Roadmap Custom Loaders Lab 5.1: The Loader Unhooking Hooks Lab 5.2: UnhookTheHook Bypassing AV/EDR Calling Home Lab 5.3: No Caller ID Writing Shellcode in C Bootcamp Lab 5.4: AMSI No More Lab 5.5: ShadowCraft S e c t i o n 5 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will cover the concepts of bypassing AV solutions and possibly EDR solutions. 63 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows data types, HINSTANCE, HMODULE, SANS SEC701
Summary: The unit contains a summary slide regarding Windows data types and their usage in red teaming. It highlights the importance of understanding these types to avoid technical issues and notes that some types like HINSTANCE and HMODULE are interchangeable.
Excerpt:
Visual caption: A summary slide from a SANS course on Windows data types and their usage in red teaming. Visible text: Module Summary; Learned you must become familiar with the Windows data types; Discussed how Windows data types could prevent future headaches; Learned some data types just stem from others: HINSTANCE and HMODULE; Discussed how seeing the definitions can help understand something better; Learned some data types are interchangeable: HINSTANCE and HMODULE; SEC701: Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Red Team, Military, Nation State, Operational Actions, purple teaming
Summary: The text discusses the different operational goals and authorities of various actors (Red Team, Military, Nation State) when developing tools for cyber operations. It highlights how tool development objectives vary based on the role's specific mandates, such as testing detections or performing destructive actions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Operational Actions Red Team: Persist, exfil data, pivot Military: Destroy, disrupt, deny, degrade, deceive Nation State: Espionage, disinformation, ransomware, etc. 9 Operational Actions After you have gotten to know your target a bit more, your objectives can be very different depending on the work role you are currently filling. If you are developing tools for a red team, you are probably not creating and releasing ransomware seeking out a payday. Instead, you might be working with the blue team to create a custom tool that is designed to test specific detections, which leads into purple teaming. If yo

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Operational Actions, Red Team objectives, Military actions, Nation State tactics
Summary: The unit describes the differences in operational objectives between Red Team, Military, and Nation-State actors. It lists specific goals such as persistence, data exfiltration, and espionage.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Operational Actions' showing different objectives for Red Team, Military, and Nation State actors. Visible text: Operational Actions; Red Team: Persist, exfil data, pivot; Military: Destroy, disrupt, deny, degrade, deceive; Nation State: Espionage, disinformation, ransomware, etc.; SECF07 / Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Red Team, Operational Actions, military authority, ransomware, purple teaming
Summary: The text discusses the different operational goals and authorities of various actors (Red Team, Red Team/Blue Team collaboration, Military, and Nation-State actors) when developing tools for cyber operations. It highlights how specific roles dictate the scope of which actions are like ransomware or destructive capabilities.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Operational Actions Red Team: Persist, exfil data, pivot Military: Destroy, disrupt, deny, degrade, deceive Nation State: Espionage, disinformation, ransomware, etc. 9 Operational Actions After you have gotten to know your target a bit more, your objectives can be very different depending on the work role you are currently filling. If you are developing tools for a red team, you are probably not creating and releasing ransomware seeking out a payday. Instead, you might be working with the blue team to create a custom tool that is designed to test specific detections, which leads into purple teaming. If yo

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SANS SEC670, Windows Tool Development, calling conventions, DLLs, SAL Annotations, Windows API
Summary: The text provides a roadmap of the SANS SEC670 course, listing various modules and labs related to Windows tool development, including DLLs, data types, SAL annotations, and API usage.
Excerpt:
In this module, we will discuss several calling conventions and which ones are specific to Windows. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Ca

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, Slide title, Security training curriculum
Summary: The unit contains a slide titled 'Course Roadmap' outlining the modules for Section 1 of the SANS SEC670 course. It lists topics such as Windows Tool Development, Developing Offensive Tools, and various technical components like Windows DLLs and APIs.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlining the modules for Section 1 of a SANS SEC670 course. Visible text: Course Roadmap; Section 1; Windows Tool Development; Developing Offensive Tools; Setting Up Your Development Environment; Windows DLLs; Windows Data Types; Call Me Maybe; SA1. Annotations; Windows API; Bootcamp Alt/source label:

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Microsoft source-code annotation language, SAL Annotations, label: SEC670, course roadmap
Summary: The unit introduces the Microsoft source-code annotation language (SAL) and lists a course roadmap for developing Windows implants, shellcode, and C2 infrastructure.
Excerpt:
In this module, we will introduce the Microsoft source-code annotation language. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Chal

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Microsoft source-code annotation language, SAL Annotations, course roadmap, Windows Tool Development
Summary: The unit introduces the Microsoft source-code annotation language (SAL) and lists a course roadmap for developing Windows tools, including topics like DLLs, data types, and API usage.
Excerpt:
In this module, we will introduce the Microsoft source-code annotation language. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Chal

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, Slide title, Security training curriculum
Summary: The unit contains a slide titled 'Course Roadmap' outlining the modules for Section 1 of the SANS SEC670 course. It lists topics such as Windows Tool Development, Windows DLLs, and the Windows API.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlining the modules for Section 1 of a SANS SEC670 course. Visible text: Course Roadmap; Section 1; Windows Tool Development; Developing Offensive Tools; Setting Up Your Development Environment; Windows DLLs; Windows Data Types; Call Me Maybe; SA1_ Annotations; Windows API; Bootcamp Alt/source label:

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Be Creative, think outside the box, signature-wise, discovery of new techniques
Summary: The unit describes the importance of creativity in red teaming and tool development. It emphasizes how creative thinking can help differentiate tools from standard signatures and lead to the discovery of new techniques.
Excerpt:
Visual caption: A slide from a SANS course titled 'Be Creative' highlighting the importance of creativity in red teaming and tool development. Visible text: Be Creative; Must learn to think outside the box; be creative; Can assist with making your tool different from other: signature-wise; Could also lead to discovery of new techniques or capabilities; SECF03; Red Teaming Tools: Developing Windows, Shellcode, Command and Control Alt/source label:

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SAL, Source-code annotation language, review questions
Summary: The unit contains a review question regarding the definition of SAL, which stands for Source-code annotation language.
Excerpt:
Unit Review Questions Q: What does SAL stand for? A: Source-code annotation language B: Structured annotation language C: Silent analysis language SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What does SAL stand for? What does SAL stand for? A Source-code annotation language A Source-code annotation language B Structured annotation language B Structured annotation language C Silent analysis language C Silent analysis language 149 149 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: course roadmap, syllabus outline, SANS SEC670, Windows Tool Development, Windows API, HelloDLL
Summary: This unit contains a course roadmap and overview of the topics covered in the SANS SEC670 Red Teaming Tools course. It lists specific labs, development environments, and core concepts like Windows DLLs, Data Types, SAL Annotations, and the Windows API.
Excerpt:
In this module, we will introduce some essential subject matter, concepts, and introductory topics required to perform advanced penetration testing and to proceed through this course. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Pe

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, Section 1, Windows Tool Development, Windows DLLs, Windows API
Summary: The unit contains a slide titled 'Course Roadmap' outlining the modules and learning objectives for Section 1 of a SANS SEC670 course. It lists topics such as Windows Tool Development, DLLs, and the Windows API.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlining the modules and labs for Section 1 of a SANS SEC670 course. Visible text: Course Roadmap; Section 1; Windows Tool Development; Developing Offensive Tools; Setting Up Your Development Environment; Windows DLLs; Windows Data Types; Call Me Maybe; SAL Annotations; Windows API; Bootcamp Alt/source label:

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: course roadmap, security training content, Windows tool development, SANS SEC670
Summary: This unit contains a course roadmap and overview of the student's learning path for developing Windows-based offensive tools, including topics like DLLs, data types, SAL annotations, and Windows APIs.
Excerpt:
In this module, we will introduce some essential subject matter, concepts, and introductory topics required to perform advanced penetration testing and to proceed through this course. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Pe

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Red Team, developing tools, security research, SEC670
Summary: The unit describes requirements for developing custom tools to support Red Team engagements. It notes that mature organizations often have dedicated developer shops supporting their internal teams.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'SEC670' detailing the requirements for developing tools to support Red Team engagements. Visible text: Requirements; The Red Team is your customer; Most mature organizations with a dedicated developer shop directly support the company's internal Red Team.; SEC670 | Red Teaming: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Red Team customer, requirement list, development shop, formal system
Summary: This unit discusses the organizational structure and workflow for developing custom tools to support a Red Team's requirements. It emphasizes the importance of formal requirement gathering processes, such as Jira tickets or documentation, between development shops and Red Team operators.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Requirements The Red Team is your customer The Red Team is your customer 14 Most mature organizations with a dedicated developer shop directly support the company’s internal Red Team. The Red Team will be a client of yours and should be producing a list of requirements that are needed for their engagements. Your objective will be to satisfy those requirements and release a tool to them. Requirements When it comes to determining how to make a capability that does X, Y, and Z things, you need to think of the end user of your tool and how they might want it deployed in an engagement. When the roles are split

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Red Team as customer, development shop, requirement gathering, Jira ticket, formal system
Summary: This unit discusses the organizational structure and workflow for developing tools specifically for Red Team operations. It outlines how a development shop should receive, evaluate, and fulfill requirements from a Red Team as their primary client.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Requirements The Red Team is your customer The Red Team is your customer 14 Most mature organizations with a dedicated developer shop directly support the company’s internal Red Team. The Red Team will be a client of yours and should be producing a list of requirements that are needed for their engagements. Your objective will be to satisfy those requirements and release a tool to them. Requirements When it comes to determining how to make a capability that does X, Y, and Z things, you need to think of the end user of your tool and how they might want it deployed in an engagement. When the roles are split

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Create* API family, system space vs user space handles, CreateFile, CreateEvent, CreateThread, CreateToolhelp32Snapshot
Summary: This unit introduces the Create* family of Windows APIs, specifically highlighting their role in creating objects in system space and providing handles for user-space interaction. It lists several common functions like CreateFile, CreateEvent, and CreateThread to be used throughout the course.
Excerpt:
Create APIs (2) The functions listed on the slide are just a very small subset of the Create* family of functions. As mentioned previously, there are almost 100 Create* functions to use. For most of them, it is easy to understand what their intended purpose is due to their descriptive names, like CreateFile. You can expect a handle to the newly created object to be returned for most of these, and it is this handle that allows you to interact with the object in system space. All objects are created in system space and user space is given handles to them. You will be using many of these throughout the remainder of the course. On your own time, you can read about them in great detail on MSDN be

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: search path order, GetSystemDirectory, GetHtmlDirectory, %PATH%, ProcessBuilderAttributes
Summary: The unit describes the standard search order for locating files and directories within a Windows environment. It lists specific system calls and environment variables used to be determined by the operating system.
Excerpt:
Visual caption: A slide from a technical course about the order of search paths for finding files and directories. Visible text: Just so you don't have to flip through several pages, here is the search order again in order.; 1. Home of the config file.; 2. Current directory of the process.; 3. System directory (this is returned by GetSystemDirectory).; 4. System directory (this is returned by GetHtmlDirectory).; 5. Directories found in %PATH%.; CommandLine; ProcessAttributes; ProcessBuilderAttributes; CreateProcessFlags; CurrentDirectory; StartupInfo; ProcessInformation Alt/source label:

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Object Manager, kernel objects, executive objects, user objects, CreateFile, CreateThread
Summary: The text describes the Windows object manager and how system resources like files, images, threads, and registry keys are represented as data structures. It explains that there are over 4,000 types of objects, categorized into kernel, executive, and user objects.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Objects (1) System resources represented as data structures in system address space System resources represented as data structures in system address space Files, images, threads, registry keys, and processes are several object types. Files, images, threads, registry keys, and processes are several object types. The Windows kernel does the hard work creating an object often at the request of a user application. There are over 4,000 object types that the Windows executive implements, some of which are not accessible via Windows APIs. 165 Windows Objects (1) Objects in Windows are simply the system’

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Objects, data structures, kernel management, files, images, threads, registry keys, processes
Summary: The unit describes how the Windows kernel manages system resources as data structures known as objects. It lists common examples of object types such as files, images, threads, registry keys, and processes.
Excerpt:
Visual caption: A presentation slide titled 'Windows Objects (1)' describing the representation of system resources as data structures. Visible text: Windows Objects (1); System resources represented as data structures in system address space; The Windows kernel does these jobs and work directly creating an object direct at the request of a user application. There are over 4,000 object types but that ; Files, images, threads, registry keys, and processes are several object types.; SEC701 / Red Team_Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Object Manager, kernel vs executive vs user objects, CreateFile/CreateThread API calls, reference to Windows Internals
Summary: The text describes the Windows object manager and how system resources like files, images, threads, and registry keys are represented as data structures. It explains the difference between kernel objects, executive objects, and user objects while detailing the role of the object manager in managing resource access and lifecycle.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Objects (1) System resources represented as data structures in system address space System resources represented as data structures in system address space Files, images, threads, registry keys, and processes are several object types. Files, images, threads, registry keys, and processes are several object types. The Windows kernel does the hard work creating an object often at the request of a user application. There are over 4,000 object types that the Windows executive implements, some of which are not accessible via Windows APIs. 165 Windows Objects (1) Objects in Windows are simply the system’

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Objects, WinObj utility, process object, thread object, section object, Mutex, Registry Key
Summary: The unit describes various Windows objects, including process, thread, and section objects, and their roles in memory management and synchronization. It references the WinObj utility for identifying object types and cites 'Windows Internals' as a source.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Objects (2) Description Object Type Virtual address space that controls execution of thread object(s) Process The executable portion of a process Thread Shared memory, file-mapping object Section Security profiles for threads/processes Token Method of synchronization for serialized access Mutex Used to refer to data in the Registry Key An object within a window station Desktop 166 Windows Objects (2) There are many types of objects on a Windows system, and the types listed on the slide are a small subset of the types of objects. The full listing can be found by running the WinObj utility from Sysi

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateFile, NtCreateFile, Executive object, handle
Summary: The unit describes the flow of creating a Windows object using the CreateFile API. It details the sequence from user application call to NtCreateFile execution and handle return.
Excerpt:
Visual caption: A slide from a cybersecurity course explaining the flow of creating an object in Windows, specifically focusing on the CreateFile API. Visible text: Windows Objects (3); Example flow of creating an object; User application calls CreateFile; CreateFile calls NtCreateFile; Executive object is created; Handle is returned to caller; SEC701 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Group Exercise, Red Team lead, requirements analysis, sentence-based task list
Summary: The unit describes a group exercise scenario where participants are tasked with analyzing requirements from a Red Team lead. Participants must identify technically impossible tasks, clarify ambiguous requirements, and establish a release timeline.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Group Exercise' outlining requirements for a new capability. Visible text: Group Exercise; Scenario: You have just received requirements from the Red Team lead; Go over the requirements; Determine which ones are not technically possible; Determine which ones need more of an explanation; Give a timeline for release; SECF23 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:
