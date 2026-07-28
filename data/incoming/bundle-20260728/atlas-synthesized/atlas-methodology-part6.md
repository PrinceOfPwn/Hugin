# Atlas Material — methodology (part 6)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: methodology
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Module Summary, Rust, AI/ML, SEC679, Red Teaming Tools
Summary: The unit contains a summary slide for a module on red teaming tools and developing Windows implants. It lists key learning points including the popularity of Rust, advancements in AI/ML, and the evolution of defensive tools.
Excerpt:
Visual caption: A summary slide from a cybersecurity training course titled 'Module Summary' listing key learning points. Visible text: Module Summary; Learned Rust is becoming more popular; Learned AI/ML is getting better; Discussed how defensive tools are getting more advanced; Discussed how you should contribute however you can; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Course Roadmap, syllabus outline, SANS SEC670, Windows Tool Development
Summary: The unit contains a slide titled 'Course Roadmap' outlining the modules for the SANS SEC670 course on Windows Tool Development. It lists various topics including development environment setup, DLLs, data types, and specific operational actions.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlining the modules for a SANS SEC670 course. Visible text: Course Roadmap; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant; Capture the Flag Challenge; Section I; Course Overview; Developing Offensive Tools; Setting Up Your Development Environment; Windows DLLs; Windows Data Types; Call Me Maybe; SA1. Annotations; Windows API; Bootcamp Alt/source label:

=== UNIT 3 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: course roadmap, syllabus content, Windows DLLs, Windows API, SANS SEC670
Summary: The text introduces the course roadmap and modules for a Red Teaming tools development course. It lists specific labs, topics such as Windows DLLs, Data Types, SAL Annotations, and Windows API.
Excerpt:
In this module, we will discuss how to properly create a development environment. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Cha

=== UNIT 4 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Setting Up Your Development Environment, virtual machines, sourcing from media downloads
Summary: The unit describes the initial setup of a virtual machine environment for tool development. It provides instructions on using provided VMs or personal environments and warns against installing updates.
Excerpt:
Visual caption: A slide titled 'Setting Up Your Development Environment (I)' with instructions for setting up a virtual machine environment. Visible text: Setting Up Your Development Environment (I); The virtual machines made available to you are already configured for this course. If you have your own development environment and would like to use it, that i; Please do not install any updates unless directed otherwise.; Copy over everything from the media downloads to your host machine. Alt/source label:

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Table of Contents, Developing Offensive Tools, PE_Loader, HelloDLL, SA1_Assessment
Summary: The unit contains a table of contents for a cybersecurity course on developing offensive and defensive tools for Windows. It lists modules including PE loaders, DLL development, and various lab exercises.
Excerpt:
Visual caption: A table of contents page from a cybersecurity course manual. Visible text: Table of Contents (1); Course Overview; Developing Offensive Tools; Developing Defensive Tools; Lab 1.1: PE_Loader; Lab 1.2: ProcDump; Setting Up Your Development Environment; Windows DLLs; Lab 1.3: HelloDLL; Windows Data Types; Call Me Maybe; Lab 1.4: Call Me Maybe; SA1_Assessment; SEC701 Red Teaming Tools Alt/source label:

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Table of Contents, Windows Implants, 100% content list
Summary: The text contains a table of contents for a course on developing Windows implants, shellcode, and command and control tools. It lists sections including offensive and defensive tool development, environment setup, DLLs, data types, and specific labs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control P a g e Table of Contents (1) 4 Course Overview 17 Developing Offensive Tools 24 Developing Defensive Tools 29 Lab 1.1: PE-sieve 31 Lab 1.2: ProcMon 34 Setting Up Your Development Environment 50 Windows DLLs 78 Lab 1.3: HelloDLL 85 Windows Data Types 110 Call Me Maybe 120 Lab 1.4: Call Me Maybe 129 SAL Annotations 2 This page intentionally left blank. 2 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: testing environment, scal100s of test cases, Windows version variety, validation
Summary: The unit describes best practices for establishing a robust testing environment for red team tools. It emphasizes the importance of scalability, testing against multiple Windows versions, and performing extensive testing iterations to ensure reliability before deployment.
Excerpt:
Visual caption: A presentation slide titled 'Your Testing Environment' outlining best practices for testing tools in a red teaming context. Visible text: Your Testing Environment; Your testing environment is just for that, testing. It should be robust and capable of scalability to suit your needs.; It might be a good idea to test your tool with various version of Windows.; Don't perform only a single test case and assume all is well—perform hundreds.; Validate your tool before you put it live on a target. Alt/source label:

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: dedicated testing VM, development vs test environment, validation of actions, snapshot capability, summary of testing principles
Summary: The unit discusses the importance of using a dedicated testing environment separate from development environments to prevent system instability and ensure reliable tool functionality. It emphasizes the need for repetitive testing and validation of specific actions (e.g., creating users, registry keys) before deployment. The text also suggests testing across multiple Windows versions.
Excerpt:
Your Testing Environment Testing your tools on the same system you use to develop them is not a good practice. Even if you were not developing offensive tools, it would not be a wise decision. Since this is an offensive development class, we want to make sure your testing environment is dedicated and not the same as your development environment. For this very reason, you were provided two primary Windows images: a development VM and a test VM. The other images will be used later for AV evasion. With offensive tools, if you are working on a capability that modified sensitive or critical parts of the registry, then there is a chance you could place your machine in an unusable state, forcing yo

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Table of Contents, Windows API, CreateFile, RegWalker, Shadow_Craft
Summary: The text is a table of contents for a training module on Windows tool development, specifically covering topics like SAL, the Windows API, and various labs involving functions like CreateFile, RegWalker, and ShadowCraft.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control P a g e Table of Contents (2) 145 Lab 1.5: Safer with SAL 155 Windows API 187 Lab 1.6: CreateFile 197 Bootcamp 199 Lab 1.7: Can’tHandleIt 200 Lab 1.8: RegWalker 201 Lab 1.9: It’s Me, WinDbg 202 Lab 1.10: ShadowCraft 3 This page intentionally left blank. 3 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Module Summary, s1000-series, SEC679, Red Teaming Tools, Windows Implants
Summary: The unit contains a summary slide from a SANS course on red teaming tools. It covers topics such as tool diversity, target platform identification, build creation for single targets, and IDE selection.
Excerpt:
Visual caption: A summary slide from a SANS Institute course on red teaming tools and Windows implants. Visible text: Module Summary; Diversity with your tools is vital; Discussed how to know your target platform; Learned to create a Build for a single target; Discussed choosing the IDE that best suits your needs; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Course Roadmap, Windows Tool Development, Windows DLLs, Windows API
Summary: The unit contains a slide titled 'Course Roadmap' outlining the modules for the SANS SEC670 course on Windows Tool Development. It lists various topics including development environment setup, DLLs, and Windows APIs.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlining the modules for a SANS SEC670 course. Visible text: Course Roadmap; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant; Capture the Flag Challenge; Section 1; Course Overview; Developing Offensive Tools; Setting Up Your Development Environment; Windows DLLs; Windows Data Types; Call Me Maybe; SA1. Annotations; Windows API; Bootcamp Alt/source label:

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: SEC670, Course Roadmap, Curriculum, Windows Tool Development, Shellcode, Evasion
Summary: The unit provides a high-level overview of the SEC670 course roadmap and curriculum. It lists specific labs, modules, and topics including Windows DLLs, API usage, and evasion techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 4 In this module, we will discuss at a high level what the course will be c

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Ntdll.dll, Kernel32.dll, Kernelbase.dll, User32.dll, gateway functions, re-exported functions, user-mode hook bypass
Summary: The text describes the role and characteristics of core Windows system DLLs including Ntdll.dll, Kernel32.dll, Kernelbase.dll, and User32.dll. It explains their functions as gateways to kernel land, re-exports, and GUI components. It also mentions a technique for bypassing user-mode hooks by unloading system DLLs.
Excerpt:
Dynamic-linked Libraries (11) There are several system DLLs that will be mapped into almost every process: Ntdll.dll, Kernel32.dll, and Kernelbase.dll. Despite them practically always being mapped, Ntdll.dll is the only one required, but the OS will take care of that for you. NTDLL exports many functions that act as a gateway of sorts before making the jump into kernel land. KERNEL32 also exports many functions and a large number of which are simply re-exported functions from NTDLL. Some functions might not have any code in them at all but are simply jumps or forwarders to a function in NTDLL. USER32 is a primary component for GUI applications as it holds various functions for creating graph

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Objectives, tool development, surveying the land, operational actions, password/persistence methods
Summary: The unit contains a slide outlining learning objectives for a module on tool development and system operations. It lists goals such as understanding tool development, surveying the land, performing operational actions, and identifying persistence methods.
Excerpt:
Visual caption: A slide titled 'Objectives' listing the learning goals for a module on tool development and system operations. Visible text: Objectives; Our objectives for this module are:; Discuss what tool development is; Determine what surveying the land means; Figure out how to carry out operational actions; Discover various persistence methods; Enhance your implant; SANS SEC679 Alt/source label:

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: explicit linking, sanc 679, DLL linking, compile-time vs runtime
Summary: The unit contains a review question regarding the difference between explicit linking and implicit linking of DLLs. It specifically mentions linking at compile time versus runtime via Windows APIs.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Unit Review Questions' featuring a multiple-choice question about explicit linking. Visible text: Unit Review Questions; What is explicit linking?; Linking to DLLs at compile time; Linking to DLLs at runtime via Windows APIs; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Course Roadmap, Windows Tool Development, SANS SEC670, Developing Offensive Tools
Summary: The unit contains a slide titled 'Course Roadmap' outlining the modules for the SANS SEC670 course on Windows Tool Development. It lists various topics including development environment setup, DLLs, data types, and offensive tool development.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlining the modules for a SANS SEC670 course. Visible text: Course Roadmap; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; Section 1; Course Overview; Developing Offensive Tools; Setting Up Your Development Environment; Windows DLLs; Windows Data Types; Call Me Maybe; SA1. Annotations; Windows API; Bootcamp Alt/source label:

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Windows data types, Course Roadmap, Developing Offensive Tools, SANS SEC670
Summary: The unit introduces Windows data types and their definitions to the student. It lists a course roadmap including topics like DLLs, SAL annotations, and various Windows APIs.
Excerpt:
In this module, we will introduce you to the Windows data types. Most of them will probably seem strange at first, but once we look at how they are defined any confusion should be gone. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • 

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: SANS SEC670, RED TEAMING TOOLS, Developing Windows Implants, shellcode, Command and Control
Summary: The text is a title page or introductory section for a SANS SEC670 course on Red Teaming tools, specifically focusing on Windows implants and shellcode. It includes administrative details like the course code, copyright information, and contact links.
Excerpt:
THE MOST TRUSTED SOURCE FOR INFORMATION SECURITY TRAINING, CERTIFICATION, AND RESEARCH | sans.org SEC670 | RED TEAMING TOOLS: DEVELOPING WINDOWS IMPLANTS, SHELLCODE, COMMAND AND CONTROL 670.2 Getting to Know Your Target f80c9b76f5e518e0ab6ab5c122e7bb7a ibmconnect2024@gmail_com ohNrhAfzA3YUEB7zYQeMv7asRrrC6mmK live https://linktr.ee/offsecexam ©a SANS Institute 2024

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: patch analysis, hot_fix identification, module objectives
Summary: The unit outlines the learning objectives for a module on identifying and analyzing system patches and hotfixes. It emphasizes understanding how these updates impact operational security during red teaming operations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Determine what patches, hotfixes, etc. might be present Discuss the importance of patches 20 Objectives The objectives are to determine what patches or hotfixes a system might have and how they might affect an operation. 20 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: process enumeration, Windows implants, process states, methodology
Summary: The unit outlines the learning objectives for a module on process enumeration in Windows environments. It covers the necessity of understanding processes, their creation, states, and various methods for enumerating them.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Understand the need for process enumeration Take a deeper look at processes Explore the various methods to enumerate processes 37 Objectives The objectives for this module are to understand the need for enumerating processes. Furthermore, to understand processes even more, we will look at what processes are, how they are created, different process states, and the several methods involved with enumeration. Let’s get to it. 37 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 21 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: Table of Contents, SEC670, Windows Implants, Process Enumeration, Directory Walks
Summary: This page contains a Table of Contents for the course 'Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control'. It lists topics such as OS information gathering, service packs, process enumeration, installed software, directory walks, and user information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control P a g e Table of Contents (1) 4 Gathering Operating System Information 14 Lab 2.1: OS Info 19 Service Packs/Hotfixes/Patches 36 Process Enumeration 45 Lab 2.2: ProcEnum 49 Lab 2.3: CreateToolhelp 53 Lab 2.4: WTSEnum 65 Installed Software 73 Directory Walks 83 Lab 2.5: FileFinder 88 User Information 101 Services and Tasks 2 This page intentionally left blank. 2 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 22 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: API evaluation, process handle, security-related API usage
Summary: The text discusses the purpose of evaluating a specific API for ease of use and its limitations, such as limited information. It notes that these limitations can be mitigated by opening process handles to PIDs returned by the API.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control What’s the Point? What’s the point? 46 What’s the Point? The point of the lab was to explore the ease of use for this API. It does have a few drawbacks, like the limited information, but that can be accounted for by opening a process handle to each PID returned by the API. 46 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 23 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: decision making, abort operation, go/no-go criteria, pre-briefs
Summary: The unit discusses the decision-making process for continuing or aborting a red team operation based on environmental factors like unknown software. It emphasizes using pre-briefs to establish GO and NOGO criteria before an engagement begins.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Should Operations Continue? When should you abort an operation? When should you abort an operation? Aborting an operation based solely on a single application being installed is quite the decision to make. If you have no idea what the application does or what it would do if you drop more tools on the system, it could be a good decision to back off. This would allow you more time to conduct some research and hit the target later, possibly. 71 Should Operations Continue? When deciding if you should continue with an operation, there is not always a clear yes or no answer. The more enumeration you do, the mor

=== UNIT 24 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: LPDWORD, PDWORD, resume_handle, user accounts
Summary: The text describes the parameters for a function used to query user accounts, specifically focusing on entriesread, totalentries, and resume_handle.
Excerpt:
entriesread, of type LPDWORD, is a pointer to the variable that will hold the number of entries the function queried. totalentries, of type LPDWORD, is a pointer to the variable that will hold the number of entries that could have been queried from a position called the resume position. resume_handle, of type PDWORD, is a pointer to a variable that is used as the resume handle. The resume handle can be used to continue searching user accounts and if this is what you want to do, then zero (0) should always be used for the first call. If you do not care about this, then passing NULL here is just fine. 94 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 25 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName
Summary: This unit describes the specific parameters and data types required when defining a Windows service, such as file paths, load order groups, and account credentials.
Excerpt:
lpBinaryPathName must be the full path where the executable is located. Command-line arguments can also be passed in here after the executable’s name. lpLoadOrderGroup is optional, so NULL is just fine here. lpdwTagId is only for kernel drivers and as this is not a kernel class, we do not need to worry about this one. lpDependencies is an optional list of strings naming other services that this service depends on for successful initialization. lpServiceStartName is the account that this service should execute under. lpPassword would be for the password to the given user account. © 2024 Jonathan Reiter 117 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 26 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: IPC, Pipes, Anonymous pipes, Named pipes
Summary: The unit describes the concept of interprocess communication (IPC) specifically focusing on user-defined pipes as a mechanism for data exchange between processes.
Excerpt:
Visual caption: A slide from a cybersecurity course about interprocess communication (IPC) using pipes. Visible text: Pipes!; One of many method of interprocess communications (IPC); Anonymous pipes; Named pipes; SEC.670 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 27 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: anonymous pipes, local only, less overhead, SANS SEC670
Summary: The unit describes the characteristics of anonymous pipes in a Windows environment for red teaming purposes. It highlights that they are local only and have less overhead than named pipes.
Excerpt:
Visual caption: A slide from a SANS Institute course explaining the characteristics of anonymous pipes. Visible text: Pipes: Anonymous; Less overhead than named pipes; Local only; One-way; SEC.670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 28 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Course Roadmap, PE Format, 3rd Section contents, Injections, Evasion
Summary: The unit contains a visual caption describing a slide showing the course roadmap and specific topics within section three of a red teaming course. The content includes terms like PE format, threads, injections, and evasion techniques.
Excerpt:
Visual caption: A slide showing the course roadmap and section 3 contents for a red teaming course. Visible text: Course Roadmap; Section 3; PE Format; Threads; Injections; Evasion; Bootcamp; SEC670 Alt/source label:

=== UNIT 29 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: 
Summary: The text lists a course roadmap for a Red Teaming tools course, specifically focusing on topics like PE format, thread management, and various injection techniques (ClassicDLLInjection, APCInjection, ThoughtHijacker). It also outlines the other sections of the book or curriculum.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 33 Course Roadmap PE Format Lab 3.1: GetFunctionAddress Threads Injections Lab 3.2: ClassicDLLInjection Lab 3.3: APCInjection Lab 3.4: ThreadHijacker Escalations Lab 3.5: TokenThief Bootcamp Lab 3.6: So, You Think You Can Type Lab 3.7: UACBypass-Research Lab 3.8: ShadowCraft S e c t i o n 3 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge Threads Before we move into injections, we need to continue learning some of the internals of the system, particularly threads. 

=== UNIT 30 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Course Roadmap, s3 topics, Windows Tool Development, Operational Actions, Persistence, Shellcode, Evasion
Summary: The unit contains a slide outlining the course roadmap for SANS SEC670. It lists topics including Windows tool development, operational actions, persistence, shellcode, evasion, and PE format.
Excerpt:
Visual caption: A slide outlining the course roadmap and section 3 topics for a SANS SEC670 training course. Visible text: Course Roadmap; Section 3; Windows Tool Development; Getting to Know the OS; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; PE Format; Threads; Injections; Evasion; Bootcamp; SEC670 | Red Team Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 31 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Thread States, Ready, Running, Waiting
Summary: The unit describes the fundamental thread states (Ready, Running, and Waiting) within a Windows environment.
Excerpt:
Visual caption: A slide titled 'Thread States' describing the three primary states of a thread: Ready, Running, and Waiting. Visible text: Thread States; Ready; Running Alt/source label:

=== UNIT 32 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Thread Scheduling, Windows dispatcher, preemptive, priority-based
Summary: The unit describes the technical mechanics of thread scheduling within the Windows operating system. It explains that Windows uses a preemptive, priority-based system to manage thread execution.
Excerpt:
Visual caption: A slide from a training course about thread scheduling in Windows. Visible text: Thread Scheduling; The Windows dispatcher; Because Windows is a preemptive, and priority-based system, threads can be selected for execution... Alt/source label:

=== UNIT 33 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Creating Threads, behind the scenes, CreateRemoteThread, PspCreateThread, thread suspended
Summary: The unit describes the internal OS-level mechanics of thread creation in Windows. It details the transition from parameter conversion to the execution of CreateRemoteThread and PspCreateThread.
Excerpt:
Visual caption: A slide from a training course about the internal processes of creating threads in Windows. Visible text: Creating Threads; What happens behind the scenes?; Parameters converted to flags; Client ID and TEB address added to an attribute list; Determine if the thread should be created in local or remote process; Call CreateRemoteThread, initialize new thread object, then call PspCreateThread; Thread is initially suspended and then later resumed to it can be scheduled; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 34 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: NtCreateThreadEx, PspCreateThread, CreateRemoteThreadEx, thread context, kernel mode jump
Summary: The text describes the internal mechanics of thread creation in Windows, specifically how CreateThread APIs transition to NtCreateThreadEx and PspCreateThread. It details the process of parameter conversion, local vs. remote process determination, and initial suspension before scheduling.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 41 Creating Threads What happens behind the scenes? What happens behind the scenes? Parameters converted to flags; Client ID and TEB address added to an attribute list Parameters converted to flags; Client ID and TEB address added to an attribute list Determine if the thread should be created in local or remote process Determine if the thread should be created in local or remote process Call NtCreateThreadEx, initialize user-mode thread context, call PspCreateThread Call NtCreateThreadEx, initialize user-mode thread context, call PspCreateThread Thread is initially suspended and then later resumed so it c

=== UNIT 35 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Course Roadmap, Section 3, Windows Tool Development, Persistence, Shellcode, Evasion, Injection
Summary: The unit contains a slide outlining the roadmap for Section 3 of a SANS course on Windows tool development. It lists specific topics including persistence, shellcode, evasion, and various injection techniques.
Excerpt:
Visual caption: A slide outlining the course roadmap and specific topics for Section 3 of a SANS Institute cybersecurity training course. Visible text: Course Roadmap; Section 3; Windows Tool Development; Getting to New Levels; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; PE Format; Threads; Injections; Evasion; Bootcamp; Lab 3.1: GetFunctionAddress; Lab 3.2: Classic DLL Injection; Lab 3.3: APCInjection; Lab 3.4: ThreadHijacker; Lab 3.5: TokenThief; Lab 3.6: You Think You Can Type; Lab 3.7: UAVPass-Research Alt/source label:

=== UNIT 36 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: DLL injection, APC injection, ThreadHijacker, TokenThief, UACBypass-Research, ShadowCraft
Summary: The text outlines a course roadmap for red teaming tools, specifically focusing on Windows implants and command and control. It lists several labs involving injection techniques such as DLL injection, APC injection, and thread hijacking.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 49 Course Roadmap PE Format Lab 3.1: GetFunctionAddress Threads Injections Lab 3.2: ClassicDLLInjection Lab 3.3: APCInjection Lab 3.4: ThreadHijacker Escalations Lab 3.5: TokenThief Bootcamp Lab 3.6: So, You Think You Can Type Lab 3.7: UACBypass-Research Lab 3.8: ShadowCraft S e c t i o n 3 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss several techniques centered around injection. There are a large number of injection methods, and

=== UNIT 37 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Windows thread processing, sourcing routine execution, APC queue, quantum
Summary: The unit contains a multiple-choice question regarding the mechanism for processing routines in Windows threads during their quantum. Options include APC queue, Contexts, and Event objects.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about Windows thread processing. Visible text: Unit Review Questions; What mechanism allows threads to process routines when it enters its quantum?; APC queue; Contexts; Event objects Alt/source label:

=== UNIT 38 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Course Roadmap, Section 3, Security tools, Windows Tool Development, Shellcode, Evasion
Summary: The unit contains a slide outlining the course roadmap and specific topics for Section 3 of a red teaming training module. It lists key areas such as Windows tool development, domain administration access, operational actions, persistence, shellcode, evasion, and C2.
Excerpt:
Visual caption: A slide outlining the course roadmap and section 3 topics for a red teaming training module. Visible text: Course Roadmap; Section 3; Windows Tool Development; Getting to Domain Admin; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; PE Format; Threads; Injections; Evasion; Bootcamp; SEC401; Red Teaming Tools Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 39 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Securable Objects, security descriptor, SECURITY_ATTRIBUTES, Create* API family, Win32 APIs, handle table, OpenProcess
Summary: The text describes the concept of Securable Objects in Windows, specifically those that have a security descriptor and can be hardened using the SECURITY_ATTRIBUTES structure. It explains how the Create* family of Win32 APIs interacts with the kernel to create objects (processes, files, threads, registry keys) and how access is controlled via handles and security descriptors.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 85 Securable Objects Objects that have a corresponding security descriptor Objects that have a corresponding security descriptor files files Most objects are created at the request of the user: CreateProcess, CreateThread, CreateFile, etc. The functions typically accept a pointer to a SECURITY_ATTRIBUTES structure. There are several object types that can be secured. processes processes threads threads reg keys reg keys Securable Objects Remember the section where we were talking about the Create* family of Win32 APIs? It might seem like a long time ago, so here is a refresher. The Create* API family is a 

=== UNIT 40 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: SEC670, RED TEAMING TOOLS, Developing Windows Implants, Persistence: Die Another Day
Summary: The unit contains a title slide for the SANS SEC670 course focusing on red teaming tools, specifically Windows implants, shellcode, and C2 infrastructure.
Excerpt:
Visual caption: A title slide for a SANS Institute course on red teaming tools and persistence. Visible text: SEC670 | RED TEAMING TOOLS: DEVELOPING WINDOWS IMPLANTS, SHELLCODE, COMMAND AND CONTROL; https://linktr.ee/offsecexam; 670.4; Persistence: Die Another Day Alt/source label:
