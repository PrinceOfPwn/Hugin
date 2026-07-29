# Atlas Material — binary-analysis (part 7)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: binary_exploit
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: QueryServiceStatusEx, Windows programming, query service status, SC_HANDLE, SC_STATUS_TYPE
Summary: The unit describes the Windows API function QueryServiceStatusEx for retrieving service status information. It details the specific parameters and return types associated with query functions.
Excerpt:
Visual caption: A slide from a SANS course explaining the QueryServiceStatusEx function in Windows programming. Visible text: QueryServiceStatusEx; Obtains the status of a service; Has a Boolean return type; QueryServiceStatus; BOOL QueryServiceStatusEx(; SC_HANDLE hService,; SC_STATUS_TYPE InfoLevel,; LPBYTE lpBuffer,; DWORD dwBufferSize,; LPWORD pBytesNeeded Alt/source label:

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: QueryServiceConfig, API function signature, service configuration, SC_HANDLE
Summary: The unit describes the QueryServiceConfig API function signature for retrieving service configurations. It details specific parameters like handle, configuration pointer, and buffer size.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'QueryServiceConfig' detailing the API function signature and its parameters. Visible text: QueryServiceConfig; Obtains configuration of a service; Has a Boolean return type; BOOL QueryServiceConfiga(; SC_HANDLE hService; QUERY_SERVICE_CONFIG pServiceConfig; cBufferSize; pBytesNeeded; SEC-703 | Red Team Toolkit: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 3 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: PE header structure, IMAGE_DOS_HERDER, e_lfanew RVA, kernelbase.dll, signature field
Summary: The text describes the structure of PE headers, specifically focusing on the IMAGE_DOS_HEADER and its relation to the IMAGE_NT_HEADERS struct. It explains how the e_lfanew value is used to locate the signature field within kernelbase.dll.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 12 NT Headers: kernelbase.dll NT Headers: kernelbase.dll For this side-by-side screenshot, the purple is coming from the IMAGE_DOS_HEADER->e_lfanew. That value there is used as an RVA that is then added to the base address of kernelbase.dll to give us the location of the first field in the IMAGE_NT_HEADERS struct, the Signature. The ASCII on the right hand side of the screenshot shows the signature being PE. Also, take note the size of the Signature is not two (2) bytes like it is for the IMAGE_DOS_HEADER->e_magic. This one is a DWORD, or 4 (4) bytes, so the next two (2) NULL bytes are part of it. Do not 

=== UNIT 4 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: injection methods, DLL Injection, APC Injection, ThreadHijacker, token thief, Windows tool development
Summary: The unit introduces a section on Windows tool development focusing on overview of injection techniques including DLL, APC, and Thread Hijacking. It lists several labs related to these topics such as PEParser, ClassicDLLInjection, and TokenThief.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 138 Course Roadmap PE Format Lab 3.1: PEParser Threads Injections Lab 3.2: ClassicDLLInjection Lab 3.3: APCInjection Lab 3.4: ThreadHijacker Escalations Lab 3.5: TokenThief Bootcamp Lab 3.6: So, You Think You Can Type Lab 3.7: UACBypass-Research Lab 3.8: ShadowCraft S e c t i o n 3 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss several techniques centered around injection. There are a large number of injection methods and as you ca

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Optional Header, kernelbase.dll, magic field, section alignment, file alignment, s_alignment
Summary: The text discusses the structure and significance of the Optional Header in Windows PE files, specifically focusing on kernelbase.dll.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 16 Optional Header: kernelbase.dll Optional Header: kernelbase.dll This is the optional header from kernelbase.dll. The optional header is not as easy to parse because not all fields are the same size. As mentioned on the previous slide, there are a few places you can check to make sure you might be in the right place. The magic field can hold several values, but typically it will either be 0x10B or 0x20B for 32-bit (PE32) or 64-bit (PE32+), respectively. It would be very uncommon these days to see a different magic value for Windows binaries, but it could happen. The section and file alignment fields are

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: PE header, DataDirectory, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR, kernelbase.dll, kernelbase.dll - data directory
Summary: The text describes the structure of the PE (Portable Executable) file format, specifically focusing on the DataDirectory field within the Optional Header. It explains how to access ands identify exports and imports using specific indices and structures like _IMAGE_EXPORT_DIRECTORY and _IMAGE_IMPORT_DESCRIPTOR.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 17 Optional Header: kernelbase.dll – data directory DataDirectory VirtualAddress _IMAGE_DATA_DIRECTORY Size VirtualAddress _IMAGE_DATA_DIRECTORY Size typedef struct _IMAGE_EXPORT_DIRECTORY { DWORD Characteristics; DWORD TimeDateStamp; WORD MajorVersion; WORD MinorVersion; DWORD Name; DWORD Base; DWORD NumberOfFunctions; DWORD NumberOfNames; DWORD AddressOfFunctions; DWORD AddressOfNames; DWORD AddressOfNameOrdinals; } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY; typedef struct _IMAGE_IMPORT_DESCRIPTOR { union { DWORD Characteristics; // 0 here indicates end of array DWORD OriginalFirstThunk; // Impor

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: IMAGE_EXPORT_DIRECTORY, GetProcAddress implementation, PE structure, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals
Summary: The text describes the structure of the IMAGE_EXPORT_DIRECTORY struct in Windows DLLs, detailing fields like NumberOfFunctions, AddressOfNames, and AddressOfNameOrdinals. It explains how GetProcAddress uses these arrays to resolve function addresses based on names or ordinals. The content focuses on technical details regarding PE file format analysis.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 19 Exports (1) typedef struct _IMAGE_EXPORT_DIRECTORY { DWORD Characteristics; DWORD TimeDateStamp; WORD MajorVersion; WORD MinorVersion; DWORD Name; DWORD Base; DWORD NumberOfFunctions; DWORD NumberOfNames; DWORD AddressOfFunctions; DWORD AddressOfNames; DWORD AddressOfNameOrdinals; } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY; AddressOfFunctions[NumberOfFunctions] = { RVA[0], RVA[1], RVA[2], RVA[3], RVA[4] }; AddressOfNames[NumberOfNames] = { “AddAtomA”, “AddAtomW”, .... }; AddressOfNameOrdinals[NumberOfNames] = { 0, 1, 2, 6, 9, 10 }; Exports (1) Following the exports is probably the most difficul

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: WinDyb command, DataDirectory field, IMAGE_DATA_DIRECTORY, RVA to virtual address conversion, PE header parsing
Summary: The text describes how to parse the DataDirectory field of the _IMAGE_OPTIONAL_HEADER64 using WinDbg and manual calculation. It specifically focuses on identifying and iterating through IMAGE_DATA_DIRECTORY structures within the PE header.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 23 Imports: kernelbase.dll typedef struct _IMAGE_DATA_DIRECTORY { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY; 0:000> dx -r1 (*((combase!_IMAGE_DATA_DIRECTORY (*)[16])0x7ffb60310178)) [0] [Type: _IMAGE_DATA_DIRECTORY] [1] [Type: _IMAGE_DATA_DIRECTORY] // imports [2] [Type: _IMAGE_DATA_DIRECTORY] [.. SNIP ..] [15] [Type: _IMAGE_DATA_DIRECTORY] 0:000> dx -r1 (*((combase!_IMAGE_DATA_DIRECTORY *)(0x7ffb60310178 + 8))) [+0x000] VirtualAddress : 0x28416c [+0x004] Size : 0x64 Imports: kernelbase.dll The DataDirectory field of the _IMAGE_OPTIONAL_HEADER64 was located at offset

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: IMAGE_IMPORT_DESCRIPTOR, s-style struct definition, Import_Table, Forwarder
Summary: The unit describes the structure of an import table in Windows binaries, specifically focusing on the header and fields like 'IMAGE_IMPORT_DESCRIPTOR' and 'Forwarder'. This information is relevant for understanding how programs interact with other libraries.
Excerpt:
Visual caption: A presentation slide titled 'Imports Structure' showing a C-style struct definition for IMAGE_IMPORT_DESCRIPTOR. Visible text: Imports Structure; IMAGE_IMPORT_DESCRIPTOR; Characteristics; Forwarder; Import_Table Alt/source label:

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Thread Structure, KTHREAD/TEB, system address space, struct _KTHREAD, struct _TEB
Summary: The unit describes the internal structure of Windows kernel threads, specifically focusing on the relationship between KTHREAD and Thread Environment Block (TEB) structures. It identifies specific data structures like _KTHREAD and _TEB.
Excerpt:
Visual caption: A slide titled 'Thread Structure' explaining the relationship between KTHREAD and TEB structures in Windows kernel space. Visible text: Thread Structure; KTHREAD/KTHREAD/TEB; All reside in system address space except the TEB; struct _KTHREAD; struct _TEB; struct _ETH Alt/source label:

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: ETHREAD, KTHREAD, TEB, TIB, PEB, system address space, process address space
Summary: The unit describes the internal structure of ETHREAD, KTHREAD, and TEB structures in Windows. It highlights that while ETHREAD and KTHREAD are in system space, only the TEB is accessible in process space for developers. The text also details the components of the TIB and mentions the importance of the user-mode accessible PEB.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 39 Thread Structure ETHREAD/KTHREAD/TEB ETHREAD/KTHREAD/TEB All reside in system address space except the TEB All reside in system address space except the TEB struct _ETHREAD { _KTHREAD Tcb; // thread control block _LARGE_INTEGER CreateTime; PVOID SartAddress; [... SNIP ...] }; struct _TEB { _NT_TIB NtTib; _CLIENT_ID ClientId; ProcessEnvironmentBlock; // PEB }; struct _NT_TIB { ExceptionList; // EXCEPTION_REGISTRATION_RECORD StackBase; StackLimit; }; Thread Structure The kernel holds the ETHREAD and KTHREAD objects in system space, but not the TEB. The structure of a thread and its environment block are 

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: CreateThread, CreateRemote_thread, HANDLE return type, SEC-701
Summary: The unit describes the technical specifications of the CreateThread and CreateRemoteThread functions in Windows programming. It highlights their usage for creating local or remote threads and notes their return type as a HANDLE.
Excerpt:
Visual caption: A slide from a training course about the CreateThread and CreateRemoteThread functions in Windows programming. Visible text: CreateThread / CreateRemoteThread; Used to create a local/remote thread; Has a HANDLE return type; SEC-701 | Red Team Toolkit: Developing Windows Injection, Command and Control Alt/source label:

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: CreateThread, CreateRemoteThread, Windows API, thread creation, shellcode execution
Summary: The unit describes the CreateThread and CreateRemoteThread Windows APIs for creating local and remote threads respectively. It details the function signatures, argument breakdowns (lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId), and their specific uses in shellcode execution.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 40 CreateThread / CreateRemoteThread CreateThread CreateRemoteThread CreateThread CreateRemoteThread Used to create a local/remote thread Used to create a local/remote thread HANDLE CreateThread( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId ); HANDLE CreateRemoteThread( HANDLE hProcess LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId ); Has a HANDLE return type Has a HANDLE ret

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Thread Hijacking, injector.exe, notepad.exe, handle acquisition, memory allocation, Suspend_thread, context modification
Summary: The unit describes a walk-through of the thread hijacking technique. It outlines specific steps such as obtaining handles, allocating memory, suspending threads, and modifying thread contexts to inject code.
Excerpt:
Visual caption: A slide titled 'Walk-through: Thread Hijacking' illustrating the process of hijacking a thread context in an application. Visible text: Walk-through: Thread Hijacking; injector.exe; notepad.exe; Obtain handle to target; Obtain handle to target's thread; Allocate memory; Suspend_thread; Write DLL path / shellcode to memory; Modify thread's context; Thread #1; Thread #2; Thread n.. Alt/source label:

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: process hollowing, hproc.exe, notepad.exe, evaluation of PE Headers, suspended process
Summary: The unit describes the technical steps involved in process hollowing, specifically involving hproc.exe, notepad.exe, and evil.exe. It details a sequence of starting a suspended process, replacing files, allocating memory, and copying headers and sections.
Excerpt:
Visual caption: A slide from a SANS course explaining the process of process hollowing with a diagram and descriptive text. Visible text: Walk-through: Process Hollowing; hproc.exe; notepad.exe; evil.exe; Create a new, suspended process; Open replacement file; Create some memory; Copy over headers/sections; PE Headers; pBuf; SEC07 | Red Team Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: PE Injection, OpenProcess, VirtualAllocEx, CreateRemoteThread, Optional Header, Size of Image, .reloc section
Summary: The unit describes the technical process of PE injection into a target process's memory space using C/C++ and Windows APIs. It outlines specific steps including obtaining a handle, allocating memory via VirtualAllocEx, copying sections, applying relocations, and executing via CreateRemoteThread.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 71 Walk-through: PE Injection HANDLE hProc MZ......... injector.exe explorer.exe Obtain handle to target Allocate memory Copy over PE header info/sections CreateRemoteThread() Thread #1 MZ........ entry point Thread 2 Thread n.. Walk-through: PE Injection We can try to visualize PE injection just like what we have done with the other injection methods thus far. Again, this method is extremely similar to process hollowing with a few differences. With this method, there is no need to have any shellcoding knowledge or experience since we can do what we need to do purely in C/C++ and the Windows APIs. Also, u

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: thread hijacking, multiple-choice question
Summary: The unit contains a multiple-choice review question regarding the technical requirements for hijacking a thread. It specifically asks which component (state, context, or priority) must be modified during the process.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about thread hijacking. Visible text: Unit Review Questions; When hijacking a thread, what construct must be modified?; Thread state; Thread context; Thread priority Alt/source label:

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Reserved fields, PE format terms, RVA vs VA, sentence structure of definitions
Summary: This unit defines basic terminology related to the Portable Executable (PE) format, including Reserved fields, Relative Virtual Address (RVA), Sections, and Virtual Address (VA). It explains the differences between RVA and VA and describes how sections are structured within a PE file.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 7 Basic Terminology Some basic terminology that will show itself repeatedly Some basic terminology that will show itself repeatedly Reserved Reserved Any fields that are marked “reserved” must be 0 RVA RVA Section Section Relative virtual address: the address of an item subtracted from the image base address A small unit, or chunk, of code/data within the image. There can be several sections. VA VA Virtual address: address of an item within the virtual address space but not subtracted from image base Basic Terminology Whether you are browsing MSDN pages or blog posts related to the PE format, there are se

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: OpenProcessToken, process access token
Summary: The unit describes the OpenProcessToken function in Windows programming. It explains that the function returns a handle to a process's access token and has a Boolean return type.
Excerpt:
Visual caption: A slide from a cybersecurity course explaining the OpenProcessToken function in Windows programming. Visible text: OpenProcessToken; Obtains a handle to a process's access token; Has a Boolean return type; BOOL OpenProcessToken; SEC-70 | Red Team Tooling: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: binary patching, SANS SEC670, learning objectives
Summary: The unit contains a slide outlining the learning objectives for a module on binary patching. It lists goals such as defining binary patching and discussing its benefits.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Objectives' listing the goals for the module on binary patching. Visible text: Objectives; Our objectives for this module are:; Define binary patching; Discuss benefits of binary patching; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 21 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: binary patching, modifying binaries, SEC701, Red Teaming Tools
Summary: The unit describes the concept of binary patching as a technique for modifying binaries to achieve specific goals. It is part of a security course on developing Windows implants and shellcode.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'What Is Binary Patching?' explaining the concept and its risks. Visible text: What Is Binary Patching?; Modifying binaries to achieve results; SEC701 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 22 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: binary patching, memory patching, disk patching, ntdll.dll, system32, av/edr solution
Summary: This unit defines binary patching as the modification of binaries on disk or in memory to change their execution behavior. It discusses the risks and consequences of patching system files like NTDLL, highlighting potential instability and detection. It also mentions that patching AV/EDR solutions can be used for persistence and tool protection.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 22 What Is Binary Patching? Modifying binaries to achieve results Modifying binaries to achieve results What would happen if you patch a system file like NTDLL where it sits in System32? Your hooks would be implemented all over the place and it could draw way too much attention to you. Instead, you could patch a secondary or tertiary DLL that NTDLL loads. What Is Binary Patching? Binary patching is often referred to as modifying a binary as it resides on disk or in memory with the intention of changing how it executes. In memory patching is often done by AV/EDR solutions to change how functions of interes

=== UNIT 23 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: PE parsing, platform-specific checks, architecture check, rebase, apply fixups, binary_execution
Summary: The unit describes the requirements for a custom PE parsing library to be used in an implant. It lists specific technical steps such as checking file format, architecture, and processing headers and sections.
Excerpt:
Visual caption: A presentation slide titled 'Implementation' detailing the requirements for a custom PE parsing library. Visible text: Implementation; Inside own process; file format check; file architecture check; process headers and all sections; Rebase, apply fixups, build import table, execute entry point Alt/source label:

=== UNIT 24 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Windows executable structures, IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint, Unit Review Answers
Summary: The unit contains a multiple-choice question and its corresponding answer regarding Windows executable structures, specifically identifying the field for the program's main function.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the correct answer to a multiple-choice question about Windows executable structures. Visible text: Unit Review Answers; What structure and field member refers to the program's main function?; IMAGE_OPTIONAL_HEADER.ImageBase; IMAGE_FILE_HEADER.PointerToSymbolTable; IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint Alt/source label:

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: WinAPI, __stdcall, multiple-choice question, Unit Review
Summary: The unit contains a slide presenting the correct answer for a multiple-choice question regarding WinAPI function calling conventions. It specifically identifies '__stdcall' as the expansion of the WINAPI type.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the answer to a multiple-choice question about the WINAPI type expansion. Visible text: Unit Review Answers; What does the type WINAPI expand to?; __stdcall; ___thiscall; __cdecl Alt/source label:

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: HKEY, handle type, Windows API, review questions
Summary: The unit contains a review question regarding the commonality between HKEY, HINSTANCE, and HRSRC types in Windows programming. It specifically addresses whether these are handles or GUI-related.
Excerpt:
Unit Review Questions Q: What do the types HKEY, HINSTANCE, HRSRC have in common? A: Nothing. B: They are all of type HANDLE. C: They all refer to GUI applications. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What do the types HKEY, HINSTANCE, HRSRC have in common? What do the types HKEY, HINSTANCE, HRSRC have in common? A Nothing. A Nothing. B They are all of type HANDLE. B They are all of type HANDLE. C They all refer to GUI applications. C They all refer to GUI applications. 104 104 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: HKEY, HHINSTANCE, HRSRC, HANDLE
Summary: The unit contains a multiple-choice question regarding Windows programming data types (HKEY, HINSTANCE, HRSRC). It identifies these types as being of the type HANDLE.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about Windows programming types. Visible text: Unit Review Answers; What do the types HKEY, HINSTANCE, HRSRC have in common?; Nothing.; They are all of type HANDLE.; They all refer to GUI applications. Alt/source label:

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: calling conventions, ECX/RCX, EDX/RDX, multiple-choice
Summary: The unit contains a multiple-choice question regarding the assembly language calling conventions, specifically identifying which convention uses the ECX/RCX and EDX/RDX registers.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about calling conventions. Visible text: Unit Review Questions; What calling convention primarily uses registers ECX/RCX and EDX/RDX?; fastcall; thiscall; stdcall Alt/source label:

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: 64-bit, RSP+20h, shadow stack enforcement, shadow store
Summary: This unit contains a multiple-choice review question regarding the memory layout of 64-bit stack arguments and shadow stack enforcement. It specifically addresses why stack arguments start at RSP+20h.
Excerpt:
Unit Review Questions Q: For 64-bit, why do stack arguments start at RSP+20 and not RSP? A: The first 20h bytes are reserved as a shadow stack enforcement B: The first 20h bytes are reserved as a shadow store C: They don’t, this is a trick question SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions For 64-bit, why do stack arguments start at RSP+20h and not RSP? For 64-bit, why do stack arguments start at RSP+20h and not RSP? A The first 20h bytes are reserved as a shadow stack enforcement A The first 20h bytes are reserved as a shadow stack enforcement B The first 20h bytes are reserved as a shadow store B The first 20h bytes are re

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: 64-bit, RSP+20h, shadow stack, stack arguments
Summary: This unit contains a review question regarding the memory layout of 64-bit stack arguments and why they start at RSP+20h. It provides multiple choice options concerning shadow stack enforcement or storage.
Excerpt:
Unit Review Questions Q: For 64-bit, why do stack arguments start at RSP+20 and not RSP? A: The first 20h bytes are reserved as a shadow stack enforcement B: The first 20h bytes are reserved as a shadow store C: They don’t, this is a trick question SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions For 64-bit, why do stack arguments start at RSP+20h and not RSP? For 64-bit, why do stack arguments start at RSP+20h and not RSP? A The first 20h bytes are reserved as a shadow stack enforcement A The first 20h bytes are reserved as a shadow stack enforcement B The first 20h bytes are reserved as a shadow store B The first 20h bytes are re

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: 64-bit, RSP+20h, shadow stack, stack arguments
Summary: This unit contains a review question regarding the memory layout of 64-bit stack arguments and why they start at RSP+20h. It provides multiple choice options concerning shadow stack enforcement or storage.
Excerpt:
Unit Review Answers Q: For 64-bit, why do stack arguments start at RSP+20 and not RSP? A: The first 20h bytes are reserved as a shadow stack enforcement B: The first 20h bytes are reserved as a shadow store C: They don’t, this is a trick question SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers For 64-bit, why do stack arguments start at RSP+20h and not RSP? For 64-bit, why do stack arguments start at RSP+20h and not RSP? A The first 20h bytes are reserved as a shadow stack enforcement A The first 20h bytes are reserved as a shadow stack enforcement B The first 20h bytes are reserved as a shadow store B The first 20h bytes are reserv

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: 64-bit, RSP+20h, stack arguments, trick question
Summary: The unit contains a slide showing the answer to a multiple-choice question regarding why 64-bit systems have stack arguments starting at RSP+20h. It explains that there are no specific reservations for shadow stacks or stores in this context.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the answer to a multiple-choice question about stack arguments in 64-bit systems. Visible text: Unit Review Answers; For 64-bit, why do stack arguments start at RSP+20h and not RSP?; The first 20h bytes are reserved as a shadow stack enforcement; The first 20h bytes are reserved as a shadow store; They don't; this is a trick question Alt/source label:

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: 64-bit, RSP+20h, shadow stack, stack arguments
Summary: This unit contains a review question regarding the memory layout of 64-bit stack arguments and why they start at RSP+20h. It provides multiple choice options concerning shadow stack enforcement and shadow store.
Excerpt:
Unit Review Answers Q: For 64-bit, why do stack arguments start at RSP+20 and not RSP? A: The first 20h bytes are reserved as a shadow stack enforcement B: The first 20h bytes are reserved as a shadow store C: They don’t, this is a trick question SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers For 64-bit, why do stack arguments start at RSP+20h and not RSP? For 64-bit, why do stack arguments start at RSP+20h and not RSP? A The first 20h bytes are reserved as a shadow stack enforcement A The first 20h bytes are reserved as a shadow stack enforcement B The first 20h bytes are reserved as a shadow store B The first 20h bytes are reserv

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: C++, CreateProcess, Basic Annotations
Summary: The unit contains a screenshot of a C++ function signature for the CreateProcess API. It highlights basic annotations within the code snippet.
Excerpt:
Visual caption: A screenshot of a C++ function signature for CreateProcess, highlighting basic annotations. Visible text: Examples: Basic Annotations; CreateProcess; SECE07 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Intermediate Annotations (2), Out_writes_bytes_all(s), Ret_maybenull_
Summary: The unit contains a technical table describing intermediate annotations for C++ functions. It specifically details the behavior of 'Out_writes_bytes_all(s)' and 'Ret_maybenull_'.
Excerpt:
Visual caption: A screenshot of a table titled 'Intermediate Annotations (2)' showing two entries with technical descriptions. Visible text: Intermediate Annotations (2); _Out_writes_bytes_all(s); All of s's bytes will be written out; _Ret_maybenull_; Function's return value will, could, or won't be a nullptr Alt/source label:

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: InitializeProcThreadAttributeList, Advanced Annotations, _Out__writes_bytes_to_opt_, _When_
Summary: The text describes the `InitializeProcThreadAttributeList` API and explains how to interpret complex function declarations using specific annotations like `_Out_writes_bytes_to_opt_()` and `_When_()`. It details how these parameters behave differently based on whether a pointer is provided or null.
Excerpt:
Example: Advanced Annotations (3) The example here is of the InitializeProcThreadAttributeList API, which is used to initialize a list of attributes to be applied to a thread or a process. The function declaration can seem complex because of the annotations used, but let’s break it down. We already went over the _Success_ annotation, so let’s skip straight to: _Out_writes_bytes_to_opt_() The last annotation to interpret is _When_(<expression>, <anno-list>). Looking at the first _When_(), you can see that when the lpAttributeList has a nullptr passed in, then it will be treated as an _Out_. The second _When_() is indicating that if there is a pointer then it will be _Inout_. In other words, w

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Create APIs, Objects and handles, 96 Windows APIs, CreateProcess exception
Summary: The unit describes Windows API functions starting with 'Create' and highlights CreateProcess as a special case because it returns a BOOL type.
Excerpt:
Visual caption: A presentation slide about Create APIs in Windows, highlighting the special case of CreateProcess. Visible text: Create APIs (1); Objects and handles make the world go around.; There are at least 96 Windows APIs that start with "Create."; CreateProcess is one exception; its return value is of type BOOL. Alt/source label:

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: CreateFile, error handling, A handle to the file, ERROR_INVALID_PARAMETER, INVALID_HANDLE_VALUE
Summary: This unit contains review questions regarding the CreateFile function in Windows programming. It specifically asks about return values when an error occurs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What does CreateFile return upon error? What does CreateFile return upon error? A A handle to the file A A handle to the file B ERROR_INVALID_PARAMETER B ERROR_INVALID_PARAMETER C INVALID_HANDLE_VALUE C INVALID_HANDLE_VALUE 190 Unit Review Questions Q: What does CreateFile return upon error? A: A handle to the file B: ERROR_INVALID_PARAMETER C: INVALID_HANDLE_VALUE 190 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: CreateFile, return value, error handling, Windows programming
Summary: The unit contains a multiple-choice question regarding the Windows API function CreateFile and its specific return value behavior when an error occurs. It identifies potential options for the handle or error codes.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about the return value of CreateFile in Windows programming. Visible text: Unit Review Questions; What does CreateFile return upon error?; A: A handle to the file; B: ERROR_INVALID_PARAMETER; C: INVALID_HANDLE_VALUE Alt/source label:

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: CreateFile, error handling, A handle to the file, ERROR_INVALID_PARAMETER, INVALID_HANDLE_VALUE
Summary: The unit contains review questions regarding the CreateFile function in Windows programming. It specifically asks about return values when an error occurs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What does CreateFile return upon error? What does CreateFile return upon error? A A handle to the file A A handle to the file B ERROR_INVALID_PARAMETER B ERROR_INVALID_PARAMETER C INVALID_HANDLE_VALUE C INVALID_HANDLE_VALUE 190 Unit Review Questions Q: What does CreateFile return upon error? A: A handle to the file B: ERROR_INVALID_PARAMETER C: INVALID_HANDLE_VALUE 190 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam
