# Atlas Material — binary-analysis (part 4)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: binary_exploit
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IMAGE_EXPORT_DIRECTORY, C-style programming, Programming structures
Summary: The unit describes the structure of the IMAGE_EXPORT_DIRECTORY in C-style programming. It specifically lists members like AddressOfFunction, AddressOfName, and AddressOfNameOrdinal.
Excerpt:
Visual caption: A presentation slide titled 'Exports (1)' showing the structure of the IMAGE_EXPORT_DIRECTORY structure in a C-style programming context. Visible text: Exports (1); typedef struct _IMAGE_EXPORT_DIRECTORY; AddressOfFunction[Number_OfFunctions]; AddressOfName[Number_OfNames]; AddressOfNameOrdinal[Number_OfNames]; SECTION 20 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: DLL exports, function names, ordinals, memory addresses, SEC.70
Summary: The unit describes a diagram illustrating the structure of DLL exports, specifically mapping function names and ordinals to memory addresses. It includes technical details such as NumberOfFunctions, AddressOfFunctions, and AddressOfOrdinal.
Excerpt:
Visual caption: A diagram illustrating the structure of exports in a DLL, showing how function names and ordinals are mapped to memory addresses. Visible text: Exports (2); NumberOfFunctions: 10; AddressOfFunctions; NumberOfFunctions: 5; AddressOfNames; AddressOfOrdinal; SEC.70 | Red Team Toolkit: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: kernel32.dll, disassembly, functions, offsets
Summary: The unit contains a visual caption describing a slide showing the disassembly of kernel32.dll, highlighting specific functions and offsets.
Excerpt:
Visual caption: A presentation slide showing the disassembly of a kernel32.dll file, highlighting specific functions and their offsets. Visible text: Exports: kernel32.dll; Number_ofFunctions; Address_ofNumbers; Length_of_Bytes; kernel32.dll Alt/source label:

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IMAGE_IMPORT_DESCRIPTOR, Import Lookup Table (ILT), Import Address Table (IAT), ForwarderChain, IMAGE_THUNK_DATA
Summary: The text describes the structure of the IMAGE_IMPORT_DESCRIPTOR array used to define imported DLLs and their functions in Windows binaries. It details specific fields like OriginalFirstThunk, FirstThunk, and ForwarderChain, explaining how they are used by the loader during execution.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 24 Imports Structure typedef struct _IMAGE_IMPORT_DESCRIPTOR { union { DWORD Characteristics; // 0 here indicates end of array DWORD OriginalFirstThunk; // Import Lookup Table (ILT) } DUMMYUNIONNAME; DWORD TimeDateStamp; // 0 = not bound, -1 = bound DWORD ForwarderChain; // -1 = no forwarders DWORD Name; DWORD FirstThunk; } IMAGE_IMPORT_DESCRIPTOR,*PIMAGE_IMPORT_DESCRIPTOR; Imports Structure The imported libraries (DLLs) and their functions are stored in this array of IMAGE_IMPORT_DESCRIPTORs, which is index 1 of the DataDirectory array. Remember, index 0 is for the exports, which we will cover later. Hig

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IMAGE_IMPORT_DESCRIPTOR, Imports Structure, image.h
Summary: The unit describes the structure of an import table in Windows binaries, specifically focusing on the definition of the IMAGE_IMPORT_DESCRIPTOR struct.
Excerpt:
Visual caption: A presentation slide titled 'Imports Structure' showing a C-style struct definition for IMAGE_IMPORT_DESCRIPTOR. Visible text: Imports Structure; IMAGE_IMPORT_DESCRIPTOR; Characteristics; Forwarder; Import_Table Alt/source label:

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IMAGE_IMPORT_ descriptor, Import Lookup Table (ILT), Import Address Table (IAT), ForwarderChain, IMAGE_THUNK_DATA
Summary: The text describes the structure of IMAGE_IMPORT_DESCRIPTOR and how DLL imports are managed in Windows PE files. It details specific fields like OriginalFirstThunk, FirstThunk, and ForwarderChain, explaining their roles during loading.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 24 Imports Structure typedef struct _IMAGE_IMPORT_DESCRIPTOR { union { DWORD Characteristics; // 0 here indicates end of array DWORD OriginalFirstThunk; // Import Lookup Table (ILT) } DUMMYUNIONNAME; DWORD TimeDateStamp; // 0 = not bound, -1 = bound DWORD ForwarderChain; // -1 = no forwarders DWORD Name; DWORD FirstThunk; } IMAGE_IMPORT_DESCRIPTOR,*PIMAGE_IMPORT_DESCRIPTOR; Imports Structure The imported libraries (DLLs) and their functions are stored in this array of IMAGE_IMPORT_DESCRIPTORs, which is index 1 of the DataDirectory array. Remember, index 0 is for the exports, which we will cover later. Hig

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: kernelbase.dll, proc filesystem, sourcing module names and paths
Summary: The unit describes a technical process for parsing kernel module information from the /proc filesystem using specific DLL imports.
Excerpt:
Visual caption: A screenshot of a technical document or slide explaining how to parse kernel module information from the `/proc` filesystem. Visible text: imports: kernelbase.dll; Evaluation expression; module_name; module_path; label; kernelbase.dll Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: PE structure, Module Summary, developing Windows Implants, manipulating PE structure
Summary: The unit provides a summary of the module covering PE file structures. It highlights that while complex, understanding these components is essential for developing advanced techniques and manipulating the structure to achieve specific goals.
Excerpt:
Visual caption: A slide summarizing the key takeaways from a module on PE file structure. Visible text: Module Summary; Learned the PE structure is complicated at first; Covered that understanding the key components aids in future techniques; Discussed how messing with the PE structure can yield interesting results; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: PE32+, magic value, Unit Review Answers
Summary: The unit contains a review question regarding the magic values for PE32+ binaries. It specifically identifies the correct option among several choices.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the correct answer to a multiple-choice question about PE32+ binary magic values. Visible text: Unit Review Answers; In the optional header, what magic value indicates a PE32+ binary?; 0x20B; 0x10B; 0x00B; SEC601 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: thread definition, thread states, thread context, thread structure, thread creation
Summary: This unit introduces the fundamental concepts of intelligence gathering regarding threads in Windows systems. It covers thread definitions, states, contexts, structures, and the creation of threads for use in injection techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 34 Objectives Our objectives for this module are: Define a thread Understand various thread states Understand thread contexts Explore the structure of a thread Create a thread Objectives The objectives for this module are to define what a thread is. We will explore the various states a thread can be in and what state we need a thread to be in for a certain injection method. Each thread will have its own context that becomes relevant when a thread enters its quantum. We will also look at how a thread is structured in the system and the components of them. Lastly, we will get some hands-on practice with cre

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: thread context, context switch, CR3 register, PML4 table, GetThreadContext, SetThreadContext, shellcode execution
Summary: The text describes the concept of thread context and how it is saved and swapped during context switching. It introduces Windows APIs GetThreadContext and SetThreadContext for manipulating thread contexts to redirect execution to shellcode.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 38 Thread Context Context is unique to each thread Context is unique to each thread Legitimate use Legitimate use Malicious use Malicious use Processor does a context switch to a new thread that is selected to run A thread is suspended, and the context is manipulated to gain shellcode execution Thread Context Before a different thread executes, the current state of the registers must be saved. Each thread has a context that is saved when its quantum is over or is preempted by a thread with a higher priority. These saved context states are swapped in and out each time a thread is entering its quantum. This

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: ETHREAD, KTHREAD, TEB, Process Environment Block (PEB), system address space, dt nt!_ethread
Summary: The unit describes the internal structure of Windows thread objects, specifically comparing ETHREAD, KTHREAD, and TEB structures. It explains that while kernel-level structures reside in system space, only the TEB is accessible within process space for information like exception handling and PEB pointers.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 39 Thread Structure ETHREAD/KTHREAD/TEB ETHREAD/KTHREAD/TEB All reside in system address space except the TEB All reside in system address space except the TEB struct _ETHREAD { _KTHREAD Tcb; // thread control block _LARGE_INTEGER CreateTime; PVOID SartAddress; [... SNIP ...] }; struct _TEB { _NT_TIB NtTib; _CLIENT_ID ClientId; ProcessEnvironmentBlock; // PEB }; struct _NT_TIB { ExceptionList; // EXCEPTION_REGISTRATION_RECORD StackBase; StackLimit; }; Thread Structure The kernel holds the ETHREAD and KTHREAD objects in system space, but not the TEB. The structure of a thread and its environment block are 

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: KTHREAD, TEB, system address space, struct _KTHREAD, struct _TEB
Summary: The unit describes the internal structure of Windows kernel threads, specifically focusing on the relationship between KTHREAD and Thread Environment Block (TEB) structures. It identifies that all components reside in system address space except for the TEB.
Excerpt:
Visual caption: A slide titled 'Thread Structure' explaining the relationship between KTHREAD and TEB structures in Windows kernel space. Visible text: Thread Structure; KTHREAD/KTHREAD/TEB; All reside in system address space except the TEB; struct _KTHREAD; struct _TEB; struct _ETH Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: ETHREAD/KTHREAD/TEB, system address space, Thread Environment Block, key fields in TEB, dt nt!_ethread, dt nt!_teb
Summary: The unit describes the internal structure of Windows thread objects, specifically focusing on ETHREAD, KTHREAD, and TEB structures. It explains that while ETHREAD and KTHREAD are in system space, only the TEB resides in user-accessible process space. The text also highlights the importance of the other fields within the TEB, such as the TIB for exception handling and the pointer to the Process Environment Block (PEB).
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 39 Thread Structure ETHREAD/KTHREAD/TEB ETHREAD/KTHREAD/TEB All reside in system address space except the TEB All reside in system address space except the TEB struct _ETHREAD { _KTHREAD Tcb; // thread control block _LARGE_INTEGER CreateTime; PVOID SartAddress; [... SNIP ...] }; struct _TEB { _NT_TIB NtTib; _CLIENT_ID ClientId; ProcessEnvironmentBlock; // PEB }; struct _NT_TIB { ExceptionList; // EXCEPTION_REGISTRATION_RECORD StackBase; StackLimit; }; Thread Structure The kernel holds the ETHREAD and KTHREAD objects in system space, but not the TEB. The structure of a thread and its environment block are 

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateThread, CreateRemoteThread, HANDLE return type, SEC-701
Summary: The unit describes the technical specifications of the CreateThread and CreateRemoteThread functions in Windows programming. It highlights their usage for creating local or remote threads and notes their return type as a HANDLE.
Excerpt:
Visual caption: A slide from a training course about the CreateThread and CreateRemoteThread functions in Windows programming. Visible text: CreateThread / CreateRemoteThread; Used to create a local/remote thread; Has a HANDLE return type; SEC-701 | Red Team Toolkit: Developing Windows Injection, Command and Control Alt/source label:

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Creating Threads, behind the scenes, schedules, CreateRemoteThread, PspCreateThread
Summary: The unit describes the internal Windows OS processes involved in creating threads. It details technical steps like parameter conversion, attribute list population, and the transition from CreateRemoteThread to PspCreateThread.
Excerpt:
Visual caption: A slide from a training course about the internal processes of creating threads in Windows. Visible text: Creating Threads; What happens behind the scenes?; Parameters converted to flags; Client ID and TEB address added to an attribute list; Determine if the thread should be created in local or remote process; Call CreateRemoteThread, initialize new thread object, then call PspCreateThread; Thread is initially suspended and then later resumed to it can be scheduled; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: QueueUserApc, APC_FUNC, handle, DWORD, user thread
Summary: The unit describes the technical details of the QueueUserApc function in a Windows environment. It specifically covers its parameters, return value type, and its use for queuing an APC to a user thread.
Excerpt:
Visual caption: A slide from a cybersecurity course explaining the 'QueueUserApc' function used for queuing an APC to a user thread. Visible text: Queueing an APC; QueueUserApc; Return value is DWORD; Used to queue an APC to user thread; DWORD QueueUserApc(APC_FUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData); SEC.70 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Thread Hijacking, taking over a process' thread, SEC601
Summary: The unit describes the concept of thread hijacking as a technique for taking over a process's thread. It is part of a cybersecurity course on red teaming tools and developing Windows implants.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Thread Hijacking' explaining the concept of taking over a process's thread. Visible text: Thread Hijacking; Taking over a process' thread; SEC601 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetThreadContext, CONTEXT structure, instruction pointer modification, shellcode redirection
Summary: The unit describes the GetThreadContext API function and its associated CONTEXT structure for 64-bit systems. It explains how debuggers use these structures to track thread states and details how an attacker can modify the instruction pointer within this context to redirect execution to shellcode.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 63 Obtaining Context GetThreadContext GetThreadContext Return value is BOOL Return value is BOOL BOOL GetThreadContext( HANDLE hThread, LPCONTEXT lpContext ); typedef struct _CONTEXT { [..SNIP..] DWORD64 Rip; }; Used to obtain a thread’s context Used to obtain a thread’s context Obtaining Context Each thread will have a context structure that is unique to each thread. The context struct is fairly large and it must be so that the system can keep track of the context each time a different thread enters its quantum. A prime example for obtaining a thread’s context is a debugger. When a thread is being debugg

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetThreadContext, CONTEXT structure, instruction pointer modification, shellcode redirection
Summary: The unit describes the GetThreadContext API function and its associated CONTEXT structure for 64-bit systems. It explains how debuggers use these structures to track thread states and details how modifying the instruction pointer within this structure allows redirecting execution to shellcode.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 63 Obtaining Context GetThreadContext GetThreadContext Return value is BOOL Return value is BOOL BOOL GetThreadContext( HANDLE hThread, LPCONTEXT lpContext ); typedef struct _CONTEXT { [..SNIP..] DWORD64 Rip; }; Used to obtain a thread’s context Used to obtain a thread’s context Obtaining Context Each thread will have a context structure that is unique to each thread. The context struct is fairly large and it must be so that the system can keep track of the context each time a different thread enters its quantum. A prime example for obtaining a thread’s context is a debugger. When a thread is being debugg

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Thread Hijacking, injector.exe, notepad.exe, Suspend_thread, Modify thread's context
Summary: The unit describes a technical walk-through of the thread hijacking technique. It outlines specific steps such as obtaining handles, allocating memory, and modifying thread contexts to inject code.
Excerpt:
Visual caption: A slide titled 'Walk-through: Thread Hijacking' illustrating the process of hijacking a thread context in an application. Visible text: Walk-through: Thread Hijacking; injector.exe; notepad.exe; Obtain handle to target; Obtain handle to target's thread; Allocate memory; Suspend_thread; Write DLL path / shellcode to memory; Modify thread's context; Thread #1; Thread #2; Thread n.. Alt/source label:

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: thread context, hijacking, Windows Implants, SEC670
Summary: The unit describes the purpose of a lab exercise focused on hijacking a thread's context. It is part of a larger course on developing Windows implants, shellcode, and command and control.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 67 What’s the Point? What’s the point? What’s the Point? The point of this lab was to explore the process of hijacking a thread’s context. © 2024 Jonathan Reiter 67 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: process hollowing, hproc.exe, notepad.exe, summary of steps
Summary: The unit describes the process of process hollowing using a diagram and descriptive text. It details specific steps such as creating a suspended process, opening a replacement file, and copying headers and sections into memory.
Excerpt:
Visual caption: A slide from a SANS course explaining the process of process hollowing with a diagram and descriptive text. Visible text: Walk-through: Process Hollowing; hproc.exe; notepad.exe; evil.exe; Create a new, suspended process; Open replacement file; Create some memory; Copy over headers/sections; PE Headers; pBuf; SEC07 | Red Team Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: PE Injection, process hollowing comparison, CreateToolhelp32Snapshot, OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, AdjustTokenPrivileges
Summary: This unit describes the PE Injection technique where a second PE image is added into an existing process's memory space without hollowing out the original. It details the specific Windows APIs used for this method, including memory allocation and remote thread creation. The text also mentions the requirements for privilege escalation to enable debug privileges.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 70 PE Injection A PE injected inside another PE Instead of replacing the PE image of the target process, or hollowing it out, this method simply adds an additional PE image inside. The target process will literally be holding two PE images. PE Injection PE injection can sometimes be confused with the process hollowing method because we are injecting a PE file in another process just like with process hollowing. However, this method does not “hollow” out the image from the target process. So, instead of the “hollowing”, we are adding another PE image in the target process. The main idea here is that a hand

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: PE Injection, OpenProcess, VirtualAllocEx, CreateRemoteThread, Optional Header, .reloc section
Summary: The unit describes the process of PE injection into a target process's memory space using C/C++ and Windows APIs. It outlines specific steps including obtaining a handle, allocating memory via VirtualAllocEx, copying sections, applying relocations, and executing via CreateRemoteThread.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 71 Walk-through: PE Injection HANDLE hProc MZ......... injector.exe explorer.exe Obtain handle to target Allocate memory Copy over PE header info/sections CreateRemoteThread() Thread #1 MZ........ entry point Thread 2 Thread n.. Walk-through: PE Injection We can try to visualize PE injection just like what we have done with the other injection methods thus far. Again, this method is extremely similar to process hollowing with a few differences. With this method, there is no need to have any shellcoding knowledge or experience since we can do what we need to do purely in C/C++ and the Windows APIs. Also, u

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SetWindowsHookExA, hook procedure, hook chain, HOOK return type
Summary: The unit describes the technical details of the system function SetWindowsHookExA used in Windows programming. It specifically mentions adding hook procedures to a chain and its return type.
Excerpt:
Visual caption: A slide from a technical presentation about the SetWindowsHookExA function in Windows programming. Visible text: SetWindowsHookExA; Add a hook procedure to hook chain; Has a HOOK return type; SEC07 | Red Team Toolkit: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: DLL injection, GUI applications, CreateRemoteQueryThread, CreateRemoteThread(), WriteProcessMemory(), SetWindowsHook_Ex
Summary: The unit contains a review section for the SEC670 course, specifically focusing on API calls used for DLL injection into GUI applications. It lists multiple variations of questions and answers regarding CreateRemoteThread(), WriteProcessMemory(), and SetWindowsHookEx().
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 75 Unit Review Questions What API allows you to inject a DLL into GUI applications? What API allows you to inject a DLL into GUI applications? A CreateRemoteThread() A CreateRemoteThread() B WriteProcessMemory() B WriteProcessMemory() C SetWindowsHookEx() C SetWindowsHookEx() Unit Review Questions Q: What API allows you to inject a DLL into GUI applications? A: CreateRemoteThread() B: WriteProcessMemory() C: SetWindowsHookEx() © 2024 Jonathan Reiter 75 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateRemoteThread(), WriteProcessMemory(), SetWindowsHook_Ex(), DLL injection, GUI applications
Summary: The unit contains a review section for the SEC670 course, specifically focusing on questions regarding Windows API functions used for DLL injection into GUI applications. It lists three specific APIs: CreateRemoteThread(), WriteProcessMemory(), and SetWindowsHookEx().
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 76 Unit Review Answers What API allows you to inject a DLL into GUI applications? What API allows you to inject a DLL into GUI applications? A CreateRemoteThread() A CreateRemoteThread() B WriteProcessMemory() B WriteProcessMemory() C SetWindowsHookEx() C SetWindowsHookEx() Unit Review Answers Q: What API allows you to inject a DLL into GUI applications? A: CreateRemoteThread() B: WriteProcessMemory() C: SetWindowsHookEx() 76 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: thread hijacking, multiple-choice question, review questions
Summary: The unit contains a multiple-choice review question regarding the technical requirements for hijacking a thread. It specifically asks which component (state, context, or priority) must be modified during the thread hijacking process.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about thread hijacking. Visible text: Unit Review Questions; When hijacking a thread, what construct must be modified?; Thread state; Thread context; Thread priority Alt/source label:

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: PE Format, APCInjection, ThreadHijacker, TokenThief, UACBypass
Summary: The text lists a course roadmap and specific lab exercises related to Windows implant development, shellcode, and command and control. It covers topics such as PE format, thread injection techniques (APC, ThreadHijacker), and privilege escalation methods like TokenThief.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 81 Course Roadmap PE Format Lab 3.1: GetFunctionAddress Threads Injections Lab 3.2: ClassicDLLInjection Lab 3.3: APCInjection Lab 3.4: ThreadHijacker Escalations Lab 3.5: TokenThief Bootcamp Lab 3.6: So, You Think You Can Type Lab 3.7: UACBypass-Research Lab 3.8: ShadowCraft S e c t i o n 3 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge In this module, we will discuss and implement various ways to escalate your local privileges. © 2024 Jonathan Reiter 81 © SANS I

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: OpenProcessToken, process access token, s-70 red team tooling
Summary: The unit describes the OpenProcessToken function in Windows programming. It explains that the function returns a handle to a process's access token and has a boolean return type.
Excerpt:
Visual caption: A slide from a cybersecurity course explaining the OpenProcessToken function in Windows programming. Visible text: OpenProcessToken; Obtains a handle to a process's access token; Has a Boolean return type; BOOL OpenProcessToken; SEC-70 | Red Team Tooling: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: QueryServiceStatusEx, SC_HANDLE, SC_STATUS_TYPE, lpBuffer, cbBufSize, pcbBytesNeeded
Summary: This unit describes the QueryServiceStatusEx API function for retrieving detailed information about Windows services. It details the five parameters of the function, including handle types and buffer sizes. The text provides technical specifications for each parameter.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 108 QueryServiceStatusEx QueryServiceStatus QueryServiceStatus Obtains the status of a service Obtains the status of a service BOOL QueryServiceStatusEx( _In_ SC_HANDLE hService, _In_ SC_STATUS_TYPE InfoLevel, _Out_opt_ LPBYTE lpBuffer, _In_ DWORD cbBufSize, _Out_ LPDWORD pcbBytesNeeded ); Has a Boolean return type Has a Boolean return type QueryServiceStatusEx After you have obtained a list of the services installed on your target, you would most likely want to query them for more detailed information. To do that, you would call the QueryServiceStatusEx API. Let us take a look at the five parameters. hSe

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: QueryServiceConfig, API function signature, SC_HANDLE, QUERY_SERVICE_CONFIG
Summary: The unit describes the QueryServiceConfig API function signature for retrieving service configurations. It details specific parameters like handle, configuration pointer, and buffer size.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'QueryServiceConfig' detailing the API function signature and its parameters. Visible text: QueryServiceConfig; Obtains configuration of a service; Has a Boolean return type; BOOL QueryServiceConfiga(; SC_HANDLE hService; QUERY_SERVICE_CONFIG pServiceConfig; cBufferSize; pBytesNeeded; SEC-703 | Red Team Toolkit: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: ChangeServiceConfig, service configuration, s407, red team toolkit
Summary: The unit describes the 'ChangeServiceConfig' function used for modifying service configurations in a Windows environment. It references the SANS SEC407 course material regarding red team tool development.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'ChangeServiceConfig' detailing the function signature and usage notes for modifying service configurations. Visible text: ChangeServiceConfig; Modifies a service's configuration; Has a Boolean return type; SEC407 | Red Team Toolkit: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows service creation, C code snippet, EvilMain, SEC70
Summary: The unit contains a slide from a technical presentation regarding the creation of Windows services. It includes a C code snippet for a service's main function named 'EvilMain'.
Excerpt:
Visual caption: A slide from a technical presentation about Windows service creation, showing a C code snippet and descriptive text. Visible text: Services: Creation (2); Small code snippet for a service's main function; VOID WINAPI EvilMain(...); SEC70 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control; 112 Alt/source label:

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateService, SC_HANDLE, CreateServiceA, SEC701
Summary: The unit describes the technical details of the Windows CreateService API function. It specifically mentions the CreateServiceA variant and related handles.
Excerpt:
Visual caption: A slide from a technical training course about the CreateService API function in Windows. Visible text: CreateService; SC_HANDLE; CreateServiceA; SEC701 | Red Team Training: Defending Windows, Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName
Summary: The text describes various parameters for a service configuration, including executable paths, load order groups, and account credentials.
Excerpt:
lpBinaryPathName must be the full path where the executable is located. Command-line arguments can also be passed in here after the executable’s name. lpLoadOrderGroup is optional, so NULL is just fine here. lpdwTagId is only for kernel drivers and as this is not a kernel class, we do not need to worry about this one. lpDependencies is an optional list of strings naming other services that this service depends on for successful initialization. lpServiceStartName is the account that this service should execute under. lpPassword would be for the password to the given user account. © 2024 Jonathan Reiter 117 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateNamedPipe, named pipes, HANDLE return type
Summary: The unit describes the technical process of creating named pipes in Windows programming. It specifically mentions the CreateNamedPipe function and its return type.
Excerpt:
Visual caption: A slide from a training course about creating named pipes in Windows programming. Visible text: Creating Named Pipes; CreateNamedPipe; Used to create named pipes; Has a HANDLE return type; SEC601 Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: UACMe Project, FusionScanDirectory, RtlSecureZeroMemory, FindFirstFile, FindNextFile
Summary: The unit describes the FusionScanDirectory function within the UACMe project. It details specific API calls like RtlSecureZeroMemory, FindFirstFile, and FindNextFile used for scanning the current directory.
Excerpt:
Visual caption: A slide from a presentation or document describing the FusionScanDirectory function in the UACMe project. Visible text: UACMe Project: FusionScanDirectory; Responsible for scanning current directory; RtlSecureZeroMemory; FindFirstFile; FindNextFile; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: binary patching, modifying binaries, security course
Summary: The unit describes the concept of binary patching as a method for modifying binaries to achieve specific goals. It is part of a security course on developing custom tools for Windows.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'What Is Binary Patching?' explaining the concept and its risks. Visible text: What Is Binary Patching?; Modifying binaries to achieve results; SEC701 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:
