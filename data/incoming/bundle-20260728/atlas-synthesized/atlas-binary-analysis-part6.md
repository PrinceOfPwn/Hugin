# Atlas Material — binary-analysis (part 6)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: binary_exploit
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Data Types, compiler size determination, BOOL, INT, DWORD, VOID, PVOID, LPVOID, HINSTANCE, HANDLE
Summary: The unit provides an overview of Windows data types and their purpose in programming. It lists specific common types like BOOL, INT, DWORD, VOID, and HANDLE.
Excerpt:
Visual caption: A slide titled 'Windows Data Types' provides an overview of Windows data types and their purpose. Visible text: Windows Data Types; Taking an in-depth look behind the Windows data types; Windows data types are used to keep compilers from determining what they think the size of an int should be sized as.; Data type name are descriptive once you understand them.; BOOL, INT, DWORD, VOID, PVOID, LPVOID, HINSTANCE, HANDLE Alt/source label:

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: BOOL, BOOLEAN, WinDef.h, WinNT.h, typedef int BOOL, typedef BYTE BOOLEAN
Summary: The unit describes the technical differences between the BOOL and BOOLEAN data types in Windows programming, specifically within headers like WinDef.h and WinNT.h. It highlights that while both can represent true/false values, they are internally different types (int vs. BYTE).
Excerpt:
Visual caption: A presentation slide comparing the internal differences between BOOL and BOOLEAN data types in Windows programming. Visible text: BOOL/BOOLEAN; BOOL and BOOLEAN appear the same, but are quite different internally; Either on or off; Functions can return TRUE/FALSE; Variable can hold TRUE/FALSE values; WinDef.h; WinNT.h; typedef int BOOL;; typedef BYTE BOOLEAN;; BOOL IsRunning = TRUE;; BOOLEAN IsElevated = TRUE; Alt/source label:

=== UNIT 3 ===
Source: MalDevAcademy - Malware Development Course - shared by Tamarisk OffsecExam.html
Value: 0.85  Key cues: OllyDbg, memory map, assembly code, dump windows
Summary: The unit contains a screenshot of the OllyDbg debugger displaying memory maps and assembly code. It includes various debugger interface elements such as stack maps, dump windows, and watch expressions.
Excerpt:
Visual caption: A screenshot of the OllyDbg debugger showing a memory map and assembly code. Visible text: OllyDbg; CPU; Log; Notes; Stack_map; Memory Map; label; Dump 1; Dump 2; Dump 3; Dump 4; Dump 5; Watch 1; Code; Stack Alt/source label: image

=== UNIT 4 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: HKEY, HINSTANCE, HRSRC, HANDLE
Summary: The unit contains a multiple-choice question regarding the shared characteristics of HKEY, HINSTANCE, and HRSRC data types. It identifies these as being of the type HANDLE.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about commonalities between HKEY, HINSTANCE, and HRSRC types. Visible text: Unit Review Questions; What do the types HKEY, HINSTANCE, HRSRC have in common?; Nothing.; They are all of type HANDLE.; They all refer to GUI applications. Alt/source label:

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: HKEY, HINSTANCE, HRSRC, HANDLE type
Summary: The unit contains a review question regarding the commonality between HKEY, HINSTANCE, and HRSRC types in Windows programming.
Excerpt:
Unit Review Answers Q: What do the types HKEY, HINSTANCE, HRSRC have in common? A: Nothing. B: They are all of type HANDLE. C: They all refer to GUI applications. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What do the types HKEY, HINSTANCE, HRSRC have in common? What do the types HKEY, HINSTANCE, HRSRC have in common? A Nothing. A Nothing. B They are all of type HANDLE. B They are all of type HANDLE. C They all refer to GUI applications. C They all refer to GUI applications. 105 105 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: DWORD, ULONG, unsigned long, multiple-choice
Summary: The unit contains a multiple-choice review question regarding the data types in C programming, specifically identifying the correct root type for a DWORD variable.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about the root type for DWORD. Visible text: Unit Review Questions; What is the root type for DWORD?; ULONG or unsigned long.; VOID or void.; WORD or double word. Alt/source label:

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: DWORD, root type, Unit Review Answers
Summary: The unit contains a review question regarding the data types in C programming, specifically identifying the correct root type for the DWORD data type.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about the root type for DWORD. Visible text: Unit Review Answers; What is the root type for DWORD?; ULONG or unsigned long.; VOID or void.; WORD or double word. Alt/source label:

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: x64 calling convention, CreateFileW assembly example, register-based argument passing, stack placement of arguments
Summary: The text provides an example of how the CreateFileW function is called in x64 assembly, illustrating the placement of arguments in registers and on the stack. It details specific register assignments (RCX, RDX, R8, R9) and corresponding memory locations for additional parameters.
Excerpt:
Example: (x64) When we look at this example compiled for x64, the arguments look a bit different and out of order than what you might think. There is no order in terms of how it looks in assembly—all that matters is that the registers are loaded with the proper values. Since there are seven arguments total, the first four will be in registers, and the remainder will be placed on the stack. Here is one way this can be visualized. Placing the registers above the arguments can help understand where things will fall into place when the call is ready to be made. RCX RDX R8 R9 stack stack stack CreateFileW( L”hello.txt”, GENERIC_WRITE, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL ); mov qwo

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: x64 calling convention, CreateFileW, assembly code, assembly instructions
Summary: The unit contains a screenshot of assembly code illustrating the x64 calling convention for the CreateFileW function. It demonstrates how parameters are passed to the system call.
Excerpt:
Visual caption: A screenshot of assembly code demonstrating the x64 calling convention for a CreateFileW function call. Visible text: Example: (x64); CreateFileW("h1ello.txt", GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);; mov qword ptr ss:[rsp+32], 0; lea rcx, qword ptr ds:[...]; xor rdx, rdx; xor r8, r8; mov qword ptr ss:[rsp+28], 1; mov r9, 40000000; call qword ptr ds:[CreateFileW] Alt/source label:

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: __fastcall, ECX/EDX registers, function name mangling, 32-bit calling conventions
Summary: The unit describes the __fastcall calling convention in 32-bit Windows environments, specifically identifying indicators like ECX and EDX register usage and naming conventions (e.g., @SomeFastFunction@12). It provides a code example demonstrating how arguments are passed to functions using this convention.
Excerpt:
Example: __fastcall There are several items on the slide that indicate that __fastcall calling convention is being used. Aside from the obvious being the function declaration, the first indicator is the use of the ECX and EDX registers. As mentioned on the previous slide, the ECX and EDX registers are heavily used for this calling convention. The second indicator is the name of the function itself as it has some strange additions to it, like the “@” before and after the function name. The “@” before the function name indicates __fastcall and the “@” followed by a number indicates the size of bytes in arguments. With these being 32-bit values, 12 means there are three arguments to SomeFastFun

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: __thiscall, x86 C++, ECX register, class member functions, memory layout
Summary: The unit describes the __thiscall calling convention used in x86 C++ class member functions on Windows systems. It explains that arguments are pushed onto the stack from right to left, while the ECX register is primarily used to hold the 'this' pointer.
Excerpt:
__thiscall Another calling convention that is specific to Microsoft and built for x86 C++ class member functions is thiscall. Just like cdecl and stdcall, all arguments are pushed on the stack in a right to left manner. The new item here is that the compiler will sneak in a pointer. This pointer points to a table that is indexed appropriately for the member function being called. The pointer is called this pointer and ECX is primarily used to hold it. A quick refresher on class member functions is on the following slide. The class, MyClass, is defined as a class that will have one function available for public use; PrintMsg. The method is not defined inside the class but instead is done outs

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: __thiscall, x86 C++, Windows-specific, this pointer, stack-based arguments
Summary: The unit describes the __thiscall calling convention used in x86 C++ for Windows. It explains that the compiler creates a 'this' pointer and that all arguments are passed via the stack.
Excerpt:
Visual caption: A slide explaining the __thiscall calling convention for x86 C++. Visible text: __thiscall; This is yet another Windows-specific calling convention for x86 C++.; Compiler creates a this pointer; Primary holder of this pointer; For C++ class members; All arguments are on the stack; Arguments pushed right to left Alt/source label:

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: x86, arguments passed to functions, RCX, RDX, R8, R9
Summary: The unit contains a multiple-choice review question regarding the mechanism of argument passing in x86 architecture functions.
Excerpt:
Unit Review Questions Q: For x86, how are arguments passed to functions? A: In registers RCX, RDX, R8, R9 B: On the stack C: In the heap SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions For x86, how are arguments passed to functions? For x86, how are arguments passed to functions? A In registers RCX, RDX, R8, R9 A In registers RCX, RDX, R8, R9 B On the stack B On the stack C In the heap C In the heap 123 123 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: x86, arguments passed to functions, RCX, RDX, R8, R9
Summary: This unit contains a review question regarding the mechanism of argument passing in x86 architecture functions. It specifically lists options for registers, stack, and heap.
Excerpt:
Unit Review Answers Q: For x86, how are arguments passed to functions? A: In registers RCX, RDX, R8, R9 B: On the stack C: In the heap SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers For x86, how are arguments passed to functions? For x86, how are arguments passed to functions? A In registers RCX, RDX, R8, R9 A In registers RCX, RDX, R8, R9 B On the stack B On the stack C In the heap C In the heap 124 124 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: calling convention, __fastcall, __thiscall, __stdcall
Summary: The unit contains a review question regarding the different calling conventions used in Windows programming, specifically identifying which one uses ECX/RCX and EDX/RDX registers.
Excerpt:
Unit Review Questions Q: What calling convention primarily uses registers ECX/RCX and EDX/RDX? A: __fastcall B: __thiscall C: __stdcall SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What calling convention primarily uses registers ECX/RCX and EDX/RDX? What calling convention primarily uses registers ECX/RCX and EDX/RDX? A __fastcall A __fastcall B __thiscall B __thiscall C __stdcall C __stdcall 125 125 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Create* API family, system space vs user space handles, CreateFile, CreateEvent, CreateThread, CreateToolhelp32Snapshot
Summary: This unit introduces the Create* family of Windows APIs, specifically highlighting their role in creating objects in system space and providing handles for user-space interaction. It lists several common functions like CreateFile, CreateEvent, and CreateThread to be used throughout the course.
Excerpt:
Create APIs (2) The functions listed on the slide are just a very small subset of the Create* family of functions. As mentioned previously, there are almost 100 Create* functions to use. For most of them, it is easy to understand what their intended purpose is due to their descriptive names, like CreateFile. You can expect a handle to the newly created object to be returned for most of these, and it is this handle that allows you to interact with the object in system space. All objects are created in system space and user space is given handles to them. You will be using many of these throughout the remainder of the course. On your own time, you can read about them in great detail on MSDN be

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: CreateProcess, STARTUPINFO, PROCESS_INFORMATION, notepad process
Summary: The text provides a basic example of using the CreateProcess function to launch a notepad process. It describes the necessary structure types, STARTUPINFO and PROCESS_INFORMATION, and explains how variables are passed as arguments to the function.
Excerpt:
Example: CreateProcess For this example of how to use CreateProcess, we are simply creating the notepad process with bare minimum effort, meaning, we are not taking full advantage of what the CreateProcess function has to offer. The previous slide went over the parameters so there is no need to go over them again here, rather the relevant ones will be discussed. First up, there is some standard housekeeping that must be done by the way of creating some variables with specific structure types: STARTUPINFO and PROCESS_INFORMATION. Each of those structures will have information filled out after CreateProcess returns. There is the commandLine variable that is simply holding the name of the proce

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Windows Handles, Handle Table, x86 vs x64 entry sizes, Audit on close flag, Protect from close flag, NtSetInformationObject
Summary: The text describes the structure and management of Windows handles, specifically focusing on the handle table architecture. It details how processes manage large numbers of handles using multiple tables and explains the size and composition of difference entries for x86 and x64 architectures.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Handles (3) Process Handle Table Lowest level table Handle Table Entry L I A Pointer to object header P Access Mask Audit on close Inheritable Lock Protect from close 32-bits 173 Windows Handles (3) Somewhere in the process’ virtual address space will be a pointer to its handle table. Just like how there are multiple tables involved with the translation of virtual addresses to physical addresses, there are multiple tables for handles. This is how a process can have a large number of handles, upwards of 16,000,000. Not all of the three tables are shown on this slide due to space limitations, but th

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Windows Handles, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE, pseudo-handle
Summary: The text describes Windows handles and their associated access rights for processes and threads, specifically highlighting PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, and PROCESS_DUP_HANDLE. It explains the concept of pseudo-handles (e.g., GetCurrentProcess) and how certain flags are like PROCESS_DUP_HANDLE for duplicating handles into child processes.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Handles (4) Access rights for processes and threads Access rights for processes and threads Description Access Flag (Constant) Give all access rights that are possible for a process object PROCESS_ALL_ACCESS Give all access rights that are possible for a thread object THREAD_ALL_ACCESS Gives permissions to create a process PROCESS_CREATE_PROCESS Gives permissions to create a thread PROCESS_CREATE_THREAD Gives permissions to duplicate a handle PROCESS_DUP_HANDLE 174 Windows Handles (4) Handles can have various permissions and some of them can be great for abuse when the right conditions are set. Th

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: GetLastError, Win32 API, error code, CreateProcess, SetLastError
Summary: This unit describes the GetLastError API function in Windows, explaining its purpose and usage for identifying specific error codes from failed Win32 API calls. It highlights that GetLastError must be called immediately after a target function to ensure accuracy. The text also mentions how errors are set during execution of Windows API functions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Handling Errors (2) GetLastError GetLastError Gets the last error for calling thread Gets the last error for calling thread // defined in errhandlingapi.h WINBASEAPI _Check_return_ _Post_equals_last_error_ DWORD WINAPI GetLastError( ..... ); 177 Handling Errors (2) The GetLastError API function does not take a single parameter, as you can see with VOID being specified inside the parentheses. Typically, the best and perhaps only times to call this function are when using functions that have a BOOL return type like CreateProcess. If you are checking to see if a Boolean function failed or succeeded based sol

=== UNIT 21 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: LSTATUS, RegOpenKeyExW, winreg.h, ERROR_SUCCESS, GetLastError()
Summary: The unit describes how to handle LSTATUS return types when using the Reg* family of APIs in Windows development. It explains that LSTATUS is a typedef for LONG and provides guidance on checking against ERROR_SUCCESS. It also suggests logging errors to a file rather than displaying them directly to the terminal.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Handling Errors (5) Checking LSTATUS return types Checking LSTATUS return types // definition from winreg.h typedef _Return_type_success(return==ERROR_SUCCESS) LONG LSTATUS // definition from winerror.h #define ERROR_SUCCESS 0L LSTATUS lStatus = RegOpenKeyExW(...); if (lStatus != ERROR_SUCCESS ) // handle error here 181 Handling Errors (5) Most of the Reg* family of APIs are defined with LSTATUS return types, so it is important to know how to check them for errors and success. The winreg.h header file defines most of the Reg* APIs but also has a definition for LSTATUS. Here, you will find that it is simpl

=== UNIT 22 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: WinDbg, Kernel and User mode structures, user mode process
Summary: The unit introduces Lab 1.9, which focuses on familiarizing users with the WinDbg debugger interface and exploring kernel and user mode structures. It also includes instructions to break into a user-mode process.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 1.9: It’s Me, WinDbg Become familiar with the WinDbg interface. Explore several Kernel and User mode structures. Break into a user mode process. 201 Lab 1.9: It’s Me, WinDbg Please refer to the eWorkbook for the details of this bootcamp challenge. 201 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 23 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, DLL structure, presentation slide, stub, PE header, COFF, optional header
Summary: The unit describes the internal structure of Dynamic-linked Libraries (DLLs), specifically focusing on content like stubs, PE headers, and sections. It outlines components such as COFF, optional headers, and image-specific file headers.
Excerpt:
Visual caption: A presentation slide titled 'Dynamic-linked Libraries (2)' explaining the internal structure of a DLL file. Visible text: Dynamic-linked Libraries (2); What is inside of a DLL?; stub; DOS stub; useless today; PE; PE0; COFF; Common object file format; optional; Image-specific file headers; section; Information about the sections; sections; Actual code, data, resources Alt/source label:

=== UNIT 24 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Relative Virtual Address, RVA, Virtual Address, calculation formula, dynamic-linked libraries
Summary: The unit describes the calculation of Relative Virtual Addresses (RVA) and Virtual Addresses for dynamic-linked libraries. It includes formulas for calculating both RVA and Virtual Address based on the assumption that a library's base address is known.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the calculation of Relative Virtual Addresses (RVA) and Virtual Addresses for dynamic-linked libraries. Visible text: Dynamic-linked Libraries (6); 10 number of Directories; Virtual Address = Base Address + RVA; RVA = Virtual Address - Base Address; SEC402: Red Teaming Tools. Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 25 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, Relative Virtual Addresses (RVA), export directory, base relocation directory, virtual address calculation
Summary: This unit explains the structure of Dynamic-linked Libraries (DLLs) in Windows, specifically focusing on Relative Virtual Addresses (RVAs) and their relationship to virtual addresses. It details the directory structure within a DLL's optional header, including export, import, and base relocation directories.
Excerpt:
Dynamic-linked Libraries (6) The last portion of the optional header is the number of directories. This is going to be important to understand as the course progresses because tools will be developed to parse through this section and modifications will be made here. Before we begin, let us first understand RVAs. RVAs are relative virtual addresses from the beginning of the file. In other words, they are simply offsets from the beginning of the file. Since DLLs can be loaded at any random address, by design, it is much easier to deal with offsets. Once a DLL is loaded, the virtual address in memory can be calculated with some simple math. Take the base address of the DLL and add the RVA to it

=== UNIT 26 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, preferred base address, relocation, RVAs, ASLR
Summary: This unit discusses the mechanics of Dynamic-linked Libraries (DLLs) and how they are loaded into memory by the loader. It covers preferred base addresses, relocation processes when address space is occupied, and the impact of Address Space Layout Randomization (ASLR).
Excerpt:
Dynamic-linked Libraries (7) It was already discussed that EXE and DLL files have a base value that indicates its preferred base address. There are times when the preferred base address for a DLL can be given by the loader when it is loaded, but the more common case is that it will not get its preferred base address. If you look at the graphic on the slide, the stack of pages on the left side of the slide shows the address space along with several items, like threads and the image itself, already occupying some memory regions. It just so happens that nothing is mapped at the DLL’s preferred base address. When the loader is mapping it in and it sees this, it will happily map it there. The sta

=== UNIT 27 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, .TEXT section, s_executable_code
Summary: The unit describes the structure of a .TEXT section within a dynamic-linked library. It highlights that this section contains the executable code for the library.
Excerpt:
Visual caption: A slide from a cybersecurity course showing the structure of a .TEXT section in a dynamic-linked library. Visible text: Dynamic-linked Libraries (8); .TEXT section; The executable code; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 28 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, .TEXT section, PAGE_EXECUTE_READ, RVA, rawdata, disasm
Summary: This unit describes the structure and permissions of the .TEXT section in a PE file, specifically highlighting how executable code is stored and protected by missing Write permissions. It details the memory mapping for this section and provides specific header values like virtual size, RVA, and raw data size.
Excerpt:
Dynamic-linked Libraries (8) The section headers should immediately follow the optional header and the number of sections can be found in the file header. The first one, TEXT, is where the executable code is located. Please pay special attention to the permissions of this section and you might notice how the Write permission flag is missing. The TEXT section is only Execute and Read because the processor must be allowed to read the instructions and execute them. If the section had the Write permission, then an attacker would be free to make changes to program code. The loader will make sure this section is mapped into a page of memory with only PAGE_EXECUTE_READ permissions set. The virtual 

=== UNIT 29 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: .rdata section, Dynamic-linked Libraries, virtual size, relocation table
Summary: The unit describes the analysis of a .rdata section within an executable file. It highlights specific properties such as dynamic-linked libraries, virtual size, and relocation table pointers.
Excerpt:
Visual caption: A screenshot of a slide or document showing the analysis of a .rdata section in an executable file, highlighting its properties and contents. Visible text: Dynamic-linked Libraries (9); .rdata name; virtual size; size of raw data; pointer to relocation table; Read only, initialized data; OPTIONAL HEADER Directories; SECTION NUMBER 20 Alt/source label:

=== UNIT 30 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: DLL exports, RVA analysis, assembly disassembly, E10002000h, PrintHello function
Summary: The unit describes the analysis of a DLL's export table and disassembly of the PrintHello function. It details how the EAX register is used to return a pointer to a string located at RVA 2000. The text includes sample output from tools like /exports and /disasm.
Excerpt:
Dynamic-linked Libraries (10) It was discovered on the previous slide that the RVA for the PrintHello function was 1000. The output from the /exports switch verified what was found with a manual lookup. Checking the output from the /disasm switch along with /section:.text, the code for the function can be seen. Understanding the assembly for the function is simple because the function only does one thing—return the pointer to a string. The __cdecl calling convention specified for this function uses the EAX register to hold the return values. Here, EAX will end up holding the RVA 2000. The data at RVA 2000 was previously seen already and is indeed the address to the string “Welcome to DLL Hel

=== UNIT 31 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: dumpbin, DLL dependencies, import analysis, callhello.exe
Summary: The unit describes a terminal window showing the output of dumpbin commands used to identify DLL dependencies and imports for an executable file named 'callhello.exe'. It lists specific libraries like kernel32.dll, user32.dll, gdi32.1, and SHELL32.ll.
Excerpt:
Visual caption: A screenshot of a terminal window showing the output of dumpbin commands to identify DLL dependencies and imports for an executable file. Visible text: DLLs: Explicit Linking (3); dumpbin /dependents callhello.exe; dumpbin /imports callhello.exe; 1.kernel32.dll; kernel32.dll; user32.dll; gdi32.dll; SHELL32.dll Alt/source label:

=== UNIT 32 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: DLL export methods, declsect(), definition file, EXTERN_C
Summary: The unit contains a review question regarding the preferred method for exporting functions within a DLL. It specifically lists three options: using declsect(), creating a definition file, and using EXTERN_C.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about exporting functions in a DLL. Visible text: Unit Review Questions; What is the preferred way to export functions in a DLL?; Using declsect(); Creating a definition file; Using EXTERN_C Alt/source label:

=== UNIT 33 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: COM library, CoCreateInstance, CoInitialize, CoMemFree
Summary: This unit contains a review question regarding the initialization of COM libraries in a Windows environment. It specifically asks for the identification of correct functions like CoCreateInstance and CoInitialize.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers How do you get the COM library ready for use in your process? How do you get the COM library ready for use in your process? A CoCreateInstance A CoCreateInstance B CoInitialize B CoInitialize C CoMemFree C CoMemFree 112 Unit Review Answers Q: How do you get the COM library ready for use in your process? A: CoCreateInstance B: CoInitialize C: CoMemFree 112 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 34 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: MIB_IPSTATS, GetIpStatistics, structure definition, network statistics
Summary: The unit describes the MIB_IPSTATS structure used by the GetIpStatistics function in Windows. It lists several members of the structure, such as dwDefaultTTL and dwInReceives, which provide detailed network statistics.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control MIB_IPSTATS Struct typedef struct _MIB_IPSTATS_LH { [..SNIP..] DWORD dwDefaultTTL; DWORD dwInReceives; DWORD dwInHdrErrors; DWORD dwInAddrErrors; DWORD dwForwDatagrams; DWORD dwInUnknownProtos; DWORD dwInDiscards; DWORD dwInDelivers; DWORD dwOutRequests; DWORD dwRoutingDiscards; DWORD dwOutDiscards; DWORD dwOutNoRoutes; [..SNIP..] } MIB_IPSTATS_LH, *PMIB_IPSTATS_LH; 121 MIB_IPSTATS Struct The MIB_IPSTATS structure is the structure that is filled out by the GetIpStatistics function. Some of the structure members are very useful and some you might not even care about other than just being extra detailed wit

=== UNIT 35 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: RegOpenKeyExW, HKEY, LSTATUS, _Out_ parameter
Summary: The unit provides a C code example for the RegOpenKeyExW function to open a registry key. It explains how the handle is returned via an _Out_ parameter and why the LSTATUS return value is used for error handling.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: RegOpenKeyEx INT main(VOID) { HKEY hHKCU = HKEY(); RegOpenKeyExW(HKEY_CURRENT_USER, L”Console”, NULL, KEY_READ, &hHKCU); } 145 Example: RegOpenKeyEx The example here initializes a variable of type HKEY that will be used to store the handle that the function gives upon success. Just like the function declares, the last parameter must be the address of the variable. Afterall, it is an _Out_ parameter so the user is responsible for making that available for the function to use. The function doesn’t “return” a handle because this function returns an LSTATUS value that could be used to determine why i

=== UNIT 36 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: RegEnumValue, registry key retrieval, ERROR_NO_MORE_ITEMS, buffer management
Summary: The unit describes the implementation of the RegEnumValue function in a loop to retrieve registry keys. It details specific parameter usage, such as buffer management for key names and values, and explains how to handle iteration until ERROR_NO_MORE_ITEMS is returned.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: RegEnumValue 150 Example: RegEnumValue The example here shows the function being used in a loop with the index variable being used as the loop iterator value, or counter. The key handle is passed followed by the dwIndex value, which is an index of the value that is to be retrieved. It is a good idea to have this value be NULL on the first iteration. Incrementing the value is fine for subsequent calls. The name of the key will be stored in the keyName buffer for the lpValueName parameter. The lpcchValueName parameter, upon return, will hold the character count stored in the buffer. Note, the count

=== UNIT 37 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: RegQueryInfoKey, registry key metadata, buffer sizes, Windows API
Summary: The unit describes the implementation of the RegQueryInfoKey function to retrieve metadata about registry keys, such as subkey counts and size limits. It details specific parameters required for the buffer sizes and data types used in this Windows API call.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: RegQueryInfoKey 152 Example: RegQueryInfoKey The example here shows how RegQueryInfoKey could be called. A standard handle to a key is given followed by three NULL values: lpClass, lpcClass, and lpReserved. Next, the address of the cSubKeys variable is passed so the function can write the number of subkeys contained by that key. Next, the address of the cbMaxSubKey variable is passed so the function can write the size of the key with the longest name, minus the NULL terminating character of course. Next, the address of the cbMaxClass variable is passed to receive the size of the longest string fo

=== UNIT 38 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: _KPROCESS, Kernel object, kernel core, ThreadListHead, DirectoryTableBase, Virtual Address Translation
Summary: The text describes the internal structure of the _KPROCESS kernel object in Windows. It details specific members like ThreadListHead and DirectoryTableBase used for thread scheduling and virtual address translation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control _KPROCESS KPROCESS KPROCESS Kernel object representing processes Kernel object representing processes //0x438 bytes (sizeof) struct _KPROCESS { struct _DISPATCHER_HEADER Header; //0x0 struct _LIST_ENTRY ProfileListHead; //0x18 ULONGLONG DirectoryTableBase; //0x28 struct _LIST_ENTRY ThreadListHead; //0x30 ULONG ProcessLock; //0x40 ULONG ProcessTimerDelay; //0x44 ULONGLONG DeepFreezeStartTime; //0x48 struct _KAFFINITY_EX Affinity; //0x50 ULONGLONG AffinityPadding[12]; //0xf8 struct _LIST_ENTRY ReadyListHead; //0x158 [..snip..] } Used by the lower layer of the Kernel Used by the lower layer of the Kernel 41 

=== UNIT 39 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: NtQuerySystemSystemInformation, SYSTEM_PROCESS_INFORMATION, SYSTEM_INFORMATION_CLASS, buffer allocation
Summary: The unit describes the NtQuerySystemInformation API, a native function used to retrieve system and process information. It details the parameters of the function, including SystemInformationClass and the buffer management required for calling it.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control NtQuerySystemInformation API NtQuerySystemInformation NtQuerySystemInformation Grabs specific information about the system Grabs specific information about the system NTSTATUS NtQuerySystemInformation( _In_ SYSTEM_INFORMATION_CLASS InfoCls, _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength ); // enum entry SystemProcessInformation // SYSTEM_PROCESS_INFORMATION struct Has NTSTATUS return type Has NTSTATUS return type 56 NtQuerySystemInformation API As mentioned on the previous slide, the NtQuerySystemInformation function is a native function as annotated by 

=== UNIT 40 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: SYSTEM_PROCESS_INFORMATION, x64dbg documentation, struct definition, memory forensics
Summary: The text defines the SYSTEM_PROCESS_INFORMATION structure used in Windows memory forensics and debugging. It provides a technical definition of fields such as thread counts, memory usage, and process identifiers.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control SYSTEM_PROCESS_INFORMATION Struct typedef struct _SYSTEM_PROCESS_INFORMATION { ULONG NextEntryOffset; ULONG NumberOfThreads; LARGE_INTEGER WorkingSetPrivateSize; // Since Vista ULONG HardFaultCount; // Since Windows 7 ULONG NumberOfThreadsHighWatermark; // Since Windows 7 ULONGLONG CycleTime; // Since Windows 7 LARGE_INTEGER CreateTime; LARGE_INTEGER UserTime; LARGE_INTEGER KernelTime; UNICODE_STRING ImageName; [..SNIP..] HANDLE UniqueProcessId; HANDLE InheritedFromUniqueProcessId; SYSTEM_THREAD_INFORMATION Threads[1]; [..SNIP..] 57 SYSTEM_PROCESS_INFORMATION Struct Here is the struct as documented by the
