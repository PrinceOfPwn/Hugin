# Atlas Material — binary-analysis (part 1)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: binary_exploit
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.95  Key cues: __thiscall, x86 C++, Windows-specific, this pointer, stack-based arguments
Summary: The unit describes the __thiscall calling convention used in x86 C++ for Windows. It explains that the compiler creates a 'this' pointer and that all arguments are passed via the stack.
Excerpt:
Visual caption: A slide explaining the __thiscall calling convention for x86 C++. Visible text: __thiscall; This is yet another Windows-specific calling convention for x86 C++.; Compiler creates a this pointer; Primary holder of this pointer; For C++ class members; All arguments are on the stack; Arguments pushed right to left Alt/source label:

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: __stdcall, x86, CreateFileW, stack layout, assembly disassembly
Summary: The unit describes the stack layout and disassembly of a `CreateFileW` call using the __stdcall convention on x86 architecture. It illustrates how parameters are pushed onto the stack before a function call, and highlights the difference between source code macros and actual assembly implementation.
Excerpt:
Example: __stdcall (x86) Look at a simple example using CreateFileW compiled for x86. The very first argument for CreateFileW is directly above it. Each additional argument falls into place one after another on the stack. Another way to look at this from a source code point of view is to annotate the stack offsets directly above the function’s parameters. Since the arguments are referenced as offsets from EBP, the following can be made as a visualization. Also, note how the code makes the call to the Unicode version of the function. This is because Unicode is supported by default in Visual Studio projects, and the CreateFileW used in the source code is just a macro that is swapped out for th

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: x86-64, stack arguments, RSP+20h, shadow stack enforcement, trick question
Summary: The unit contains a multiple-choice question regarding the memory layout of x86-64 architecture stack arguments. It specifically addresses why certain offsets from RSP are used in 64-bit systems.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about x86-64 architecture stack arguments. Visible text: Unit Review Questions; For 64-bit, why do stack arguments start at RSP+20h and not RSP?; The first 20h bytes are reserved as a shadow stack enforcement; The first 20h bytes are reserved as a shadow store; They don't; this is a trick question Alt/source label:

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: WIN32_FIND_DATA, struct definition, AlternateFileName, 8.3 filename convention
Summary: The unit describes the WIN32_FIND_DATA structure in Windows, specifically highlighting its members like file attributes and timestamps. It explains the 14-character AlternateFileName field used for 8.3 short naming conventions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control WIN32_FIND_DATA Struct typedef struct _WIN32_FIND_DATAA { DWORD dwFileAttributes; FILETIME ftCreationTime; FILETIME ftLastAccessTime; FILETIME ftLastWriteTime; DWORD nFileSizeHigh; DWORD nFileSizeLow; DWORD dwReserved0; DWORD dwReserved1; CHAR cFileName[MAX_PATH]; CHAR cAlternateFileName[14]; DWORD dwFileType; DWORD dwCreatorType; WORD wFinderFlags; } WIN32_FIND_DATAA, *PWIN32_FIND_DATAA, *LPWIN32_FIND_DATAA; 79 WIN32_FIND_DATA Struct The WIN32_FIND_DATA structure is filled with useful information. Many of the struct members do not need any explanation, like FileAttributes, CreationTime, LastAccessTime, L

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: thread hijacking, Thread state, thread context, thread priority
Summary: This unit contains a review question regarding the technical requirements for hijacking a thread in a Windows environment. It specifically asks which construct must be modified during this process.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 78 Unit Review Answers When hijacking a thread, what construct must be modified? When hijacking a thread, what construct must be modified? A Thread state A Thread state B Thread context B Thread context C Thread priority C Thread priority Unit Review Answers Q: When hijacking a thread, what construct must be modified? A: Thread state B: Thread context C: Thread priority 78 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: dumpbin, PE header, dumpbin /headers, IMAGE_FILE_MACHINE_I386, optional header size, DLL
Summary: The text describes the use of the dumpbin utility to analyze PE headers and identify file characteristics such as machine architecture, number of sections, and optional header size. It specifically demonstrates how these values are used when parsing DLL files. The content includes a sample output from the dumpbin /headers command.
Excerpt:
Dynamic-linked Libraries (4) As mentioned previously, the dumpbin utility ships with the SDK and as such, it is only available on your Dev-VM. Dumpbin offers a wide array of commands, everything from dumping headers to showing the disassembly of an image’s section, like the TEXT section. Running the dumpbin /headers headers command will direct dumpbin to parse the entire image’s PE header. The tool will provide verbose output similar to the output shown on the slide. The output shown indicates that it checks the validity of the image being parsed to ensure it knows the file format. If you were to give dumpbin a file it does not know the format of, like a Windows header file, it will return t

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Heaven's Gate, x86 program, ntdll.dll - offset, 32-bit to 64-bit transition
Summary: The unit describes the transition of 32-bit code to 64-bit mode in a Windows environment using ntdll.dll. It specifically addresses how x86 programs can operate in 64-bit space.
Excerpt:
Visual caption: A presentation slide titled 'Heaven's Gate: The Transition' explaining how 32-bit code can transition to 64-bit mode in Windows. Visible text: Heaven's Gate: The Transition; x86 program; ntdll.dll - offset; ntdll.dll; SEC/701 / Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: NTDLL.dll, CreateFileMapping, MapViewOfFile, .text section, memory mapping
Summary: The text describes a technique for restoring a fresh copy of NTDLL.dll on disk using file mapping APIs. It outlines a specific sequence of procedure: CreateFileA, CreateFileMapping, and MapViewOfFile to map the library into memory and identify the .text section. Once identified, it explains that the copying process is used to overwrite tampered sections in memory.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 51 A Fresh Copy Visualization On disk On disk In memory In memory Ntdll.dll Ntdll.dll .text .text 1. CreateFileA(ntdll.dll, ...) 2. CreateFileMapping(hNtdll, ...) 3. MapViewOfFile(hNtdllMapping, ...) 4. Find NtHeader 5. Find .text section 6. memcpy() section over A Fresh Copy Visualization Perhaps the best way to copy over a fresh copy of NTDLL on disk is to create a file mapping. The process is not complicated at all once you become familiar with the few APIs involved. The first action to execute is to obtain a module handle to the DLL using the CreateFile API, which will return a handle to us. From the 

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.9  Key cues: __stdcall, s8 architecture, CreateFile function, assembly code, ds_imp__CreateFile@28
Summary: The unit contains a screenshot of assembly code illustrating the `__stdcall` calling convention in x86 architecture for a CreateFile function call. It includes specific assembly instructions like push operations and a call to ds_imp__CreateFile@28.
Excerpt:
Visual caption: A screenshot of assembly code demonstrating a `__stdcall` calling convention in x86 architecture. Visible text: Example: __stdcall (x86); CreateFile("C:\test.txt", ...); push 0; push 08h; push 5; push 0; push 40000000h; push offset .file1.name; call ds_imp__CreateFile@28; mov edi, eax; SEC070 | Red Teaming Tools. Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.9  Key cues: CreateFile, ERROR_INVALID_PARAMETER, INVALID_HANDLE_VALUE, Unit Review
Summary: This unit contains a review question regarding the return values of the CreateFile function in Windows API programming. It specifically addresses whether it returns a handle or an error code when a failure occurs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What does CreateFile return upon error? What does CreateFile return upon error? A A handle to the file A A handle to the file B ERROR_INVALID_PARAMETER B ERROR_INVALID_PARAMETER C INVALID_HANDLE_VALUE C INVALID_HANDLE_VALUE 191 Unit Review Answers Q: What does CreateFile return upon error? A: A handle to the file B: ERROR_INVALID_PARAMETER C: INVALID_HANDLE_VALUE 191 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.9  Key cues: FindFirstFileW, FindNextFileW, directory enumeration, CString, do/while loop
Summary: The text describes the basic usage of FindFirstFileW and FindNextFileW APIs for directory enumeration in Windows. It explains how to use a CString buffer, handle potential failures, and process entries within a do/while loop.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: FindFirstFile, FindNextFile, FindClose 82 Example: FindFirstFile, FindNextFile, FindClose The short example on the slide shows very basic usage for the two main APIs that are involved in enumerating a directory. The FindFirstFileW API is used to kick off the process of enumeration. The first argument being passed to the API is a CString type that has a method GetBuffer() to get a pointer to the buffer. This is done to satisfy the requirement of the API. The function can fail, so be sure to check for success for failure. The next part is the do/while loop that will continue as long as the FindNext

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WINAPI, expansion, __stdcall, __thiscall, __cdecl
Summary: The unit contains a multiple-choice question regarding the technical definition of the WINAPI calling convention.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about the WINAPI expansion. Visible text: Unit Review Questions; What does the type WINAPI expand to?; __stdcall; __thiscall; __cdecl Alt/source label:

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WINAPI, __stdcall, Unit Review Answers
Summary: This unit contains the answers to a review section regarding Windows API calling conventions. Specifically, it identifies that WINAPI expands to __stdcall.
Excerpt:
Unit Review Answers Q: What does the type WINAPI expand as? A: __stdcall B: __thiscall C: __cdecl SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What does the type WINAPI expand as? What does the type WINAPI expand as? A __stdcall A __stdcall B __thiscall B __thiscall C __cdecl C __cdecl 103 103 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HKEY, HINSTANCE, HRSRC, HANDLE
Summary: The unit contains a multiple-choice question regarding the shared characteristics of specific Windows handle types (HKEY, HINSTANCE, and HRSRC).
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about commonalities between HKEY, HINSTANCE, and HRSRC types. Visible text: Unit Review Questions; What do the types HKEY, HINSTANCE, HRSRC have in common?; Nothing.; They are all of type HANDLE.; They all refer to GUI applications. Alt/source label:

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HKEY, handle type, Windows API
Summary: The unit contains a review question regarding the commonality between HKEY, HINSTANCE, and HRSRC types in Windows programming.
Excerpt:
Unit Review Questions Q: What do the types HKEY, HINSTANCE, HRSRC have in common? A: Nothing. B: They are all of type HANDLE. C: They all refer to GUI applications. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What do the types HKEY, HINSTANCE, HRSRC have in common? What do the types HKEY, HINSTANCE, HRSRC have in common? A Nothing. A Nothing. B They are all of type HANDLE. B They are all of type HANDLE. C They all refer to GUI applications. C They all refer to GUI applications. 104 104 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HKEY, handle type, Windows programming, Security-related data types
Summary: The unit contains a review question regarding the commonality between HKEY, HINSTANCE, and HRSRC types in Windows programming. It specifically addresses whether these are handles or related to GUI applications.
Excerpt:
Unit Review Answers Q: What do the types HKEY, HINSTANCE, HRSRC have in common? A: Nothing. B: They are all of type HANDLE. C: They all refer to GUI applications. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What do the types HKEY, HINSTANCE, HRSRC have in common? What do the types HKEY, HINSTANCE, HRSRC have in common? A Nothing. A Nothing. B They are all of type HANDLE. B They are all of type HANDLE. C They all refer to GUI applications. C They all refer to GUI applications. 105 105 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HKEY, handle type, Windows API
Summary: The unit contains a review question regarding the commonality between HKEY, HINSTANCE, and HRSRC types in Windows programming.
Excerpt:
Unit Review Answers Q: What do the types HKEY, HINSTANCE, HRSRC have in common? A: Nothing. B: They are all of type HANDLE. C: They all refer to GUI applications. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What do the types HKEY, HINSTANCE, HRSRC have in common? What do the types HKEY, HINSTANCE, HRSRC have in common? A Nothing. A Nothing. B They are all of type HANDLE. B They are all of type HANDLE. C They all refer to GUI applications. C They all refer to GUI applications. 105 105 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: DWORD, ULONG, WORD, VOID
Summary: This unit contains a review section for the SANS SEC670 course, specifically focusing on data types in Windows programming. It lists questions and answers regarding the root types of DWORD, VOID, and WORD.
Excerpt:
Unit Review Answers Q: What is the root type for DWORD? A: ULONG or unsigned long. B: VOID or void. C: WORD or double word. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What is the root type for DWORD? What is the root type for DWORD? A ULONG or unsigned long. A ULONG or unsigned long. B VOID or void. B VOID or void. C WORD or double word. C WORD or double word. 107 107 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateFileW, __stdcall (x86), stack offsets, push instructions, assembly disassembly
Summary: The unit describes the stack layout and disassembly of the CreateFileW function using the __stdcall convention on x86 architecture. It illustrates how parameters are pushed onto the stack before a function call and shows the example of a Unicode version of the function.
Excerpt:
Example: __stdcall (x86) Look at a simple example using CreateFileW compiled for x86. The very first argument for CreateFileW is directly above it. Each additional argument falls into place one after another on the stack. Another way to look at this from a source code point of view is to annotate the stack offsets directly above the function’s parameters. Since the arguments are referenced as offsets from EBP, the following can be made as a visualization. Also, note how the code makes the call to the Unicode version of the function. This is because Unicode is supported by default in Visual Studio projects, and the CreateFileW used in the source code is just a macro that is swapped out for th

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: __stdcall, x86 architecture, CreateFile, assembly code, ds_imp__CreateFile@28
Summary: The unit contains a screenshot of assembly code illustrating the `__stdcall` calling convention in x86 architecture for a CreateFile function call. It includes specific assembly instructions like push operations and a call to ds_imp__CreateFile@28.
Excerpt:
Visual caption: A screenshot of assembly code demonstrating a `__stdcall` calling convention in x86 architecture. Visible text: Example: __stdcall (x86); CreateFile("C:\test.txt", ...); push 0; push 08h; push 5; push 0; push 40000000h; push offset .file1.name; call ds_imp__CreateFile@28; mov edi, eax; SEC070 | Red Teaming Tools. Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: x64 calling convention, CreateFileW assembly, register/stack mapping
Summary: The text provides an example of the x64 assembly representation of a CreateFileW function call. It illustrates how arguments are mapped to registers and the stack when there are more than four parameters.
Excerpt:
Example: (x64) When we look at this example compiled for x64, the arguments look a bit different and out of order than what you might think. There is no order in terms of how it looks in assembly—all that matters is that the registers are loaded with the proper values. Since there are seven arguments total, the first four will be in registers, and the remainder will be placed on the stack. Here is one way this can be visualized. Placing the registers above the arguments can help understand where things will fall into place when the call is ready to be made. RCX RDX R8 R9 stack stack stack CreateFileW( L”hello.txt”, GENERIC_WRITE, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL ); mov qwo

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: x64 calling convention, CreateWindowExW, assembly code, mov qword ptr, lea rcx
Summary: The unit contains a screenshot of assembly code illustrating the x64 calling convention for a CreateWindowExW function call. It specifically shows register assignments and memory movements for parameters before a function call.
Excerpt:
Visual caption: A screenshot of assembly code demonstrating the x64 calling convention for a CreateWindowExW function call. Visible text: Example: (x64); CreateFileW; mov qword ptr ss:[rsp+30], 0; lea rcx, qword ptr ds:[...]; xor rdx, rdx; xor r8, r8; mov qword ptr ss:[rsp+20], 1; mov r9, 40000000; call qword ptr ds:[CreateFileW+0x] Alt/source label:

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: x64 calling convention, CreateFileW assembly example, register-to-stack mapping, calling convention visualization
Summary: The text provides an example of how the CreateFileW function is called in x64 assembly, illustrating the mapping between high-level API calls and register/stack placement for multiple arguments. It details specific register assignments (RCX, RDX, R8, R9) and stack offsets for parameters like file attributes and security settings.
Excerpt:
Example: (x64) When we look at this example compiled for x64, the arguments look a bit different and out of order than what you might think. There is no order in terms of how it looks in assembly—all that matters is that the registers are loaded with the proper values. Since there are seven arguments total, the first four will be in registers, and the remainder will be placed on the stack. Here is one way this can be visualized. Placing the registers above the arguments can help understand where things will fall into place when the call is ready to be made. RCX RDX R8 R9 stack stack stack CreateFileW( L”hello.txt”, GENERIC_WRITE, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL ); mov qwo

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: fastcall, __fastcall, calling convention, assembly language
Summary: The unit describes the assembly language fastcall calling convention. It details how the first two arguments are passed in registers and subsequent arguments are placed on the stack.
Excerpt:
Visual caption: A slide explaining the fastcall calling convention in assembly language. Visible text: __fastcall; __fastcall The faster calling convention, seriously.; First 2 arguments passed in registers; Remainder arguments on stack; Fastest when 2 arguments used; Arguments pushed right to left Alt/source label:

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: __fastcall, ECX/EDX registers, function decoration, @SomeFastFunction@12
Summary: The unit describes the characteristics of the __fastcall calling convention in 32-bit Windows environments, specifically identifying indicators like register usage (ECX and EDX) and naming conventions for decorated functions.
Excerpt:
Example: __fastcall There are several items on the slide that indicate that __fastcall calling convention is being used. Aside from the obvious being the function declaration, the first indicator is the use of the ECX and EDX registers. As mentioned on the previous slide, the ECX and EDX registers are heavily used for this calling convention. The second indicator is the name of the function itself as it has some strange additions to it, like the “@” before and after the function name. The “@” before the function name indicates __fastcall and the “@” followed by a number indicates the size of bytes in arguments. With these being 32-bit values, 12 means there are three arguments to SomeFastFun

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: __fastcall, ECX/EDX registers, @SomeFastFunction@12, calling convention
Summary: The text describes the identification of the __fastcall calling convention in 32-bit assembly code. It highlights specific indicators such as the use of ECX and EDX registers and naming conventions involving '@' symbols to denote function size.
Excerpt:
Example: __fastcall There are several items on the slide that indicate that __fastcall calling convention is being used. Aside from the obvious being the function declaration, the first indicator is the use of the ECX and EDX registers. As mentioned on the previous slide, the ECX and EDX registers are heavily used for this calling convention. The second indicator is the name of the function itself as it has some strange additions to it, like the “@” before and after the function name. The “@” before the function name indicates __fastcall and the “@” followed by a number indicates the size of bytes in arguments. With these being 32-bit values, 12 means there are three arguments to SomeFastFun

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: __thiscall, x86 C++, ECX register, class member functions, memory layout
Summary: The text describes the __thiscall calling convention used in x86 C++ class member functions on Windows systems. It explains that arguments are pushed onto the stack from right to left, while the ECX register is primarily used to hold the 'this' pointer.
Excerpt:
__thiscall Another calling convention that is specific to Microsoft and built for x86 C++ class member functions is thiscall. Just like cdecl and stdcall, all arguments are pushed on the stack in a right to left manner. The new item here is that the compiler will sneak in a pointer. This pointer points to a table that is indexed appropriately for the member function being called. The pointer is called this pointer and ECX is primarily used to hold it. A quick refresher on class member functions is on the following slide. The class, MyClass, is defined as a class that will have one function available for public use; PrintMsg. The method is not defined inside the class but instead is done outs

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: x86, arguments passed to functions, RCX, RDX, R8, R9
Summary: The unit contains a multiple-choice question regarding the mechanism of argument passing in x86 architecture functions.
Excerpt:
Unit Review Questions Q: For x86, how are arguments passed to functions? A: In registers RCX, RDX, R8, R9 B: On the stack C: In the heap SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions For x86, how are arguments passed to functions? For x86, how are arguments passed to functions? A In registers RCX, RDX, R8, R9 A In registers RCX, RDX, R8, R9 B On the stack B On the stack C In the heap C In the heap 123 123 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: x86_64 architecture, function argument passing, RCX, RDX, R8, R9
Summary: The unit contains a multiple-choice question regarding the mechanism of argument passing in x86_64 architecture. It specifically asks for the location of arguments (registers vs. stack).
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about x86_64 architecture function argument passing. Visible text: Unit Review Questions; For x86, how are arguments passed to functions?; In registers RCX, RDX, R8, R9; On the stack; In the heap Alt/source label:

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: x86, arguments passed to functions, RCX, RDX, R8, R9
Summary: The unit contains a review question regarding the mechanism of argument passing in x86 architecture functions.
Excerpt:
Unit Review Questions Q: For x86, how are arguments passed to functions? A: In registers RCX, RDX, R8, R9 B: On the stack C: In the heap SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions For x86, how are arguments passed to functions? For x86, how are arguments passed to functions? A In registers RCX, RDX, R8, R9 A In registers RCX, RDX, R8, R9 B On the stack B On the stack C In the heap C In the heap 123 123 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: x86, arguments passed to functions, RCX, RDX, R8, R9
Summary: This unit contains a review question regarding the mechanism of argument passing in x86 architecture functions. It lists multiple choice options for stack, heap, and register-based delivery.
Excerpt:
Unit Review Answers Q: For x86, how are arguments passed to functions? A: In registers RCX, RDX, R8, R9 B: On the stack C: In the heap SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers For x86, how are arguments passed to functions? For x86, how are arguments passed to functions? A In registers RCX, RDX, R8, R9 A In registers RCX, RDX, R8, R9 B On the stack B On the stack C In the heap C In the heap 124 124 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: x86, arguments passed to functions, RCX, RDX, R8, R9
Summary: This unit contains a review question regarding the mechanism of argument passing in x86 architecture functions. It specifically lists options for registers, stack, and heap.
Excerpt:
Unit Review Answers Q: For x86, how are arguments passed to functions? A: In registers RCX, RDX, R8, R9 B: On the stack C: In the heap SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers For x86, how are arguments passed to functions? For x86, how are arguments passed to functions? A In registers RCX, RDX, R8, R9 A In registers RCX, RDX, R8, R9 B On the stack B On the stack C In the heap C In the heap 124 124 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: x86-64, function arguments, RCX, RDX, R8, R9, stack
Summary: The unit contains a multiple-choice question regarding the mechanism of passing function arguments in x86-64 architecture. It specifically lists options such as registers and the stack.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about x86-64 architecture function arguments. Visible text: Unit Review Answers; For x86, how are arguments passed to functions?; In registers RCX, RDX, R8, R9; On the stack; In the heap Alt/source label:

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: calling convention, ECX/RCX, EDX/RDX, multiple-choice
Summary: The unit contains a multiple-choice question regarding the calling conventions used in Windows programming, specifically identifying which one utilizes the ECX/RCX and EDX/RDX registers.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about calling conventions. Visible text: Unit Review Answers; What calling convention primarily uses registers ECX/RCX and EDX/RDX?; __fastcall; __thiscall; __stdcall Alt/source label:

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetExitCodeThread, _Out_, _Success_(), BOOL return type, explanation of status codes
Summary: The text describes the GetExitCodeThread API and its usage of advanced annotations like _Out_ and _Success_(). It explains how a BOOL return type indicates success or failure, while the specific exit code is stored in an out-parameter.
Excerpt:
Example: Advanced Annotations (2) The second example is of the API GetExitCodeThread, which is used to get a thread’s termination status. Side note here: notice how the function is declared with a BOOL return type. This means that the function will not be returning an exit code but simply a TRUE/FALSE status if the function succeeded or not. Notice the _Out_ parameter—this is where the exit code will be going. Anyway, notice the _Success_() annotation describing the function. This indicates that a successful return value for this function will not be equal to 0. Any nonzero would indicate success in this case and only 0, or NULL, would indicate failure. SEC670 | Red Teaming Tools: Developing

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WldpQueryDynamicCodeTrust, Device Guard policy, C++ compiler annotations, When() expressions
Summary: The unit describes the WldpQueryDynamicCodeTrust API and its role in determining if in-memory dynamic code is trusted by Device Guard policy. It explains how to interpret specific C++ compiler annotations (When() expressions) regarding fileHandle, baseImage, and imageSize parameters.
Excerpt:
Example: Advanced Annotations (4) The example here is of the WldpQueryDynamicCodeTrust API, which is used to grab a value to figure out if the specified in-memory dynamic code is trusted by Device Guard policy. It's a pretty cool function! Anyway, let’s tackle some of these _When_() expressions. At a high level, this is saying that if the fileHandle is not NULL, then baseImage better be NULL. The opposite is also true: if the baseImage is not NULL, then the fileHandle better be NULL. Okay, on to the expressions. The first one indicates that the fileHandle will be optional when the baseImage is not NULL. The second one indicates that the fileHandle will be read-only and required when the base

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows API, Create*, CreateFile, CreateThread, CreateToolhelp32Snapshot
Summary: The unit contains a list of Windows API functions starting with 'Create' used for system interaction. These include functions like CreateFile, CreateFileMapping, and CreateThread.
Excerpt:
Visual caption: A slide titled 'Create APIs (2)' listing various Windows API functions starting with the word 'Create'. Visible text: Create APIs (2); CreateFile; CreateFileMapping; CreateDirectory; CreateTimerQueue; CreateMutex; CreateEvent; CreateThread; CreateToolhelp32Snapshot Alt/source label:

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateProcessW, process creation, pApplicationName, pCommandLine, Windows API
Summary: The text describes the CreateProcessW API function for creating new processes on a Windows system. It details the specific parameters of the sentence, such as pApplicationName and pCommandLine, and explains how they handle file paths and extensions.
Excerpt:
Create APIs (3) Creating processes on a target system can be very useful in accomplishing your objectives. The CreateProcessW API must be given a valid executable image, or it will fail. It is not as fancy as what Explorer uses behind the scenes that will determine the file type and choose the appropriate executable. If you were to double-click on a TXT file, Explorer uses the ShellExecuteEx, or similar, to search through the Registry and pick the application based on the file extension type association found for it. CreateProcessW takes nine parameters and will return TRUE upon success. The return value can be misleading because the process can still fail to start but the function returned 

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateProcessW, Windows programming, Boolean return type
Summary: The unit describes the CreateProcessW API function in Windows programming. It highlights its purpose as creating a new process and notes its return type.
Excerpt:
Visual caption: A slide from a SANS course about the CreateProcessW API function in Windows programming. Visible text: Create APIs (3); CreateProcessW; Used to create a new process; Has a Boolean return type; BOOL CreateProcessW; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateProcessW, process creation, pApplicationName, pCommandLine, API documentation
Summary: The unit describes the CreateProcessW API function, detailing its parameters and behavior for creating new processes on a Windows system. It explains how to use pApplicationName and pCommandLine to specify executable paths and command-line arguments. The text also includes the formal C/C++ signature of the CreateProcessW function.
Excerpt:
Create APIs (3) Creating processes on a target system can be very useful in accomplishing your objectives. The CreateProcessW API must be given a valid executable image, or it will fail. It is not as fancy as what Explorer uses behind the scenes that will determine the file type and choose the appropriate executable. If you were to double-click on a TXT file, Explorer uses the ShellExecuteEx, or similar, to search through the Registry and pick the application based on the file extension type association found for it. CreateProcessW takes nine parameters and will return TRUE upon success. The return value can be misleading because the process can still fail to start but the function returned 
