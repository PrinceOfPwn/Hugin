# Atlas Material — binary-analysis (part 9)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: binary_exploit
Units: 26

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: LPVOID, PVOID, difference, Unit Review Questions
Summary: The unit contains a multiple-choice question regarding the technical differences between LPVOID and PVOID in C programming for Windows. It is part of a review section within a course on developing Windows implants.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about the difference between LPVOID and PVOID. Visible text: Unit Review Questions; On modern systems, what is the difference between LPVOID and PVOID?; There is no difference.; LPVOID is a long pointer, PVOID is not.; LPVOID is not a pointer.; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: LPVOID, PVOID, Windows programming, multiple-choice question
Summary: The unit contains a multiple-choice question regarding the technical differences between LPVOID and PVOID in Windows programming. It identifies that there is no difference between these two types.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about the difference between LPVOID and PVOID in Windows programming. Visible text: Unit Review Answers; On modern systems, what is the difference between LPVOID and PVOID?; There is no difference.; LPVOID is a long pointer, PVOID is not.; LPVOID is not a pointer.; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 3 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: __fastcall, assembly language, INT FASTCALL, register usage
Summary: The unit provides an assembly language example of the __fastcall calling convention. It demonstrates how to pass parameters and use registers for function calls in a Windows environment.
Excerpt:
Visual caption: A code snippet demonstrating the use of the __fastcall calling convention in assembly language. Visible text: Example: __fastcall; INT FASTCALL SomeFastFunction( PWORD, PWORD, BOOL);; push 1; lea [ebp+4], 2; lea [ebp+8], 3; call SomeFastFunction(x,y,z); mov [ebp+9], eax Alt/source label:

=== UNIT 4 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: 64-bit, RSP+20h, shadow stack enforcement, shadow store
Summary: This unit contains a review question regarding the memory layout of 64-bit stack arguments and why they start at RSP+20h.
Excerpt:
Unit Review Questions Q: For 64-bit, why do stack arguments start at RSP+20 and not RSP? A: The first 20h bytes are reserved as a shadow stack enforcement B: The first 20h bytes are reserved as a shadow store C: They don’t, this is a trick question SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions For 64-bit, why do stack arguments start at RSP+20h and not RSP? For 64-bit, why do stack arguments start at RSP+20h and not RSP? A The first 20h bytes are reserved as a shadow stack enforcement A The first 20h bytes are reserved as a shadow stack enforcement B The first 20h bytes are reserved as a shadow store B The first 20h bytes are re

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: 64-bit, RSP+20h, shadow stack enforcement, shadow store
Summary: This unit contains a review question regarding the memory layout of 64-bit stack arguments and why they start at RSP+20h.
Excerpt:
Unit Review Answers Q: For 64-bit, why do stack arguments start at RSP+20 and not RSP? A: The first 20h bytes are reserved as a shadow stack enforcement B: The first 20h bytes are reserved as a shadow store C: They don’t, this is a trick question SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers For 64-bit, why do stack arguments start at RSP+20h and not RSP? For 64-bit, why do stack arguments start at RSP+20h and not RSP? A The first 20h bytes are reserved as a shadow stack enforcement A The first 20h bytes are reserved as a shadow stack enforcement B The first 20h bytes are reserved as a shadow store B The first 20h bytes are reserv

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: CreateProcessW, pApplication159, process creation, command-line arguments, kernel behavior
Summary: The text describes the CreateProcessW API function, detailing its parameters and behavior for creating new processes on a Windows system. It explains how to use pApplicationName and pCommandLine to specify executable paths and command-line arguments. The section also notes that a successful return value from the100% success rate of the function itself does not guarantee process startup.
Excerpt:
Create APIs (3) Creating processes on a target system can be very useful in accomplishing your objectives. The CreateProcessW API must be given a valid executable image, or it will fail. It is not as fancy as what Explorer uses behind the scenes that will determine the file type and choose the appropriate executable. If you were to double-click on a TXT file, Explorer uses the ShellExecuteEx, or similar, to search through the Registry and pick the application based on the file extension type association found for it. CreateProcessW takes nine parameters and will return TRUE upon success. The return value can be misleading because the process can still fail to start but the function returned 

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: CreateFile, ERROR_INVALID_PARAMETER, INVALID_HANDLE_VALUE
Summary: This unit contains a review question regarding the return values of the CreateFile function in Windows programming.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What does CreateFile return upon error? What does CreateFile return upon error? A A handle to the file A A handle to the file B ERROR_INVALID_PARAMETER B ERROR_INVALID_PARAMETER C INVALID_HANDLE_VALUE C INVALID_HANDLE_VALUE 190 Unit Review Questions Q: What does CreateFile return upon error? A: A handle to the file B: ERROR_INVALID_PARAMETER C: INVALID_HANDLE_VALUE 190 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: HRESULT, SUCCEEDED, FAILED, GetLastError
Summary: The unit contains a review question regarding the identification of macros used to check HRESULT function return types in Windows programming.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What macro(s) can be used to check HRESULT function return types? What macro(s) can be used to check HRESULT function return types? A SUCCEEDED / FAILED A SUCCEEDED / FAILED B GetLastError B GetLastError C STATUS_OK / STATUS_FAILED C STATUS_OK / STATUS_FAILED 192 Unit Review Questions Q: What macro(s) can be used to check HRESULT function return types? A: SUCCEEDED / FAILED B: GetLastError C: STATUS_OK / STATUS_FAILED 192 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: user-mode process, handle organization, user-mode handles
Summary: This unit contains review questions and answers regarding how user-mode processes organize handles in Windows. It specifically addresses the technical details of handle management within a process.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers How does a user-mode process organize handles? How does a user-mode process organize handles? A By storing them in a system wide table shared with other processes A By storing them in a system wide table shared with other processes B By storing them in the process handle table B By storing them in the process handle table C By leaving it up to the developer to organize and maintain C By leaving it up to the developer to organize and maintain 195 Unit Review Answers Q: How does a user-mode process organize handles? A: By storing them in a system wide table shared with other processes B:

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: WIN32_FIND_DATA, KUSER_SHARED_DATA, FILE_OBJECT
Summary: The unit contains a review question regarding the specific user-mode structure that holds file attributes in Windows.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What user-mode structure holds the attributes of a file? What user-mode structure holds the attributes of a file? A WIN32_FIND_DATA A WIN32_FIND_DATA B KUSER_SHARED_DATA B KUSER_SHARED_DATA C FILE_OBJECT C FILE_OBJECT 86 Unit Review Questions Q: What user-mode structure holds the attributes of a file? A: WIN32_FIND_DATA B: KUSER_SHARED_DATA C: FILE_OBJECT 86 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: MS-DOS 2.0 EXE Header, e_magic (4D 5A), e_lfanew at offset 0x3C, Total PE tool
Summary: The text describes the structure of the MS-DOS 2.0 EXE header within a PE file, specifically focusing on fields like e_magic and e_lfanew.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 10 MS-DOS 2.0 EXE Header: kernelbase.dll MS-DOS 2.0 EXE Header: kernelbase.dll Now that you know the structure of the DOS header, we can start to make sense of the hexdump of kernelbase.dll. The screenshot is from Visual Studio Code to see the structures and Total PE, a tool written by Pavel Yosifovich. A side-by-side layout like this can help make your way through the various PE headers and the fields inside each structure. For this IMAGE_DOS_HEADER structure, almost each field is a WORD size. Now that you know this, it is easier to identify each field and move on to the next field, you just jump two (2)

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: IMAGE_OPTIONAL_HEADER64, Magic field, PE32+, DllCharacteristics, DataDirectory, import/export entries
Summary: The text describes the structure and purpose of the IMAGE_OPTIONAL_HEADER64 for 64-bit Windows executables (PE32+). It details specific fields such as Magic, size fields, entry point, ImageBase, DllCharacteristics, and the DataDirectory.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 15 Optional Header typedef struct _IMAGE_OPTIONAL_HEADER64 { WORD Magic; // 0x20b BYTE MajorLinkerVersion; BYTE MinorLinkerVersion; DWORD SizeOfCode; SizeOfInitializedData; SizeOfUninitializedData; DWORD AddressOfEntryPoint; ULONGLONG ImageBase; WORD DllCharacteristics; ULONGLONG SizeOfStackReserve; SizeOfStackCommit; IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64; typedef struct _IMAGE_DATA_DIRECTORY { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY; Optional Header First off, there are several fi

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: Lab 3.1, GetFunctionAddress, Parse a PE file, function address
Summary: This unit describes Lab 3.1, which focuses on parsing a Portable Executable (PE) file to obtain the address of a specific function. It is part of a course on developing custom tools for Windows.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 26 Lab 3.1: GetFunctionAddress Parse a PE file to obtain the address of a given function Parse a PE file to obtain the address of a given function Please refer to the eWorkbook for the details of the lab. Lab 3.1: GetFunctionAddress Please refer to the eWorkbook for the details of the lab. 26 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: GetFunctionAddress, Parse a PE file, eWorkbook reference
Summary: The unit describes a laboratory exercise titled 'Lab 3.1: GetFunctionAddress'. It instructs students to parse a PE file to find the address of a specific function. The content refers users to an eWorkbook for further details.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Lab 3.1: GetFunctionAddress' providing instructions to refer to an eWorkbook for details. Visible text: Lab 3.1: GetFunctionAddress; Parse a PE file to obtain the address of a given function; Please refer to the eWorkbook for the details of the lab.; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: MS-DOS header, 0x00, 0x90, 0x5A
Summary: The unit contains a review question regarding the structure of MS-DOS headers in executable files. It specifically asks for the byte following the header.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 29 Unit Review Questions What is typically the next byte that comes after the MS-DOS header? What is typically the next byte that comes after the MS-DOS header? A 0x00 A 0x00 B 0x90 B 0x90 C 0x5A C 0x5A Unit Review Questions Q: What is typically the next byte that comes after the MS-DOS header? A: 0x00 B: 0x90 C: 0x5A © 2024 Jonathan Reiter 29 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: PE32+, magic value, 0x20B, 0x10B, 00B
Summary: The unit contains a multiple-choice question regarding the identification of PE32+ binaries based on their magic values. It specifically asks for the value that distinguishes these from standard PE32 binaries.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about the magic value for PE32+ binaries. Visible text: Unit Review Questions; In the optional header, what magic value indicates a PE32+ binary?; 0x20B; 0x10B; 0x00B Alt/source label:

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: PE32+, magic value, optional header, 0x20B
Summary: The unit contains review questions regarding the identification of PE32+ binary magic values in optional headers. It specifically asks for the value 0x20B.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 31 Unit Review Questions In the optional header, what magic value indicates a PE32+ binary? In the optional header, what magic value indicates a PE32+ binary? A 0x20B A 0x20B B 0x10B B 0x10B C 0x00B C 0x00B Unit Review Questions Q: In the optional header, what magic value indicates a PE32+ binary? A: 0x20B B: 0x10B C: 0x00B © 2024 Jonathan Reiter 31 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: PE32+, magic value, 00x00B, 0x10B, 0x20B
Summary: The unit contains a slide showing the correct answer to a multiple-choice question regarding PE32+ binary magic values. It specifically identifies 0x20B as the correct value.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the correct answer to a multiple-choice question about PE32+ binary magic values. Visible text: Unit Review Answers; In the optional header, what magic value indicates a PE32+ binary?; 0x20B; 0x10B; 00x00B; SEC601 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: PE32+, magic value, optional header, 0x20B
Summary: The unit contains a review question regarding the magic value for identifying PE32+ binaries in an optional header. It provides multiple-choice options and the correct answer.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 32 Unit Review Answers In the optional header, what magic value indicates a PE32+ binary? In the optional header, what magic value indicates a PE32+ binary? A 0x20B A 0x20B B 0x10B B 0x10B C 0x00B C 0x00B Unit Review Answers Q: In the optional header, what magic value indicates a PE32+ binary? A: 0x20B B: 0x10B C: 0x00B 32 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: DWORD64, R11-R15, Rip, LaufExceptionTop, CONTEXT, *CONTEXT
Summary: The unit contains a snippet of assembly-like code or data structure definitions involving 64-bit registers and context pointers.
Excerpt:
Visual caption: A snippet of assembly-like code or data structure definitions showing DWORD64 variables and a context pointer. Visible text: DWORD64 R11;; DWORD64 R12;; DWORD64 R13;; DWORD64 R14;; DWORD64 R15;; DWORD64 Rip;; .SNP; ; DWORD64 LaufExceptionTop; ; DWORD64 LaufExceptionBottom; ; CONTEXT, *CONTEXT Alt/source label:

=== UNIT 21 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: thread hijacking, Thread state, Thread context, Thread priority
Summary: The unit contains a review question regarding the technical requirements for hijacking a thread in a Windows environment. It specifically asks which construct must be modified during this process.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 77 Unit Review Questions When hijacking a thread, what construct must be modified? When hijacking a thread, what construct must be modified? A Thread state A Thread state B Thread context B Thread context C Thread priority C Thread priority Unit Review Questions Q: When hijacking a thread, what construct must be modified? A: Thread state B: Thread context C: Thread priority © 2024 Jonathan Reiter 77 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 22 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.8  Key cues: thread hijacking, Thread state, Thread context, Thread priority
Summary: This unit contains a review question regarding the technical requirements for hijacking a thread in a Windows environment. It specifically asks which construct must be modified to achieve this.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 78 Unit Review Answers When hijacking a thread, what construct must be modified? When hijacking a thread, what construct must be modified? A Thread state A Thread state B Thread context B Thread context C Thread priority C Thread priority Unit Review Answers Q: When hijacking a thread, what construct must be modified? A: Thread state B: Thread context C: Thread priority 78 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 23 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: SetNamedSecurityInfoA, SANS Institute, SEC701
Summary: The unit describes the function 'SetNamedSecurityInfoA', including its signature and parameters as part of a SANS Institute course.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'SetNamedSecurityInfoA' detailing the function signature and its parameters. Visible text: SetNamedSecurityInfoA; SANS Institute; SEC701; parameters Alt/source label:

=== UNIT 24 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: multiple-choice, function signature, native application, NTSTATUS, main()
Summary: The unit contains a multiple-choice question regarding the function signature for native applications in Windows environments. It specifically asks to identify the correct syntax among three options.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about the function signature for a native application. Visible text: Unit Review Questions; What is the function signature for a native application?; A. NTSTATUS NT_main(PEB); B. DWORD NT_main(int argc, const char* argv[]); C. INT main(int argc, const char* argv[]) Alt/source label:

=== UNIT 25 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: IMAGE_OPTIONAL_HEADER, ImageBase, PointerToSymbolTable, AddressOfEntryPoint
Summary: This unit contains a review question regarding the structure and field member that identifies the program's main function in Windows binaries.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 24 Unit Review Questions What structure and field member refers to the program’s main function? What structure and field member refers to the program’s main function? A IMAGE_OPTIONAL_HEADER.ImageBase A IMAGE_OPTIONAL_HEADER.ImageBase B IMAGE_FILE_HEADER.PointerToSymbolTable B IMAGE_FILE_HEADER.PointerToSymbolTable C IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint C IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint Unit Review Questions Q: What structure and field member refers to the program’s main function? A: IMAGE_OPTIONAL_HEADER.ImageBase B: IMAGE_FILE_HEADER.PointerToSymbolTable C: IMAGE_OPTIONAL_HEADER.AddressOf

=== UNIT 26 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: Windows executable headers, IMAGE_OPTIONAL_HEADER.ImageBase, IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint
Summary: The unit contains a multiple-choice question regarding Windows executable headers, specifically identifying the structure and field member for the program's main function.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about Windows executable headers. Visible text: Unit Review Questions; What structure and field member refers to the program's main function?; IMAGE_OPTIONAL_HEADER.ImageBase; IMAGE_FILE_HEADER.PointerToSymbolTable; IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint Alt/source label:
